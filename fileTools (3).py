# meta developer: @Scp079Modules
# meta banner: https://raw.githubusercontent.com/hikariatama/assets/master/FileTools.jpg
# scope: hikka_min 1.6.0
# requires: pypdf

import asyncio
import json
import logging
import mimetypes
import os
import shutil
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from hikkatl.types import Message

from .. import loader, utils
from ..inline.types import InlineCall

logger = logging.getLogger(__name__)


@loader.tds
class FileToolsMod(loader.Module):
    """Инструменты для работы с файлами: чтение текста, просмотр PDF и конвертация"""

    strings = {
        "name": "FileTools",
        "no_reply": "❌ <b>Ответь на сообщение с файлом</b>",
        "no_file": "❌ <b>В реплае нет файла</b>",
        "downloading": "⏳ <b>Скачиваю файл…</b>",
        "rendering": "⏳ <b>Обрабатываю PDF…</b>",
        "converting": "⏳ <b>Конвертирую…</b>",
        "deleted": "🗑 <b>Удалено</b>",
        "expired": "❌ Сессия устарела",
        "unsupported_pdf": "❌ <b>Это не PDF</b>",
        "empty": "❌ <b>Файл пустой</b>",
        "reply_needed": "❌ <b>Используй команду ответом на файл</b>",
        "conv_done": "✅ <b>Готово:</b> <code>{}</code>",
        "conv_fail": "❌ <b>Конвертация не удалась</b>\n<code>{}</code>",
        "deps_missing": "❌ <b>Нет доступных конвертаций</b>\n<code>{}</code>",
        "choose_conv": "✨ <b>Конвертация файла</b>\n\nВыбери формат для <code>{}</code>",
        "too_many_pages": "❌ <b>Слишком много страниц</b> (лимит 50)",
        "file_too_big": "❌ <b>Файл слишком большой</b> (лимит 80 МБ)",
        "no_pdf_engine": (
            "❌ <b>Нет движка для PDF</b>\n\n"
            "Установи:\n"
            "• <code>pip install pymupdf</code> (с картинками)\n"
            "• <code>pip install pypdf</code> (только текст)"
        ),
    }

    strings_ru = strings

    SESSION_TTL = 50 * 60
    MAX_PDF_PAGES = 50
    MAX_FILE_SIZE = 80 * 1024 * 1024

    def __init__(self):
        self._sessions: Dict[str, dict] = {}
        self._tmpdirs: List[str] = []
        self._cleaner_task: Optional[asyncio.Task] = None

    async def client_ready(self, client, db):
        self._client = client
        self._db = db
        self._cleaner_task = asyncio.create_task(self._session_cleaner())

    async def on_unload(self):
        if self._cleaner_task:
            self._cleaner_task.cancel()
        for td in list(self._tmpdirs):
            shutil.rmtree(td, ignore_errors=True)
        self._sessions.clear()

    async def _session_cleaner(self):
        while True:
            try:
                await asyncio.sleep(120)
                now = time.time()
                for sid in list(self._sessions):
                    if now - self._sessions[sid].get("created", 0) > self.SESSION_TTL:
                        self._kill_session(sid)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("session cleaner")

    def _kill_session(self, sid: str):
        session = self._sessions.pop(sid, None)
        if not session:
            return
        media_id = session.get("media_msg_id")
        chat_id = session.get("chat_id")
        if media_id and chat_id:
            try:
                asyncio.create_task(self._client.delete_messages(chat_id, [media_id]))
            except Exception:
                pass
        td = session.get("info", {}).get("tmpdir")
        if td and os.path.isdir(td):
            shutil.rmtree(td, ignore_errors=True)
            if td in self._tmpdirs:
                try:
                    self._tmpdirs.remove(td)
                except ValueError:
                    pass

    def _new_session(self, **kwargs) -> str:
        sid = f"{int(time.time() * 1000)}_{len(self._sessions)}"
        kwargs["created"] = time.time()
        self._sessions[sid] = kwargs
        return sid

    def _get_session(self, sid: str) -> Optional[dict]:
        s = self._sessions.get(sid)
        if not s:
            return None
        if time.time() - s.get("created", 0) > self.SESSION_TTL:
            self._kill_session(sid)
            return None
        s["created"] = time.time()
        return s

    # ─────────────────── Команды ───────────────────

    @loader.command(ru_doc="Читать текстовый файл по страницам")
    async def rfcmd(self, message: Message):
        """Читает текстовый файл из реплая и показывает его по страницам с кнопками навигации"""
        reply = await message.get_reply_message()
        if not reply:
            return await utils.answer(message, self.strings("reply_needed"))
        if not getattr(reply, "file", None):
            return await utils.answer(message, self.strings("no_file"))

        status = await utils.answer(message, self.strings("downloading"))
        try:
            info = await self._download_reply(reply)
            if info["size"] > self.MAX_FILE_SIZE:
                return await status.edit(self.strings("file_too_big"))

            text, encoding = self._read_text_file(info["path"])
            if not text.strip():
                return await status.edit(self.strings("empty"))

            pages = self._split_text(text)
            sid = self._new_session(
                mode="text",
                info=info,
                pages=pages,
                encoding=encoding,
                current=0,
                chat_id=utils.get_chat_id(message),
            )

            await self.inline.form(
                message=status,
                text=self._render_text_page(sid),
                reply_markup=self._text_markup(sid),
                force_me=True,
                silent=True,
            )
        except Exception as e:
            logger.exception("RF")
            await status.edit(f"❌ <b>Ошибка</b>\n<code>{utils.escape_html(str(e)[:450])}</code>")

    @loader.command(ru_doc="Просмотр PDF по страницам")
    async def rpdfcmd(self, message: Message):
        """Открывает PDF из реплая. Показывает страницы картинками (если есть pymupdf) или текстом"""
        reply = await message.get_reply_message()
        if not reply:
            return await utils.answer(message, self.strings("reply_needed"))
        if not getattr(reply, "file", None):
            return await utils.answer(message, self.strings("no_file"))

        status = await utils.answer(message, self.strings("rendering"))
        try:
            info = await self._download_reply(reply)
            if info["size"] > self.MAX_FILE_SIZE:
                return await status.edit(self.strings("file_too_big"))

            ext = info["ext"].lower()
            mime = (info.get("mime") or "").lower()
            if ext != ".pdf" and "pdf" not in mime:
                return await status.edit(self.strings("unsupported_pdf"))

            result = await asyncio.get_running_loop().run_in_executor(
                None, self._process_pdf, info["path"]
            )

            if result is None:
                return await status.edit(self.strings("no_pdf_engine"))

            mode, data = result
            chat_id = utils.get_chat_id(message)

            if mode == "image":
                if len(data) > self.MAX_PDF_PAGES:
                    return await status.edit(self.strings("too_many_pages"))

                first_msg = await self._client.send_file(
                    chat_id,
                    data[0],
                    caption=self._pdf_simple_caption(info["name"], 1, len(data), info["size"]),
                )

                sid = self._new_session(
                    mode="pdf",
                    info=info,
                    images=data,
                    current=0,
                    chat_id=chat_id,
                    media_msg_id=first_msg.id,
                )

                await self.inline.form(
                    message=status,
                    text=f"📕 <b>{utils.escape_html(info['name'])}</b>\nСтраница <b>1/{len(data)}</b>",
                    reply_markup=self._pdf_markup(sid),
                    force_me=True,
                    silent=True,
                )
            else:
                pages = data
                if not any(p.strip() for p in pages):
                    return await status.edit(self.strings("empty"))

                sid = self._new_session(
                    mode="text",
                    info=info,
                    pages=pages,
                    encoding="pdf-text",
                    current=0,
                    chat_id=chat_id,
                )

                await self.inline.form(
                    message=status,
                    text=self._render_text_page(sid),
                    reply_markup=self._text_markup(sid),
                    force_me=True,
                    silent=True,
                )

        except Exception as e:
            logger.exception("RPDF")
            await status.edit(f"❌ <b>Ошибка PDF</b>\n<code>{utils.escape_html(str(e)[:500])}</code>")

    @loader.command(ru_doc="Конвертировать файл в другой формат")
    async def convcmd(self, message: Message):
        """Конвертирует файл из реплая (документы, картинки, аудио, видео, архивы)"""
        reply = await message.get_reply_message()
        if not reply:
            return await utils.answer(message, self.strings("reply_needed"))
        if not getattr(reply, "file", None):
            return await utils.answer(message, self.strings("no_file"))

        status = await utils.answer(message, self.strings("downloading"))
        try:
            info = await self._download_reply(reply)
            if info["size"] > self.MAX_FILE_SIZE:
                return await status.edit(self.strings("file_too_big"))

            options = self._detect_conversions(info)
            if not options:
                return await status.edit(
                    self.strings("deps_missing").format("для этого типа файла нет конвертаций")
                )

            sid = self._new_session(
                mode="conv",
                info=info,
                options=options,
                chat_id=utils.get_chat_id(message),
            )

            await self.inline.form(
                message=status,
                text=self.strings("choose_conv").format(utils.escape_html(info["name"]))
                     + "\n\n" + self._conv_info_text(sid),
                reply_markup=self._conv_markup(sid),
                force_me=True,
                silent=True,
            )
        except Exception as e:
            logger.exception("CONV")
            await status.edit(f"❌ <b>Ошибка</b>\n<code>{utils.escape_html(str(e)[:450])}</code>")

    # ─────────────────── Callbacks ───────────────────

    async def _close(self, call: InlineCall, sid: str):
        self._kill_session(sid)
        try:
            await call.delete()
        except Exception:
            try:
                await call.edit(self.strings("deleted"))
            except Exception:
                pass

    async def _text_nav(self, call: InlineCall, sid: str, delta: int):
        session = self._get_session(sid)
        if not session:
            return await call.answer(self.strings("expired"), show_alert=True)
        total = len(session["pages"])
        session["current"] = (session["current"] + delta) % total
        await call.edit(
            text=self._render_text_page(sid),
            reply_markup=self._text_markup(sid),
        )

    async def _pdf_nav(self, call: InlineCall, sid: str, delta: int):
        session = self._get_session(sid)
        if not session:
            return await call.answer(self.strings("expired"), show_alert=True)

        total = len(session["images"])
        session["current"] = (session["current"] + delta) % total
        idx = session["current"]
        path = session["images"][idx]
        chat_id = session["chat_id"]

        old_id = session.get("media_msg_id")
        if old_id:
            try:
                await self._client.delete_messages(chat_id, [old_id])
            except Exception:
                pass

        new_msg = await self._client.send_file(
            chat_id,
            path,
            caption=self._pdf_simple_caption(
                session["info"]["name"], idx + 1, total, session["info"]["size"]
            ),
        )
        session["media_msg_id"] = new_msg.id

        await call.edit(
            text=f"📕 <b>{utils.escape_html(session['info']['name'])}</b>\nСтраница <b>{idx+1}/{total}</b>",
            reply_markup=self._pdf_markup(sid),
        )

    async def _show_info(self, call: InlineCall, sid: str):
        session = self._get_session(sid)
        if not session:
            return await call.answer(self.strings("expired"), show_alert=True)
        await call.answer(self._short_info(session), show_alert=True)

    async def _do_convert(self, call: InlineCall, sid: str, target: str):
        session = self._get_session(sid)
        if not session:
            return await call.answer(self.strings("expired"), show_alert=True)

        await call.edit(self.strings("converting"))

        try:
            out_path = await asyncio.get_running_loop().run_in_executor(
                None, self._convert_file, session["info"], target
            )

            chat_id = session.get("chat_id") or utils.get_chat_id(call)

            await self._client.send_file(
                chat_id,
                out_path,
                reply_to=session["info"].get("reply_id"),
                caption=self.strings("conv_done").format(os.path.basename(out_path)),
            )

            await call.edit(
                self.strings("choose_conv").format(utils.escape_html(session["info"]["name"]))
                + "\n\n" + self._conv_info_text(sid),
                reply_markup=self._conv_markup(sid),
            )
        except Exception as e:
            logger.exception("Convert failed")
            await call.edit(
                self.strings("conv_fail").format(utils.escape_html(str(e)[:550])),
                reply_markup=self._conv_markup(sid),
            )

    # ─────────────────── Markup ───────────────────

    def _text_markup(self, sid: str):
        s = self._sessions[sid]
        total = len(s["pages"])
        rows = []
        if total > 1:
            rows.append([
                {"text": "◀️", "callback": self._text_nav, "args": (sid, -1)},
                {"text": f"{s['current']+1}/{total}", "callback": self._show_info, "args": (sid,)},
                {"text": "▶️", "callback": self._text_nav, "args": (sid, 1)},
            ])
        rows.append([
            {"text": "ℹ️", "callback": self._show_info, "args": (sid,)},
            {"text": "🗑", "callback": self._close, "args": (sid,)},
        ])
        return rows

    def _pdf_markup(self, sid: str):
        s = self._sessions[sid]
        total = len(s["images"])
        rows = []
        if total > 1:
            rows.append([
                {"text": "◀️", "callback": self._pdf_nav, "args": (sid, -1)},
                {"text": f"{s['current']+1}/{total}", "callback": self._show_info, "args": (sid,)},
                {"text": "▶️", "callback": self._pdf_nav, "args": (sid, 1)},
            ])
        rows.append([
            {"text": "ℹ️", "callback": self._show_info, "args": (sid,)},
            {"text": "🗑", "callback": self._close, "args": (sid,)},
        ])
        return rows

    def _conv_markup(self, sid: str):
        s = self._sessions[sid]
        rows = []
        row = []
        for opt in s["options"]:
            row.append({
                "text": f"🔄 {opt['to'].upper()}",
                "callback": self._do_convert,
                "args": (sid, opt["to"]),
            })
            if len(row) == 2:
                rows.append(row)
                row = []
        if row:
            rows.append(row)
        rows.append([{"text": "ℹ️", "callback": self._show_info, "args": (sid,)}])
        rows.append([{"text": "🗑 Закрыть", "callback": self._close, "args": (sid,)}])
        return rows

    # ─────────────────── Helpers ───────────────────

    async def _download_reply(self, reply) -> dict:
        td = tempfile.mkdtemp(prefix="ft_")
        self._tmpdirs.append(td)
        path = str(await reply.download_media(file=td))
        name = os.path.basename(path)
        ext = Path(name).suffix or ""
        mime = (
            getattr(getattr(reply, "file", None), "mime_type", None)
            or mimetypes.guess_type(name)[0]
            or "application/octet-stream"
        )
        size = os.path.getsize(path) if os.path.exists(path) else 0
        return {
            "path": path,
            "name": name,
            "ext": ext,
            "mime": mime,
            "size": size,
            "reply_id": getattr(reply, "id", None),
            "tmpdir": td,
        }

    def _read_text_file(self, path: str) -> Tuple[str, str]:
        with open(path, "rb") as f:
            raw = f.read()
        if not raw:
            return "", "unknown"
        for enc in ("utf-8", "utf-16", "utf-16-le", "utf-16-be", "cp1251", "latin-1"):
            try:
                text = raw.decode(enc)
                if "\x00" not in text[:2500]:
                    return text, enc
            except Exception:
                continue
        try:
            import chardet
            guess = chardet.detect(raw).get("encoding")
            if guess:
                return raw.decode(guess, errors="replace"), guess
        except Exception:
            pass
        if b"\x00" in raw[:4096]:
            raise ValueError("Бинарный файл")
        return raw.decode("utf-8", errors="replace"), "utf-8?"

    def _split_text(self, text: str, limit: int = 3500) -> List[str]:
        text = text.replace("\r\n", "\n")
        chunks, cur = [], ""
        for line in text.split("\n"):
            if len(cur) + len(line) + 1 > limit:
                if cur:
                    chunks.append(cur)
                    cur = ""
                while len(line) > limit:
                    chunks.append(line[:limit])
                    line = line[limit:]
            cur += ("\n" if cur else "") + line
        if cur:
            chunks.append(cur)
        return chunks or [text[:limit]]

    def _render_text_page(self, sid: str) -> str:
        s = self._sessions[sid]
        idx = s["current"]
        total = len(s["pages"])
        info = s["info"]

        header = (
            f"📄 <b>{utils.escape_html(info['name'])}</b>\n"
            f"╭ <b>Размер:</b> <code>{self._human(info['size'])}</code>\n"
            f"├ <b>Тип:</b> <code>{utils.escape_html(info['mime'])}</code>\n"
            f"├ <b>Кодировка:</b> <code>{utils.escape_html(s.get('encoding', '?'))}</code>\n"
            f"╰ <b>Страница:</b> <code>{idx + 1}/{total}</code>\n\n"
        )
        return header + f"<pre>{utils.escape_html(s['pages'][idx])}</pre>"

    def _pdf_simple_caption(self, name: str, current: int, total: int, size: int = 0) -> str:
        size_str = f" • {self._human(size)}" if size else ""
        return f"📕 <b>{utils.escape_html(name)}</b>\nСтраница {current}/{total}{size_str}"

    def _conv_info_text(self, sid: str) -> str:
        s = self._sessions[sid]
        info = s["info"]
        lines = [
            f"📦 <b>Файл:</b> <code>{utils.escape_html(info['name'])}</code>",
            f"🧩 <b>Тип:</b> <code>{utils.escape_html(info['mime'])}</code>",
            f"⚖️ <b>Размер:</b> <code>{self._human(info['size'])}</code>",
            "",
            "<b>Доступные конвертации:</b>",
        ]
        for o in s["options"]:
            lines.append(f"• <code>{o['to']}</code> — {o['label']}")
        return "\n".join(lines)

    def _short_info(self, session: dict) -> str:
        info = session["info"]
        parts = [
            f"Файл: {info['name']}",
            f"Размер: {self._human(info['size'])}",
            f"Тип: {info['mime']}",
            f"Расширение: {info['ext'] or '—'}",
        ]

        if session["mode"] == "text":
            parts += [
                f"Кодировка: {session.get('encoding', '?')}",
                f"Страниц: {len(session['pages'])}",
                f"Текущая страница: {session['current'] + 1}",
            ]
        elif session["mode"] == "pdf":
            parts += [
                f"Страниц PDF: {len(session['images'])}",
                f"Текущая страница: {session['current'] + 1}",
            ]
        elif session["mode"] == "conv":
            parts.append("Доступные конвертации:")
            for o in session.get("options", [])[:8]:
                parts.append(f"  → {o['to']}")

        return "\n".join(parts)[:3900]

    def _human(self, size: int) -> str:
        """Правильный человекочитаемый размер"""
        if size < 0:
            size = 0
        if size < 1024:
            return f"{size} B"
        for unit in ("KB", "MB", "GB", "TB"):
            size /= 1024.0
            if size < 1024.0 or unit == "TB":
                if size < 10:
                    return f"{size:.2f} {unit}"
                return f"{size:.1f} {unit}"
        return f"{size:.1f} PB"

    def _process_pdf(self, path: str):
        """Возвращает ("image", [paths]) или ("text", [pages]) или None"""
        try:
            import fitz
            doc = fitz.open(path)
            images = []
            mat = fitz.Matrix(1.7, 1.7)
            for i, page in enumerate(doc):
                if i >= self.MAX_PDF_PAGES:
                    break
                pix = page.get_pixmap(matrix=mat, alpha=False)
                out = os.path.join(os.path.dirname(path), f"p_{i+1:03d}.jpg")
                pix.save(out, output="jpeg", jpg_quality=80)
                images.append(out)
            doc.close()
            if images:
                return "image", images
        except Exception as e:
            logger.debug(f"fitz failed: {e}")

        try:
            from pypdf import PdfReader
            reader = PdfReader(path)
            pages = []
            for i, page in enumerate(reader.pages):
                if i >= self.MAX_PDF_PAGES:
                    break
                text = (page.extract_text() or "").strip()
                pages.append(text or "(пустая страница)")
            if pages:
                return "text", pages
        except Exception as e:
            logger.debug(f"pypdf failed: {e}")

        return None

    def _detect_conversions(self, info: dict) -> List[dict]:
        ext = info["ext"].lower().lstrip(".")
        has_ffmpeg = bool(shutil.which("ffmpeg"))
        has_soffice = bool(shutil.which("soffice") or shutil.which("libreoffice"))
        has_pandoc = bool(shutil.which("pandoc"))

        options = []
        office = {"doc", "docx", "odt", "rtf", "ppt", "pptx", "odp", "xls", "xlsx", "ods"}
        textish = {"txt", "md", "json", "xml", "html", "htm", "css", "js", "py", "java", "c", "cpp", "go", "rs", "sh", "php", "sql", "csv", "log", "yaml", "yml"}
        image = {"png", "jpg", "jpeg", "webp", "bmp", "tiff", "gif"}
        audio = {"mp3", "wav", "ogg", "flac", "m4a", "aac"}
        video = {"mp4", "mkv", "avi", "mov", "webm", "flv"}

        if ext in office and has_soffice:
            options.append({"to": "pdf", "label": "→ PDF", "engine": "soffice"})
        if ext in {"docx", "odt", "md", "html", "txt"} and has_pandoc:
            for to in ("html", "md", "txt", "docx"):
                if to != ext:
                    options.append({"to": to, "label": "Pandoc", "engine": "pandoc"})
        if ext in image and has_ffmpeg:
            for to in ("png", "jpg", "webp"):
                if to != ext:
                    options.append({"to": to, "label": "Картинка", "engine": "ffmpeg"})
        if ext in audio and has_ffmpeg:
            for to in ("mp3", "wav", "ogg", "flac"):
                if to != ext:
                    options.append({"to": to, "label": "Аудио", "engine": "ffmpeg"})
        if ext in video and has_ffmpeg:
            for to in ("mp4", "mkv", "webm", "mp3", "gif"):
                if to != ext:
                    options.append({"to": to, "label": "Видео", "engine": "ffmpeg"})
        if ext in textish:
            for to in ("txt", "md", "html", "json"):
                if to != ext:
                    options.append({"to": to, "label": "Текст", "engine": "builtin"})
        if ext == "zip":
            options.append({"to": "unzip", "label": "Распаковать", "engine": "unzip"})

        seen = set()
        uniq = []
        for o in options:
            key = (o["to"], o["engine"])
            if key not in seen:
                seen.add(key)
                uniq.append(o)
        return uniq[:14]

    def _convert_file(self, info: dict, target: str) -> str:
        src = info["path"]
        ext = info["ext"].lower().lstrip(".")
        out_dir = info["tmpdir"]
        stem = Path(src).stem

        if target == "pdf":
            soffice = shutil.which("soffice") or shutil.which("libreoffice")
            if not soffice:
                raise RuntimeError("LibreOffice не найден")
            proc = subprocess.run(
                [soffice, "--headless", "--convert-to", "pdf", "--outdir", out_dir, src],
                capture_output=True, text=True, timeout=120
            )
            if proc.returncode != 0:
                raise RuntimeError((proc.stderr or proc.stdout or "ошибка")[:700])
            out = os.path.join(out_dir, stem + ".pdf")
            if not os.path.exists(out):
                raise RuntimeError("PDF не создан")
            return out

        if shutil.which("pandoc") and target in {"html", "md", "txt", "docx"}:
            out = os.path.join(out_dir, f"{stem}.{target}")
            proc = subprocess.run(["pandoc", src, "-o", out], capture_output=True, text=True, timeout=60)
            if proc.returncode != 0:
                raise RuntimeError((proc.stderr or proc.stdout or "pandoc")[:700])
            return out

        if shutil.which("ffmpeg") and target in {
            "png", "jpg", "webp", "mp3", "wav", "ogg", "flac", "mp4", "mkv", "webm", "gif"
        }:
            out = os.path.join(out_dir, f"{stem}.{target}")
            cmd = ["ffmpeg", "-y", "-i", src]
            if target in {"mp3", "wav", "ogg", "flac"}:
                cmd += ["-vn"]
            if target == "gif":
                cmd += ["-vf", "fps=8,scale=480:-1:flags=lanczos"]
            cmd.append(out)
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
            if proc.returncode != 0:
                raise RuntimeError((proc.stderr or proc.stdout or "ffmpeg")[:700])
            return out

        if target in {"txt", "md", "html", "json"}:
            text, _ = self._read_text_file(src)
            out = os.path.join(out_dir, f"{stem}.{target}")
            with open(out, "w", encoding="utf-8") as f:
                if target == "json":
                    json.dump({"name": info["name"], "content": text}, f, ensure_ascii=False, indent=2)
                elif target == "html":
                    f.write(f"<html><body><pre>{utils.escape_html(text)}</pre></body></html>")
                elif target == "md":
                    f.write("```\n" + text + "\n```")
                else:
                    f.write(text)
            return out

        if target == "unzip" and ext == "zip":
            folder = os.path.join(out_dir, stem + "_out")
            os.makedirs(folder, exist_ok=True)
            with zipfile.ZipFile(src, "r") as zf:
                zf.extractall(folder)
            zip_out = os.path.join(out_dir, stem + "_extracted.zip")
            with zipfile.ZipFile(zip_out, "w", zipfile.ZIP_DEFLATED) as zout:
                for root, _, files in os.walk(folder):
                    for file in files:
                        fp = os.path.join(root, file)
                        zout.write(fp, os.path.relpath(fp, folder))
            return zip_out

        raise RuntimeError(f"Конвертация в {target} недоступна")