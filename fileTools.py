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
import uuid
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from hikkatl.types import Message

from .. import loader, utils
from ..inline.types import InlineCall

logger = logging.getLogger(__name__)


class _SafetyLimitError(RuntimeError):
    """Отказ от обработки файла из-за превышения защитных лимитов."""



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
    MAX_TEXT_FILE_SIZE = 10 * 1024 * 1024
    MAX_PDF_RENDERED_SIZE = 200 * 1024 * 1024
    MAX_SESSIONS = 30
    MAX_ZIP_FILES = 2000
    MAX_ZIP_UNPACKED = 200 * 1024 * 1024
    MAX_ZIP_RATIO = 100
    MAX_PDF_PIXELS = 25_000_000
    MAX_CONCURRENT_CONVERSIONS = 2

    def __init__(self):
        self._sessions: Dict[str, dict] = {}
        self._tmpdirs: List[str] = []
        self._cleaner_task: Optional[asyncio.Task] = None
        self._conversion_semaphore = asyncio.Semaphore(self.MAX_CONCURRENT_CONVERSIONS)
        self._session_locks: Dict[str, asyncio.Lock] = {}
        self._unloading = False

    async def client_ready(self, client, db):
        self._unloading = False
        self._client = client
        self._db = db
        self._cleaner_task = asyncio.create_task(self._session_cleaner())

    async def on_unload(self):
        """Дожидается операций с сессиями, прежде чем удалять их временные файлы."""
        self._unloading = True
        if self._cleaner_task:
            self._cleaner_task.cancel()
            try:
                await self._cleaner_task
            except asyncio.CancelledError:
                pass
            self._cleaner_task = None

        # Не удаляем файлы, пока executor/Telegram ещё используют их.
        for sid in list(self._sessions):
            lock = self._session_locks.get(sid)
            if lock is not None:
                try:
                    await lock.acquire()
                except asyncio.CancelledError:
                    raise
                try:
                    self._kill_session(sid, delete_media=False)
                finally:
                    if lock.locked():
                        lock.release()
            else:
                self._kill_session(sid, delete_media=False)

        for td in list(self._tmpdirs):
            shutil.rmtree(td, ignore_errors=True)
        self._tmpdirs.clear()
        self._sessions.clear()
        self._session_locks.clear()

    async def _session_cleaner(self):
        """Удаляет просроченные сессии только после получения их блокировки."""
        while True:
            try:
                await asyncio.sleep(30)
                now = time.time()
                for sid in list(self._sessions):
                    lock = self._session_locks.get(sid)
                    if lock is None:
                        # Повреждённая запись реестра: удаляем только если сессия ещё существует.
                        if sid in self._sessions:
                            self._kill_session(sid)
                        continue

                    # Не проверяем lock.locked() отдельно: это создаёт race condition.
                    # Захват блокировки делает проверку и удаление атомарными относительно callback.
                    try:
                        await asyncio.wait_for(lock.acquire(), timeout=0.05)
                    except asyncio.TimeoutError:
                        continue
                    try:
                        session = self._sessions.get(sid)
                        if session and now - session.get("created", 0) > self.SESSION_TTL:
                            self._kill_session(sid)
                    finally:
                        if lock.locked():
                            lock.release()
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("session cleaner")

    def _kill_session(self, sid: str, delete_media: bool = True):
        session = self._sessions.pop(sid, None)
        self._session_locks.pop(sid, None)
        if not session:
            return
        media_id = session.get("media_msg_id")
        chat_id = session.get("chat_id")
        if delete_media and media_id and chat_id:
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
        now = time.time()
        for old_sid in list(self._sessions):
            old_lock = self._session_locks.get(old_sid)
            if (not old_lock or not old_lock.locked()) and now - self._sessions[old_sid].get("created", 0) > self.SESSION_TTL:
                self._kill_session(old_sid)
        if len(self._sessions) >= self.MAX_SESSIONS:
            raise RuntimeError("Слишком много активных сессий. Закройте старые и повторите попытку.")
        sid = uuid.uuid4().hex
        kwargs["created"] = time.time()
        self._sessions[sid] = kwargs
        self._session_locks[sid] = asyncio.Lock()
        return sid

    def _cleanup_info(self, info: Optional[dict]):
        """Безопасно удаляет временные файлы, принадлежащие одной операции."""
        if not info:
            return
        td = info.get("tmpdir")
        if td and td in self._tmpdirs:
            shutil.rmtree(td, ignore_errors=True)
            try:
                self._tmpdirs.remove(td)
            except ValueError:
                pass

    def _get_session(self, sid: str) -> Optional[dict]:
        """Возвращает живую сессию; удаление просроченных выполняет cleaner под lock."""
        session = self._sessions.get(sid)
        if not session:
            return None
        if time.time() - session.get("created", 0) > self.SESSION_TTL:
            return None
        session["created"] = time.time()
        return session

    async def _acquire_session(self, sid: str, timeout: float = 0.05):
        """Неблокирующий захват сессии. Возвращает (session, lock) или None."""
        if self._unloading:
            return None
        lock = self._session_locks.get(sid)
        if lock is None:
            return None
        try:
            await asyncio.wait_for(lock.acquire(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

        session = self._sessions.get(sid)
        if self._unloading or session is None:
            lock.release()
            return None
        if time.time() - session.get("created", 0) > self.SESSION_TTL:
            self._kill_session(sid)
            lock.release()
            return None

        session["created"] = time.time()
        return session, lock

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
        info = None
        sid = None
        try:
            info = await self._download_reply(reply)
            if info["size"] > self.MAX_FILE_SIZE:
                self._cleanup_info(info)
                return await status.edit(self.strings("file_too_big"))

            if info["size"] > self.MAX_TEXT_FILE_SIZE:
                self._cleanup_info(info)
                return await status.edit("❌ <b>Текстовый файл слишком большой</b> (лимит 10 МБ)")
            text, encoding = self._read_text_file(info["path"])
            if not text.strip():
                self._cleanup_info(info)
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
            if sid:
                self._kill_session(sid)
            else:
                self._cleanup_info(info)
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
        info = None
        sid = None
        try:
            info = await self._download_reply(reply)
            if info["size"] > self.MAX_FILE_SIZE:
                self._cleanup_info(info)
                return await status.edit(self.strings("file_too_big"))

            ext = info["ext"].lower()
            mime = (info.get("mime") or "").lower()
            if ext != ".pdf" and "pdf" not in mime:
                self._cleanup_info(info)
                return await status.edit(self.strings("unsupported_pdf"))
            with open(info["path"], "rb") as pdf_file:
                if pdf_file.read(5) != b"%PDF-":
                    self._cleanup_info(info)
                    return await status.edit(self.strings("unsupported_pdf"))

            result = await asyncio.get_running_loop().run_in_executor(
                None, self._process_pdf, info["path"]
            )

            if result is None:
                self._cleanup_info(info)
                return await status.edit(self.strings("no_pdf_engine"))

            mode, data = result
            if mode == "error":
                self._cleanup_info(info)
                if "50 страниц" in data:
                    return await status.edit(self.strings("too_many_pages"))
                return await status.edit(f"❌ <b>PDF не обработан</b>\n<code>{utils.escape_html(str(data)[:400])}</code>")
            chat_id = utils.get_chat_id(message)

            if mode == "image":
                if len(data) > self.MAX_PDF_PAGES:
                    self._cleanup_info(info)
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
                    self._cleanup_info(info)
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
            if sid:
                self._kill_session(sid)
            else:
                self._cleanup_info(info)
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
        info = None
        sid = None
        try:
            info = await self._download_reply(reply)
            if info["size"] > self.MAX_FILE_SIZE:
                self._cleanup_info(info)
                return await status.edit(self.strings("file_too_big"))

            options = self._detect_conversions(info)
            if not options:
                self._cleanup_info(info)
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
            if sid:
                self._kill_session(sid)
            else:
                self._cleanup_info(info)
            await status.edit(f"❌ <b>Ошибка</b>\n<code>{utils.escape_html(str(e)[:450])}</code>")

    # ─────────────────── Callbacks ───────────────────

    async def _close(self, call: InlineCall, sid: str):
        acquired = await self._acquire_session(sid)
        if not acquired:
            if sid not in self._sessions:
                return await call.answer(self.strings("expired"), show_alert=True)
            return await call.answer("Сначала дождитесь завершения операции", show_alert=True)
        session, lock = acquired
        try:
            # Удаляем запись и временные данные, пока эксклюзивная блокировка удерживается.
            self._kill_session(sid)
        finally:
            if lock.locked():
                lock.release()
        try:
            await call.delete()
        except Exception:
            try:
                await call.edit(self.strings("deleted"))
            except Exception:
                pass

    async def _text_nav(self, call: InlineCall, sid: str, delta: int):
        acquired = await self._acquire_session(sid)
        if not acquired:
            if sid not in self._sessions:
                return await call.answer(self.strings("expired"), show_alert=True)
            return await call.answer("Дождитесь завершения текущей операции", show_alert=True)
        session, lock = acquired
        try:
            total = len(session["pages"])
            session["current"] = (session["current"] + delta) % total
            await call.edit(
                text=self._render_text_page(sid),
                reply_markup=self._text_markup(sid),
            )
        finally:
            if lock.locked():
                lock.release()

    async def _pdf_nav(self, call: InlineCall, sid: str, delta: int):
        acquired = await self._acquire_session(sid)
        if not acquired:
            if sid not in self._sessions:
                return await call.answer(self.strings("expired"), show_alert=True)
            return await call.answer("Дождитесь завершения текущей операции", show_alert=True)
        session, lock = acquired
        try:
            total = len(session["images"])
            next_index = (session["current"] + delta) % total
            path = session["images"][next_index]
            chat_id = session["chat_id"]

            # Сначала отправляем новую страницу; старую удаляем только после успеха.
            new_msg = await self._client.send_file(
                chat_id,
                path,
                caption=self._pdf_simple_caption(
                    session["info"]["name"], next_index + 1, total, session["info"]["size"]
                ),
            )
            old_id = session.get("media_msg_id")
            session["current"] = next_index
            session["media_msg_id"] = new_msg.id
            if old_id:
                try:
                    await self._client.delete_messages(chat_id, [old_id])
                except Exception:
                    logger.warning("Не удалось удалить предыдущую страницу PDF: %s", old_id)

            await call.edit(
                text=f"📕 <b>{utils.escape_html(session['info']['name'])}</b>\nСтраница <b>{next_index + 1}/{total}</b>",
                reply_markup=self._pdf_markup(sid),
            )
        finally:
            if lock.locked():
                lock.release()

    async def _show_info(self, call: InlineCall, sid: str):
        session = self._get_session(sid)
        if not session:
            return await call.answer(self.strings("expired"), show_alert=True)
        await call.answer(self._short_info(session), show_alert=True)

    async def _do_convert(self, call: InlineCall, sid: str, target: str):
        acquired = await self._acquire_session(sid)
        if not acquired:
            if sid not in self._sessions:
                return await call.answer(self.strings("expired"), show_alert=True)
            return await call.answer("Операция уже выполняется", show_alert=True)
        session, lock = acquired
        try:
            allowed_targets = {item.get("to") for item in session.get("options", [])}
            if target not in allowed_targets:
                return await call.answer("Недопустимый формат конвертации", show_alert=True)

            await call.edit(self.strings("converting"))
            async with self._conversion_semaphore:
                out_path = await asyncio.get_running_loop().run_in_executor(
                    None, self._convert_file, session["info"], target
                )

            # Lock удерживается до отправки результата: close/cleaner не удалят tmpdir раньше.
            if self._sessions.get(sid) is not session:
                raise RuntimeError("Сессия была закрыта")
            chat_id = session.get("chat_id") or utils.get_chat_id(call)
            await self._client.send_file(
                chat_id,
                out_path,
                reply_to=session["info"].get("reply_id"),
                caption=self.strings("conv_done").format(
                    utils.escape_html(os.path.basename(out_path))
                ),
            )
            await call.edit(
                self.strings("choose_conv").format(utils.escape_html(session["info"]["name"]))
                + "\n\n" + self._conv_info_text(sid),
                reply_markup=self._conv_markup(sid),
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.exception("Convert failed")
            if self._sessions.get(sid) is session:
                try:
                    await call.edit(
                        self.strings("conv_fail").format(utils.escape_html(str(e)[:550])),
                        reply_markup=self._conv_markup(sid),
                    )
                except Exception:
                    logger.debug("Не удалось обновить сообщение после ошибки конвертации", exc_info=True)
            else:
                try:
                    await call.edit(self.strings("expired"))
                except Exception:
                    pass
        finally:
            if lock.locked():
                lock.release()

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
        """Скачивает файл в изолированную временную директорию с проверками размера."""
        media = getattr(reply, "file", None)
        declared_size = getattr(media, "size", None)
        if declared_size is not None:
            try:
                if int(declared_size) > self.MAX_FILE_SIZE:
                    raise ValueError("Файл слишком большой (лимит 80 МБ)")
            except (TypeError, ValueError):
                if isinstance(declared_size, (int, float)) and declared_size > self.MAX_FILE_SIZE:
                    raise ValueError("Файл слишком большой (лимит 80 МБ)")

        td = tempfile.mkdtemp(prefix="ft_")
        self._tmpdirs.append(td)
        try:
            downloaded = await reply.download_media(file=td)
            if not downloaded:
                raise RuntimeError("Telegram не вернул путь к скачанному файлу")
            path = os.path.realpath(str(downloaded))
            root = os.path.realpath(td)
            if os.path.commonpath((root, path)) != root:
                raise RuntimeError("Некорректный путь загруженного файла")
            if not os.path.isfile(path):
                raise RuntimeError("Скачанный файл не найден")

            size = os.path.getsize(path)
            if size <= 0:
                raise ValueError("Файл пустой")
            if size > self.MAX_FILE_SIZE:
                raise ValueError("Файл слишком большой (лимит 80 МБ)")

            original_name = os.path.basename(path)
            # Убираем управляющие символы и опасные разделители из отображаемого имени.
            name = "".join(ch for ch in original_name if ch.isprintable() and ch not in "\\/")[:180] or "file"
            ext = Path(name).suffix[:16]
            mime = (
                getattr(media, "mime_type", None)
                or mimetypes.guess_type(name)[0]
                or "application/octet-stream"
            )
            return {
                "path": path,
                "name": name,
                "ext": ext,
                "mime": str(mime)[:128],
                "size": size,
                "reply_id": getattr(reply, "id", None),
                "tmpdir": td,
            }
        except Exception:
            self._cleanup_info({"tmpdir": td})
            raise

    def _safe_extract_zip(self, src: str, destination: str):
        """Распаковка ZIP с защитой от path traversal, symlink и ZIP-бомб."""
        root = Path(destination).resolve()
        os.makedirs(root, exist_ok=True)
        total_size = 0
        entries = []

        with zipfile.ZipFile(src, "r") as archive:
            infos = archive.infolist()
            if len(infos) > self.MAX_ZIP_FILES:
                raise RuntimeError("В архиве слишком много файлов")

            for info in infos:
                name = info.filename.replace("\\", "/")
                member = Path(name)
                if (not name or not member.parts or name.startswith("/") or member.is_absolute()
                        or ".." in member.parts or ":" in member.parts[0]):
                    raise RuntimeError("Архив содержит небезопасный путь")
                mode = (info.external_attr >> 16) & 0xFFFF
                if (mode & 0o170000) == 0o120000:
                    raise RuntimeError("Символические ссылки в ZIP запрещены")
                if info.flag_bits & 0x1:
                    raise RuntimeError("Зашифрованные ZIP-файлы не поддерживаются")
                total_size += info.file_size
                if total_size > self.MAX_ZIP_UNPACKED:
                    raise RuntimeError("Распакованный архив превышает лимит 200 МБ")
                if info.file_size and info.compress_size == 0:
                    raise RuntimeError("Подозрительная степень сжатия в ZIP")
                if info.compress_size and info.file_size / info.compress_size > self.MAX_ZIP_RATIO:
                    raise RuntimeError("Подозрительная степень сжатия в ZIP")
                target = (root / member).resolve()
                if os.path.commonpath((str(root), str(target))) != str(root):
                    raise RuntimeError("Архив пытается записать файл за пределами папки")
                entries.append((info, target))

            actual_total = 0
            for info, target in entries:
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with archive.open(info, "r") as source, open(target, "xb") as output:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        written += len(chunk)
                        actual_total += len(chunk)
                        if written > info.file_size or actual_total > self.MAX_ZIP_UNPACKED:
                            raise RuntimeError("Некорректный или слишком большой ZIP-архив")
                        output.write(chunk)

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
            f"Файл: {utils.escape_html(info['name'])}",
            f"Размер: {self._human(info['size'])}",
            f"Тип: {utils.escape_html(info['mime'])}",
            f"Расширение: {utils.escape_html(info['ext'] or '—')}",
        ]

        if session["mode"] == "text":
            parts += [
                f"Кодировка: {utils.escape_html(session.get('encoding', '?'))}",
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
        """Возвращает ("image", [paths]), ("text", [pages]), error или None."""
        doc = None
        try:
            import fitz
            doc = fitz.open(path)
            if doc.page_count > self.MAX_PDF_PAGES:
                doc.close()
                raise _SafetyLimitError("PDF содержит больше 50 страниц")
            images = []
            rendered_size = 0
            mat = fitz.Matrix(1.2, 1.2)
            for i, page in enumerate(doc):
                rect = page.rect
                estimated_pixels = int(rect.width * 1.2) * int(rect.height * 1.2)
                if estimated_pixels > self.MAX_PDF_PIXELS:
                    raise _SafetyLimitError("Страница PDF слишком большая для безопасного рендеринга")
                pix = page.get_pixmap(matrix=mat, alpha=False)
                out = os.path.join(os.path.dirname(path), f"p_{i+1:03d}.jpg")
                pix.save(out, output="jpeg", jpg_quality=80)
                rendered_size += os.path.getsize(out)
                if rendered_size > self.MAX_PDF_RENDERED_SIZE:
                    raise _SafetyLimitError("Общий размер изображений PDF превышает лимит 200 МБ")
                images.append(out)
            doc.close()
            doc = None
            if images:
                return "image", images
        except _SafetyLimitError as e:
            if doc is not None:
                doc.close()
            logger.warning("PDF rejected by safety limits: %s", e)
            return "error", str(e)
        except Exception as e:
            if doc is not None:
                try:
                    doc.close()
                except Exception:
                    pass
            logger.debug(f"fitz failed: {e}")

        try:
            from pypdf import PdfReader
            reader = PdfReader(path, strict=True)
            if len(reader.pages) > self.MAX_PDF_PAGES:
                raise _SafetyLimitError("PDF содержит больше 50 страниц")
            pages = []
            extracted_chars = 0
            for page in reader.pages:
                text = (page.extract_text() or "").strip()
                extracted_chars += len(text)
                if extracted_chars > 2_000_000:
                    raise _SafetyLimitError("В PDF слишком много извлекаемого текста")
                pages.append(text or "(пустая страница)")
            if pages:
                return "text", pages
        except _SafetyLimitError as e:
            logger.warning("PDF rejected by safety limits: %s", e)
            return "error", str(e)
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
                [soffice, "--headless", "--norestore", "--nodefault", "--nolockcheck", "--convert-to", "pdf", "--outdir", out_dir, src],
                capture_output=True, text=True, timeout=120, stdin=subprocess.DEVNULL
            )
            if proc.returncode != 0:
                raise RuntimeError((proc.stderr or proc.stdout or "ошибка")[:700])
            out = os.path.join(out_dir, stem + ".pdf")
            if not os.path.isfile(out) or os.path.getsize(out) <= 0:
                raise RuntimeError("PDF не создан или пуст")
            if os.path.getsize(out) > self.MAX_FILE_SIZE * 4:
                raise RuntimeError("Результат конвертации превышает допустимый размер")
            return out

        if shutil.which("pandoc") and target in {"html", "md", "txt", "docx"}:
            out = os.path.join(out_dir, f"{stem}.{target}")
            proc = subprocess.run(["pandoc", src, "-o", out], capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
            if proc.returncode != 0:
                raise RuntimeError((proc.stderr or proc.stdout or "pandoc")[:700])
            if not os.path.isfile(out) or os.path.getsize(out) <= 0:
                raise RuntimeError("Pandoc не создал результат")
            if os.path.getsize(out) > self.MAX_FILE_SIZE * 4:
                raise RuntimeError("Результат конвертации превышает допустимый размер")
            return out

        if shutil.which("ffmpeg") and target in {
            "png", "jpg", "webp", "mp3", "wav", "ogg", "flac", "mp4", "mkv", "webm", "gif"
        }:
            out = os.path.join(out_dir, f"{stem}.{target}")
            cmd = ["ffmpeg", "-nostdin", "-v", "error", "-y", "-threads", "2", "-max_pixels", "25000000", "-i", src]
            if target in {"mp3", "wav", "ogg", "flac"}:
                cmd += ["-vn"]
            if target == "gif":
                cmd += ["-vf", "fps=8,scale=480:-1:flags=lanczos"]
            cmd += ["-fs", str(self.MAX_FILE_SIZE * 4), out]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180, stdin=subprocess.DEVNULL)
            if proc.returncode != 0:
                raise RuntimeError((proc.stderr or proc.stdout or "ffmpeg")[:700])
            if not os.path.isfile(out) or os.path.getsize(out) <= 0:
                raise RuntimeError("FFmpeg не создал результат")
            if os.path.getsize(out) > self.MAX_FILE_SIZE * 4:
                raise RuntimeError("Результат конвертации превышает допустимый размер")
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
            if os.path.getsize(out) > self.MAX_FILE_SIZE * 4:
                os.remove(out)
                raise RuntimeError("Результат конвертации превышает допустимый размер")
            return out

        if target == "unzip" and ext == "zip":
            folder = os.path.join(out_dir, stem + "_out_" + uuid.uuid4().hex[:8])
            os.makedirs(folder, exist_ok=True)
            try:
                self._safe_extract_zip(src, folder)
            except Exception:
                shutil.rmtree(folder, ignore_errors=True)
                raise
            zip_out = os.path.join(out_dir, stem + "_extracted.zip")
            with zipfile.ZipFile(zip_out, "w", zipfile.ZIP_DEFLATED) as zout:
                for root, _, files in os.walk(folder):
                    for file in files:
                        fp = os.path.join(root, file)
                        zout.write(fp, os.path.relpath(fp, folder))
            if not os.path.isfile(zip_out) or os.path.getsize(zip_out) > self.MAX_FILE_SIZE * 4:
                raise RuntimeError("Результат распаковки слишком большой")
            return zip_out

        raise RuntimeError(f"Конвертация в {target} недоступна")
