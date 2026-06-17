# modules/vtcheck.py
# meta developer: @Scp079Modules
# meta banner: https://www.malwarebytes.com/wp-content/uploads/sites/2/2021/05/asset_upload_file13254_232175.png
# License: MIT - You can modify this file but must keep author credit

import asyncio
import base64
import hashlib
import math
import os
import re
import tempfile
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import aiohttp
from hikka import loader, utils

VT_API = "https://www.virustotal.com/api/v3"
CACHE_TTL = 60 * 20
BIG_FILE_THRESHOLD = 32 * 1024 * 1024
MAX_FILE_SIZE_HARD = 650 * 1024 * 1024
PAGE_SIZE = 10
HISTORY_PAGE_SIZE = 8
HTTP_TOTAL_TIMEOUT = 180
ANALYSIS_POLLS = 20
ANALYSIS_DELAY = 8
HISTORY_DB_KEY = "vtchecker_history"


@dataclass
class CachedResult:
    created_at: float
    data: dict


@loader.tds
class VirusTotalChecker(loader.Module):
    """VirusTotal module for hash, file, and URL analysis via the VT API"""

    strings = {"name": "VirusTotalChecker"}

    strings_ru = {
        "config_missing": "❌ API-ключ VirusTotal не настроен. Укажите его через конфиг модуля.",
        "no_input": "❌ Объект для проверки не указан.\n\nОтветьте на файл, ссылку или сообщение со ссылкой, либо передайте ссылку в тексте команды.",
        "downloading": "📥 Выполняется загрузка файла...",
        "uploading": "📤 Выполняется отправка файла на анализ...\n📄 Имя: {filename}\n📦 Размер: {size}",
        "checking_url": "🔗 Выполняется проверка URL...\n{url}",
        "checking_hash": "🔑 Выполняется проверка hash...\n{sha256}",
        "reanalyzing_file": "🔄 Выполняется повторный анализ файла...\n{sha256}",
        "too_big": "❌ Размер файла превышает допустимый предел VirusTotal.\nМаксимум: до 650 МБ через upload URL\nРазмер файла: {size}",
        "download_error": "❌ Не удалось загрузить файл.\n{error}",
        "bad_request": "❌ Запрос отклонён API. Проверьте корректность файла или ссылки.",
        "server_error": "❌ Сервис VirusTotal временно недоступен. Повторите попытку позднее.",
        "network_error": "❌ Произошла сетевая ошибка при обращении к VirusTotal.",
        "timeout_error": "⚠️ Время ожидания результата анализа истекло.",
        "rate_limit": "⚠️ VirusTotal временно ограничил количество запросов. Повторите попытку позднее.",
        "file_not_found": "❌ Отчёт по файлу в базе VirusTotal не найден.",
        "url_not_found": "❌ Отчёт по указанному URL в базе VirusTotal не найден.",
        "parse_error": "❌ Не удалось обработать ответ API VirusTotal.",
        "api_error": "❌ Ошибка API: {error}",
        "status_text": "🛡️ VirusTotal\n• Записей в кэше: {cache_items}\n• TTL кэша: {ttl} мин\n• Ключ в конфиге: {cfg}",
        "results_file": (
            "🛡️ ОТЧЁТ ПО ФАЙЛУ\n\n"
            "📄 Имя: {filename}\n"
            "📦 Размер: {size}\n"
            "📁 Формат: {filetype}\n"
            "🔑 SHA-256: {sha256}\n\n"
        ),
        "results_url": (
            "🛡️ ОТЧЁТ ПО URL\n\n"
            "🔗 Адрес: {url}\n\n"
        ),
        "results_hash": (
            "🛡️ ОТЧЁТ ПО HASH\n\n"
            "🔑 SHA-256: {sha256}\n\n"
        ),
        "stats_line": (
            "📊 Результаты анализа:\n"
            "🔴 Вредоносные: {malicious}\n"
            "🟡 Подозрительные: {suspicious}\n"
            "🟢 Безопасные: {harmless}\n"
            "⚪ Не обнаружено: {undetected}\n"
            "🟠 Ошибки анализа: {failure}\n"
            "⏱ Таймауты: {timeout}"
        ),
        "detections_page": "\n\n⚠️ Сработавшие движки: {count}\n📄 Страница {page}/{pages}",
        "detection_item": "\n• {engine}: {threat}",
        "no_detections": "\n\n✅ По доступным данным вредоносных или подозрительных срабатываний не зафиксировано.",
        "deleted": "🗑 Сообщение удалено.",
        "inline_expired": "⌛ Время жизни интерактивного сообщения истекло.",
        "btn_prev": "◀ Назад",
        "btn_next": "▶ Вперёд",
        "btn_delete": "🗑 Удалить",
        "btn_report": "📄 Отчёт",
        "btn_history": "🕘 История",
        "btn_clear_history": "🧹 Очистить историю",
        "btn_confirm_yes": "✅ Да",
        "btn_confirm_no": "❌ Нет",
        "btn_back_history": "↩️ В историю",
        "btn_back_list": "◀ Назад к списку",
        "btn_open_full": "📑 Полный отчёт",
        "btn_delete_record": "🗑 Удалить запись",
        "history_title": "🕘 История VirusTotal",
        "history_empty": "🕘 История пуста.",
        "history_list_hint": "Нажмите на запись, чтобы открыть мини-отчёт.",
        "history_short": (
            "🕘 МИНИ-ОТЧЁТ\n\n"
            "📄 Имя: {filename}\n"
            "📦 Размер: {size}\n"
            "📁 Формат: {filetype}\n"
            "🔎 Детекты: {detections}\n"
            "🕒 Проверка: {checked_at}\n"
        ),
        "history_full": "📑 ПОЛНЫЙ ОТЧЁТ ИЗ ИСТОРИИ",
        "history_delete_confirm": "Удалить запись?",
        "history_clear_confirm": "Удалить всю историю?",
        "history_cleared": "🧹 История очищена.",
        "record_deleted": "🗑 Запись удалена.",
        "record_not_found": "❌ Запись не найдена.",
        "help_text": (
            "🛡️ VirusTotalChecker\n\n"
            "Модуль для проверки SHA-256 hash, файлов и URL через VirusTotal API.\n\n"
            "Команды:\n"
            "• {prefix}chash [hash] — Проверить hash файла\n"
            "• Ответ на файл, ссылка или ответ на ссылку + {prefix}vtcheck — проверка через VirusTotal\n"
            "• {prefix}vthistory — Показать историю проверок\n"
            "• {prefix}vthelp — показать эту справку\n"
        ),
    }

    strings_en = {
        "config_missing": "❌ VirusTotal API key is not configured. Set it through module config.",
        "no_input": "❌ No object was provided for analysis.\n\nReply to a file, a URL, or a message with a URL, or pass a URL in the command text.",
        "downloading": "📥 Downloading file...",
        "uploading": "📤 Uploading file for analysis...\n📄 Name: {filename}\n📦 Size: {size}",
        "checking_url": "🔗 Checking URL...\n{url}",
        "checking_hash": "🔑 Checking hash...\n{sha256}",
        "reanalyzing_file": "🔄 Reanalyzing file...\n{sha256}",
        "too_big": "❌ File size exceeds the VirusTotal limit.\nMaximum: up to 650 MB via upload URL\nFile size: {size}",
        "download_error": "❌ Failed to download the file.\n{error}",
        "bad_request": "❌ The request was rejected by the API. Verify the file or URL.",
        "server_error": "❌ VirusTotal is temporarily unavailable. Try again later.",
        "network_error": "❌ A network error occurred while contacting VirusTotal.",
        "timeout_error": "⚠️ The analysis result was not received in time.",
        "rate_limit": "⚠️ VirusTotal temporarily limited requests. Try again later.",
        "file_not_found": "❌ No VirusTotal report was found for the file.",
        "url_not_found": "❌ No VirusTotal report was found for the URL.",
        "parse_error": "❌ Failed to process the VirusTotal API response.",
        "api_error": "❌ API error: {error}",
        "status_text": "🛡️ VirusTotal\n• Cached entries: {cache_items}\n• Cache TTL: {ttl} min\n• Key in config: {cfg}",
        "results_file": (
            "🛡️ FILE REPORT\n\n"
            "📄 Name: {filename}\n"
            "📦 Size: {size}\n"
            "📁 Format: {filetype}\n"
            "🔑 SHA-256: {sha256}\n\n"
        ),
        "results_url": (
            "🛡️ URL REPORT\n\n"
            "🔗 Address: {url}\n\n"
        ),
        "results_hash": (
            "🛡️ HASH REPORT\n\n"
            "🔑 SHA-256: {sha256}\n\n"
        ),
        "stats_line": (
            "📊 Analysis results:\n"
            "🔴 Malicious: {malicious}\n"
            "🟡 Suspicious: {suspicious}\n"
            "🟢 Harmless: {harmless}\n"
            "⚪ Undetected: {undetected}\n"
            "🟠 Analysis failures: {failure}\n"
            "⏱ Timeouts: {timeout}"
        ),
        "detections_page": "\n\n⚠️ Triggered engines: {count}\n📄 Page {page}/{pages}",
        "detection_item": "\n• {engine}: {threat}",
        "no_detections": "\n\n✅ No malicious or suspicious detections were reported by the available engines.",
        "deleted": "🗑 Message deleted.",
        "inline_expired": "⌛ The interactive message has expired.",
        "btn_prev": "◀ Prev",
        "btn_next": "▶ Next",
        "btn_delete": "🗑 Delete",
        "btn_report": "📄 Report",
        "btn_history": "🕘 History",
        "btn_clear_history": "🧹 Clear history",
        "btn_confirm_yes": "✅ Yes",
        "btn_confirm_no": "❌ No",
        "btn_back_history": "↩️ History",
        "btn_back_list": "◀ Back to list",
        "btn_open_full": "📑 Full report",
        "btn_delete_record": "🗑 Delete record",
        "history_title": "🕘 VirusTotal history",
        "history_empty": "🕘 History is empty.",
        "history_list_hint": "Press an entry to open a short report.",
        "history_short": (
            "🕘 SHORT REPORT\n\n"
            "📄 Name: {filename}\n"
            "📦 Size: {size}\n"
            "📁 Format: {filetype}\n"
            "🔎 Detections: {detections}\n"
            "🕒 Checked: {checked_at}\n"
        ),
        "history_full": "📑 FULL REPORT FROM HISTORY",
        "history_delete_confirm": "Delete record?",
        "history_clear_confirm": "Delete all history?",
        "history_cleared": "🧹 History cleared.",
        "record_deleted": "🗑 Record deleted.",
        "record_not_found": "❌ Record not found.",
        "help_text": (
            "🛡️ VirusTotalChecker\n\n"
            "Module for SHA-256 hash, file, and URL analysis through the VirusTotal API.\n\n"
            "Commands:\n"
            "• {prefix}chash [hash] — Check file hash\n"
            "• Reply to a file, URL, or reply to a URL + {prefix}vtcheck — VirusTotal scan\n"
            "• {prefix}vthistory — Show scan history\n"
            "• {prefix}vthelp — show this help\n"
        ),
    }

    def __init__(self):
        self.client = None
        self.db = None
        self.lang = "ru"
        self.prefix = "."
        self.cache: Dict[str, CachedResult] = {}
        self.inline_states: Dict[str, CachedResult] = {}
        self.history: List[dict] = []
        self.last_429_until = 0.0
        self.last_backoff = 2.0

        self.config = loader.ModuleConfig(
            loader.ConfigValue(
                "api_key",
                "",
                lambda: (
                    "VirusTotal API key. Open https://www.virustotal.com/gui/my-apikey "
                    "while signed in, copy your personal API key and paste it here. "
                    "Do not send the key in public chats."
                ),
                validator=loader.validators.Hidden(loader.validators.String()),
            )
        )

    async def client_ready(self, client, db):
        self.client = client
        self.db = db
        self.lang = db.get("hikka.loader", "lang", "ru")
        self.prefix = db.get("hikka.loader", "prefix", ".")
        raw = self.db.get(self.__class__.__name__, HISTORY_DB_KEY, [])
        if isinstance(raw, list):
            self.history = raw

    @property
    def api_key(self):
        return (self.config["api_key"] or "").strip()

    def _(self, key, **kwargs):
        strings = self.strings_ru if self.lang == "ru" else self.strings_en
        text = strings.get(key, key)
        return text.format(**kwargs) if kwargs else text

    def _headers(self):
        return {"x-apikey": self.api_key}

    def _cache_get(self, key: str):
        item = self.cache.get(key)
        if not item:
            return None
        if time.time() - item.created_at > CACHE_TTL:
            self.cache.pop(key, None)
            return None
        return item.data

    def _cache_set(self, key: str, data: dict):
        self.cache[key] = CachedResult(time.time(), data)

    def _inline_get(self, key: str):
        item = self.inline_states.get(key)
        if not item:
            return None
        if time.time() - item.created_at > CACHE_TTL:
            self.inline_states.pop(key, None)
            return None
        return item.data

    def _inline_set(self, key: str, data: dict):
        self.inline_states[key] = CachedResult(time.time(), data)

    def _clean_url(self, raw: Optional[str]) -> Optional[str]:
        raw = (raw or "").strip()
        if not raw:
            return None
        if raw.startswith(("http://", "https://")):
            return raw
        if "." in raw and " " not in raw:
            return f"https://{raw}"
        return None

    def _extract_url(self, text: Optional[str]) -> Optional[str]:
        if not text:
            return None
        pattern = (
            r"(?:https?://)?(?:www\.)?"
            r"[-a-zA-Z0-9@:%._\+~#=]{1,256}"
            r"\.[a-zA-Z0-9()]{1,24}\b"
            r"(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)"
        )
        found = re.findall(pattern, text)
        return self._clean_url(found[0]) if found else None

    def _is_sha256(self, text: str) -> bool:
        return bool(re.fullmatch(r"[A-Fa-f0-9]{64}", (text or "").strip()))

    def _format_size(self, size: int) -> str:
        if size < 1024:
            return f"{size} Б" if self.lang == "ru" else f"{size} B"
        if size < 1024 * 1024:
            return f"{size / 1024:.1f} КБ" if self.lang == "ru" else f"{size / 1024:.1f} KB"
        return f"{size / (1024 * 1024):.1f} МБ" if self.lang == "ru" else f"{size / (1024 * 1024):.1f} MB"

    def _get_file_type(self, filename: str) -> str:
        ext = os.path.splitext(filename or "")[1].lower()
        return ext[1:].upper() if ext else ("Не определён" if self.lang == "ru" else "Unknown")

    def _url_id(self, url: str) -> str:
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def _report_url(self, result: dict) -> str:
        if result["type"] == "file":
            return f"https://www.virustotal.com/gui/file/{result['sha256']}/detection"
        if result["type"] == "hash":
            return f"https://www.virustotal.com/gui/file/{result['sha256']}/detection"
        return f"https://www.virustotal.com/gui/url/{result['id']}/detection"

    def _state_key(self, result: dict) -> str:
        base = result["sha256"] if result["type"] in ("file", "hash") else result["id"]
        return hashlib.md5(base.encode()).hexdigest()[:16]

    def _history_key(self, item: dict) -> str:
        return item.get("key") or item.get("sha256") or item.get("url") or item.get("id") or item.get("filename", "")

    def _history_find_index(self, key: str) -> int:
        for i, item in enumerate(self.history):
            if self._history_key(item) == key:
                return i
        return -1

    def _history_item_from_state(self, state: dict) -> dict:
        res = state.get("result", {})
        meta = state.get("meta", {})
        key = meta.get("sha256") or meta.get("url") or res.get("sha256") or res.get("id") or meta.get("filename", "")
        stats = res.get("stats", {})
        threats = res.get("threats", [])
        return {
            "key": key,
            "type": res.get("type"),
            "filename": meta.get("filename", "unknown"),
            "size": meta.get("size", "?"),
            "filetype": meta.get("filetype", "?"),
            "sha256": meta.get("sha256"),
            "url": meta.get("url"),
            "stats": stats,
            "threats": threats,
            "checked_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "result": res,
            "meta": meta,
        }

    def _save_history(self):
        if self.db:
            self.db.set(self.__class__.__name__, HISTORY_DB_KEY, self.history)

    def _history_add(self, state: dict):
        item = self._history_item_from_state(state)
        key = item.get("key")
        if not key:
            return
        idx = self._history_find_index(key)
        if idx != -1:
            self.history[idx] = item
        else:
            self.history.insert(0, item)
        self._save_history()

    def _history_delete_one(self, key: str) -> bool:
        idx = self._history_find_index(key)
        if idx == -1:
            return False
        self.history.pop(idx)
        self._save_history()
        return True

    def _history_clear(self):
        self.history.clear()
        self._save_history()

    def _history_pages(self) -> int:
        return max(1, math.ceil(len(self.history) / HISTORY_PAGE_SIZE))

    def _history_slice(self, page: int):
        pages = self._history_pages()
        page = max(1, min(page, pages))
        start = (page - 1) * HISTORY_PAGE_SIZE
        end = start + HISTORY_PAGE_SIZE
        return page, pages, self.history[start:end]

    def _history_button_label(self, item: dict) -> str:
        name = item.get("filename") or item.get("url") or item.get("sha256") or "unknown"
        return name if len(name) <= 36 else name[:33] + "..."

    def _history_short_text(self, item: dict) -> str:
        detections = len(item.get("threats", []))
        return self._(
            "history_short",
            filename=item.get("filename", "unknown"),
            size=item.get("size", "?"),
            filetype=item.get("filetype", "?"),
            detections=detections,
            checked_at=item.get("checked_at", "?"),
        )

    def _history_full_text(self, item: dict) -> str:
        state = {"page": 1, "result": item.get("result", {}), "meta": item.get("meta", {})}
        return self._render_result_text(state)

    def _confirm_markup(self, yes_cb, yes_args, no_cb, no_args):
        return [[
            {"text": self._("btn_confirm_yes"), "callback": yes_cb, "args": yes_args},
            {"text": self._("btn_confirm_no"), "callback": no_cb, "args": no_args},
        ]]

    def _build_markup(self, state_key: str, show_history: bool = False):
        state = self._inline_get(state_key)
        if not state:
            return [[{"text": self._("btn_delete"), "callback": self._cb_delete, "args": (state_key,)}]]

        res = state["result"]
        threats = res.get("threats", [])
        pages = max(1, math.ceil(max(1, len(threats)) / PAGE_SIZE))
        page = ((state["page"] - 1) % pages) + 1
        report_url = self._report_url(res)

        markup = []
        if threats and pages > 1:
            markup.append([
                {"text": self._("btn_prev"), "callback": self._cb_prev, "args": (state_key,)},
                {"text": f"{page}/{pages}", "callback": self._cb_noop, "args": (state_key,)},
                {"text": self._("btn_next"), "callback": self._cb_next, "args": (state_key,)},
            ])

        action_row = [{"text": self._("btn_report"), "url": report_url}]
        if show_history:
            action_row.append({"text": self._("btn_history"), "callback": self._cb_history_from_report, "args": (state_key,)})
        action_row.append({"text": self._("btn_delete"), "callback": self._cb_delete, "args": (state_key,)})
        markup.append(action_row)
        return markup

    def _history_list_markup(self, page: int):
        page, pages, items = self._history_slice(page)
        markup = []
        for item in items:
            markup.append([{
                "text": self._history_button_label(item),
                "callback": self._cb_history_open,
                "args": (item["key"], page),
            }])
        nav = []
        if pages > 1:
            nav.append({"text": self._("btn_prev"), "callback": self._cb_history_prev, "args": (page,)})
            nav.append({"text": f"{page}/{pages}", "callback": self._cb_noop, "args": ("history",)})
            nav.append({"text": self._("btn_next"), "callback": self._cb_history_next, "args": (page,)})
            markup.append(nav)
        markup.append([
            {"text": self._("btn_clear_history"), "callback": self._cb_history_clear_confirm, "args": ()},
            {"text": self._("btn_delete"), "callback": self._cb_delete_message, "args": ("history_list",)},
        ])
        return markup

    def _history_short_markup(self, key: str, back_page: int):
        return [
            [{"text": self._("btn_open_full"), "callback": self._cb_history_full, "args": (key, back_page)}],
            [
                {"text": self._("btn_back_history"), "callback": self._cb_history_back_list, "args": (back_page,)},
                {"text": self._("btn_delete_record"), "callback": self._cb_history_delete_confirm, "args": (key, back_page)},
            ],
            [{"text": self._("btn_delete"), "callback": self._cb_delete_message, "args": ("history_short",)}],
        ]

    def _history_full_markup(self, key: str, back_page: int):
        return [
            [{"text": self._("btn_back_history"), "callback": self._cb_history_back_short, "args": (key, back_page)}],
            [
                {"text": self._("btn_delete_record"), "callback": self._cb_history_delete_confirm, "args": (key, back_page)},
                {"text": self._("btn_back_list"), "callback": self._cb_history_back_list, "args": (back_page,)},
            ],
            [{"text": self._("btn_delete"), "callback": self._cb_delete_message, "args": ("history_full",)}],
        ]

    async def _respect_backoff(self):
        now = time.time()
        if now < self.last_429_until:
            await asyncio.sleep(self.last_429_until - now)

    async def _request(self, session, method: str, url: str, *, retry: int = 4, **kwargs):
        if not self.api_key:
            return {"error": "auth"}

        await self._respect_backoff()
        headers = dict(self._headers())
        headers.update(kwargs.pop("headers", {}))
        timeout = kwargs.pop("timeout", aiohttp.ClientTimeout(total=HTTP_TOTAL_TIMEOUT))

        try:
            async with session.request(method, url, headers=headers, timeout=timeout, **kwargs) as resp:
                if resp.status in (200, 201):
                    self.last_backoff = 2.0
                    ctype = resp.headers.get("Content-Type", "")
                    if "application/json" in ctype:
                        return await resp.json()
                    return {"ok": True, "status": resp.status}

                if resp.status == 204:
                    self.last_backoff = 2.0
                    return {"ok": True, "status": 204}

                if resp.status == 400:
                    try:
                        data = await resp.json()
                    except Exception:
                        data = {}
                    return {"error": "bad_request", "details": data}

                if resp.status == 401:
                    return {"error": "auth"}

                if resp.status == 404:
                    return None

                if resp.status == 429:
                    retry_after = resp.headers.get("Retry-After")
                    if retry_after and retry_after.isdigit():
                        wait_for = max(1, int(retry_after))
                    else:
                        wait_for = int(min(self.last_backoff, 60))
                    self.last_backoff = min(self.last_backoff * 2, 60)
                    self.last_429_until = time.time() + wait_for
                    if retry > 0:
                        await asyncio.sleep(wait_for)
                        return await self._request(session, method, url, retry=retry - 1, **kwargs)
                    return {"error": "ratelimit"}

                if resp.status >= 500:
                    wait_for = int(min(self.last_backoff, 30))
                    self.last_backoff = min(self.last_backoff * 2, 30)
                    if retry > 0:
                        await asyncio.sleep(wait_for)
                        return await self._request(session, method, url, retry=retry - 1, **kwargs)
                    return {"error": "server"}

                return {"error": f"http_{resp.status}"}

        except asyncio.TimeoutError:
            if retry > 0:
                await asyncio.sleep(2)
                return await self._request(session, method, url, retry=retry - 1, **kwargs)
            return {"error": "timeout"}
        except aiohttp.ClientError:
            return {"error": "network"}

    async def _analysis_wait(self, session, analysis_id: str):
        for _ in range(ANALYSIS_POLLS):
            data = await self._request(session, "GET", f"{VT_API}/analyses/{analysis_id}")
            if not data or (isinstance(data, dict) and data.get("error")):
                return data
            try:
                status = data["data"]["attributes"]["status"]
            except (KeyError, TypeError):
                return {"error": "parse"}
            if status == "completed":
                return data
            await asyncio.sleep(ANALYSIS_DELAY)
        return {"error": "timeout"}

    def _collect_threats(self, results: dict) -> List[Tuple[str, str]]:
        threats = []
        for engine, val in (results or {}).items():
            category = val.get("category")
            result = (val.get("result") or "").strip()
            if category in ("malicious", "suspicious") and result and result.lower() not in {"clean", "undetected"}:
                threats.append((engine, result))
        threats.sort(key=lambda x: x[0].lower())
        return threats

    async def _get_large_upload_url(self, session) -> Optional[str]:
        data = await self._request(session, "GET", f"{VT_API}/files/upload_url")
        if not data or (isinstance(data, dict) and data.get("error")):
            return None
        return data.get("data")

    async def _upload_file(self, session, filepath: str, filename: str, size: int):
        if size > MAX_FILE_SIZE_HARD:
            return {"error": "too_big"}

        target_url = f"{VT_API}/files"
        if size > BIG_FILE_THRESHOLD:
            upload_url = await self._get_large_upload_url(session)
            if not upload_url:
                return {"error": "upload_url"}
            target_url = upload_url

        form = aiohttp.FormData()
        with open(filepath, "rb") as f:
            form.add_field("file", f, filename=filename)
            return await self._request(session, "POST", target_url, data=form)

    async def _get_file_report(self, session, sha256: str):
        data = await self._request(session, "GET", f"{VT_API}/files/{sha256}")
        if data is None:
            return None
        if isinstance(data, dict) and data.get("error"):
            return data
        try:
            attrs = data["data"]["attributes"]
            return {
                "type": "file",
                "sha256": sha256,
                "stats": attrs.get("last_analysis_stats", {}),
                "threats": self._collect_threats(attrs.get("last_analysis_results", {})),
            }
        except (KeyError, TypeError):
            return {"error": "parse"}

    async def _reanalyze_file(self, session, sha256: str):
        data = await self._request(session, "POST", f"{VT_API}/files/{sha256}/analyse")
        if not data or (isinstance(data, dict) and data.get("error")):
            return data
        try:
            analysis_id = data["data"]["id"]
        except (KeyError, TypeError):
            return {"error": "parse"}
        wait = await self._analysis_wait(session, analysis_id)
        if wait and isinstance(wait, dict) and wait.get("error"):
            return wait
        return await self._get_file_report(session, sha256)

    async def _scan_file(self, sha256: str, filepath: Optional[str] = None, filename: str = "file.bin", force: bool = False):
        cache_key = f"file:{sha256}:{int(force)}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached

        async with aiohttp.ClientSession() as session:
            if force:
                result = await self._reanalyze_file(session, sha256)
                if result and not (isinstance(result, dict) and result.get("error")):
                    self._cache_set(cache_key, result)
                return result

            existing = await self._get_file_report(session, sha256)
            if existing and not (isinstance(existing, dict) and existing.get("error")):
                self._cache_set(cache_key, existing)
                return existing

            if isinstance(existing, dict) and existing.get("error"):
                return existing

            if not filepath:
                return None

            size = os.path.getsize(filepath)
            upload = await self._upload_file(session, filepath, filename, size)
            if not upload or (isinstance(upload, dict) and upload.get("error")):
                return upload

            try:
                analysis_id = upload["data"]["id"]
            except (KeyError, TypeError):
                return {"error": "parse"}

            wait = await self._analysis_wait(session, analysis_id)
            if wait and isinstance(wait, dict) and wait.get("error"):
                return wait

            final = await self._get_file_report(session, sha256)
            if final and not (isinstance(final, dict) and final.get("error")):
                self._cache_set(cache_key, final)
            return final

    async def _get_url_report(self, session, url: str):
        url_id = self._url_id(url)
        data = await self._request(session, "GET", f"{VT_API}/urls/{url_id}")
        if data is None:
            return None
        if isinstance(data, dict) and data.get("error"):
            return data
        try:
            attrs = data["data"]["attributes"]
            return {
                "type": "url",
                "url": url,
                "id": url_id,
                "stats": attrs.get("last_analysis_stats", {}),
                "threats": self._collect_threats(attrs.get("last_analysis_results", {})),
            }
        except (KeyError, TypeError):
            return {"error": "parse"}

    async def _submit_url(self, session, url: str):
        data = await self._request(session, "POST", f"{VT_API}/urls", data={"url": url})
        if not data or (isinstance(data, dict) and data.get("error")):
            return data
        try:
            analysis_id = data["data"]["id"]
        except (KeyError, TypeError):
            return {"error": "parse"}
        wait = await self._analysis_wait(session, analysis_id)
        if wait and isinstance(wait, dict) and wait.get("error"):
            return wait
        return await self._get_url_report(session, url)

    async def _scan_url(self, url: str, force: bool = False):
        cache_key = f"url:{self._url_id(url)}:{int(force)}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached

        async with aiohttp.ClientSession() as session:
            if not force:
                existing = await self._get_url_report(session, url)
                if existing and not (isinstance(existing, dict) and existing.get("error")):
                    self._cache_set(cache_key, existing)
                    return existing
                if isinstance(existing, dict) and existing.get("error") and existing.get("error") != "bad_request":
                    return existing

            result = await self._submit_url(session, url)
            if result and not (isinstance(result, dict) and result.get("error")):
                self._cache_set(cache_key, result)
            return result

    async def _compute_sha256(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def _render_result_text(self, state: dict) -> str:
        res = state["result"]
        meta = state["meta"]
        page = state["page"]

        if res["type"] == "file":
            text = self._(
                "results_file",
                filename=meta["filename"],
                size=meta["size"],
                filetype=meta["filetype"],
                sha256=meta["sha256"],
            )
        elif res["type"] == "hash":
            text = self._("results_hash", sha256=meta["sha256"])
        else:
            text = self._("results_url", url=meta["url"])

        stats = res.get("stats", {})
        text += self._(
            "stats_line",
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            undetected=stats.get("undetected", 0),
            failure=stats.get("failure", 0),
            timeout=stats.get("timeout", 0),
        )

        threats = res.get("threats", [])
        if not threats:
            text += self._("no_detections")
            return text

        pages = max(1, math.ceil(len(threats) / PAGE_SIZE))
        page = ((page - 1) % pages) + 1
        start = (page - 1) * PAGE_SIZE
        end = start + PAGE_SIZE

        text += self._("detections_page", count=len(threats), page=page, pages=pages)
        for engine, threat in threats[start:end]:
            text += self._("detection_item", engine=engine, threat=threat)

        return text

    async def _answer_inline(self, msg, state: dict):
        state_key = self._state_key(state["result"])
        self._inline_set(state_key, state)
        self._history_add(state)

        text = self._render_result_text(state)
        markup = self._build_markup(state_key, show_history=False)

        if hasattr(self, "inline") and hasattr(self.inline, "form"):
            await self.inline.form(
                text=text,
                message=msg,
                reply_markup=markup,
                disable_security=True,
            )
            return

        await utils.answer(msg, text)

    async def _edit_inline(self, call, state_key: str):
        state = self._inline_get(state_key)
        if not state:
            try:
                await call.answer(self._("inline_expired"), show_alert=True)
            except Exception:
                pass
            return

        text = self._render_result_text(state)
        markup = self._build_markup(state_key, show_history=False)

        try:
            await call.edit(text, reply_markup=markup)
        except Exception:
            try:
                await call.answer(self._("inline_expired"), show_alert=True)
            except Exception:
                pass

    async def _edit_history_list(self, call, page: int):
        if not self.history:
            try:
                await call.edit(self._("history_empty"), reply_markup=[
                    [{"text": self._("btn_delete"), "callback": self._cb_delete_message, "args": ("history_empty",)}]
                ])
            except Exception:
                pass
            return
        page, pages, _ = self._history_slice(page)
        text = self._("history_title") + "\n\n" + self._("history_list_hint")
        try:
            await call.edit(text, reply_markup=self._history_list_markup(page))
        except Exception:
            try:
                await call.answer(self._("inline_expired"), show_alert=True)
            except Exception:
                pass

    async def _cb_noop(self, call, *args):
        try:
            await call.answer()
        except Exception:
            pass

    async def _cb_prev(self, call, state_key: str):
        state = self._inline_get(state_key)
        if not state:
            await call.answer(self._("inline_expired"), show_alert=True)
            return
        threats = state["result"].get("threats", [])
        pages = max(1, math.ceil(max(1, len(threats)) / PAGE_SIZE))
        state["page"] = pages if state["page"] <= 1 else state["page"] - 1
        self._inline_set(state_key, state)
        await self._edit_inline(call, state_key)

    async def _cb_next(self, call, state_key: str):
        state = self._inline_get(state_key)
        if not state:
            await call.answer(self._("inline_expired"), show_alert=True)
            return
        threats = state["result"].get("threats", [])
        pages = max(1, math.ceil(max(1, len(threats)) / PAGE_SIZE))
        state["page"] = 1 if state["page"] >= pages else state["page"] + 1
        self._inline_set(state_key, state)
        await self._edit_inline(call, state_key)

    async def _cb_delete(self, call, state_key: str):
        self.inline_states.pop(state_key, None)
        try:
            await call.delete()
        except Exception:
            try:
                await call.edit(self._("deleted"), reply_markup=None)
            except Exception:
                pass

    async def _cb_history_from_report(self, call, state_key: str):
        state = self._inline_get(state_key)
        if not state:
            await call.answer(self._("inline_expired"), show_alert=True)
            return
        await self._show_history_from_state(call, state, 1)

    async def _show_history_from_state(self, call, state: dict, page: int):
        item = self._history_item_from_state(state)
        key = item["key"]
        idx = self._history_find_index(key)
        if idx == -1:
            self.history.insert(0, item)
            self._save_history()
        text = self._history_short_text(item)
        try:
            await call.edit(text, reply_markup=self._history_short_markup(key, page))
        except Exception:
            try:
                await call.answer(self._("inline_expired"), show_alert=True)
            except Exception:
                pass

    async def _cb_history_prev(self, call, page: int):
        await call.answer()
        await self._edit_history_list(call, page - 1)

    async def _cb_history_next(self, call, page: int):
        await call.answer()
        await self._edit_history_list(call, page + 1)

    async def _cb_history_open(self, call, key: str, back_page: int):
        idx = self._history_find_index(key)
        if idx == -1:
            await call.answer(self._("record_not_found"), show_alert=True)
            return
        item = self.history[idx]
        text = self._history_short_text(item)
        await call.edit(text, reply_markup=self._history_short_markup(key, back_page))

    async def _cb_history_full(self, call, key: str, back_page: int):
        idx = self._history_find_index(key)
        if idx == -1:
            await call.answer(self._("record_not_found"), show_alert=True)
            return
        item = self.history[idx]
        text = self._("history_full") + "\n\n" + self._history_full_text(item)
        await call.edit(text, reply_markup=self._history_full_markup(key, back_page))

    async def _cb_history_back_list(self, call, back_page: int):
        await call.answer()
        await self._edit_history_list(call, back_page)

    async def _cb_history_back_short(self, call, key: str, back_page: int):
        idx = self._history_find_index(key)
        if idx == -1:
            await call.answer(self._("record_not_found"), show_alert=True)
            return
        item = self.history[idx]
        await call.edit(self._history_short_text(item), reply_markup=self._history_short_markup(key, back_page))

    async def _cb_history_delete_confirm(self, call, key: str, back_page: int):
        await call.edit(
            self._("history_delete_confirm"),
            reply_markup=self._confirm_markup(
                self._cb_history_delete_yes, (key, back_page),
                self._cb_history_delete_no, (key, back_page),
            ),
        )

    async def _cb_history_delete_yes(self, call, key: str, back_page: int):
        if not self._history_delete_one(key):
            await call.answer(self._("record_not_found"), show_alert=True)
            return
        await call.answer(self._("record_deleted"))
        await self._edit_history_list(call, back_page)

    async def _cb_history_delete_no(self, call, key: str, back_page: int):
        idx = self._history_find_index(key)
        if idx == -1:
            await call.answer(self._("record_not_found"), show_alert=True)
            return
        item = self.history[idx]
        await call.edit(self._history_short_text(item), reply_markup=self._history_short_markup(key, back_page))

    async def _cb_history_clear_confirm(self, call):
        await call.edit(
            self._("history_clear_confirm"),
            reply_markup=self._confirm_markup(
                self._cb_history_clear_yes, (),
                self._cb_history_clear_no, (),
            ),
        )

    async def _cb_history_clear_yes(self, call):
        self._history_clear()
        await call.edit(self._("history_empty"), reply_markup=[
            [{"text": self._("btn_delete"), "callback": self._cb_delete_message, "args": ("history_empty",)}]
        ])

    async def _cb_history_clear_no(self, call):
        await self._edit_history_list(call, 1)

    async def _cb_delete_message(self, call, *_):
        try:
            await call.delete()
        except Exception:
            try:
                await call.edit(self._("deleted"), reply_markup=None)
            except Exception:
                pass

    async def _show_error(self, msg_or_status, err: str):
        mapping = {
            "auth": self._("config_missing"),
            "bad_request": self._("bad_request"),
            "server": self._("server_error"),
            "network": self._("network_error"),
            "timeout": self._("timeout_error"),
            "ratelimit": self._("rate_limit"),
            "parse": self._("parse_error"),
            "too_big": self._("too_big", size=">650 MB"),
            "upload_url": self._("api_error", error="upload_url"),
        }
        text = mapping.get(err, self._("api_error", error=err))
        try:
            await msg_or_status.edit(text)
        except Exception:
            await utils.answer(msg_or_status, text)

    @loader.command()
    async def vthelpcmd(self, msg):
        """Показать справку по использованию модуля"""
        await utils.answer(msg, self._("help_text", prefix=self.prefix))

    @loader.command()
    async def vtstatuscmd(self, msg):
        """Показать состояние модуля и статус локального кэша"""
        cfg = "да" if self.api_key and self.lang == "ru" else "yes" if self.api_key else "нет" if self.lang == "ru" else "no"
        await utils.answer(
            msg,
            self._("status_text", cache_items=len(self.cache) + len(self.inline_states), ttl=CACHE_TTL // 60, cfg=cfg),
        )

    @loader.command()
    async def vtcheckcmd(self, msg):
        """Проверить файл, URL или hash через VirusTotal"""
        await self._run_check(msg, force=False)

    @loader.command()
    async def vthistorycmd(self, msg):
        """Показать историю проверок"""
        if not self.history:
            await utils.answer(msg, self._("history_empty"))
            return
        text = self._("history_title") + "\n\n" + self._("history_list_hint")
        if hasattr(self, "inline") and hasattr(self.inline, "form"):
            await self.inline.form(
                text=text,
                message=msg,
                reply_markup=self._history_list_markup(1),
                disable_security=True,
            )
            return
        await utils.answer(msg, text)

    @loader.command()
    async def chashcmd(self, msg):
        """Проверить SHA-256 hash файла через VirusTotal"""
        await self._run_check(msg, force=False, hash_mode=True)

    async def _run_check(self, msg, force: bool = False, hash_mode: bool = False):
        if not self.api_key:
            await utils.answer(msg, self._("config_missing"))
            return

        tmpfile = None

        try:
            cmd_args = utils.get_args_raw(msg).strip()
            url = self._extract_url(cmd_args)

            if hash_mode:
                sha256 = cmd_args.split()[0] if cmd_args else ""
                if self._is_sha256(sha256):
                    status = await utils.answer(msg, self._("checking_hash", sha256=sha256))
                    res = await self._scan_file(sha256, filepath=None, filename="file.bin", force=force)
                    if isinstance(res, dict) and res.get("error"):
                        await self._show_error(status, res["error"])
                        return
                    state = {
                        "page": 1,
                        "result": res,
                        "meta": {"filename": "file.bin", "size": "?", "filetype": "Unknown", "sha256": sha256},
                    }
                    await status.delete()
                    await self._answer_inline(msg, state)
                    return

            if url:
                status = await utils.answer(
                    msg,
                    self._("checking_url", url=url[:200]),
                )
                res = await self._scan_url(url, force=force)
                if isinstance(res, dict) and res.get("error"):
                    await self._show_error(status, res["error"])
                    return
                state = {"page": 1, "result": res, "meta": {"url": url}}
                await status.delete()
                await self._answer_inline(msg, state)
                return

            if msg.reply_to:
                reply = await msg.get_reply_message()

                if getattr(reply, "document", None):
                    status = await utils.answer(msg, self._("downloading"))
                    try:
                        tmpfile = await self.client.download_media(reply, tempfile.gettempdir())
                    except Exception as e:
                        await status.edit(self._("download_error", error=str(e)[:120]))
                        return

                    if not tmpfile or not os.path.exists(tmpfile):
                        await status.edit(self._("download_error", error="unknown"))
                        return

                    size = os.path.getsize(tmpfile)
                    size_fmt = self._format_size(size)
                    if size > MAX_FILE_SIZE_HARD:
                        await status.edit(self._("too_big", size=size_fmt))
                        return

                    fname = "unknown"
                    try:
                        for attr in reply.document.attributes:
                            if hasattr(attr, "file_name") and attr.file_name:
                                fname = attr.file_name
                                break
                    except Exception:
                        pass

                    sha256 = await self._compute_sha256(tmpfile)
                    ftype = self._get_file_type(fname)

                    await status.edit(self._("reanalyzing_file", sha256=sha256) if force else self._("uploading", filename=fname[:80], size=size_fmt))

                    res = await self._scan_file(sha256, filepath=tmpfile, filename=fname, force=force)
                    if isinstance(res, dict) and res.get("error"):
                        await self._show_error(status, res["error"])
                        return

                    state = {
                        "page": 1,
                        "result": res,
                        "meta": {
                            "filename": fname[:120],
                            "size": size_fmt,
                            "filetype": ftype,
                            "sha256": sha256,
                        },
                    }
                    await status.delete()
                    await self._answer_inline(msg, state)
                    return

                reply_text = getattr(reply, "text", None) or getattr(reply, "raw_text", None)
                if reply_text:
                    url = self._extract_url(reply_text)
                    if url:
                        status = await utils.answer(
                            msg,
                            self._("checking_url", url=url[:200]),
                        )
                        res = await self._scan_url(url, force=force)
                        if isinstance(res, dict) and res.get("error"):
                            await self._show_error(status, res["error"])
                            return
                        state = {"page": 1, "result": res, "meta": {"url": url}}
                        await status.delete()
                        await self._answer_inline(msg, state)
                        return

            await utils.answer(msg, self._("no_input"))

        except Exception as e:
            await utils.answer(msg, self._("api_error", error=str(e)[:120]))
        finally:
            if tmpfile and os.path.exists(tmpfile):
                try:
                    os.remove(tmpfile)
                except OSError:
                    pass
