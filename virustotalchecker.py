# modules/vtcheck.py
# meta developer: @Scp079Modules
# meta banner: https://www.malwarebytes.com/wp-content/uploads/sites/2/2021/05/asset_upload_file13254_232175.png
# License: MIT - You can modify this file but must keep author credit

import asyncio
import base64
import hashlib
import html
import math
import os
import re
import tempfile
import time
from urllib.parse import urlsplit
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
        "btn_details": "📋 Details",
        "btn_relations": "🔗 Relations",
        "btn_behavior": "🧪 Behavior",
        "btn_community": "💬 Community",
        "btn_url_domain": "🌐 URL / Домен",
        "btn_back_report": "↩️ К отчёту",
        "extra_loading": "⏳ Загружаю дополнительные сведения...",
        "extra_unavailable": "ℹ️ Дополнительные сведения недоступны для этого объекта или вашего уровня API.",
        "extra_empty": "ℹ️ VirusTotal не вернул дополнительных сведений.",
        "extra_error": "❌ Не удалось получить дополнительные сведения: {error}",
        "extra_page": "Страница {page}/{pages}",
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
        "btn_details": "📋 Details",
        "btn_relations": "🔗 Relations",
        "btn_behavior": "🧪 Behavior",
        "btn_community": "💬 Community",
        "btn_url_domain": "🌐 URL / Domain",
        "btn_back_report": "↩️ Back to report",
        "extra_loading": "⏳ Loading additional information...",
        "extra_unavailable": "ℹ️ Additional information is unavailable for this object or your API tier.",
        "extra_empty": "ℹ️ VirusTotal returned no additional information.",
        "extra_error": "❌ Failed to get additional information: {error}",
        "extra_page": "Page {page}/{pages}",
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

        # Compact two-column navigation. Extra API data is fetched on demand.
        if res.get("type") in ("file", "hash"):
            markup.extend([
                [
                    {"text": self._("btn_details"), "callback": self._cb_extra_tab, "args": (state_key, "details", 0)},
                    {"text": self._("btn_relations"), "callback": self._cb_extra_tab, "args": (state_key, "relations", 0)},
                ],
                [
                    {"text": self._("btn_behavior"), "callback": self._cb_extra_tab, "args": (state_key, "behavior", 0)},
                    {"text": self._("btn_community"), "callback": self._cb_extra_tab, "args": (state_key, "community", 0)},
                ],
            ])
        else:
            markup.append([
                {"text": self._("btn_details"), "callback": self._cb_extra_tab, "args": (state_key, "details", 0)},
                {"text": self._("btn_community"), "callback": self._cb_extra_tab, "args": (state_key, "community", 0)},
            ])
            markup.append([
                {"text": self._("btn_url_domain"), "callback": self._cb_extra_tab, "args": (state_key, "url_domain", 0)}
            ])
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
                        try:
                            return await resp.json(content_type=None)
                        except (aiohttp.ClientError, ValueError, TypeError):
                            return {"error": "parse"}
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

                if resp.status == 403:
                    return {"error": "http_403"}

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
        except (ValueError, TypeError, OSError):
            return {"error": "request_data"}
        except Exception:
            # Prevent unexpected transport/decoder errors from crashing Hikka handlers.
            return {"error": "internal"}

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

    def _threat_profile(self, stats: dict, threats: list) -> dict:
        """Build a transparent heuristic threat/risk summary from VT verdicts."""
        stats = stats if isinstance(stats, dict) else {}
        def _count(key):
            try:
                return max(0, int(stats.get(key, 0) or 0))
            except (TypeError, ValueError, OverflowError):
                return 0

        malicious = _count("malicious")
        suspicious = _count("suspicious")
        harmless = _count("harmless")
        undetected = _count("undetected")
        timeout = _count("timeout")
        failure = _count("failure")
        total = malicious + suspicious + harmless + undetected + timeout + failure
        detections = malicious + suspicious
        detection_pct = (detections / total * 100.0) if total else None
        # Suspicious verdicts weigh half as much as confirmed malicious verdicts.
        risk_pct = ((malicious + suspicious * 0.5) / total * 100.0) if total else None

        is_ru = self.lang == "ru"
        labels = {
            "Trojan": "Троян" if is_ru else "Trojan",
            "Ransomware": "Вымогатель (Ransomware)" if is_ru else "Ransomware",
            "Spyware": "Шпионское ПО (Spyware)" if is_ru else "Spyware",
            "Adware": "Рекламное ПО (Adware)" if is_ru else "Adware",
            "Worm": "Червь (Worm)" if is_ru else "Worm",
            "Backdoor": "Бэкдор (Backdoor)" if is_ru else "Backdoor",
            "Rootkit": "Руткит (Rootkit)" if is_ru else "Rootkit",
            "Keylogger": "Кейлоггер (Keylogger)" if is_ru else "Keylogger",
            "Downloader": "Загрузчик (Downloader)" if is_ru else "Downloader",
            "Dropper": "Дроппер (Dropper)" if is_ru else "Dropper",
            "Virus": "Вирус" if is_ru else "Virus",
            "Phishing": "Фишинг" if is_ru else "Phishing",
            "Exploit": "Эксплойт" if is_ru else "Exploit",
        }
        patterns = {
            "Ransomware": ("ransom", "cryptor", "cryptolocker"),
            "Spyware": ("spyware", "stealer", "infosteal", "passwordsteal"),
            "Keylogger": ("keylog",),
            "Backdoor": ("backdoor", "rat.", "remoteaccess"),
            "Rootkit": ("rootkit",),
            "Worm": ("worm",),
            "Adware": ("adware", "advert"),
            "Downloader": ("downloader",),
            "Dropper": ("dropper",),
            "Phishing": ("phish",),
            "Exploit": ("exploit",),
            "Trojan": ("trojan", "trj", "troj"),
            "Virus": ("virus", "fileinfector"),
        }
        counts = {name: 0 for name in patterns}
        for item in threats or []:
            try:
                signature = str(item[1]).lower()
            except (TypeError, IndexError):
                continue
            for kind, needles in patterns.items():
                if any(token in signature for token in needles):
                    counts[kind] += 1
        detected_kinds = sorted(((count, kind) for kind, count in counts.items() if count), reverse=True)
        if detected_kinds:
            top = detected_kinds[0][0]
            kinds = [labels[kind] for count, kind in detected_kinds if count == top]
            threat_type = ", ".join(kinds[:3])
        elif detections:
            threat_type = "Не удалось точно классифицировать" if is_ru else "Unclassified detection"
        else:
            threat_type = "Не выявлен" if is_ru else "Not detected"

        if risk_pct is None:
            risk_label = "Недостаточно данных" if is_ru else "Insufficient data"
        elif risk_pct >= 30:
            risk_label = "КРИТИЧЕСКИЙ" if is_ru else "CRITICAL"
        elif risk_pct >= 15:
            risk_label = "ВЫСОКИЙ" if is_ru else "HIGH"
        elif risk_pct >= 5:
            risk_label = "УМЕРЕННЫЙ" if is_ru else "MODERATE"
        elif detections:
            risk_label = "НИЗКИЙ, но есть срабатывания" if is_ru else "LOW, detections present"
        else:
            risk_label = "НИЗКИЙ" if is_ru else "LOW"
        return {"type": threat_type, "detection_pct": detection_pct, "risk_pct": risk_pct,
                "risk_label": risk_label, "total": total, "detections": detections}

    def _render_risk_summary(self, stats: dict, threats: list) -> str:
        profile = self._threat_profile(stats, threats)
        is_ru = self.lang == "ru"
        if profile["detection_pct"] is None:
            detection = "н/д" if is_ru else "n/a"
            risk = "н/д" if is_ru else "n/a"
        else:
            detection = f"{profile['detection_pct']:.1f}%"
            risk = f"{profile['risk_pct']:.1f}%"
        if is_ru:
            return ("\n\n🧬 <b>Классификация угрозы:</b> " + profile["type"] +
                    "\n📊 <b>Процент обнаружений:</b> " + detection +
                    "\n⚠️ <b>Оценка риска:</b> " + risk + " — <b>" + profile["risk_label"] + "</b>" +
                    f"\n🔎 <b>Сработало движков:</b> {profile['detections']} из {profile['total']}" +
                    "\n<i>Оценка эвристическая: подозрительные срабатывания учитываются с половинным весом; это не вероятность заражения.</i>")
        return ("\n\n🧬 <b>Threat classification:</b> " + profile["type"] +
                "\n📊 <b>Detection rate:</b> " + detection +
                "\n⚠️ <b>Risk score:</b> " + risk + " — <b>" + profile["risk_label"] + "</b>" +
                f"\n🔎 <b>Triggered engines:</b> {profile['detections']} of {profile['total']}" +
                "\n<i>Heuristic estimate: suspicious verdicts count half; this is not the probability of infection.</i>")

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
        text += self._render_risk_summary(stats, threats)
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

    def _extra_object_id(self, result: dict) -> str:
        if result.get("type") in ("file", "hash"):
            return result.get("sha256") or ""
        return result.get("id") or ""

    def _display_value(self, value, limit: int = 900) -> str:
        if value is None or value == "":
            return "—"
        if isinstance(value, bool):
            if self.lang == "ru":
                return "да" if value else "нет"
            return "yes" if value else "no"
        if isinstance(value, (dict, list, tuple)):
            value = ", ".join(str(x) for x in value) if isinstance(value, (list, tuple)) else "; ".join(f"{k}: {v}" for k, v in value.items())
        value = str(value).replace("\x00", "")
        value = value if len(value) <= limit else value[:limit - 1] + "…"
        return html.escape(value, quote=False)

    def _unix_date(self, value) -> str:
        try:
            return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(int(value)))
        except (TypeError, ValueError, OverflowError):
            return self._display_value(value)

    async def _get_extra_object(self, session, result: dict):
        object_id = self._extra_object_id(result)
        if not object_id:
            return {"error": "missing_object_id"}
        kind = "files" if result.get("type") in ("file", "hash") else "urls"
        return await self._request(session, "GET", f"{VT_API}/{kind}/{object_id}")

    async def _get_relationship(self, session, sha256: str, relationship: str):
        return await self._request(
            session, "GET", f"{VT_API}/files/{sha256}/{relationship}", params={"limit": 10}
        )

    async def _load_extra_tab(self, result: dict, tab: str):
        object_id = self._extra_object_id(result)
        if not object_id:
            return {"error": "missing_object_id"}

        async with aiohttp.ClientSession() as session:
            if tab == "details":
                data = await self._get_extra_object(session, result)
                if not isinstance(data, dict) or data.get("error"):
                    return data or {"error": "unavailable"}
                try:
                    return {"attributes": data["data"]["attributes"]}
                except (KeyError, TypeError):
                    return {"error": "parse"}

            if tab == "relations":
                if result.get("type") not in ("file", "hash"):
                    return {"error": "unavailable"}
                names = (
                    "contacted_domains", "contacted_ips", "contacted_urls",
                    "execution_parents", "execution_children", "dropped_files",
                )
                output = {}
                for name in names:
                    data = await self._get_relationship(session, object_id, name)
                    if isinstance(data, dict) and not data.get("error"):
                        output[name] = data.get("data", [])
                    elif isinstance(data, dict) and data.get("error") not in ("http_403", "http_404"):
                        output[name] = {"error": data.get("error")}
                    else:
                        output[name] = []
                return {"relationships": output}

            if tab == "behavior":
                if result.get("type") not in ("file", "hash"):
                    return {"error": "unavailable"}
                summary = await self._request(session, "GET", f"{VT_API}/files/{object_id}/behaviour_summary")
                reports = await self._request(session, "GET", f"{VT_API}/files/{object_id}/behaviours", params={"limit": 10})
                if (not summary or (isinstance(summary, dict) and summary.get("error"))) and (not reports or (isinstance(reports, dict) and reports.get("error"))):
                    return summary or reports or {"error": "unavailable"}
                summary_attrs = summary.get("data", {}) if isinstance(summary, dict) else {}
                report_items = reports.get("data", []) if isinstance(reports, dict) else []
                return {"summary": summary_attrs, "reports": report_items}

            if tab == "url_domain":
                if result.get("type") != "url":
                    return {"error": "unavailable"}
                url_data = await self._get_extra_object(session, result)
                if not isinstance(url_data, dict) or url_data.get("error"):
                    return url_data or {"error": "unavailable"}
                url_attrs = (url_data.get("data") or {}).get("attributes") or {}
                raw_url = result.get("url") or ""
                try:
                    host = (urlsplit(raw_url).hostname or "").lower().rstrip(".")
                except (TypeError, ValueError):
                    host = ""
                domain_attrs = {}
                if host:
                    domain_data = await self._request(session, "GET", f"{VT_API}/domains/{host}")
                    if isinstance(domain_data, dict) and not domain_data.get("error"):
                        domain_attrs = ((domain_data.get("data") or {}).get("attributes") or {})
                redirects = {}
                # Some URL objects/permissions expose redirect relationships; absence is normal.
                for rel in ("redirecting_to", "redirected_from"):
                    rel_data = await self._request(session, "GET", f"{VT_API}/urls/{object_id}/{rel}", params={"limit": 10})
                    if isinstance(rel_data, dict) and not rel_data.get("error"):
                        redirects[rel] = rel_data.get("data", [])
                    else:
                        redirects[rel] = []
                return {"url_attributes": url_attrs, "domain": host, "domain_attributes": domain_attrs, "redirects": redirects}

            if tab == "community":
                kind = "files" if result.get("type") in ("file", "hash") else "urls"
                data = await self._request(session, "GET", f"{VT_API}/{kind}/{object_id}/comments", params={"limit": 10})
                if not isinstance(data, dict) or data.get("error"):
                    return data or {"error": "unavailable"}
                return {"comments": data.get("data", [])}

        return {"error": "unknown_tab"}

    def _section(self, title: str, icon: str = "▫️") -> str:
        return f"\n{icon} <b>{title}</b>\n━━━━━━━━━━━━━━━━━━\n"

    def _render_details_tab(self, attrs: dict, state: dict) -> str:
        is_ru = self.lang == "ru"
        labels = [
            ("md5", "MD5"), ("sha1", "SHA-1"), ("sha256", "SHA-256"),
            ("vhash", "Vhash"), ("authentihash", "Authentihash"),
            ("imphash", "Imphash"), ("ssdeep", "SSDEEP"), ("tlsh", "TLSH"),
            ("type_description", "Тип файла" if is_ru else "File type"),
            ("magic", "Сигнатура" if is_ru else "Magic"),
            ("trid", "TrID"), ("detectiteasy", "Detect It Easy"), ("magika", "Magika"),
            ("size", "Размер" if is_ru else "File size"),
            ("reputation", "Репутация" if is_ru else "Reputation"),
            ("meaningful_name", "Имя" if is_ru else "Meaningful name"),
            ("times_submitted", "Отправок" if is_ru else "Submissions"),
            ("first_submission_date", "Первая отправка" if is_ru else "First submission"),
            ("last_submission_date", "Последняя отправка" if is_ru else "Last submission"),
            ("last_analysis_date", "Последний анализ" if is_ru else "Last analysis"),
            ("creation_date", "Время создания" if is_ru else "Creation time"),
        ]
        title = "📋 ПОДРОБНОСТИ ФАЙЛА" if is_ru else "📋 FILE DETAILS"
        lines = [f"<b>{title}</b>", "<i>VirusTotal · Object metadata</i>"]
        hash_keys = {"md5", "sha1", "sha256", "vhash", "authentihash", "imphash", "ssdeep", "tlsh"}
        for key, label in labels:
            value = attrs.get(key)
            if value is None or value == "":
                continue
            if key.endswith("_date") and value:
                value = self._unix_date(value)
            elif key == "size":
                value = f"{self._format_size(int(value))} ({value} bytes)"
            value = self._display_value(value, 240)
            if hash_keys.__contains__(key):
                lines.append(f"<b>{label}:</b> <code>{value}</code>")
            else:
                lines.append(f"<b>{label}:</b> {value}")

        for key, label in (("names", "Имена" if is_ru else "Known names"),
                           ("tags", "Теги" if is_ru else "Tags"),
                           ("type_tags", "Типы" if is_ru else "Type tags")):
            values = attrs.get(key) or []
            if values:
                lines.append(self._section(label, "🏷️"))
                for item in values[:12]:
                    lines.append(f"• {self._display_value(item, 150)}")
                if len(values) > 12:
                    lines.append(f"… +{len(values) - 12}")

        pe = attrs.get("pe_info") or {}
        if isinstance(pe, dict) and pe:
            lines.append(self._section("PE / Windows", "🧩"))
            for key in ("machine_type", "timestamp", "rich_pe_header_hash", "import_list", "export_list"):
                value = pe.get(key)
                if not value:
                    continue
                if isinstance(value, list):
                    value = ", ".join(str(x.get("library_name", x)) if isinstance(x, dict) else str(x) for x in value[:6])
                lines.append(f"• <b>{key}:</b> {self._display_value(value, 220)}")
        return "\n".join(lines)[:3900]

    def _render_relations_tab(self, payload: dict) -> str:
        is_ru = self.lang == "ru"
        labels = {
            "contacted_domains": "Контактировавшие домены" if is_ru else "Contacted domains",
            "contacted_ips": "Контактировавшие IP" if is_ru else "Contacted IP addresses",
            "contacted_urls": "Контактировавшие URL" if is_ru else "Contacted URLs",
            "execution_parents": "Родительские файлы" if is_ru else "Execution parents",
            "execution_children": "Дочерние файлы" if is_ru else "Execution children",
            "dropped_files": "Созданные файлы" if is_ru else "Dropped files",
        }
        lines = ["<b>🔗 СВЯЗАННЫЕ ОБЪЕКТЫ</b>" if is_ru else "<b>🔗 RELATED OBJECTS</b>",
                 "<i>VirusTotal · Relations</i>"]
        rels = payload.get("relationships", {})
        for key, label in labels.items():
            items = rels.get(key, [])
            count = len(items) if isinstance(items, list) else 0
            lines.append(self._section(f"{label} · {count}", "🌐"))
            if isinstance(items, dict):
                lines.append(f"⚠️ {self._display_value(items.get('error', 'API error'), 100)}")
            elif not items:
                lines.append("<i>Нет данных</i>" if is_ru else "<i>No data</i>")
            else:
                for item in items[:8]:
                    attrs = item.get("attributes", {}) if isinstance(item, dict) else {}
                    name = attrs.get("name") or attrs.get("meaningful_name") or attrs.get("url") or (item.get("id", "unknown") if isinstance(item, dict) else "unknown")
                    stats = attrs.get("last_analysis_stats", {})
                    detections = int(stats.get("malicious", 0)) + int(stats.get("suspicious", 0)) if isinstance(stats, dict) else 0
                    lines.append(f"• <code>{self._display_value(name, 170)}</code> · 🔴 {detections}")
                if count > 8:
                    lines.append(f"<i>… ещё {count - 8}</i>" if is_ru else f"<i>… {count - 8} more</i>")
        return "\n".join(lines)[:3900]

    def _render_behavior_tab(self, payload: dict) -> str:
        is_ru = self.lang == "ru"
        summary = payload.get("summary") or {}
        reports = payload.get("reports") or []
        lines = ["<b>🧪 ПОВЕДЕНЧЕСКИЙ АНАЛИЗ</b>" if is_ru else "<b>🧪 BEHAVIOR ANALYSIS</b>",
                 "<i>VirusTotal · Sandbox intelligence</i>"]
        fields = (
            ("tags", "Поведенческие теги" if is_ru else "Behavior tags"),
            ("calls_highlighted", "Подсвеченные вызовы" if is_ru else "Highlighted calls"),
            ("command_executions", "Команды" if is_ru else "Command executions"),
            ("files_opened", "Открытые файлы" if is_ru else "Files opened"),
            ("files_written", "Созданные/изменённые файлы" if is_ru else "Files written"),
            ("files_deleted", "Удалённые файлы" if is_ru else "Files deleted"),
            ("processes_created", "Созданные процессы" if is_ru else "Processes created"),
            ("modules_loaded", "Загруженные модули" if is_ru else "Modules loaded"),
            ("registry_keys_set", "Изменения реестра" if is_ru else "Registry changes"),
            ("mutexes_created", "Созданные mutex" if is_ru else "Mutexes created"),
            ("dns_lookups", "DNS-запросы" if is_ru else "DNS lookups"),
            ("ip_traffic", "Сетевой трафик" if is_ru else "IP traffic"),
            ("http_conversations", "HTTP-соединения" if is_ru else "HTTP conversations"),
            ("mitre_attack_techniques", "MITRE ATT&CK"),
            ("sigma_analysis_results", "Sigma Rules"), ("ids_alerts", "IDS Alerts"),
        )
        found = False
        for key, label in fields:
            values = summary.get(key)
            if not values:
                continue
            found = True
            lines.append(self._section(label, "🧬"))
            for value in values[:6] if isinstance(values, list) else [values]:
                if isinstance(value, dict):
                    value = value.get("rule_title") or value.get("technique") or value.get("name") or value
                lines.append(f"• {self._display_value(value, 180)}")
        if reports:
            found = True
            lines.append(self._section("Отчёты песочниц" if is_ru else "Sandbox reports", "📦"))
            for report in reports[:8]:
                attrs = report.get("attributes", {})
                name = attrs.get("sandbox_name") or report.get("id", "Sandbox")
                tags = ", ".join(attrs.get("tags", [])[:4])
                date = self._unix_date(attrs.get("analysis_date")) if attrs.get("analysis_date") else "—"
                lines.append(f"• <b>{self._display_value(name, 90)}</b> · {date}" + (f"\n  {self._display_value(tags, 180)}" if tags else ""))
        if not found:
            lines.append("\nℹ️ Нет доступных поведенческих данных." if is_ru else "\nℹ️ No behavior data is available.")
        return "\n".join(lines)[:3900]

    def _render_community_tab(self, payload: dict) -> str:
        is_ru = self.lang == "ru"
        comments = payload.get("comments") or []
        title = "💬 СООБЩЕСТВО" if is_ru else "💬 COMMUNITY"
        lines = [f"<b>{title} · {len(comments)}</b>", "<i>VirusTotal · Community comments</i>"]
        if not comments:
            lines.append("\nℹ️ Комментариев пока нет." if is_ru else "\nℹ️ No comments yet.")
        for item in comments[:8]:
            attrs = item.get("attributes", {}) if isinstance(item, dict) else {}
            author_data = attrs.get("author")
            author = author_data.get("name") if isinstance(author_data, dict) else author_data
            date = self._unix_date(attrs.get("date")) if attrs.get("date") else ""
            comment = attrs.get("text") or attrs.get("html") or attrs.get("votes", "")
            lines.append(self._section(f"{self._display_value(author or 'unknown', 70)} · {date}", "👤"))
            lines.append(self._display_value(comment, 420))
        return "\n".join(lines)[:3900]

    def _render_url_domain_tab(self, payload: dict) -> str:
        ru = self.lang == "ru"
        ua = payload.get("url_attributes") or {}
        da = payload.get("domain_attributes") or {}
        host = payload.get("domain") or "—"
        lines = ["<b>🌐 URL И ДОМЕН</b>" if ru else "<b>🌐 URL & DOMAIN</b>",
                 "<i>VirusTotal · URL intelligence</i>"]

        def add(label, value, icon="▫️", limit=220):
            if value is None or value == "":
                return
            lines.append(f"{icon} <b>{label}:</b> {self._display_value(value, limit)}")

        lines.append(self._section("ДОМЕН" if ru else "DOMAIN", "🌍"))
        add("Hostname", host)
        add("Registrar" if not ru else "Регистратор", da.get("registrar"))
        add("Страна сервера" if ru else "Server country", da.get("country") or ua.get("country"))
        add("Дата регистрации" if ru else "Registered", self._unix_date(da.get("creation_date")) if da.get("creation_date") else None)
        add("Истекает" if ru else "Expires", self._unix_date(da.get("expiration_date")) if da.get("expiration_date") else None)
        add("Репутация" if ru else "Reputation", da.get("reputation"))

        dns = da.get("last_dns_records") or []
        ips = []
        for record in dns if isinstance(dns, list) else []:
            if isinstance(record, dict) and record.get("type") in ("A", "AAAA") and record.get("value"):
                ips.append(record["value"])
        add("IP-адреса" if ru else "IP addresses", ", ".join(dict.fromkeys(ips)) if ips else None, "📡")

        lines.append(self._section("САЙТ И HTTP" if ru else "WEBSITE & HTTP", "🖥️"))
        add("HTTP-статус" if ru else "HTTP status", ua.get("last_http_response_code"), "📶")
        add("Финальный URL" if ru else "Final URL", ua.get("last_final_url"), "➡️", 300)
        add("Категории" if ru else "Categories", ua.get("categories") or da.get("categories"), "🏷️")
        stats = ua.get("last_analysis_stats") or da.get("last_analysis_stats") or {}
        if isinstance(stats, dict):
            det = int(stats.get("malicious", 0) or 0) + int(stats.get("suspicious", 0) or 0)
            add("Обнаружения" if ru else "Detections", f"{det} / {sum(int(v or 0) for v in stats.values() if isinstance(v, (int, float)))}", "🛡️")
        else:
            add("Обнаружения" if ru else "Detections", None)
        engine_results = ua.get("last_analysis_results") or da.get("last_analysis_results") or {}
        if isinstance(engine_results, dict):
            flagged = []
            for engine, info in engine_results.items():
                if isinstance(info, dict) and info.get("category") in ("malicious", "suspicious"):
                    flagged.append((engine, info.get("result") or info.get("category")))
            if flagged:
                lines.append(self._section("СРАБАТЫВАНИЯ АНТИВИРУСОВ" if ru else "ANTIVIRUS DETECTIONS", "🚨"))
                for engine, threat in flagged[:8]:
                    lines.append(f"• <b>{self._display_value(engine, 70)}:</b> {self._display_value(threat, 130)}")
                if len(flagged) > 8:
                    lines.append(f"… +{len(flagged) - 8}")

        cert = da.get("last_https_certificate") or ua.get("last_https_certificate") or {}
        if isinstance(cert, dict) and cert:
            lines.append(self._section("SSL-СЕРТИФИКАТ" if ru else "SSL CERTIFICATE", "🔒"))
            subject = cert.get("subject") or {}
            issuer = cert.get("issuer") or {}
            add("Владелец" if ru else "Subject", subject.get("CN") or subject.get("O") or subject, "👤")
            add("Издатель" if ru else "Issuer", issuer.get("CN") or issuer.get("O") or issuer, "🏢")
            validity = cert.get("validity") or {}
            add("Действителен с" if ru else "Valid from", validity.get("not_before"), "📅")
            add("Действителен до" if ru else "Valid until", validity.get("not_after"), "📅")
            add("SHA-256 отпечаток" if ru else "SHA-256 fingerprint", cert.get("thumbprint_sha256") or cert.get("thumbprint"), "🔑", 150)
        else:
            lines.append(self._section("SSL-СЕРТИФИКАТ" if ru else "SSL CERTIFICATE", "🔒"))
            lines.append("ℹ️ Нет доступных данных сертификата." if ru else "ℹ️ No certificate data available.")

        redirects = payload.get("redirects") or {}
        lines.append(self._section("ПЕРЕНАПРАВЛЕНИЯ" if ru else "REDIRECTS", "↪️"))
        found_redirect = False
        for rel, label in (("redirecting_to", "Ведёт на" if ru else "Redirects to"), ("redirected_from", "Перенаправлен с" if ru else "Redirected from")):
            items = redirects.get(rel) or []
            for item in items[:8]:
                found_redirect = True
                attrs = item.get("attributes", {}) if isinstance(item, dict) else {}
                target = attrs.get("url") or attrs.get("meaningful_name") or (item.get("id") if isinstance(item, dict) else item)
                lines.append(f"• <b>{label}:</b> <code>{self._display_value(target, 240)}</code>")
        if not found_redirect:
            chain = ua.get("redirection_chain") or ua.get("redirect_chain") or []
            if chain:
                for target in chain[:8]:
                    lines.append(f"• <code>{self._display_value(target, 240)}</code>")
                    found_redirect = True
        if not found_redirect:
            lines.append("ℹ️ Перенаправления не найдены или API их не предоставил." if ru else "ℹ️ No redirects found or returned by the API.")

        lines.append("\n<i>Часть полей зависит от доступности данных и уровня API VirusTotal.</i>" if ru else "\n<i>Field availability depends on VirusTotal data and API tier.</i>")
        return "\n".join(lines)[:3900]

    def _extra_tab_markup(self, state_key: str):
        return [[{"text": self._("btn_back_report"), "callback": self._cb_extra_back, "args": (state_key,)}]]

    async def _cb_extra_tab(self, call, state_key: str, tab: str, page: int = 0):
        state = self._inline_get(state_key)
        if not state:
            await call.answer(self._("inline_expired"), show_alert=True)
            return
        try:
            await call.answer()
        except Exception:
            pass
        try:
            await call.edit(self._("extra_loading"), reply_markup=self._extra_tab_markup(state_key))
            payload = await self._load_extra_tab(state["result"], tab)
            if not isinstance(payload, dict) or payload.get("error"):
                error = payload.get("error", "unavailable") if isinstance(payload, dict) else "unavailable"
                if error in ("http_403", "http_404", "unavailable", "missing_object_id"):
                    text = self._("extra_unavailable")
                else:
                    text = self._("extra_error", error=error)
            elif tab == "details":
                text = self._render_details_tab(payload.get("attributes", {}), state)
            elif tab == "relations":
                text = self._render_relations_tab(payload)
            elif tab == "behavior":
                text = self._render_behavior_tab(payload)
            elif tab == "community":
                text = self._render_community_tab(payload)
            elif tab == "url_domain":
                text = self._render_url_domain_tab(payload)
            else:
                text = self._("extra_unavailable")
            await call.edit(text, reply_markup=self._extra_tab_markup(state_key))
        except Exception as e:
            try:
                await call.edit(self._("extra_error", error=str(e)[:100]), reply_markup=self._extra_tab_markup(state_key))
            except Exception:
                pass

    async def _cb_extra_back(self, call, state_key: str):
        await call.answer()
        await self._edit_inline(call, state_key)

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
            "http_403": self._("extra_unavailable"),
            "http_404": self._("extra_unavailable"),
            "request_data": self._("parse_error"),
            "internal": self._("network_error"),
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
