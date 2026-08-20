# meta developer: @Scp079Modules
# meta desc: Информация о городах + погода
# License: MIT - You can modify this file but must keep author credit

import asyncio
import re
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any, List

import aiohttp
from hikkatl.types import Message
from .. import loader, utils
from ..inline.types import InlineCall


WMO = {
    0: "☀️ Ясно",
    1: "🌤 Преим. ясно",
    2: "⛅ Перем. облачность",
    3: "☁️ Пасмурно",
    45: "🌫 Туман",
    48: "🌫 Инейный туман",
    51: "🌦 Морось слабая",
    53: "🌦 Морось",
    55: "🌧 Морось сильная",
    56: "🌧 Ледяная морось",
    57: "🌧 Ледяная морось сильн.",
    61: "🌧 Дождь слабый",
    63: "🌧 Дождь",
    65: "🌧 Дождь сильный",
    66: "🌧 Ледяной дождь",
    67: "🌧 Ледяной дождь сильн.",
    71: "🌨 Снег слабый",
    73: "🌨 Снег",
    75: "❄️ Снег сильный",
    77: "🌨 Снежные зёрна",
    80: "🌦 Ливень слабый",
    81: "🌧 Ливень",
    82: "⛈ Ливень сильный",
    85: "🌨 Снегопад слабый",
    86: "❄️ Снегопад сильный",
    95: "⛈ Гроза",
    96: "⛈ Гроза + град",
    99: "⛈ Гроза + сильный град",
}

FEATURE_CODES = {
    "PPLC": "Столица страны",
    "PPLA": "Адм. центр 1-го уровня",
    "PPLA2": "Адм. центр 2-го уровня",
    "PPLA3": "Адм. центр 3-го уровня",
    "PPLA4": "Адм. центр 4-го уровня",
    "PPL": "Населённый пункт",
    "PPLX": "Район / квартал",
}


@loader.tds
class CityInfoMod(loader.Module):
    """Информация о городе + погода на день / неделю"""

    strings = {
        "name": "CityInfo",
        "usage": (
            "ℹ️ <b>Использование:</b>\n"
            "<code>{}cityinfo &lt;город&gt;</code>\n\n"
            "Показывает подробную информацию о городе "
            "(население, высота, год основания, регион, часовой пояс и др.) "
            "и погоду на 24 часа / неделю."
        ),
        "searching": "🔎 Ищу информацию о <b>{}</b>…",
        "not_found": "❌ Город <b>{}</b> не найден.",
        "error": "⚠️ Ошибка: <code>{}</code>",
        "corrected": "✏️ Искали: <i>{}</i> → <b>{}</b>",
        "btn_day": "🌤 24 часа",
        "btn_week": "📅 Неделя",
        "btn_back": "⬅️ Назад",
        "btn_delete": "🗑 Удалить",
        "loading_weather": "⏳ Загружаю погоду…",
        "no_coords": "❌ Нет координат для погоды.",
    }

    strings_ru = strings

    # ─── HTTP ───────────────────────────────────────────────

    async def _get_json(
        self,
        session: aiohttp.ClientSession,
        url: str,
        params: dict = None,
        *,
        timeout: float = 10,
        retries: int = 2,
    ) -> Optional[dict]:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/128.0.0.0 Safari/537.36"
            ),
            "Accept": "application/json",
        }
        for attempt in range(max(1, retries)):
            try:
                async with session.get(
                    url,
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    headers=headers,
                ) as r:
                    if r.status == 429:
                        if attempt + 1 < retries:
                            await asyncio.sleep(0.8 * (attempt + 1))
                            continue
                        return None
                    if r.status != 200:
                        return None
                    return await r.json()
            except Exception:
                if attempt + 1 < retries:
                    await asyncio.sleep(0.3)
                    continue
                return None
        return None

    # ─── Геокодинг + автоисправление ────────────────────────

    async def _geocode(
        self, session: aiohttp.ClientSession, query: str, count: int = 3
    ) -> Optional[dict]:
        data = await self._get_json(
            session,
            "https://geocoding-api.open-meteo.com/v1/search",
            {
                "name": query,
                "count": count,
                "language": "ru",
                "format": "json",
            },
            timeout=8,
            retries=2,
        )
        if not data or not data.get("results"):
            return None
        results = data["results"]
        # предпочитаем более крупный населённый пункт
        results.sort(
            key=lambda x: (x.get("population") or 0),
            reverse=True,
        )
        return results[0]

    async def _suggest_name(
        self, session: aiohttp.ClientSession, query: str
    ) -> Optional[str]:
        """Подсказка при опечатке через Wikipedia OpenSearch."""
        data = await self._get_json(
            session,
            "https://ru.wikipedia.org/w/api.php",
            {
                "action": "opensearch",
                "search": query,
                "limit": 5,
                "namespace": 0,
                "format": "json",
            },
            timeout=6,
            retries=1,
        )
        # opensearch: [query, [titles], [descriptions], [urls]]
        if not data or not isinstance(data, list) or len(data) < 2:
            return None
        titles = data[1] or []
        if not titles:
            # fallback en
            data = await self._get_json(
                session,
                "https://en.wikipedia.org/w/api.php",
                {
                    "action": "opensearch",
                    "search": query,
                    "limit": 5,
                    "namespace": 0,
                    "format": "json",
                },
                timeout=6,
                retries=1,
            )
            if not data or not isinstance(data, list) or len(data) < 2:
                return None
            titles = data[1] or []
        if not titles:
            return None
        # берём первый осмысленный title (без скобок «значения» и т.п.)
        for t in titles:
            if not t:
                continue
            low = t.lower()
            if "значения" in low or "disambiguation" in low:
                continue
            # убираем уточнение в скобках для геокодинга: «Калифорния (штат)» → «Калифорния»
            clean = re.sub(r"\s*\([^)]*\)\s*$", "", t).strip()
            if clean and clean.lower() != query.lower():
                return clean
        # если все с disambiguation — всё равно вернём первый clean
        t0 = titles[0]
        return re.sub(r"\s*\([^)]*\)\s*$", "", t0).strip() or t0

    async def _resolve_place(
        self, session: aiohttp.ClientSession, query: str
    ) -> Tuple[Optional[dict], Optional[str]]:
        """
        Геокодинг + автоисправление опечаток.
        Возвращает (geo, corrected_name или None).
        """
        q = (query or "").strip()
        if not q:
            return None, None

        geo = await self._geocode(session, q)
        if geo:
            return geo, None

        # не нашли — пробуем исправить опечатку
        suggestion = await self._suggest_name(session, q)
        if not suggestion or suggestion.lower() == q.lower():
            return None, None

        geo = await self._geocode(session, suggestion)
        if geo:
            return geo, suggestion

        # иногда лучше геокодить исходный title из wiki без чистки
        geo = await self._geocode(session, suggestion)
        return geo, suggestion if geo else None

    # ─── Год основания / возраст / население / сниппет ─────────

    def _parse_time_year(self, time_str: str) -> Optional[int]:
        if not time_str:
            return None
        m = re.search(r"[+-]?(\d{1,4})", time_str)
        if not m:
            return None
        year = int(m.group(1))
        if 1 <= year <= datetime.now().year + 1:
            return year
        return None

    def _parse_wikidata_year(self, claims: dict) -> Optional[int]:
        """P571: preferred → value → somevalue + qualifiers."""
        p571 = claims.get("P571") or []
        p571 = sorted(p571, key=lambda c: 0 if c.get("rank") == "preferred" else 1)
        for claim in p571:
            mainsnak = claim.get("mainsnak") or {}
            snaktype = mainsnak.get("snaktype")
            if snaktype == "value":
                time_str = (
                    (mainsnak.get("datavalue") or {})
                    .get("value", {})
                    .get("time", "")
                )
                year = self._parse_time_year(time_str)
                if year is not None:
                    return year
            elif snaktype == "somevalue":
                quals = claim.get("qualifiers") or {}
                for qprop in ("P1326", "P580", "P585"):
                    for q in quals.get(qprop) or []:
                        if q.get("snaktype") == "value":
                            time_str = (
                                (q.get("datavalue") or {})
                                .get("value", {})
                                .get("time", "")
                            )
                            year = self._parse_time_year(time_str)
                            if year is not None:
                                return year
        return None

    def _parse_wikidata_population(self, claims: dict) -> Optional[int]:
        """Самое свежее P1082."""
        best_pop, best_time = None, ""
        for claim in claims.get("P1082") or []:
            if claim.get("rank") == "deprecated":
                continue
            mainsnak = claim.get("mainsnak") or {}
            if mainsnak.get("snaktype") != "value":
                continue
            val = (mainsnak.get("datavalue") or {}).get("value")
            try:
                if isinstance(val, dict):
                    amount = str(val.get("amount", "0")).lstrip("+")
                    pop = int(float(amount))
                else:
                    pop = int(val)
            except (TypeError, ValueError):
                continue
            if pop <= 0:
                continue
            time_str = ""
            for q in (claim.get("qualifiers") or {}).get("P585") or []:
                if q.get("snaktype") == "value":
                    time_str = (
                        (q.get("datavalue") or {})
                        .get("value", {})
                        .get("time", "")
                    )
                    break
            if not best_time or (time_str and time_str > best_time):
                best_time, best_pop = time_str, pop
            elif best_pop is None:
                best_pop = pop
        return best_pop

    def _year_from_text(self, text: str) -> Optional[int]:
        """Поиск года основания в тексте статьи (fallback)."""
        if not text:
            return None
        patterns = [
            # основан/заложен/учреждён [дата] YEAR
            re.compile(
                r"(?:основан[ао]?|основание|заложен[ао]?|учрежд[её]н[ао]?|"
                r"возник|появил(?:ся|ась))\s*"
                r"(?:в\s+|около\s+|примерно\s+)?"
                r"(?:\d{1,2}\s+(?:января|февраля|марта|апреля|мая|июня|"
                r"июля|августа|сентября|октября|ноября|декабря)\s+)?"
                r"(\d{3,4})\s*(?:год[ауе]?|г\.?)?",
                re.I | re.S,
            ),
            # впервые упоминается / известен с / упоминается в YEAR
            re.compile(
                r"(?:впервые\s+упоминан[ао]?|известен\s+с|упоминается\s+с|"
                r"упоминается\s+в)\s*"
                r"(?:в\s+)?"
                r"(\d{3,4})\s*(?:год[ауе]?|г\.?)?",
                re.I | re.S,
            ),
            # YEAR год — основан / основание
            re.compile(
                r"(\d{3,4})\s*(?:год[ауе]?|г\.?)\s*"
                r"(?:[—–−-]?\s*)?(?:основан|основание|заложен|учрежд|"
                r"founded|established)",
                re.I | re.S,
            ),
            # founded / established in YEAR
            re.compile(
                r"(?:founded|established|settled)\s+(?:in\s+|on\s+)?"
                r"(?:\d{1,2}\s+\w+\s+)?"
                r"(\d{3,4})",
                re.I | re.S,
            ),
            # с YEAR года / с YEAR г.
            re.compile(
                r"(?:^|[^\d])с\s+(\d{3,4})\s*(?:год[ауе]?|г\.?)",
                re.I,
            ),
        ]
        for pat in patterns:
            m = pat.search(text)
            if m:
                year = int(m.group(1))
                if 500 <= year <= datetime.now().year:
                    return year
        return None

    async def _wiki_page(
        self, session: aiohttp.ClientSession, title: str, lang: str = "ru"
    ) -> Tuple[Optional[str], Optional[str]]:
        """Один запрос: extract + QID."""
        data = await self._get_json(
            session,
            f"https://{lang}.wikipedia.org/w/api.php",
            {
                "action": "query",
                "prop": "extracts|pageprops",
                "exintro": 1,
                "explaintext": 1,
                "exchars": 900,
                "titles": title,
                "format": "json",
                "redirects": 1,
            },
            timeout=7,
            retries=1,
        )
        if not data:
            return None, None
        pages = data.get("query", {}).get("pages", {})
        for p in pages.values():
            if "missing" in p:
                continue
            ext = (p.get("extract") or "").strip()
            qid = (p.get("pageprops") or {}).get("wikibase_item")
            snippet = ext[:500].replace("\n", " ").strip() if ext else None
            return snippet, qid
        return None, None

    async def _wikidata_claims(
        self, session: aiohttp.ClientSession, qid: str
    ) -> Optional[dict]:
        if not qid:
            return None
        data = await self._get_json(
            session,
            "https://www.wikidata.org/w/api.php",
            {
                "action": "wbgetentities",
                "ids": qid,
                "props": "claims",
                "format": "json",
            },
            timeout=7,
            retries=1,
        )
        if not data:
            return None
        entity = (data.get("entities") or {}).get(qid) or {}
        return entity.get("claims") or {}

    async def _wikidata_search_and_claims(
        self, session: aiohttp.ClientSession, query: str, lang: str = "ru"
    ) -> Tuple[Optional[int], Optional[int]]:
        """Поиск + claims. Возвращает (year, pop)."""
        data = await self._get_json(
            session,
            "https://www.wikidata.org/w/api.php",
            {
                "action": "wbsearchentities",
                "search": query,
                "language": lang,
                "uselang": lang,
                "type": "item",
                "limit": 3,
                "format": "json",
            },
            timeout=6,
            retries=1,
        )
        if not data:
            return None, None
        qids = [
            item["id"]
            for item in (data.get("search") or [])
            if item.get("id", "").startswith("Q")
        ][:3]
        if not qids:
            return None, None

        data2 = await self._get_json(
            session,
            "https://www.wikidata.org/w/api.php",
            {
                "action": "wbgetentities",
                "ids": "|".join(qids),
                "props": "claims",
                "format": "json",
            },
            timeout=7,
            retries=1,
        )
        if not data2:
            return None, None

        best_year, best_pop = None, None
        entities = data2.get("entities") or {}
        for qid in qids:
            claims = (entities.get(qid) or {}).get("claims") or {}
            year = self._parse_wikidata_year(claims)
            pop = self._parse_wikidata_population(claims)
            if year is not None:
                return year, pop or best_pop
            if pop and best_pop is None:
                best_pop = pop
        return best_year, best_pop

    async def _get_city_extra(
        self,
        session: aiohttp.ClientSession,
        city_name: str,
        country: str = "",
        admin1: str = "",
    ) -> Tuple[Optional[int], Optional[int], Optional[str]]:
        """
        (year, wiki_population, snippet)
        Быстрый путь: максимум 2–3 запроса для обычных мест,
        без длинных цепочек для деревень.
        """
        year = None
        pop = None
        snippet = None

        # 1) Одна попытка Wikipedia (ru) по точному имени
        snip, qid = await self._wiki_page(session, city_name, "ru")
        if snip:
            snippet = snip
        if qid:
            claims = await self._wikidata_claims(session, qid)
            if claims:
                year = self._parse_wikidata_year(claims)
                pop = self._parse_wikidata_population(claims)

        # 2) Если нет года — один поиск Wikidata (ru)
        if year is None:
            y, p = await self._wikidata_search_and_claims(session, city_name, "ru")
            if y is not None:
                year = y
            if p and pop is None:
                pop = p

        # 3) Regex по уже полученному тексту
        if year is None and snippet:
            year = self._year_from_text(snippet)

        # 4) Если совсем нет сниппета — быстрый en / вариант с регионом
        if not snippet:
            for title in (
                f"{city_name} ({admin1})" if admin1 else None,
                f"{city_name} ({country})" if country else None,
                city_name,
            ):
                if not title:
                    continue
                lang = "ru" if title != city_name or not snippet else "en"
                snip, qid = await self._wiki_page(
                    session, title, "ru" if country or admin1 else "en"
                )
                if snip:
                    snippet = snip
                    if year is None:
                        year = self._year_from_text(snip)
                    if year is None and qid:
                        claims = await self._wikidata_claims(session, qid)
                        if claims:
                            year = self._parse_wikidata_year(claims)
                            pop = self._parse_wikidata_population(claims) or pop
                    break

        return year, pop, snippet

    # ─── Погода ─────────────────────────────────────────────

    async def _weather(
        self,
        session: aiohttp.ClientSession,
        lat: float,
        lon: float,
        timezone: str = "auto",
    ) -> Optional[dict]:
        return await self._get_json(
            session,
            "https://api.open-meteo.com/v1/forecast",
            {
                "latitude": lat,
                "longitude": lon,
                "current": (
                    "temperature_2m,apparent_temperature,relative_humidity_2m,"
                    "precipitation_probability,weather_code,wind_speed_10m,is_day"
                ),
                "hourly": (
                    "temperature_2m,apparent_temperature,relative_humidity_2m,"
                    "precipitation_probability,weather_code,wind_speed_10m"
                ),
                "daily": (
                    "weather_code,temperature_2m_max,temperature_2m_min,"
                    "apparent_temperature_max,apparent_temperature_min,"
                    "precipitation_sum,precipitation_hours,"
                    "wind_speed_10m_max,sunrise,sunset"
                ),
                "timezone": timezone or "auto",
                "forecast_days": 7,
            },
            timeout=10,
            retries=2,
        )

    def _wmo(self, code) -> str:
        try:
            return WMO.get(int(code), f"❔ {code}")
        except (TypeError, ValueError):
            return "❔"

    def _fmt_day_hourly(self, w: dict, city: str) -> str:
        current = w.get("current") or {}
        hourly = w.get("hourly") or {}
        times = hourly.get("time") or []
        temps = hourly.get("temperature_2m") or []
        feels = hourly.get("apparent_temperature") or []
        hums = hourly.get("relative_humidity_2m") or []
        pops = hourly.get("precipitation_probability") or []
        codes = hourly.get("weather_code") or []
        winds = hourly.get("wind_speed_10m") or []

        if not times:
            return "❌ Нет почасовых данных."

        # Текущая погода
        cur_temp = current.get("temperature_2m")
        cur_feel = current.get("apparent_temperature")
        cur_hum = current.get("relative_humidity_2m")
        cur_pop = current.get("precipitation_probability")
        cur_code = current.get("weather_code")
        cur_wind = current.get("wind_speed_10m")
        cur_time = current.get("time") or ""

        lines = [
            f"🌤 <b>Сейчас · {utils.escape_html(city)}</b>",
        ]

        if cur_temp is not None:
            desc = self._wmo(cur_code)
            lines.append(
                f"<b>{cur_temp}°</b> (ощущ. {cur_feel}°)  {desc}\n"
                f"💧 {cur_hum}%   🌧 {cur_pop}%   💨 {cur_wind} км/ч"
            )
        else:
            lines.append("<i>Нет данных о текущей погоде</i>")

        lines.append("\n<b>📅 Следующие 24 часа</b>")

        # Начинаем с текущего часа (или следующего)
        start_idx = 0
        if cur_time:
            for i, t in enumerate(times):
                if t >= cur_time:
                    start_idx = i
                    break
        else:
            # fallback: берём с начала
            start_idx = 0

        end_idx = min(start_idx + 24, len(times))
        prev_day = None

        for i in range(start_idx, end_idx):
            t = times[i]
            try:
                day_part = t.split("T")[0][5:]  # MM-DD
                hh = t.split("T")[1][:5]
            except Exception:
                day_part, hh = "??", "??"

            # показываем дату только при смене дня
            day_label = ""
            if day_part != prev_day:
                day_label = f"<b>{day_part}</b> "
                prev_day = day_part

            temp = temps[i] if i < len(temps) else "?"
            feel = feels[i] if i < len(feels) else "?"
            hum = hums[i] if i < len(hums) else "?"
            pop = pops[i] if i < len(pops) else "?"
            code = codes[i] if i < len(codes) else None
            wind = winds[i] if i < len(winds) else "?"
            desc = self._wmo(code)

            # Компактный однострочный формат
            lines.append(
                f"{day_label}<code>{hh}</code>  <b>{temp}°</b> "
                f"(ощущ. {feel}°)  {desc}  "
                f"💧{hum}% 🌧{pop}% 💨{wind}"
            )

        text = "\n".join(lines)
        return text[:4000] + "…" if len(text) > 4000 else text

    def _fmt_week(self, w: dict, city: str) -> str:
        daily = w.get("daily") or {}
        times = daily.get("time") or []
        tmax = daily.get("temperature_2m_max") or []
        tmin = daily.get("temperature_2m_min") or []
        amax = daily.get("apparent_temperature_max") or []
        amin = daily.get("apparent_temperature_min") or []
        codes = daily.get("weather_code") or []
        rain = daily.get("precipitation_sum") or []
        phours = daily.get("precipitation_hours") or []
        wind = daily.get("wind_speed_10m_max") or []
        sunrise = daily.get("sunrise") or []
        sunset = daily.get("sunset") or []

        if not times:
            return "❌ Нет данных на неделю."

        wd = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"]
        lines = [
            f"📅 <b>Погода на неделю</b>\n"
            f"<b>{utils.escape_html(city)}</b>\n"
        ]

        for i, day in enumerate(times[:7]):
            try:
                d = datetime.fromisoformat(day)
                label = f"{wd[d.weekday()]} {d.strftime('%d.%m')}"
            except Exception:
                label = day

            mx = tmax[i] if i < len(tmax) else "?"
            mn = tmin[i] if i < len(tmin) else "?"
            amx = amax[i] if i < len(amax) else "?"
            amn = amin[i] if i < len(amin) else "?"
            code = codes[i] if i < len(codes) else None
            pr = rain[i] if i < len(rain) else "?"
            ph = phours[i] if i < len(phours) else "?"
            wn = wind[i] if i < len(wind) else "?"

            sr = ss = ""
            try:
                if i < len(sunrise) and sunrise[i]:
                    sr = sunrise[i].split("T")[1][:5]
                if i < len(sunset) and sunset[i]:
                    ss = sunset[i].split("T")[1][:5]
            except Exception:
                pass

            # Более компактный и читаемый блок
            lines.append(
                f"\n<b>{label}</b>  {self._wmo(code)}\n"
                f"🌡 <b>{mx}°</b> / <b>{mn}°</b>  "
                f"<i>(ощущ. {amx}° / {amn}°)</i>\n"
                f"🌧 {pr} мм · {ph} ч   💨 до {wn} км/ч"
            )
            if sr or ss:
                lines.append(f"🌅 {sr}   🌇 {ss}")

        return "\n".join(lines)

    # ─── Карточка города ────────────────────────────────────

    def _fmt_city_card(
        self,
        geo: dict,
        year: Optional[int],
        snippet: Optional[str],
        wiki_pop: Optional[int] = None,
    ) -> str:
        name = geo.get("name") or "?"
        country = geo.get("country") or "—"
        cc = geo.get("country_code") or ""
        admin1 = geo.get("admin1") or ""
        admin2 = geo.get("admin2") or ""
        admin3 = geo.get("admin3") or ""
        elevation = geo.get("elevation")
        # Население: предпочитаем свежие данные Wikidata
        pop = wiki_pop if isinstance(wiki_pop, int) and wiki_pop > 0 else geo.get("population")
        tz = geo.get("timezone") or "—"
        lat = geo.get("latitude")
        lon = geo.get("longitude")
        fcode = geo.get("feature_code") or ""
        postcodes = geo.get("postcodes") or []

        # Регион
        region_parts = [p for p in (admin1, admin2, admin3) if p]
        region = " → ".join(region_parts) if region_parts else "—"

        # Тип
        ftype = FEATURE_CODES.get(fcode, fcode) if fcode else "—"

        # Население
        pop_s = f"{pop:,}".replace(",", " ") if isinstance(pop, int) else "—"

        # Высота
        elev_s = f"{elevation:.0f} м" if isinstance(elevation, (int, float)) else "—"

        # Год и возраст (только если год достоверно найден)
        founded = "—"
        age = "—"
        if year:
            founded = str(year)
            a = datetime.now().year - year
            if a >= 0:
                if a % 10 == 1 and a % 100 != 11:
                    age = f"{a} год"
                elif 2 <= a % 10 <= 4 and not (12 <= a % 100 <= 14):
                    age = f"{a} года"
                else:
                    age = f"{a} лет"

        # Индексы
        pc_s = ", ".join(str(p) for p in postcodes[:5]) if postcodes else "—"
        if len(postcodes) > 5:
            pc_s += "…"

        text = (
            f"🏙 <b>{utils.escape_html(name)}</b>\n"
            f"{utils.escape_html(country)}"
            + (f" · <code>{cc}</code>" if cc else "")
            + "\n\n"
            f"📍 <b>Регион:</b> {utils.escape_html(region)}\n"
            f"🏛 <b>Тип:</b> {utils.escape_html(ftype)}\n"
            f"👥 <b>Население:</b> <code>{pop_s}</code>\n"
            f"⛰ <b>Высота:</b> <code>{elev_s}</code>\n"
            f"📅 <b>Основан:</b> {founded}  ·  <b>Возраст:</b> {age}\n"
            f"🕐 <b>Часовой пояс:</b> <code>{utils.escape_html(tz)}</code>\n"
            f"🗺 <b>Координаты:</b> <code>{lat}, {lon}</code>\n"
            f"📮 <b>Индекс(ы):</b> {utils.escape_html(pc_s)}"
        )

        if snippet:
            # обрезаем аккуратно и делаем expandable
            snip = snippet.strip()
            if len(snip) > 380:
                snip = snip[:380].rsplit(" ", 1)[0] + "…"
            text += (
                f"\n\n<blockquote expandable>"
                f"📝 {utils.escape_html(snip)}"
                f"</blockquote>"
            )

        return text

    def _main_markup(self, city_key: str):
        return [
            [
                {
                    "text": self.strings("btn_day"),
                    "callback": self._cb_weather_day,
                    "args": (city_key,),
                },
                {
                    "text": self.strings("btn_week"),
                    "callback": self._cb_weather_week,
                    "args": (city_key,),
                },
            ],
            [{"text": self.strings("btn_delete"), "callback": self._cb_delete}],
        ]

    def _weather_markup(self, city_key: str, mode: str):
        toggle_text = (
            self.strings("btn_week") if mode == "day" else self.strings("btn_day")
        )
        toggle_cb = (
            self._cb_weather_week if mode == "day" else self._cb_weather_day
        )
        return [
            [
                {
                    "text": self.strings("btn_back"),
                    "callback": self._cb_back,
                    "args": (city_key,),
                },
                {
                    "text": toggle_text,
                    "callback": toggle_cb,
                    "args": (city_key,),
                },
                {"text": self.strings("btn_delete"), "callback": self._cb_delete},
            ],
        ]

    # ─── Кэш ────────────────────────────────────────────────

    def _cache_get(self) -> Dict[str, Any]:
        if not hasattr(self, "_city_cache"):
            self._city_cache: Dict[str, Any] = {}
        return self._city_cache

    def _store_city(self, geo: dict, year, snippet, card_html: str) -> str:
        key = f"{geo.get('name')}_{geo.get('latitude')}_{geo.get('longitude')}"
        self._cache_get()[key] = {
            "geo": geo,
            "year": year,
            "snippet": snippet,
            "card": card_html,
            "weather": None,
        }
        return key

    # ─── Команда ────────────────────────────────────────────

    @loader.command(
        ru_doc="<город> — подробная информация о городе",
    )
    async def cityinfocmd(self, message: Message):
        """<city> — detailed city information + weather forecast (24h / 7 days)"""
        args = utils.get_args_raw(message)
        if not args:
            await utils.answer(
                message, self.strings("usage").format(self.get_prefix())
            )
            return

        await utils.answer(
            message, self.strings("searching").format(utils.escape_html(args))
        )

        async with aiohttp.ClientSession() as session:
            geo, corrected = await self._resolve_place(session, args)
            if not geo:
                await utils.answer(
                    message,
                    self.strings("not_found").format(utils.escape_html(args)),
                )
                return

            name = geo.get("name") or args
            country = geo.get("country") or ""
            admin1 = geo.get("admin1") or ""
            year, wiki_pop, snippet = await self._get_city_extra(
                session, name, country, admin1
            )

        card = self._fmt_city_card(geo, year, snippet, wiki_pop)
        if corrected:
            note = self.strings("corrected").format(
                utils.escape_html(args),
                utils.escape_html(corrected),
            )
            card = note + "\n\n" + card

        city_key = self._store_city(geo, year, snippet, card)

        await self.inline.form(
            text=card,
            message=message,
            reply_markup=self._main_markup(city_key),
            silent=True,
        )

    # ─── Callbacks ──────────────────────────────────────────

    async def _ensure_weather(self, city_key: str) -> Optional[dict]:
        cache = self._cache_get().get(city_key)
        if not cache:
            return None
        if cache.get("weather"):
            return cache["weather"]

        geo = cache["geo"]
        lat, lon = geo.get("latitude"), geo.get("longitude")
        if lat is None or lon is None:
            return None

        async with aiohttp.ClientSession() as session:
            w = await self._weather(
                session, lat, lon, geo.get("timezone") or "auto"
            )
        if w:
            cache["weather"] = w
        return w

    async def _cb_weather_day(self, call: InlineCall, city_key: str):
        await call.edit(text=self.strings("loading_weather"))
        cache = self._cache_get().get(city_key)
        if not cache:
            await call.edit(text="❌ Сессия устарела. Вызови команду снова.")
            return

        w = await self._ensure_weather(city_key)
        if not w:
            await call.edit(
                text=self.strings("no_coords"),
                reply_markup=self._main_markup(city_key),
            )
            return

        city = cache["geo"].get("name") or "город"
        text = self._fmt_day_hourly(w, city)
        await call.edit(
            text=text,
            reply_markup=self._weather_markup(city_key, "day"),
        )

    async def _cb_weather_week(self, call: InlineCall, city_key: str):
        await call.edit(text=self.strings("loading_weather"))
        cache = self._cache_get().get(city_key)
        if not cache:
            await call.edit(text="❌ Сессия устарела. Вызови команду снова.")
            return

        w = await self._ensure_weather(city_key)
        if not w:
            await call.edit(
                text=self.strings("no_coords"),
                reply_markup=self._main_markup(city_key),
            )
            return

        city = cache["geo"].get("name") or "город"
        text = self._fmt_week(w, city)
        await call.edit(
            text=text,
            reply_markup=self._weather_markup(city_key, "week"),
        )

    async def _cb_back(self, call: InlineCall, city_key: str):
        cache = self._cache_get().get(city_key)
        if not cache:
            await call.edit(text="❌ Сессия устарела. Вызови команду снова.")
            return
        await call.edit(
            text=cache["card"],
            reply_markup=self._main_markup(city_key),
        )

    async def _cb_delete(self, call: InlineCall):
        await call.delete()
