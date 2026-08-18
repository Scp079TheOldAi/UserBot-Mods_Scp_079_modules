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
    """Информация о городе + погода на день / неделю (Open-Meteo)"""

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
        self, session: aiohttp.ClientSession, url: str, params: dict = None
    ) -> Optional[dict]:
        try:
            async with session.get(
                url,
                params=params,
                timeout=aiohttp.ClientTimeout(total=12),
                headers={"User-Agent": "Hikka-CityInfo/1.2"},
            ) as r:
                if r.status != 200:
                    return None
                return await r.json()
        except Exception:
            return None

    # ─── Геокодинг ──────────────────────────────────────────

    async def _geocode(
        self, session: aiohttp.ClientSession, query: str
    ) -> Optional[dict]:
        data = await self._get_json(
            session,
            "https://geocoding-api.open-meteo.com/v1/search",
            {"name": query, "count": 1, "language": "ru", "format": "json"},
        )
        if not data or not data.get("results"):
            return None
        return data["results"][0]

    # ─── Википедия ──────────────────────────────────────────

    async def _wiki_extract(
        self, session: aiohttp.ClientSession, title: str, lang: str = "ru"
    ) -> Optional[str]:
        data = await self._get_json(
            session,
            f"https://{lang}.wikipedia.org/w/api.php",
            {
                "action": "query",
                "prop": "extracts",
                "exintro": 1,
                "explaintext": 1,
                "titles": title,
                "format": "json",
                "redirects": 1,
            },
        )
        if not data:
            return None
        pages = data.get("query", {}).get("pages", {})
        for p in pages.values():
            ext = (p.get("extract") or "").strip()
            if ext:
                return ext[:1200]
        return None

    async def _wiki_founded_year(
        self, session: aiohttp.ClientSession, city_name: str, country: str
    ) -> Tuple[Optional[int], Optional[str]]:
        variants = [
            ("ru", city_name),
            ("en", city_name),
            ("ru", f"{city_name} ({country})" if country else city_name),
        ]
        tasks = [self._wiki_extract(session, title, lang) for lang, title in variants]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        patterns = [
            re.compile(
                r"(?:основан[ао]?|основание|впервые\s+упоминан|известен\s+с|"
                r"founded|established|mentioned).{0,55}?(\d{3,4})",
                re.I | re.S,
            ),
            re.compile(
                r"(\d{3,4})\s*(?:год[ауе]?|г\.).{0,35}?(?:основан|основание|founded)",
                re.I | re.S,
            ),
            re.compile(r"\b(1[0-9]{3}|20[0-2][0-9])\b"),
        ]

        for text in results:
            if not isinstance(text, str) or not text:
                continue
            for pat in patterns:
                m = pat.search(text)
                if m:
                    year = int(m.group(1))
                    if 1 <= year <= datetime.now().year:
                        snippet = text[:450].replace("\n", " ").strip()
                        return year, snippet
            return None, text[:450].replace("\n", " ").strip()
        return None, None

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
        )

    def _wmo(self, code) -> str:
        try:
            return WMO.get(int(code), f"❔ {code}")
        except (TypeError, ValueError):
            return "❔"

    def _fmt_day_hourly(self, w: dict, city: str) -> str:
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

        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        start_idx = 0
        for i, t in enumerate(times):
            try:
                dt = datetime.fromisoformat(t)
                if dt.replace(tzinfo=None) >= now.replace(tzinfo=None):
                    start_idx = i
                    break
            except Exception:
                continue

        end_idx = min(start_idx + 24, len(times))
        lines = [
            f"🌤 <b>Погода на 24 часа</b>\n"
            f"<b>{utils.escape_html(city)}</b>\n"
        ]

        for i in range(start_idx, end_idx):
            t = times[i]
            try:
                hh = t.split("T")[1][:5]
                day = t.split("T")[0][5:]  # MM-DD
            except Exception:
                hh, day = "??", ""
            temp = temps[i] if i < len(temps) else "?"
            feel = feels[i] if i < len(feels) else "?"
            hum = hums[i] if i < len(hums) else "?"
            pop = pops[i] if i < len(pops) else "?"
            code = codes[i] if i < len(codes) else None
            wind = winds[i] if i < len(winds) else "?"
            desc = self._wmo(code)

            lines.append(
                f"<code>{day} {hh}</code>  <b>{temp}°</b> (ощущ. {feel}°)  {desc}\n"
                f"     💧{hum}%  🌧{pop}%  💨{wind} км/ч"
            )

        lines.append("\n<i>Источник: Open-Meteo</i>")
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

            sr = ""
            ss = ""
            try:
                if i < len(sunrise) and sunrise[i]:
                    sr = sunrise[i].split("T")[1][:5]
                if i < len(sunset) and sunset[i]:
                    ss = sunset[i].split("T")[1][:5]
            except Exception:
                pass

            lines.append(
                f"\n<b>{label}</b>  {self._wmo(code)}\n"
                f"🌡 День <b>{mx}°</b>  ·  Ночь <b>{mn}°</b>\n"
                f"   ощущ. {amx}° / {amn}°\n"
                f"🌧 {pr} мм ({ph} ч)  ·  💨 до {wn} км/ч"
            )
            if sr or ss:
                lines.append(f"🌅 {sr}  🌇 {ss}")

        lines.append("\n<i>Источник: Open-Meteo</i>")
        return "\n".join(lines)

    # ─── Карточка города ────────────────────────────────────

    def _fmt_city_card(
        self, geo: dict, year: Optional[int], snippet: Optional[str]
    ) -> str:
        name = geo.get("name") or "?"
        country = geo.get("country") or "—"
        cc = geo.get("country_code") or ""
        admin1 = geo.get("admin1") or ""
        admin2 = geo.get("admin2") or ""
        admin3 = geo.get("admin3") or ""
        elevation = geo.get("elevation")
        pop = geo.get("population")
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

        # Год
        founded = "—"
        age = "—"
        if year:
            founded = str(year)
            a = datetime.now().year - year
            age = f"{a} лет" if a >= 0 else "—"

        # Индексы
        pc_s = ", ".join(postcodes[:5]) if postcodes else "—"
        if len(postcodes) > 5:
            pc_s += "…"

        text = (
            f"🏙 <b>{utils.escape_html(name)}</b>\n"
            f"{utils.escape_html(country)}"
            + (f" · <code>{cc}</code>" if cc else "")
            + "\n\n"
            f"<b>Регион:</b> {utils.escape_html(region)}\n"
            f"<b>Тип:</b> {utils.escape_html(ftype)}\n"
            f"<b>Население:</b> <code>{pop_s}</code>\n"
            f"<b>Высота:</b> <code>{elev_s}</code>\n"
            f"<b>Основан:</b> {founded}  ·  <b>Возраст:</b> {age}\n"
            f"<b>Часовой пояс:</b> <code>{utils.escape_html(tz)}</code>\n"
            f"<b>Координаты:</b> <code>{lat}, {lon}</code>\n"
            f"<b>Индекс(ы):</b> {utils.escape_html(pc_s)}"
        )

        if snippet:
            text += (
                f"\n\n<blockquote expandable>"
                f"📝 {utils.escape_html(snippet)}…"
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
            geo = await self._geocode(session, args)
            if not geo:
                await utils.answer(
                    message,
                    self.strings("not_found").format(utils.escape_html(args)),
                )
                return

            name = geo.get("name") or args
            country = geo.get("country") or ""
            year, snippet = await self._wiki_founded_year(session, name, country)

        card = self._fmt_city_card(geo, year, snippet)
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
