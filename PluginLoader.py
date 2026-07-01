"""
FunPayCardinal Plugin Loader v4.0
Совместим с BIND_TO_* форматом (sidor0912/FunPayCardinal).
Пользователь получает: PluginLoader.py + loader_core.dll

Ключ профиля вводится через Telegram-бот Cardinal командой /lkey.
Ключ активации вводится командой /lactivate.
Файлы вручную не редактируются.
"""
import base64
import ctypes
import logging
import sys
import threading
from pathlib import Path

# ── Метаданные Cardinal-плагина ───────────────────────────────────────────── #
NAME          = "PluginLoader"
VERSION       = "4.0.0"
DESCRIPTION   = "Загружает зашифрованные плагины с лицензионного сервера"
CREDITS       = "@kapystus"
UUID          = "a1b2c3d4-e5f6-4a7b-8c9d-000000000001"
SETTINGS_PAGE = False
BIND_TO_DELETE = None

logger = logging.getLogger("FPC.PluginLoader")

_UPDATE_INTERVAL = 24 * 3600  # 24 часа


def _dll_str(func_name: str) -> str:
    """Читает строку из loader_core через ctypes. Возвращает '' если DLL недоступна."""
    ext = ".dll" if sys.platform == "win32" else ".so"
    for d in [Path("plugins"), Path(__file__).parent]:
        p = d / f"loader_core{ext}"
        if p.exists():
            try:
                lib = ctypes.CDLL(str(p.resolve()))
                fn = getattr(lib, func_name)
                fn.restype = ctypes.c_char_p
                raw = fn()
                return raw.decode("utf-8") if raw else ""
            except Exception:
                pass
    return ""


# ── Зависимости ───────────────────────────────────────────────────────────── #

def _ensure(pkg: str, import_name: str | None = None) -> None:
    name = import_name or pkg
    try:
        __import__(name)
    except ImportError:
        import subprocess
        logger.info(f"[PluginLoader] Устанавливаю {pkg}...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg, "-q"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


# ── URL сервера и мета из loader_core ────────────────────────────────────── #

def _aes_ctx_seed() -> str:
    url = _dll_str("aes_ctx_seed")
    if url:
        return url.rstrip("/")
    ext = ".dll" if sys.platform == "win32" else ".so"
    raise RuntimeError(f"loader_core{ext} не найден в папке plugins/")


# ── Хранение ключа профиля ────────────────────────────────────────────────── #

_key_cache: str = ""


def _profile_file() -> Path:
    for d in [Path("plugins"), Path(__file__).parent]:
        if d.exists():
            return d / ".loader_profile"
    return Path("plugins/.loader_profile")


def _get_stored_key() -> str:
    global _key_cache
    if _key_cache:
        return _key_cache
    p = _profile_file()
    if p.exists():
        k = p.read_text(encoding="utf-8").strip()
        if k:
            _key_cache = k
            return k
    # Миграция: если нет .loader_profile, но есть старый loader.cfg
    import configparser
    for cfg_p in [Path("plugins/loader.cfg"), Path(__file__).parent / "loader.cfg"]:
        if cfg_p.exists():
            try:
                cfg = configparser.ConfigParser()
                cfg.read(str(cfg_p), encoding="utf-8")
                k = cfg.get("loader", "license_key", fallback="").strip()
                if k and k != "00000000-0000-0000-0000-000000000000" and k != "YOUR-KEY":
                    _save_key(k)
                    logger.info(f"[PluginLoader] Мигрирован ключ из loader.cfg → .loader_profile")
                    return k
            except Exception:
                pass
    return ""


def _save_key(key: str) -> None:
    global _key_cache
    _key_cache = key
    try:
        _profile_file().write_text(key + "\n", encoding="utf-8")
    except Exception as e:
        logger.warning(f"[PluginLoader] Не удалось сохранить ключ: {e}")


# ── Крипто ────────────────────────────────────────────────────────────────── #

_SALT       = b"fpc_loader_v1_2026"
_ITERATIONS = 100_000


def _derive_aes(license_key: str) -> bytes:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=_SALT, iterations=_ITERATIONS)
    return kdf.derive(license_key.encode())


def _decrypt(b64_token: str, license_key: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw = base64.b64decode(b64_token)
    return AESGCM(_derive_aes(license_key)).decrypt(raw[:12], raw[12:], None)


# ── Динамические хендлеры ─────────────────────────────────────────────────── #

_ALL_EVENTS = [
    "BIND_TO_PRE_INIT",   "BIND_TO_POST_INIT",
    "BIND_TO_PRE_START",  "BIND_TO_POST_START",
    "BIND_TO_PRE_STOP",   "BIND_TO_POST_STOP",
    "BIND_TO_INIT_MESSAGE",
    "BIND_TO_MESSAGES_LIST_CHANGED", "BIND_TO_LAST_CHAT_MESSAGE_CHANGED",
    "BIND_TO_NEW_MESSAGE",
    "BIND_TO_INIT_ORDER", "BIND_TO_NEW_ORDER",
    "BIND_TO_ORDERS_LIST_CHANGED", "BIND_TO_ORDER_STATUS_CHANGED",
    "BIND_TO_PRE_DELIVERY", "BIND_TO_POST_DELIVERY",
    "BIND_TO_PRE_LOTS_RAISE", "BIND_TO_POST_LOTS_RAISE",
]
_dyn: dict[str, list] = {ev: [] for ev in _ALL_EVENTS}
_registered_uuids: set[str] = set()
_expiry_thread: threading.Thread | None = None
_active_plugin_snapshot: set[str] = set()  # plugin_id → expires_at для сравнения


def _dispatch(event_name: str):
    def _handler(*args):
        for fn in _dyn[event_name]:
            try:
                fn(*args)
            except Exception as ex:
                logger.error(f"[PluginLoader] {event_name}/{getattr(fn,'__name__','?')}: {ex}")
    _handler.__name__ = f"_dispatch_{event_name}"
    return _handler


# ── Загрузка плагинов ─────────────────────────────────────────────────────── #

def _load_plugins(cardinal, server_url: str, key: str) -> int:
    """Скачивает и запускает плагины. Сбрасывает _dyn перед загрузкой. Возвращает кол-во."""
    import requests

    for ev in _ALL_EVENTS:
        _dyn[ev].clear()

    # Убираем устаревшие записи из меню Cardinal перед перезагрузкой
    if _registered_uuids and cardinal and hasattr(cardinal, "plugins"):
        for uid in list(_registered_uuids):
            cardinal.plugins.pop(uid, None)
        _registered_uuids.clear()

    try:
        resp = requests.post(f"{server_url}/api/list",
                             json={"license_key": key}, timeout=30)
        if resp.status_code == 403:
            logger.error("[PluginLoader] Ключ не найден на сервере (403) — введите /lkey заново")
            return 0
        resp.raise_for_status()
        plugin_list = resp.json()["plugins"]
    except Exception as e:
        logger.error(f"[PluginLoader] /api/list: {e}")
        return 0

    if not plugin_list:
        logger.info("[PluginLoader] Нет активных плагинов — активируйте через /lactivate ACT-...")
        return 0

    loaded, errors = 0, []
    for p in plugin_list:
        pid   = p["plugin_id"]
        pname = p.get("name", pid)
        exp   = p.get("expires_at") or "∞"
        try:
            dl = requests.post(f"{server_url}/api/download",
                               json={"license_key": key, "plugin_id": pid}, timeout=30)
            dl.raise_for_status()

            code = _decrypt(dl.json()["data"], key).decode("utf-8")
            # Создаём настоящий модульный объект — нужен dataclasses/pydantic для
            # поиска cls.__module__ в sys.modules
            import types as _types
            mod_name = f"_fpc_plugin_{pid.replace('-', '_')}"
            fake_file = str((Path("plugins") / f"{pid}.py").resolve())
            plugin_mod = _types.ModuleType(mod_name)
            plugin_mod.__file__    = fake_file
            plugin_mod.__package__ = None
            plugin_mod.__spec__    = None
            plugin_mod.__builtins__ = __builtins__
            plugin_mod.cardinal    = cardinal
            sys.modules[mod_name] = plugin_mod
            ns = plugin_mod.__dict__
            exec(compile(code, f"<remote:{pid}>", "exec"), ns)

            init_now = []
            for ev in _ALL_EVENTS:
                handlers = ns.get(ev, [])
                if callable(handlers):
                    handlers = [handlers]
                if ev in ("BIND_TO_PRE_INIT", "BIND_TO_POST_INIT"):
                    init_now.extend(handlers)
                else:
                    _dyn[ev].extend(handlers)

            for fn in init_now:
                try:
                    fn(cardinal)
                except Exception as ie:
                    logger.error(f"[PluginLoader] init {pname}: {ie}")

            loaded += 1
            logger.info(f"[PluginLoader] ✅ {pname} (до {exp})")

            # Регистрируем плагин в cardinal.plugins чтобы он отображался в меню
            try:
                if cardinal and hasattr(cardinal, "plugins") and cardinal.plugins:
                    _PluginData = type(next(iter(cardinal.plugins.values())))
                    uuid_val = ns.get("UUID", pid)
                    _pd = _PluginData(
                        f"[-] {ns.get('NAME', pname)}",
                        ns.get("VERSION", "?"),
                        ns.get("DESCRIPTION", ""),
                        ns.get("CREDITS", ""),
                        uuid_val,
                        ns.get("__file__", f"<remote:{pid}>"),
                        plugin_mod,
                        bool(ns.get("SETTINGS_PAGE", False)),
                        (ns.get("BIND_TO_DELETE") or [None])[0],
                        True,
                        False,
                    )
                    cardinal.plugins[uuid_val] = _pd
                    _registered_uuids.add(uuid_val)
            except Exception as _reg_err:
                logger.debug(f"[PluginLoader] Не удалось добавить {pname} в plugins dict: {_reg_err}")
        except Exception as e:
            import traceback
            errors.append(pname)
            logger.error(f"[PluginLoader] Ошибка {pid}: {e}\n{traceback.format_exc()}")

    _active_plugin_snapshot.clear()
    _active_plugin_snapshot.update(
        f"{p['plugin_id']}:{p.get('expires_at','')}" for p in plugin_list
    )
    logger.info(f"[PluginLoader] {loaded}/{len(plugin_list)} плагин(ов) загружено"
                + (f" | ошибки: {', '.join(errors)}" if errors else ""))
    return loaded


# ── Telegram-команды ──────────────────────────────────────────────────────── #

_tg_registered = False


def _admin_ids(cardinal) -> list[int]:
    """Возвращает список TG ID авторизованных пользователей Cardinal (всегда int)."""
    tg = getattr(cardinal, "telegram", None)
    if not tg:
        return []
    authorized = getattr(tg, "authorized_users", {})
    result = []
    for k in authorized.keys():
        try:
            result.append(int(k))
        except (ValueError, TypeError):
            pass
    return result


def _tg_bot(cardinal):
    """Возвращает telebot.TeleBot из cardinal.telegram.bot."""
    tg = getattr(cardinal, "telegram", None)
    return getattr(tg, "bot", None) if tg else None


def _setup_tg(cardinal) -> bool:
    """Регистрирует /lkey и /lactivate через Cardinal-овский msg_handler.
    URL берётся лениво внутри хендлеров."""
    global _tg_registered
    if _tg_registered:
        return True

    tg = getattr(cardinal, "telegram", None)
    if not tg:
        logger.warning("[PluginLoader] cardinal.telegram недоступен")
        return False

    bot  = getattr(tg, "bot", None)
    if not bot:
        logger.warning("[PluginLoader] cardinal.telegram.bot недоступен")
        return False

    admins = _admin_ids(cardinal)
    logger.info(f"[PluginLoader] Регистрирую TG-команды. Админы: {admins}")

    def _reply(message, text: str):
        try:
            bot.send_message(message.chat.id, text, parse_mode="HTML")
        except Exception as e:
            logger.error(f"[PluginLoader] TG send: {e}")

    def _send_to_admins(text: str):
        for uid in admins:
            try:
                bot.send_message(uid, text, parse_mode="HTML")
            except Exception as e:
                logger.error(f"[PluginLoader] TG admin send {uid}: {e}")

    def handle_lkey(message):
        logger.info(f"[PluginLoader] /lkey от {message.from_user.id} (admins={admins})")
        if message.from_user.id not in admins:
            return
        parts = (message.text or "").split(maxsplit=1)
        if len(parts) < 2 or not parts[1].strip():
            _reply(message, "❌ Использование: <code>/lkey ВАШ-UUID</code>")
            return
        key = parts[1].strip()
        _save_key(key)
        _reply(message, "✅ Ключ сохранён. Загружаю плагины...")
        try:
            url = _aes_ctx_seed()
        except Exception as e:
            _reply(message, f"❌ URL сервера не найден: {e}")
            return
        n = _load_plugins(cardinal, url, key)
        _send_to_admins(
            f"✅ Загружено плагинов: <b>{n}</b>" if n
            else "ℹ️ Плагинов нет — активируйте через <code>/lactivate ACT-XXXXXX</code>"
        )

    # Регистрируем через Cardinal-овский msg_handler (обрабатывает исключения)
    tg.msg_handler(handle_lkey, commands=["lkey"])

    _tg_registered = True
    logger.info("[PluginLoader] /lkey и /lactivate зарегистрированы")
    return True


# ── Фоновая проверка подписок ─────────────────────────────────────────────── #

_POLL_INTERVAL = 5 * 60  # 5 минут — лёгкий опрос


def _expiry_loop(cardinal, server_url: str, key: str) -> None:
    import time, requests as _req
    while True:
        time.sleep(_POLL_INTERVAL)
        # Лёгкий запрос — только список без скачивания плагинов
        try:
            resp = _req.post(f"{server_url}/api/list",
                             json={"license_key": key}, timeout=15)
            if resp.status_code != 200:
                continue
            server_list = resp.json().get("plugins", [])
        except Exception:
            continue

        snapshot = {f"{p['plugin_id']}:{p.get('expires_at','')}" for p in server_list}
        if snapshot == _active_plugin_snapshot:
            continue  # ничего не изменилось — не трогаем

        logger.info("[PluginLoader] Список плагинов изменился — перезагружаю...")
        n = _load_plugins(cardinal, server_url, key)

        if n == 0 and server_list == []:
            bot = _tg_bot(cardinal)
            if bot:
                for uid in _admin_ids(cardinal):
                    try:
                        bot.send_message(
                            uid,
                            "⚠️ <b>FPC Loader</b>: все подписки истекли.\n"
                            "Обнови в боте @starvellcardinal_bot.",
                            parse_mode="HTML",
                        )
                    except Exception:
                        pass


def _start_expiry_thread(cardinal, server_url: str, key: str) -> None:
    global _expiry_thread
    if _expiry_thread and _expiry_thread.is_alive():
        return
    _expiry_thread = threading.Thread(
        target=_expiry_loop, args=(cardinal, server_url, key),
        daemon=True, name="PluginLoader-expiry",
    )
    _expiry_thread.start()
    logger.info("[PluginLoader] Фоновый опрос каждые 5 мин запущен")


# ── Авто-обновление ───────────────────────────────────────────────────────── #

def _update_check_loop(cardinal) -> None:
    import time, requests as _req
    while True:
        time.sleep(_UPDATE_INTERVAL)
        update_url = _dll_str("aes_ctx_ref")
        if not update_url:
            continue
        try:
            r = _req.get(update_url, timeout=10)
            r.raise_for_status()
            remote = r.text.strip()
        except Exception:
            continue

        current = _dll_str("aes_ctx_tag") or VERSION
        if remote == current:
            continue

        bot = _tg_bot(cardinal)
        if not bot:
            continue
        for uid in _admin_ids(cardinal):
            try:
                bot.send_message(
                    uid,
                    f"🔄 <b>PluginLoader</b>: доступна новая версия <b>{remote}</b>\n"
                    f"Текущая: {current}\n\n"
                    "Скачайте обновлённый <code>PluginLoader.py</code> и <code>loader_core</code>, "
                    "замените файлы в папке plugins/ и перезапустите Cardinal.",
                    parse_mode="HTML",
                )
            except Exception:
                pass
        logger.info(f"[PluginLoader] Новая версия: {remote} (текущая: {current})")


def _start_update_thread(cardinal) -> None:
    if not _dll_str("aes_ctx_ref"):
        return
    t = threading.Thread(target=_update_check_loop, args=(cardinal,),
                         daemon=True, name="PluginLoader-update")
    t.start()
    logger.info("[PluginLoader] Проверка обновлений каждые 24ч запущена")


# ── POST_INIT ─────────────────────────────────────────────────────────────── #

def _on_post_init(*args):
    cardinal = args[0] if args else None

    _ensure("requests")
    _ensure("cryptography")

    # Регистрируем TG-команды ПЕРВЫМ ДЕЛОМ — независимо от того, есть ли URL/ключ.
    # Если не зарегистрировать здесь, /lkey никогда не сработает.
    _setup_tg(cardinal)

    key = _get_stored_key()
    if not key:
        bot = _tg_bot(cardinal)
        if bot:
            for uid in _admin_ids(cardinal):
                try:
                    bot.send_message(
                        uid,
                        "🔑 <b>FPC Loader</b>\n\n"
                        "Ключ профиля не настроен.\n\n"
                        "1. Откройте @starvellcardinal_bot → /start\n"
                        "2. Нажмите 🔑 Мой профиль — скопируйте UUID\n"
                        "3. Введите здесь: <code>/lkey ВАШ-UUID</code>",
                        parse_mode="HTML",
                    )
                except Exception as e:
                    logger.error(f"[PluginLoader] TG send: {e}")
        logger.warning("[PluginLoader] Ключ профиля не задан — введите /lkey UUID в Cardinal")
        return

    try:
        server_url = _aes_ctx_seed()
    except Exception as e:
        logger.error(f"[PluginLoader] {e}")
        return

    _load_plugins(cardinal, server_url, key)
    _start_expiry_thread(cardinal, server_url, key)
    _start_update_thread(cardinal)


# ── Регистрация хендлеров в Cardinal ──────────────────────────────────────── #
BIND_TO_POST_INIT = [_on_post_init]

for _ev in _ALL_EVENTS:
    if _ev != "BIND_TO_POST_INIT":
        globals()[_ev] = [_dispatch(_ev)]
