"""
Модуль для загрузки настроек из config.yaml и .env.
Все модули импортируют константы отсюда.

Источники:
  - config.yaml  — настройки (пороги, задержки, пути)
  - .env         — секреты (API-ключи, токены)
"""

import os
import yaml
from dotenv import load_dotenv

load_dotenv()

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "config.yaml")

try:
    with open(CONFIG_FILE, encoding="utf-8") as _f:
        _CFG = yaml.safe_load(_f)
except FileNotFoundError:
    raise FileNotFoundError(f"Файл конфигурации не найден: {CONFIG_FILE}")
except yaml.YAMLError as e:
    raise ValueError(f"Ошибка разбора config.yaml: {e}")

if not isinstance(_CFG, dict):
    raise ValueError(
        f"config.yaml должен содержать словарь настроек, получен {type(_CFG).__name__}"
    )

_REQUIRED_SECTIONS = ("files", "thresholds", "virustotal", "vulners", "private_networks")
_missing = [s for s in _REQUIRED_SECTIONS if s not in _CFG]
if _missing:
    raise ValueError(f"В config.yaml отсутствуют обязательные секции: {', '.join(_missing)}")

# Пути к файлам
LOG_FILE    = os.path.join(BASE_DIR, _CFG["files"]["log"])
REPORT_FILE = os.path.join(BASE_DIR, _CFG["files"]["report"])
CHART_FILE  = os.path.join(BASE_DIR, _CFG["files"]["chart"])

# Пороги реагирования 
ALERT_THRESHOLD  = _CFG["thresholds"]["alert_threshold"]
BLOCK_THRESHOLD  = _CFG["thresholds"]["block_threshold"]
VT_MALICIOUS_MIN = _CFG["thresholds"]["vt_malicious_min"]

# VirusTotal 
VT_API_KEY       = os.getenv("VT_API_KEY", "").strip() or None
VT_REQUEST_DELAY = _CFG["virustotal"]["request_delay"]
VT_RETRY_COUNT   = _CFG["virustotal"]["retry_count"]
VT_RETRY_DELAY   = _CFG["virustotal"]["retry_delay"]

# Vulners
VULNERS_API_KEY           = os.getenv("VULNERS_API_KEY", "").strip() or None
VULNERS_REQUEST_DELAY     = _CFG["vulners"]["request_delay"]

# Приватные сети
PRIVATE_NETS = _CFG["private_networks"]

# Telegram
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "").strip() or None
TG_CHAT_ID   = os.getenv("TG_CHAT_ID",   "").strip() or None
TELEGRAM_CFG: dict = _CFG.get("telegram", {})