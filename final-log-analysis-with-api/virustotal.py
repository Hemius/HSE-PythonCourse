"""
virustotal.py — проверка IoC через VirusTotal API v3.

Назначение:
  - проверять IP, домены и хэши файлов в VirusTotal;
  - возвращать унифицированные результаты для дальнейшего анализа и реагирования;
  - учитывать ограничения API (паузы, повторы, обработка ошибок).

Публичные функции:
  - vt_check(ioc, ioc_type, retries=VT_RETRY_COUNT)
  - run_virustotal(suspicious_ips, suspicious_domains, suspicious_hashes=None)
"""

from __future__ import annotations

import logging
import time
from urllib.parse import quote

import requests

from config import (
    VT_API_KEY,
    VT_MALICIOUS_MIN,
    VT_REQUEST_DELAY,
    VT_RETRY_COUNT,
    VT_RETRY_DELAY,
)

logger = logging.getLogger(__name__)

_VT_API_BASE = "https://www.virustotal.com/api/v3"
_ALLOWED_IOC_TYPES = {"ip_addresses", "domains", "files"}


def _base_result(ioc: str, ioc_type: str, status: str) -> dict:
    """Возвращает результат с базовой схемой полей."""
    return {
        "ioc": ioc,
        "type": ioc_type,
        "status": status,
        "malicious": 0,
        "suspicious": 0,
    }


def _format_verdict(result: dict) -> str:
    """Форматирует краткий вердикт для логов."""
    malicious = int(result.get("malicious", 0))
    suspicious = int(result.get("suspicious", 0))
    if malicious >= VT_MALICIOUS_MIN:
        return f"MALICIOUS ({malicious})"
    if suspicious > 0:
        return f"suspicious ({suspicious})"
    return "clean"


def vt_check(ioc: str, ioc_type: str, retries: int = VT_RETRY_COUNT) -> dict:
    """Проверяет один IoC в VirusTotal API v3 и возвращает результат анализа.

    Аргументы:
      - ioc:      проверяемый индикатор (IP, домен или SHA-256/MD5 хеш файла)
      - ioc_type: тип IoC — 'ip_addresses' | 'domains' | 'files'
      - retries:  число повторов при сетевых ошибках и ответе 429

    Возвращает словарь с полями: ioc, type, status, malicious, suspicious,
    harmless, undetected. При ошибке status содержит описание причины.
    """
    if ioc_type not in _ALLOWED_IOC_TYPES:
        return _base_result(ioc, ioc_type, "invalid_ioc_type")

    safe_ioc = quote(ioc, safe="")
    url = f"{_VT_API_BASE}/{ioc_type}/{safe_ioc}"
    headers = {"x-apikey": VT_API_KEY}

    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=15, verify=True)

            if resp.status_code == 200:
                try:
                    payload = resp.json()
                    stats = payload["data"]["attributes"]["last_analysis_stats"]
                except (ValueError, KeyError, TypeError):
                    return _base_result(ioc, ioc_type, "bad_response_schema")

                result = _base_result(ioc, ioc_type, "ok")
                result.update(
                    {
                        "malicious": int(stats.get("malicious", 0) or 0),
                        "suspicious": int(stats.get("suspicious", 0) or 0),
                        "harmless": int(stats.get("harmless", 0) or 0),
                        "undetected": int(stats.get("undetected", 0) or 0),
                    }
                )
                return result

            if resp.status_code == 404:
                return _base_result(ioc, ioc_type, "not_found")

            if resp.status_code == 429:
                logger.warning(
                    f"    ⚠️  VT: превышен лимит запросов "
                    f"(попытка {attempt}/{retries}), пауза 60 сек..."
                )
                time.sleep(60)
                continue

            return _base_result(ioc, ioc_type, f"error_{resp.status_code}")

        except (requests.exceptions.SSLError, requests.exceptions.ConnectionError) as exc:
            logger.warning(
                f"    ⚠️  Ошибка соединения ({type(exc).__name__}, попытка {attempt}/{retries}), "
                f"повтор через {VT_RETRY_DELAY} сек..."
            )
            time.sleep(VT_RETRY_DELAY)
        except requests.RequestException as exc:
            result = _base_result(ioc, ioc_type, f"exception: {exc}")
            return result

    return _base_result(ioc, ioc_type, "ssl_error_max_retries")


def _validate_api_key() -> bool:
    """Проверяет корректность VT_API_KEY через endpoint /users/me."""
    if not VT_API_KEY:
        return False

    try:
        resp = requests.get(
            f"{_VT_API_BASE}/users/me",
            headers={"x-apikey": VT_API_KEY},
            timeout=10,
        )
        if resp.status_code == 200:
            return True
        if resp.status_code == 401:
            logger.warning("  ❌ VT_API_KEY недействителен (401 Unauthorized)")
        else:
            logger.warning(
                f"  ⚠️  VT: неожиданный ответ при проверке ключа: {resp.status_code}"
            )
        return False
    except requests.RequestException as exc:
        logger.warning(f"  ⚠️  VT: не удалось проверить ключ: {exc}")
        return False


def run_virustotal(
    suspicious_ips: list[str],
    suspicious_domains: list[str],
    suspicious_hashes: list[dict] | None = None,
) -> list[dict]:
    """Проверяет собранные IoC и возвращает список результатов VirusTotal."""
    logger.info("\n" + "=" * 60)
    logger.info("  ЭТАП 2б: Проверка IoC через VirusTotal")
    logger.info("=" * 60)

    if not VT_API_KEY:
        logger.warning("  ❌ VT_API_KEY не задан в .env — пропускаем проверку VT")
        return []

    if not _validate_api_key():
        return []

    # Собираем IoC в очередь: (ioc_value, ioc_type, display_label, extra_fields).
    ioc_queue: list[tuple[str, str, str, dict]] = []
    seen: set[tuple[str, str]] = set()

    def _push(ioc_value: str, ioc_type: str, label: str, extra: dict) -> None:
        key = (ioc_type, ioc_value)
        if key in seen:
            return
        seen.add(key)
        ioc_queue.append((ioc_value, ioc_type, label, extra))

    for ip in suspicious_ips:
        ip_value = str(ip).strip()
        if ip_value:
            _push(ip_value, "ip_addresses", f"IP: {ip_value}", {})

    for domain in suspicious_domains:
        domain_value = str(domain).strip()
        if domain_value:
            _push(domain_value, "domains", f"домен: {domain_value}", {})

    for entry in suspicious_hashes or []:
        hash_value = str(entry.get("hash") or "").strip()
        if not hash_value:
            continue
        filename = str(entry.get("filename") or "unknown")
        _push(
            hash_value,
            "files",
            f"файл: {filename} [{hash_value[:12]}...]",
            {"filename": filename},
        )

    results: list[dict] = []
    for idx, (ioc, ioc_type, label, extra) in enumerate(ioc_queue):
        logger.info(f"  🔍 Проверяю {label} ...")
        result = vt_check(ioc, ioc_type)
        result.update(extra)
        results.append(result)
        logger.info(f"       {_format_verdict(result)}")

        # Пауза между запросами, кроме последнего.
        if idx < len(ioc_queue) - 1:
            time.sleep(VT_REQUEST_DELAY)

    return results