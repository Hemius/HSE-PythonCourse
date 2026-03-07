"""
vulners.py — обогащение данных CVE через Vulners API.

Извлекает CVE ID из сигнатур Suricata-алертов и получает:
  - CVSS3 (score + vector)
  - описание уязвимости
  - дату публикации

Источник:
  1) Vulners API (/api/v3/search/id)

API key опционален: без ключа запросы могут быть ограничены по частоте.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any

import pandas as pd
import requests

from config import VULNERS_API_KEY, VULNERS_REQUEST_DELAY

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
_VULNERS_API = "https://vulners.com/api/v3/search/id"


def extract_cves(alerts_df: pd.DataFrame) -> list[str]:
    """Извлекает уникальные CVE ID из signature и alert_cves."""
    cves: set[str] = set()

    if "signature" in alerts_df.columns:
        for sig in alerts_df["signature"].dropna():
            for match in _CVE_RE.findall(str(sig)):
                cves.add(match.upper())

    if "alert_cves" in alerts_df.columns:
        for cve_list in alerts_df["alert_cves"].dropna():
            if not isinstance(cve_list, (list, tuple, set)):
                continue
            for cve in cve_list:
                if isinstance(cve, str):
                    cve = cve.strip().upper()
                    if _CVE_RE.fullmatch(cve):
                        cves.add(cve)

    return sorted(cves)


def _to_float_score(val: Any) -> float | None:
    """Приводит значение score к float, если это возможно."""
    if val is None:
        return None
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, str):
        try:
            return float(val.strip().replace(",", "."))
        except ValueError:
            return None
    return None


def _extract_cvss3_from_vulners(doc: dict) -> tuple[float | None, str | None]:
    """
    Извлекает CVSS3 из структуры Vulners.

    Ожидаемый формат:
      doc["cvss3"]["cvssV31"]["baseScore"]
      doc["cvss3"]["cvssV31"]["vectorString"]

    Также поддерживает:
      - cvssV30
      - fallback на старый плоский формат score/vector
    """
    cvss3 = doc.get("cvss3")

    if not isinstance(cvss3, dict):
        return None, None

    for key in ("cvssV31", "cvssV30"):
        block = cvss3.get(key)
        if isinstance(block, dict):
            score = _to_float_score(block.get("baseScore"))
            vector = block.get("vectorString")
            if score is not None:
                return score, vector if isinstance(vector, str) else None

    score = _to_float_score(cvss3.get("score"))
    vector = cvss3.get("vector")
    if score is not None:
        return score, vector if isinstance(vector, str) else None

    return None, None


def vulners_check(cve_id: str) -> dict:
    """Запрашивает данные по одному CVE из Vulners API и возвращает CVSS3."""
    cve_id = (cve_id or "").strip().upper()
    if not _CVE_RE.fullmatch(cve_id):
        return {
            "cve": cve_id,
            "status": "invalid_cve",
            "cvss3_score": None,
            "cvss3_vector": None,
            "cvss3_source": None,
            "description": "",
            "published": "",
        }

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "vulners-cve-checker/1.0",
    }
    if VULNERS_API_KEY:
        headers["X-Api-Key"] = VULNERS_API_KEY

    payload = {
        "id": cve_id,
        "fields": ["id", "title", "description", "published", "cvss3"],
        "references": False,
    }

    try:
        resp = None
        for attempt in range(1, 4):
            resp = requests.post(_VULNERS_API, json=payload, headers=headers, timeout=15)

            if resp.status_code == 429:
                logger.warning(f"    ⚠️  Vulners: лимит запросов (попытка {attempt}/3), пауза 10 сек...")
                time.sleep(10 * attempt)
                continue
            break

        if resp is None:
            return {
                "cve": cve_id,
                "status": "request_failed",
                "cvss3_score": None,
                "cvss3_vector": None,
                "cvss3_source": None,
                "description": "",
                "published": "",
            }

        if resp.status_code != 200:
            return {
                "cve": cve_id,
                "status": f"error_{resp.status_code}",
                "cvss3_score": None,
                "cvss3_vector": None,
                "cvss3_source": None,
                "description": "",
                "published": "",
            }

        data = resp.json()
        if data.get("result") != "OK":
            return {
                "cve": cve_id,
                "status": "not_found",
                "cvss3_score": None,
                "cvss3_vector": None,
                "cvss3_source": None,
                "description": "",
                "published": "",
            }

        documents = (data.get("data") or {}).get("documents") or {}
        doc = documents.get(cve_id) or {}

        score3, vector3 = _extract_cvss3_from_vulners(doc)

        return {
            "cve": cve_id,
            "status": "ok",
            "cvss3_score": score3,
            "cvss3_vector": vector3,
            "cvss3_source": "vulners" if score3 is not None else None,
            "description": str(doc.get("description") or "")[:300],
            "published": str(doc.get("published") or "")[:10],
        }

    except requests.RequestException as e:
        return {
            "cve": cve_id,
            "status": f"exception: {e}",
            "cvss3_score": None,
            "cvss3_vector": None,
            "cvss3_source": None,
            "description": "",
            "published": "",
        }
    except ValueError:
        return {
            "cve": cve_id,
            "status": "bad_response_json",
            "cvss3_score": None,
            "cvss3_vector": None,
            "cvss3_source": None,
            "description": "",
            "published": "",
        }


def run_vulners(alerts_df: pd.DataFrame) -> list[dict]:
    """Извлекает CVE из алертов и обогащает их данными CVSS3 из Vulners API.

    Возвращает список словарей с полями:
      cve, status, cvss3_score, cvss3_vector, cvss3_source, description, published.
    Если CVE не найдены — возвращает пустой список.
    """
    logger.info("\n" + "=" * 60)
    logger.info("  ЭТАП 2в: Обогащение CVE через Vulners")
    logger.info("=" * 60)

    cves = extract_cves(alerts_df)
    if not cves:
        logger.info("  ℹ️  CVE в сигнатурах не обнаружены — пропуск")
        return []

    logger.info(f"  Найдено CVE: {len(cves)}")
    if not VULNERS_API_KEY:
        logger.warning("  ⚠️  VULNERS_API_KEY не задан — работаем без ключа (ограниченный лимит)")

    results: list[dict] = []
    for idx, cve_id in enumerate(cves):
        result = vulners_check(cve_id)
        results.append(result)

        if result["status"] == "ok":
            score = result.get("cvss3_score")
            src = result.get("cvss3_source") or "—"
            status_str = f"CVSS3 {score} ({src})" if score is not None else "нет CVSS3"
        else:
            status_str = result["status"]

        logger.info(f"  🔍 {cve_id} ... {status_str}")

        if idx < len(cves) - 1:
            time.sleep(VULNERS_REQUEST_DELAY)

    return results