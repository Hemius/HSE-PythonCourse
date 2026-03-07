"""
responder.py — модуль принятия решений по реагированию на угрозы.

Назначение:
  - определить действие по каждому подозрительному IP на основе числа алертов
    и подтверждения вредоносности в VirusTotal;
  - добавить отдельные действия блокировки для вредоносных доменов;
  - вернуть унифицированный список действий для отчёта и уведомлений.

Публичная точка входа:
  - respond(ip_counts: pd.DataFrame, vt_results: list[dict]) -> list[dict]
"""

import logging

import pandas as pd

from config import ALERT_THRESHOLD, BLOCK_THRESHOLD, VT_MALICIOUS_MIN

logger = logging.getLogger(__name__)


def _extract_malicious_iocs(vt_results: list[dict]) -> tuple[set[str], set[str]]:
    """Возвращает множества вредоносных IP и доменов по данным VirusTotal."""
    malicious_ips: set[str] = set()
    malicious_domains: set[str] = set()

    for result in vt_results:
        if result.get("malicious", 0) < VT_MALICIOUS_MIN:
            continue

        ioc = str(result.get("ioc") or "").strip()
        if not ioc:
            continue

        ioc_type = result.get("type")
        if ioc_type == "ip_addresses":
            malicious_ips.add(ioc)
        elif ioc_type == "domains":
            malicious_domains.add(ioc)

    return malicious_ips, malicious_domains


def _decide_ip_action(alert_count: int, vt_confirmed: bool) -> tuple[str, list[str]]:
    """Возвращает действие и список причин для конкретного IP."""
    reasons: list[str] = []

    if alert_count >= BLOCK_THRESHOLD:
        reasons.append(f"{alert_count} подозрительных событий в логе")
    if vt_confirmed:
        reasons.append("подтверждён VirusTotal")

    if reasons:
        return "BLOCK", reasons
    if alert_count >= ALERT_THRESHOLD:
        return "ALERT", [f"{alert_count} аномалий, требуется наблюдение"]
    return "WATCH", [f"{alert_count} аномалий"]


def respond(ip_counts: pd.DataFrame, vt_results: list[dict]) -> list[dict]:
    """Формирует список действий реагирования для IP и доменов."""
    logger.info("\n" + "=" * 60)
    logger.info("  ЭТАП 3: Реагирование на угрозы")
    logger.info("=" * 60)

    malicious_ips, malicious_domains = _extract_malicious_iocs(vt_results)
    actions: list[dict] = []

    required_cols = {"src_ip", "alert_count"}
    if not required_cols.issubset(ip_counts.columns):
        missing = ", ".join(sorted(required_cols - set(ip_counts.columns)))
        logger.warning(f"  ⚠️  Пропущена обработка IP: отсутствуют колонки: {missing}")
    else:
        # Обходим агрегированную статистику по IP и назначаем действие
        for src_ip, raw_count in ip_counts[["src_ip", "alert_count"]].itertuples(index=False, name=None):
            ip = str(src_ip)
            count = int(raw_count)
            is_vt_confirmed = ip in malicious_ips

            action, reasons = _decide_ip_action(count, is_vt_confirmed)
            if action == "BLOCK":
                logger.info(f"\n  [BLOCK] IP {ip}")
                logger.info(f"     Причина: {', '.join(reasons)}")
                logger.info(f"     [ИМИТАЦИЯ] iptables -A INPUT -s {ip} -j DROP")
            elif action == "ALERT":
                logger.info(f"\n  [ALERT] IP {ip} — {reasons[0]}")
            else:
                logger.info(f"\n  [WATCH] IP {ip} — {reasons[0]}")

            actions.append(
                {
                    "ip": ip,
                    "alert_count": count,
                    "vt_confirmed": is_vt_confirmed,
                    "action": action,
                }
            )

    # Отдельно добавляем блокировки вредоносных доменов (с дедупликацией по множеству)
    for domain in sorted(malicious_domains):
        logger.info(f"\n  [BLOCK] Домен {domain}")
        logger.info("     [ИМИТАЦИЯ] Добавляем в DNS blackhole / hosts-файл")
        actions.append(
            {
                "domain": domain,
                "vt_confirmed": True,
                "action": "BLOCK",
            }
        )

    return actions