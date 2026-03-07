"""
analysis.py — анализ аномалий и извлечение IoC (Indicators of Compromise) с дедупликацией.

Что делает модуль:
- фильтрует события, помеченные как алерты (is_alert=True)
- считает статистику по IP и категориям атак
- извлекает IoC для дальнейшего обогащения (VT и т.п.):
  - внешние IP (исключая приватные сети)
  - домены из DNS/TLS/HTTP контекста
  - хэши файлов из fileinfo (предпочитаем SHA-256)
"""

import ipaddress
import logging
import pandas as pd
from config import PRIVATE_NETS

logger = logging.getLogger(__name__)


def _is_external(ip: str) -> bool:
    """Возвращает True, если IP является публично маршрутизируемым адресом.

    Проверяет два условия:
      1. ipaddress: стандартные приватные диапазоны (RFC 1918, loopback, link-local и др.)
      2. PRIVATE_NETS: пользовательский список префиксов из config.yaml для кастомных исключений.
    """
    try:
        if not ipaddress.ip_address(ip).is_global:
            return False
    except ValueError:
        return False  # некорректный IP — не отправляем в VT
    return not any(ip.startswith(net) for net in PRIVATE_NETS)


def analyze(df: pd.DataFrame) -> dict:
    """Анализирует DataFrame событий Suricata и возвращает агрегаты и IoC.

    Возвращает словарь:
      - ip_counts (DataFrame)       — топ IP-источников по числу алертов
      - cat_counts (DataFrame)      — распределение категорий атак
      - suspicious_ips (list[str])  — внешние IP для проверки в VirusTotal
      - suspicious_domains (list[str]) — домены из DNS/TLS/HTTP алертов
      - suspicious_hashes (list[dict]) — хэши файлов из fileinfo-алертов
      - alerts_df (DataFrame)       — только строки с is_alert=True
    """
    logger.info("\n" + "=" * 60)
    logger.info("  ЭТАП 2: Анализ данных")
    logger.info("=" * 60)

    alerts_df = df[df["is_alert"]].copy()

    # Завершение работы при отсутствии алертов
    if alerts_df.empty:
        logger.info("  ℹ️  Алертов не обнаружено — анализ завершён.")
        return {
            "ip_counts":          pd.DataFrame(columns=["src_ip", "alert_count"]),
            "cat_counts":         pd.DataFrame(columns=["category", "count"]),
            "suspicious_domains": [],
            "suspicious_ips":     [],
            "suspicious_hashes":  [],
            "alerts_df":          alerts_df,
        }

    # Топ источников (src_ip) по числу алертов
    ip_counts = (
        alerts_df.groupby("src_ip")
        .size()
        .reset_index(name="alert_count")
        .sort_values("alert_count", ascending=False)
    )

    # Распределение по типам атак
    cat_counts = (
        alerts_df.groupby("category")
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
    )

    # Дедупликация IoC — seen_iocs хранит уже добавленные значения,
    # чтобы один адрес/домен не попал в несколько списков одновременно
    seen_iocs: set[str] = set()

    # Обработка только внешних подозрительных IP адресов для дальнейшего анализа
    suspicious_ips: list[str] = []
    for ip in sorted(alerts_df["src_ip"].dropna().unique()):
        if ip in seen_iocs:
            continue
        if not _is_external(ip):
            continue
        seen_iocs.add(ip)
        suspicious_ips.append(ip)

    # Подозрительные домены (из DNS/TLS/HTTP аномалий)
    suspicious_domains: list[str] = []
    for domain in sorted(alerts_df["domain"].dropna().unique()):
        if domain not in seen_iocs:
            seen_iocs.add(domain)
            suspicious_domains.append(domain)

    # Хэши файлов только из fileinfo-алертов (предпочитаем SHA-256)
    fileinfo_df = alerts_df[alerts_df["event_type"] == "fileinfo"].copy()
    seen_hashes: set[str] = set()
    suspicious_hashes: list[dict] = []
    for _, row in fileinfo_df.iterrows():
        h = row.get("file_sha256") or row.get("file_md5")
        if h and h not in seen_hashes:
            seen_hashes.add(h)
            suspicious_hashes.append({
                "hash":      h,
                "hash_type": "sha256" if row.get("file_sha256") else "md5",
                "filename":  row.get("filename"),
            })

    # Вывод результатов
    logger.info("\n  Топ подозрительных IP:")
    for _, row in ip_counts.iterrows():
        logger.info(f"    {row['src_ip']:20} → {row['alert_count']} подозрительных событий")

    logger.info("\n  Категории атак:")
    for _, row in cat_counts.iterrows():
        logger.info(f"    {row['count']:3}x  {row['category']}")

    logger.info("\n  Подозрительные домены:")
    if suspicious_domains:
        for d in suspicious_domains:
            logger.info(f"    {d}")
    else:
        logger.info("    —")

    logger.info("\n  IP для проверки VT:")
    if suspicious_ips:
        for ip in suspicious_ips:
            logger.info(f"    {ip}")
    else:
        logger.info("    —")

    logger.info("\n  Хэши файлов для проверки VT:")
    if suspicious_hashes:
        for h in suspicious_hashes:
            logger.info(f"    {h['hash']}  ({h['filename'] or 'unknown'})")
    else:
        logger.info("    —")

    return {
        "ip_counts":          ip_counts,
        "cat_counts":         cat_counts,
        "suspicious_domains": suspicious_domains,
        "suspicious_ips":     suspicious_ips,
        "suspicious_hashes":  suspicious_hashes,
        "alerts_df":          alerts_df,
    }