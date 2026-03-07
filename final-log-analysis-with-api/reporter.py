"""
reporter.py — формирование и сохранение итогового JSON-отчёта.

Назначение:
  - собрать агрегированную статистику по событиям и алертам;
  - добавить результаты обогащения (VirusTotal и Vulners);
  - сохранить единый отчёт в файл REPORT_FILE.

Публичная точка входа:
  - save_report(df, analysis, vt_results, actions, vulners_results=None)
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from config import LOG_FILE, REPORT_FILE

logger = logging.getLogger(__name__)


def _timestamp_or_none(value: object) -> str | None:
    """Преобразует timestamp в строку; для пустых значений возвращает None."""
    if pd.isna(value):
        return None
    return str(value)


def save_report(
    df: pd.DataFrame,
    analysis: dict,
    vt_results: list[dict],
    actions: list[dict],
    vulners_results: list[dict] | None = None,
) -> None:
    """Собирает и сохраняет итоговый JSON-отчёт."""
    logger.info("\n" + "=" * 60)
    logger.info("  ЭТАП 4: Сохранение отчёта")
    logger.info("=" * 60)

    # Берём агрегаты из analysis с безопасными значениями по умолчанию
    alerts_df = analysis.get("alerts_df", pd.DataFrame(columns=["src_ip"]))
    cat_counts = analysis.get("cat_counts", pd.DataFrame(columns=["category", "count"]))
    ip_counts = analysis.get("ip_counts", pd.DataFrame(columns=["src_ip", "alert_count"]))

    # Поддерживаем отчёт даже при частично пустых/неполных данных
    is_alert = df["is_alert"] if "is_alert" in df.columns else pd.Series(False, index=df.index)
    event_type = (
        df["event_type"] if "event_type" in df.columns else pd.Series("", index=df.index)
    )
    timestamp = (
        df["timestamp"]
        if "timestamp" in df.columns
        else pd.Series([pd.NaT] * len(df), index=df.index)
    )
    alert_src_ip = (
        alerts_df["src_ip"] if "src_ip" in alerts_df.columns else pd.Series(dtype="object")
    )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "log_file": LOG_FILE,
        "summary": {
            "total_events": len(df),
            "total_alerts": int(is_alert.sum()),
            "total_anomalies": int((event_type == "anomaly").sum()),
            "normal_events": int((~is_alert & (event_type != "anomaly")).sum()),
            "unique_alert_ips": int(alert_src_ip.nunique()),
            "unique_alert_domains": len(analysis.get("suspicious_domains", [])),
            "unique_alert_files": len(analysis.get("suspicious_hashes", [])),
            "period_start": _timestamp_or_none(timestamp.min()),
            "period_end": _timestamp_or_none(timestamp.max()),
        },
        "attack_categories": cat_counts.to_dict(orient="records"),
        "top_threat_ips": ip_counts.to_dict(orient="records"),
        "suspicious_domains": analysis.get("suspicious_domains", []),
        "suspicious_files": [
            {
                "filename": h.get("filename"),
                "hash": h.get("hash"),
                "hash_type": h.get("hash_type"),
            }
            for h in analysis.get("suspicious_hashes", [])
        ],
        "virustotal_results": vt_results,
        "vulners_cve": vulners_results or [],
        "response_actions": actions,
    }

    report_path = Path(REPORT_FILE)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    with report_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    logger.info(f"  ✅ Отчёт сохранён: {REPORT_FILE}")