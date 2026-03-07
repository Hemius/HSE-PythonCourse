"""
telegram.py — отправка уведомлений в Telegram Bot API.

Назначение:
  - отправлять оперативные уведомления по действиям реагирования;
  - отправлять итоговую сводку анализа (опционально с графиком);
  - учитывать настройки из config.yaml и переменные окружения из .env.

Публичные функции:
  - notify_actions(actions, vt_results, n_alerts=0, n_anomalies=0)
  - notify_summary(df, analysis, actions, vulners_results=None)
"""

from __future__ import annotations

import html
import logging
import os
from pathlib import Path

import pandas as pd
import requests

from config import CHART_FILE, TELEGRAM_CFG, VT_MALICIOUS_MIN

logger = logging.getLogger(__name__)

# Данные Telegram-бота из .env
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "").strip() or None
TG_CHAT_ID = os.getenv("TG_CHAT_ID", "").strip() or None

# Настройки поведения из config.yaml
TG_ENABLED = TELEGRAM_CFG.get("enabled", False)
TG_MIN_LEVEL = str(TELEGRAM_CFG.get("min_level", "alert")).strip().lower()
TG_SUMMARY = TELEGRAM_CFG.get("send_summary", True)
TG_CHART = TELEGRAM_CFG.get("send_chart", True)


def _api_base() -> str:
    """Возвращает базовый URL Telegram Bot API для текущего токена."""
    return f"https://api.telegram.org/bot{TG_BOT_TOKEN}"


def _is_ready() -> bool:
    """Проверяет, что отправка включена и заданы TG_BOT_TOKEN/TG_CHAT_ID."""
    if not TG_ENABLED:
        return False
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        logger.warning("  ⚠️  TG: TG_BOT_TOKEN или TG_CHAT_ID не заданы в .env")
        return False
    return True


def _should_send(action: str) -> bool:
    """Определяет, отправлять ли событие по уровню фильтра TG_MIN_LEVEL."""
    level = TG_MIN_LEVEL if TG_MIN_LEVEL in {"block", "alert", "all"} else "alert"
    if level == "block":
        return action == "BLOCK"
    if level == "alert":
        return action in {"BLOCK", "ALERT"}
    return True


def _send_message(text: str, parse_mode: str = "HTML") -> bool:
    """Отправляет текстовое сообщение в Telegram."""
    try:
        resp = requests.post(
            f"{_api_base()}/sendMessage",
            json={"chat_id": TG_CHAT_ID, "text": text, "parse_mode": parse_mode},
            timeout=10,
        )
        if resp.status_code == 200:
            return True
        logger.warning(f"  ⚠️  TG: sendMessage вернул {resp.status_code}: {resp.text[:200]}")
        return False
    except requests.RequestException as exc:
        logger.warning(f"  ⚠️  TG: ошибка отправки сообщения: {exc}")
        return False


def _send_photo(path: str, caption: str = "") -> bool:
    """Отправляет изображение в Telegram с подписью."""
    try:
        with open(path, "rb") as photo:
            resp = requests.post(
                f"{_api_base()}/sendPhoto",
                data={"chat_id": TG_CHAT_ID, "caption": caption, "parse_mode": "HTML"},
                files={"photo": photo},
                timeout=30,
            )
        if resp.status_code == 200:
            return True
        logger.warning(f"  ⚠️  TG: sendPhoto вернул {resp.status_code}: {resp.text[:200]}")
        return False
    except (requests.RequestException, OSError) as exc:
        logger.warning(f"  ⚠️  TG: ошибка отправки фото: {exc}")
        return False


def _cvss_emoji(score: float | None) -> str:
    """Возвращает индикатор критичности для значения CVSS3."""
    if score is None:
        return "⬜"
    if score >= 9:
        return "🔴"
    if score >= 7:
        return "🟠"
    if score >= 4:
        return "🟡"
    return "🟢"


def notify_actions(
    actions: list[dict],
    vt_results: list[dict],
    n_alerts: int = 0,
    n_anomalies: int = 0,
) -> None:
    """Отправляет одно агрегированное сообщение по действиям реагирования.

    Включает: BLOCK/ALERT по IP, блокировки доменов (с числом детектов VT),
    вредоносные и подозрительные файлы из fileinfo-алертов.
    Фильтрует по уровню TG_MIN_LEVEL (block | alert | all).
    """
    logger.info("\n" + "=" * 60)
    logger.info("  ЭТАП 5: Telegram-уведомления")
    logger.info("=" * 60)

    if not _is_ready():
        logger.info("  ⏭️  TG отключён или параметры не заданы — пропуск")
        return

    vt_map = {
        str(r.get("ioc")): r
        for r in vt_results
        if r.get("type") == "ip_addresses" and r.get("ioc")
    }
    vt_domain_map = {
        str(r.get("ioc")): r
        for r in vt_results
        if r.get("type") == "domains" and r.get("ioc")
    }

    lines = [
        "🛡 <b>Результаты реагирования</b>",
        f"Алертов: <b>{n_alerts}</b>  |  Аномалий: <b>{n_anomalies}</b>",
    ]
    sent_items = 0

    for action in actions:
        action_type = str(action.get("action", "")).upper()
        if not _should_send(action_type):
            continue

        if "domain" in action:
            domain_raw = str(action.get("domain", ""))
            domain = html.escape(domain_raw)
            if not domain:
                continue
            vt_d = vt_domain_map.get(domain_raw)
            vt_str = ""
            if vt_d and vt_d.get("malicious", 0) > 0:
                vt_str = f", VT: 🔴 {int(vt_d['malicious'])} детектов"
            elif vt_d and vt_d.get("suspicious", 0) > 0:
                vt_str = f", VT: 🟡 {int(vt_d['suspicious'])} suspicious"
            else:
                vt_str = ", VirusTotal подтверждён"
            lines.append("\n🚫 <b>ДОМЕН заблокирован</b>")
            lines.append(f"  <code>{domain}</code>{vt_str}")
            sent_items += 1
            continue

        ip = str(action.get("ip", "")).strip()
        if not ip:
            continue

        count = int(action.get("alert_count", 0))
        vt = vt_map.get(ip)

        if action_type == "BLOCK":
            lines.append("\n🚫 <b>БЛОКИРОВКА IP</b>")
        else:
            lines.append("\n⚠️ <b>ПРЕДУПРЕЖДЕНИЕ IP</b>")

        vt_str = ""
        if vt and vt.get("malicious", 0) > 0:
            vt_str = f", VT: 🔴 {int(vt['malicious'])} детектов"
        elif vt and vt.get("suspicious", 0) > 0:
            vt_str = f", VT: 🟡 {int(vt['suspicious'])} suspicious"

        lines.append(f"  <code>{html.escape(ip)}</code> — {count} алертов{vt_str}")
        sent_items += 1

    for r in vt_results:
        if r.get("type") != "files":
            continue
        malicious = int(r.get("malicious", 0))
        suspicious = int(r.get("suspicious", 0))
        if malicious >= VT_MALICIOUS_MIN:
            verdict_str = f"VT: 🔴 {malicious} детектов"
            header = "\n☣️ <b>ВРЕДОНОСНЫЙ ФАЙЛ</b>"
        elif suspicious > 0:
            verdict_str = f"VT: 🟡 {suspicious} suspicious"
            header = "\n⚠️ <b>ПОДОЗРИТЕЛЬНЫЙ ФАЙЛ</b>"
        else:
            continue
        filename = html.escape(str(r.get("filename") or "unknown"))
        ioc = str(r.get("ioc") or "")
        ioc_short = html.escape(ioc[:16] + "..." if len(ioc) > 16 else ioc)
        lines.append(header)
        lines.append(f"  {filename} — <code>{ioc_short}</code> — {verdict_str}")
        sent_items += 1

    if sent_items == 0:
        logger.info("  ℹ️  TG: нет действий для отправки")
        return

    if _send_message("\n".join(lines)):
        logger.info("  ✅ TG: сообщение с действиями отправлено")


def notify_summary(
    df: pd.DataFrame,
    analysis: dict,
    actions: list[dict],
    vulners_results: list[dict] | None = None,
) -> None:
    """Отправляет итоговую сводку анализа и, при наличии, график с подписью.

    Сводка включает: статистику событий, реагирование, топ категорий атак,
    CVE с CVSS3, подозрительные домены и хеши файлов.
    Если график существует и помещается в caption (≤1024 символов) — отправляется фото с подписью,
    иначе отдельным сообщением.
    """
    if not _is_ready() or not TG_SUMMARY:
        return

    is_alert = df["is_alert"] if "is_alert" in df.columns else pd.Series(False, index=df.index)
    event_type = (
        df["event_type"] if "event_type" in df.columns else pd.Series([""] * len(df), index=df.index)
    )

    n_total = len(df)
    n_alerts = int(is_alert.sum())
    n_anomalies = int((event_type == "anomaly").sum())
    n_block = sum(1 for a in actions if str(a.get("action", "")).upper() == "BLOCK")
    n_alert = sum(1 for a in actions if str(a.get("action", "")).upper() == "ALERT")

    cat_counts = analysis.get("cat_counts", pd.DataFrame(columns=["category", "count"]))
    top_cats = cat_counts.head(3) if not cat_counts.empty else pd.DataFrame(columns=["category", "count"])

    cats_lines = []
    for _, row in top_cats.iterrows():
        category = html.escape(str(row.get("category", "—")))
        count = int(row.get("count", 0))
        cats_lines.append(f"  • {category} — {count}")
    cats_str = "\n".join(cats_lines) if cats_lines else "  • нет данных"

    cve_lines = ""
    cve_ok = sorted(
        [r for r in (vulners_results or []) if r.get("status") == "ok" and r.get("cve")],
        key=lambda x: x.get("cvss3_score") or 0,
        reverse=True,
    )

    if cve_ok:
        rows = []
        for result in cve_ok:
            score = result.get("cvss3_score")
            emoji = _cvss_emoji(score)
            score_str = f"{float(score):.1f}" if score is not None else "—"
            cve = html.escape(str(result.get("cve", "")))
            vector = html.escape(str(result.get("cvss3_vector") or ""))
            source = html.escape(str(result.get("cvss3_source") or ""))

            row = f"  {emoji} <code>{cve}</code> — CVSS3 <b>{score_str}</b>"
            if source:
                row += f" ({source})"
            if vector:
                row += f"\n    <code>{vector}</code>"

            rows.append(row)

        cve_lines = "\n\nCVE уязвимости:\n" + "\n".join(rows)
    elif vulners_results is not None:
        cve_lines = "\n\nCVE уязвимости: не обнаружены"

    domains = analysis.get("suspicious_domains", [])
    domains_lines = ""
    if domains:
        domain_items = "\n".join(f"  • <code>{html.escape(d)}</code>" for d in domains)
        domains_lines = f"\n\nПодозрительные домены:\n{domain_items}"

    hashes = analysis.get("suspicious_hashes", [])
    hashes_lines = ""
    if hashes:
        hash_items = "\n".join(
            f"  • {html.escape(h['filename'] or 'unknown')}  <code>{html.escape(h['hash'])}</code>"
            for h in hashes
        )
        hashes_lines = f"\n\nХеши файлов:\n{hash_items}"

    summary = (
        "📊 <b>Анализ завершён</b>\n\n"
        f"Событий в логе: <b>{n_total}</b>\n"
        f"Алертов: <b>{n_alerts}</b>\n"
        f"Аномалий: <b>{n_anomalies}</b>\n\n"
        "Реагирование:\n"
        f"  🚫 Блокировок: <b>{n_block}</b>\n"
        f"  ⚠️  Предупреждений: <b>{n_alert}</b>\n\n"
        f"Топ категорий атак:\n{cats_str}"
        f"{cve_lines}"
        f"{domains_lines}"
        f"{hashes_lines}"
    )

    if TG_CHART and Path(CHART_FILE).exists():
        short_caption = summary if len(summary) <= 1024 else "📊 <b>Итоговая сводка</b>"
        sent_photo = _send_photo(CHART_FILE, caption=short_caption)
        if not sent_photo:
            _send_message(summary)
        elif short_caption != summary:
            _send_message(summary)
    else:
        _send_message(summary)

    logger.info("  ✅ TG: сводка отправлена")