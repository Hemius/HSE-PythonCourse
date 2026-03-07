"""
analyzer.py — основной файл системы мониторинга и реагирования на угрозы.

Источники данных:
  1. Suricata EVE JSON (локальный файл: NDJSON или JSON-массив)
  2. VirusTotal API v3 — проверка подозрительных IP, доменов и хэшей файлов
  3. Vulners API — обогащение CVE (CVSS3 score, вектор, описание, дата публикации)

Результат работы:
  - вывод этапов анализа и действий реагирования в консоль
  - report.json — сводный отчёт
  - threats_chart.png — графики

Запуск:
  python analyzer.py
"""

import logging

from config     import LOG_FILE, REPORT_FILE, CHART_FILE
from loader     import load_log
from analysis   import analyze
from virustotal import run_virustotal
from vulners    import run_vulners
from responder  import respond
from reporter   import save_report
from charts     import build_charts
from telegram   import notify_actions, notify_summary

logger = logging.getLogger(__name__)

def main() -> None:
    """Запускает полный пайплайн анализа:
    загрузка лога → анализ IoC → VirusTotal → Vulners → реагирование →
    отчёт → графики → Telegram-уведомления → итоговый вывод в консоль.
    """
    # Настраиваем логирование для всего приложения
    # Используем простой формат, чтобы вывод оставался читаемым в консоли
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    logger.info("\n" + "=" * 60)
    logger.info("  🛡  СИСТЕМА МОНИТОРИНГА И РЕАГИРОВАНИЯ НА УГРОЗЫ")
    logger.info("=" * 60)

    # Загрузка и нормализация лога
    df       = load_log(LOG_FILE)
    
    # Анализ событий: выделение алертов и извлечение IoC
    analysis_result = analyze(df)

    # Проверка найденных IoC через VirusTotal
    vt_results      = run_virustotal(
        analysis_result["suspicious_ips"],
        analysis_result["suspicious_domains"],
        analysis_result["suspicious_hashes"],
    )
    
    # Получение информации о CVE через Vulners
    vulners_results = run_vulners(analysis_result["alerts_df"])
    
    # Формирование действий реагирования
    actions = respond(analysis_result["ip_counts"], vt_results)

    # Сохранение отчёта и построение графиков
    save_report(df, analysis_result, vt_results, actions, vulners_results)
    build_charts(analysis_result, df, vulners_results)

    # Отправка уведомлений в Telegram
    n_alerts   = int(analysis_result["alerts_df"].shape[0])
    n_anomalies = int((df["event_type"] == "anomaly").sum())
    notify_actions(actions, vt_results, n_alerts, n_anomalies)
    notify_summary(df, analysis_result, actions, vulners_results)

    # Вывод финального сообщения
    logger.info(f"\n{'=' * 60}")
    logger.info("  ✅ Анализ завершён")
    logger.info(f"     Отчёт:   {REPORT_FILE}")
    logger.info(f"     График:  {CHART_FILE}")

    suspicious_domains = analysis_result.get("suspicious_domains", [])
    if suspicious_domains:
        logger.info(f"     Подозрительных доменов: {len(suspicious_domains)}")
        for domain in suspicious_domains:
            logger.info(f"       • {domain}")

    suspicious_hashes = analysis_result.get("suspicious_hashes", [])
    if suspicious_hashes:
        logger.info(f"     Хешей файлов для проверки: {len(suspicious_hashes)}")
        for h in suspicious_hashes:
            logger.info(f"       • {h['filename'] or 'unknown'}  {h['hash']}")

    logger.info("=" * 60 + "\n")


if __name__ == "__main__":
    main()