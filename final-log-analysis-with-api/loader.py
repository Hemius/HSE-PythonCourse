"""
loader.py — модуль загрузки и нормализации логов Suricata EVE JSON.

Назначение:
  - прочитать лог из файла и автоматически определить его формат;
  - валидировать структуру входных данных (ожидаются JSON-объекты событий);
  - привести события к единой плоской структуре pandas.DataFrame.

Поддерживаемые форматы:
  1. NDJSON (один JSON-объект на строку) — типичный формат реального EVE-лога.
     Читается потоково (построчно), без загрузки всего файла в память.
  2. JSON-массив — формат тестовых или mock-данных.
     Загружается целиком (потоковый разбор JSON-массивов нетривиален).

Публичная точка входа:
  - load_log(path: str) -> pandas.DataFrame
"""

import json
import logging
from collections.abc import Iterable, Iterator

import pandas as pd

logger = logging.getLogger(__name__)

# Единая схема колонок для итогового DataFrame
# Нужна, чтобы пустой лог возвращал корректную таблицу без KeyError ниже по пайплайну
_COLUMNS = [
    "timestamp",
    "event_type",
    "src_ip",
    "dest_ip",
    "dest_port",
    "proto",
    "app_proto",
    "is_alert",
    "severity",
    "signature",
    "category",
    "domain",
    "http_uri",
    "http_method",
    "user_agent",
    "tls_ja3",
    "ssh_client",
    "filename",
    "file_md5",
    "file_sha256",
    "alert_cves",
]


def _stream_ndjson(f, path: str) -> Iterator[dict]:
    """Генератор: построчно читает NDJSON из открытого файла.

    Закрывает файловый дескриптор по завершении или при исключении (через finally).
    Вызывающая сторона не должна закрывать f после передачи его сюда.
    """
    try:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as e:
                raise ValueError(f"Некорректный JSON в строке {i} файла {path}: {e}")
            if not isinstance(event, dict):
                raise ValueError(
                    f"Строка {i} файла {path}: ожидается JSON-объект, "
                    f"получен {type(event).__name__}"
                )
            yield event
    finally:
        f.close()


def _parse_raw(path: str) -> Iterator[dict]:
    """Открывает файл, определяет формат и возвращает итератор событий.

    Ошибки файловой системы и формата выбрасываются немедленно (не отложенно).

    Для JSON-массива: загружает и валидирует целиком, возвращает iter() по списку.
    Для NDJSON: возвращает потоковый генератор — файл читается построчно,
                без хранения всех событий в памяти одновременно.
    """
    try:
        f = open(path, encoding="utf-8-sig")
    except FileNotFoundError:
        raise FileNotFoundError(f"Файл лога не найден: {path}")
    except OSError as e:
        raise OSError(f"Ошибка чтения файла {path}: {e}")

    try:
        # Определяем формат по первому непробельному символу
        first_non_ws = ""
        while True:
            ch = f.read(1)
            if not ch:
                break
            if not ch.isspace():
                first_non_ws = ch
                break

        if not first_non_ws:
            raise ValueError(f"Файл лога пуст: {path}")

        if first_non_ws == "[":
            # JSON-массив: загружаем и валидируем целиком, затем закрываем файл
            try:
                f.seek(0)
                data = json.load(f)
            except json.JSONDecodeError as e:
                raise ValueError(f"Некорректный JSON-массив в {path}: {e}")
            if not isinstance(data, list):
                raise ValueError(
                    f"Ожидался JSON-массив в {path}, получен {type(data).__name__}"
                )
            for i, event in enumerate(data, 1):
                if not isinstance(event, dict):
                    raise ValueError(
                        f"Элемент JSON-массива #{i} в {path} должен быть объектом, "
                        f"получен {type(event).__name__}"
                    )
            f.close()
            return iter(data)

        # NDJSON: передаём открытый файл генератору; тот закроет его сам
        f.seek(0)
        return _stream_ndjson(f, path)

    except Exception:
        # Закрываем файл при любой ошибке до передачи его генератору
        f.close()
        raise


def _normalize(events: Iterable[dict]) -> pd.DataFrame:
    """Преобразует итерируемое событий Suricata в плоский DataFrame фиксированной схемы."""
    rows = []
    for e in events:
        alert    = e.get("alert")    or {}
        dns      = e.get("dns")      or {}
        http     = e.get("http")     or {}
        tls      = e.get("tls")      or {}
        ssh      = e.get("ssh")      or {}
        anomaly  = e.get("anomaly")  or {}
        fileinfo = e.get("fileinfo") or {}

        # Домен берём по приоритету: DNS rrname -> TLS SNI -> HTTP hostname
        domain = (
            dns.get("rrname")
            or tls.get("sni")
            or http.get("hostname")
            or None
        )

        # Severity берём из alert, а если alert отсутствует — из anomaly
        severity = alert.get("severity") or anomaly.get("severity")

        rows.append({
            "timestamp":   e.get("timestamp"),
            "event_type":  e.get("event_type"),
            "src_ip":      e.get("src_ip"),
            "dest_ip":     e.get("dest_ip"),
            "dest_port":   e.get("dest_port"),
            "proto":       e.get("proto"),
            "app_proto":   e.get("app_proto"),
            # Блок alert
            "is_alert":    bool(alert),
            "severity":    severity,
            "signature":   alert.get("signature"),
            "category":    alert.get("category"),
            # Сетевые поля
            "domain":      domain,
            "http_uri":    http.get("url"),
            "http_method": http.get("http_method"),
            "user_agent":  http.get("http_user_agent"),
            "tls_ja3":     tls.get("ja3"),
            "ssh_client":  (ssh.get("client") or {}).get("software_version"),
            # Файловые поля
            "filename":    fileinfo.get("filename"),
            "file_md5":    fileinfo.get("md5"),
            "file_sha256": fileinfo.get("sha256"),
            # CVE из alert.metadata
            "alert_cves":  alert.get("metadata", {}).get("cve") or [],
        })

    # Проверяем после итерации — с Iterable нельзя узнать заранее, пуст ли он
    if not rows:
        return pd.DataFrame(columns=_COLUMNS)

    df = pd.DataFrame(rows)
    # Некорректные timestamp не роняют пайплайн, а конвертируются в NaT
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    return df


def load_log(path: str) -> pd.DataFrame:
    """Загружает лог из файла, нормализует события и логирует базовую статистику."""
    logger.info("\n" + "=" * 60)
    logger.info("  ЭТАП 1: Загрузка лога")
    logger.info("=" * 60)

    events = _parse_raw(path)
    df     = _normalize(events)

    n_alerts  = int(df["is_alert"].sum())
    n_anomaly = int((df["event_type"] == "anomaly").sum())
    n_other   = len(df) - n_alerts - n_anomaly

    logger.info(f"  Загружено событий:  {len(df)}")
    logger.info(f"  Алертов:            {n_alerts}  (event_type=alert)")
    logger.info(f"  Аномалий:           {n_anomaly}  (event_type=anomaly)")
    logger.info(f"  Прочих:             {n_other}  (dns, flow, http, tls, ...)")
    logger.info(f"  Период:             {df['timestamp'].min()} → {df['timestamp'].max()}")
    logger.info(f"  Типы событий:       {dict(df['event_type'].value_counts())}")
    return df