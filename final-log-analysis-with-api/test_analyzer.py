"""
Unit-тесты для модулей analysis.py, responder.py, loader.py, virustotal.py
Запуск: python -m pytest test_analyzer.py -v
     или: python test_analyzer.py
"""

import json
import os
import sys
import unittest
import tempfile

# Гарантируем, что папка проекта первой в пути поиска,
# чтобы импорты работали одинаково и при pytest, и при python test_analyzer.py.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pandas as pd
from unittest.mock import patch, MagicMock
from loader import _parse_raw

MOCK_CONFIG = {
    "files":          {"log": "suricata_events.json", "report": "report.json", "chart": "threats_chart.png"},
    "thresholds":     {"alert_threshold": 3, "block_threshold": 5, "vt_malicious_min": 1},
    "virustotal":     {"request_delay": 15, "retry_count": 3, "retry_delay": 5},
    "vulners":        {"request_delay": 2},
    "private_networks": ["192.168.", "10.", "127.", "172.16.", "172.17."],
}

with patch("yaml.safe_load", return_value=MOCK_CONFIG), \
     patch("dotenv.load_dotenv"), \
     patch("os.getenv", return_value=""):
    import config
    from analysis   import analyze
    from responder  import respond
    from virustotal import _validate_api_key, run_virustotal
    from vulners   import extract_cves



def make_df(events: list) -> pd.DataFrame:
    rows = []
    for e in events:
        rows.append({
            "timestamp":   pd.Timestamp("2026-03-01 09:00:00", tz="UTC"),
            "event_type":  e.get("event_type", "dns"),
            "src_ip":      e.get("src_ip", "192.168.1.1"),
            "dest_ip":     e.get("dest_ip", "8.8.8.8"),
            "dest_port":   e.get("dest_port"),
            "proto":       e.get("proto", "UDP"),
            "app_proto":   e.get("app_proto"),
            "is_alert":    e.get("is_alert", False),
            "severity":    e.get("severity"),
            "signature":   e.get("signature"),
            "category":    e.get("category"),
            "domain":      e.get("domain"),
            "http_uri":    e.get("http_uri"),
            "http_method": e.get("http_method"),
            "user_agent":  e.get("user_agent"),
            "tls_ja3":     e.get("tls_ja3"),
            "ssh_client":  e.get("ssh_client"),
            "filename":    e.get("filename"),
            "file_md5":    e.get("file_md5"),
            "file_sha256": e.get("file_sha256"),
            "alert_cves":  e.get("alert_cves", []),
        })
    return pd.DataFrame(rows)


# ──────────────────────────────────────────────────────────────────────────────
# analysis.py
# ──────────────────────────────────────────────────────────────────────────────

class TestAnalyze(unittest.TestCase):

    def test_normal_events_not_counted_as_alerts(self):
        """Нормальные события не должны попадать в alerts_df."""
        df = make_df([
            {"src_ip": "192.168.1.10", "is_alert": False},
            {"src_ip": "192.168.1.11", "is_alert": False},
        ])
        result = analyze(df)
        self.assertEqual(len(result["alerts_df"]), 0)

    def test_alert_count_per_ip(self):
        """ip_counts должен корректно считать алерты по IP."""
        df = make_df([
            {"src_ip": "1.2.3.4", "is_alert": True,  "category": "Network Scan"},
            {"src_ip": "1.2.3.4", "is_alert": True,  "category": "Network Scan"},
            {"src_ip": "5.6.7.8", "is_alert": True,  "category": "Web Application Attack"},
            {"src_ip": "192.168.1.1", "is_alert": False},
        ])
        result = analyze(df)
        ip_map = dict(zip(result["ip_counts"]["src_ip"], result["ip_counts"]["alert_count"]))
        self.assertEqual(ip_map.get("1.2.3.4"), 2)
        self.assertEqual(ip_map.get("5.6.7.8"), 1)

    def test_private_ips_excluded_from_vt(self):
        """Приватные IP не должны попадать в список для VT."""
        df = make_df([
            {"src_ip": "192.168.1.5",   "is_alert": True, "category": "Network Scan"},
            {"src_ip": "10.0.0.1",      "is_alert": True, "category": "Network Scan"},
            {"src_ip": "185.220.101.1", "is_alert": True, "category": "Network Scan"},
        ])
        result = analyze(df)
        for ip in result["suspicious_ips"]:
            self.assertFalse(
                any(ip.startswith(net) for net in config.PRIVATE_NETS),
                f"Приватный IP {ip} попал в список VT"
            )

    def test_ioc_deduplication(self):
        """Один и тот же IoC не должен дублироваться."""
        df = make_df([
            {"src_ip": "1.2.3.4", "is_alert": True, "category": "Network Scan", "domain": "evil.com"},
            {"src_ip": "1.2.3.4", "is_alert": True, "category": "Network Scan", "domain": "evil.com"},
        ])
        result = analyze(df)
        self.assertEqual(result["suspicious_ips"].count("1.2.3.4"), 1)
        self.assertEqual(result["suspicious_domains"].count("evil.com"), 1)

    def test_suspicious_domains_extracted(self):
        """Домены из аномалий должны попасть в suspicious_domains."""
        df = make_df([
            {"src_ip": "1.2.3.4", "is_alert": True,  "category": "Potentially Bad Traffic", "domain": "malware.ru"},
            {"src_ip": "1.2.3.4", "is_alert": False, "domain": "google.com"},
        ])
        result = analyze(df)
        self.assertIn("malware.ru", result["suspicious_domains"])
        self.assertNotIn("google.com", result["suspicious_domains"])

    def test_empty_alerts_returns_empty_structures(self):
        """Если нет алертов — analyze возвращает пустые структуры без краша."""
        df = make_df([
            {"src_ip": "192.168.1.1", "is_alert": False},
            {"src_ip": "192.168.1.2", "is_alert": False},
        ])
        result = analyze(df)
        self.assertTrue(result["ip_counts"].empty)
        self.assertTrue(result["cat_counts"].empty)
        self.assertEqual(result["suspicious_ips"], [])
        self.assertEqual(result["suspicious_domains"], [])

    def test_empty_alerts_has_required_keys(self):
        """При пустом df возвращаются все ожидаемые ключи."""
        df = make_df([{"is_alert": False}])
        result = analyze(df)
        for key in ("ip_counts", "cat_counts", "suspicious_ips", "suspicious_domains",
                     "suspicious_hashes", "alerts_df"):
            self.assertIn(key, result)


# ──────────────────────────────────────────────────────────────────────────────
# responder.py
# ──────────────────────────────────────────────────────────────────────────────

class TestRespond(unittest.TestCase):

    def test_respond_blocks_high_count_ip(self):
        """IP с >= BLOCK_THRESHOLD аномалий → BLOCK."""
        ip_counts = pd.DataFrame({
            "src_ip":      ["1.2.3.4"],
            "alert_count": [config.BLOCK_THRESHOLD],
        })
        actions = respond(ip_counts, vt_results=[])
        self.assertEqual(actions[0]["action"], "BLOCK")

    def test_respond_alerts_medium_count_ip(self):
        """IP с >= ALERT_THRESHOLD, но < BLOCK_THRESHOLD → ALERT."""
        ip_counts = pd.DataFrame({
            "src_ip":      ["1.2.3.4"],
            "alert_count": [config.ALERT_THRESHOLD],
        })
        actions = respond(ip_counts, vt_results=[])
        self.assertEqual(actions[0]["action"], "ALERT")

    def test_respond_blocks_vt_confirmed_ip(self):
        """IP подтверждённый VT → BLOCK даже с малым числом аномалий."""
        ip_counts = pd.DataFrame({
            "src_ip":      ["1.2.3.4"],
            "alert_count": [1],
        })
        vt_results = [{"ioc": "1.2.3.4", "type": "ip_addresses",
                       "malicious": 5, "status": "ok"}]
        actions = respond(ip_counts, vt_results=vt_results)
        self.assertEqual(actions[0]["action"], "BLOCK")
        self.assertTrue(actions[0]["vt_confirmed"])

    def test_respond_malicious_domain_added_to_actions(self):
        """Вредоносный домен из VT должен добавляться в actions с action=BLOCK."""
        ip_counts = pd.DataFrame(columns=["src_ip", "alert_count"])
        vt_results = [{"ioc": "evil.ru", "type": "domains",
                       "malicious": 3, "status": "ok"}]
        actions = respond(ip_counts, vt_results=vt_results)
        domain_actions = [a for a in actions if a.get("domain") == "evil.ru"]
        self.assertEqual(len(domain_actions), 1)
        self.assertEqual(domain_actions[0]["action"], "BLOCK")
        self.assertTrue(domain_actions[0]["vt_confirmed"])

    def test_respond_clean_domain_not_in_actions(self):
        """Чистый домен из VT не должен попадать в actions."""
        ip_counts = pd.DataFrame(columns=["src_ip", "alert_count"])
        vt_results = [{"ioc": "safe.com", "type": "domains",
                       "malicious": 0, "status": "ok"}]
        actions = respond(ip_counts, vt_results=vt_results)
        domain_actions = [a for a in actions if a.get("domain") == "safe.com"]
        self.assertEqual(len(domain_actions), 0)

    def test_respond_empty_inputs_returns_empty_list(self):
        """Пустые входные данные → пустой список actions."""
        ip_counts = pd.DataFrame(columns=["src_ip", "alert_count"])
        actions = respond(ip_counts, vt_results=[])
        self.assertEqual(actions, [])


# ──────────────────────────────────────────────────────────────────────────────
# loader.py
# ──────────────────────────────────────────────────────────────────────────────

class TestLoader(unittest.TestCase):

    def test_missing_file_raises_file_not_found(self):
        """Отсутствующий файл → FileNotFoundError с понятным сообщением."""
        with self.assertRaises(FileNotFoundError) as ctx:
            _parse_raw("/nonexistent/path/file.json")
        self.assertIn("не найден", str(ctx.exception))

    def test_empty_file_raises_value_error(self):
        """Пустой файл → ValueError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write("")
            path = f.name
        try:
            with self.assertRaises(ValueError) as ctx:
                _parse_raw(path)
            self.assertIn("пуст", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_invalid_json_array_raises_value_error(self):
        """Некорректный JSON-массив → ValueError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            f.write("[{broken json")
            path = f.name
        try:
            with self.assertRaises(ValueError):
                _parse_raw(path)
        finally:
            os.unlink(path)

    def test_invalid_ndjson_line_raises_value_error(self):
        """Некорректная строка NDJSON → ValueError с номером строки."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
            f.write('{"event_type": "dns"}\n')
            f.write("{broken line}\n")
            path = f.name
        try:
            # NDJSON читается потоково: ошибка возникает при потреблении генератора
            with self.assertRaises(ValueError) as ctx:
                list(_parse_raw(path))
            self.assertIn("строке 2", str(ctx.exception))
        finally:
            os.unlink(path)

    def test_valid_json_array_parsed(self):
        """Корректный JSON-массив → список событий."""
        events = [{"event_type": "alert"}, {"event_type": "dns"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(events, f)
            path = f.name
        try:
            result = list(_parse_raw(path))
            self.assertEqual(len(result), 2)
            self.assertEqual(result[0]["event_type"], "alert")
        finally:
            os.unlink(path)

    def test_valid_ndjson_parsed(self):
        """Корректный NDJSON → список событий."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8") as f:
            f.write('{"event_type": "alert"}\n')
            f.write('{"event_type": "dns"}\n')
            path = f.name
        try:
            result = list(_parse_raw(path))
            self.assertEqual(len(result), 2)
            self.assertEqual(result[1]["event_type"], "dns")
        finally:
            os.unlink(path)


# ──────────────────────────────────────────────────────────────────────────────
# virustotal.py
# ──────────────────────────────────────────────────────────────────────────────

class TestVTValidation(unittest.TestCase):

    @patch("virustotal.VT_API_KEY", "testkey")
    @patch("virustotal.requests.get")
    def test_valid_key_returns_true(self, mock_get):
        """Ответ 200 → ключ действителен."""
        mock_get.return_value = MagicMock(status_code=200)
        self.assertTrue(_validate_api_key())

    @patch("virustotal.VT_API_KEY", "testkey")
    @patch("virustotal.requests.get")
    def test_invalid_key_returns_false(self, mock_get):
        """Ответ 401 → ключ недействителен."""
        mock_get.return_value = MagicMock(status_code=401)
        self.assertFalse(_validate_api_key())

    @patch("virustotal.VT_API_KEY", "testkey")
    @patch("virustotal.requests.get")
    def test_network_error_returns_false(self, mock_get):
        """Сетевая ошибка при проверке ключа → False, без исключений."""
        import requests as req
        mock_get.side_effect = req.exceptions.ConnectionError("timeout")
        self.assertFalse(_validate_api_key())

    @patch("virustotal.VT_API_KEY", "")
    def test_empty_key_skips_vt(self):
        """Пустой VT_API_KEY → run_virustotal возвращает [] без обращений к API."""
        with patch("virustotal.requests.get") as mock_get:
            result = run_virustotal(["1.2.3.4"], [])
            mock_get.assert_not_called()
            self.assertEqual(result, [])

    @patch("virustotal.VT_API_KEY", "testkey")
    @patch("virustotal._validate_api_key", return_value=True)
    @patch("virustotal.vt_check")
    def test_file_hashes_checked_via_vt(self, mock_vt_check, _mock_validate):
        """Хэши файлов проверяются через /files/{hash}, filename сохраняется в результате."""
        mock_vt_check.return_value = {
            "ioc": "abc123", "type": "files",
            "malicious": 0, "suspicious": 0, "status": "ok",
        }
        hashes = [{"hash": "abc123", "hash_type": "sha256", "filename": "evil.exe"}]
        results = run_virustotal([], [], suspicious_hashes=hashes)
        mock_vt_check.assert_called_once_with("abc123", "files")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["filename"], "evil.exe")


# ──────────────────────────────────────────────────────────────────────────────
# analysis.py — file hash extraction
# ──────────────────────────────────────────────────────────────────────────────

class TestAnalyzeHashes(unittest.TestCase):

    def test_fileinfo_sha256_extracted(self):
        """SHA-256 из fileinfo-алерта попадает в suspicious_hashes."""
        df = make_df([
            {"event_type": "fileinfo", "is_alert": True, "category": "Malware",
             "src_ip": "1.2.3.4", "file_sha256": "aabbcc112233", "filename": "bad.exe"},
        ])
        result = analyze(df)
        hashes = [h["hash"] for h in result["suspicious_hashes"]]
        self.assertIn("aabbcc112233", hashes)

    def test_fileinfo_md5_fallback(self):
        """Если SHA-256 нет — используется MD5."""
        df = make_df([
            {"event_type": "fileinfo", "is_alert": True, "category": "Malware",
             "src_ip": "1.2.3.4", "file_md5": "deadbeef1234", "filename": "suspect.dll"},
        ])
        result = analyze(df)
        hashes = [h["hash"] for h in result["suspicious_hashes"]]
        self.assertIn("deadbeef1234", hashes)
        self.assertEqual(result["suspicious_hashes"][0]["hash_type"], "md5")

    def test_fileinfo_sha256_preferred_over_md5(self):
        """Когда оба поля заполнены — используется SHA-256."""
        df = make_df([
            {"event_type": "fileinfo", "is_alert": True, "category": "Malware",
             "src_ip": "1.2.3.4", "file_sha256": "sha256value", "file_md5": "md5value",
             "filename": "f.bin"},
        ])
        result = analyze(df)
        self.assertEqual(result["suspicious_hashes"][0]["hash"], "sha256value")
        self.assertEqual(result["suspicious_hashes"][0]["hash_type"], "sha256")

    def test_fileinfo_hash_deduplication(self):
        """Один и тот же хэш не добавляется дважды."""
        df = make_df([
            {"event_type": "fileinfo", "is_alert": True, "category": "Malware",
             "src_ip": "1.2.3.4", "file_sha256": "dupe", "filename": "a.exe"},
            {"event_type": "fileinfo", "is_alert": True, "category": "Malware",
             "src_ip": "1.2.3.5", "file_sha256": "dupe", "filename": "b.exe"},
        ])
        result = analyze(df)
        self.assertEqual(len(result["suspicious_hashes"]), 1)

    def test_fileinfo_filename_stored(self):
        """Имя файла сохраняется вместе с хэшем."""
        df = make_df([
            {"event_type": "fileinfo", "is_alert": True, "category": "Malware",
             "src_ip": "1.2.3.4", "file_sha256": "hash1", "filename": "malware.exe"},
        ])
        result = analyze(df)
        self.assertEqual(result["suspicious_hashes"][0]["filename"], "malware.exe")


# ──────────────────────────────────────────────────────────────────────────────
# vulners.py — CVE extraction
# ──────────────────────────────────────────────────────────────────────────────

class TestVulners(unittest.TestCase):

    def test_cve_from_signature(self):
        """CVE в тексте подписи извлекается через regex."""
        df = make_df([
            {"is_alert": True, "category": "Exploit",
             "signature": "ET EXPLOIT CVE-2021-44228 Log4Shell Attempt"},
        ])
        cves = extract_cves(df)
        self.assertIn("CVE-2021-44228", cves)

    def test_cve_from_metadata(self):
        """CVE из alert.metadata.cve извлекается напрямую."""
        df = make_df([
            {"is_alert": True, "category": "Exploit",
             "signature": "ET SCAN Possible SSH Brute Force",
             "alert_cves": ["CVE-2020-1472"]},
        ])
        cves = extract_cves(df)
        self.assertIn("CVE-2020-1472", cves)

    def test_cve_deduplication(self):
        """Один и тот же CVE из обоих источников не дублируется."""
        df = make_df([
            {"is_alert": True, "category": "Exploit",
             "signature": "CVE-2019-0708 BlueKeep",
             "alert_cves": ["CVE-2019-0708"]},
        ])
        cves = extract_cves(df)
        self.assertEqual(cves.count("CVE-2019-0708"), 1)

    def test_no_cves_returns_empty(self):
        """Алерты без CVE → пустой список."""
        df = make_df([
            {"is_alert": True, "category": "Network Scan",
             "signature": "ET SCAN Port Sweep"},
        ])
        cves = extract_cves(df)
        self.assertEqual(cves, [])

    def test_cve_uppercased(self):
        """CVE нормализуются к верхнему регистру."""
        df = make_df([
            {"is_alert": True, "category": "Exploit",
             "alert_cves": ["cve-2020-1472"]},
        ])
        cves = extract_cves(df)
        self.assertIn("CVE-2020-1472", cves)


if __name__ == "__main__":
    unittest.main(verbosity=2)