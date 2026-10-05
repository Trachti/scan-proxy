from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

from openpyxl import Workbook

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPOSITORY_ROOT / "src" / "scan_proxy.py"
SPEC = importlib.util.spec_from_file_location("scan_proxy", MODULE_PATH)
scan_proxy = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(scan_proxy)


class ScanProxyTests(unittest.TestCase):
    def test_is_enabled_accepts_documented_values(self):
        for value in (True, "true", "1", "yes", "on", "x"):
            with self.subTest(value=value):
                self.assertTrue(scan_proxy.is_enabled(value))
        for value in (False, "false", "0", "no", "off", ""):
            with self.subTest(value=value):
                self.assertFalse(scan_proxy.is_enabled(value))

    def test_normalize_ip_rejects_loopback_and_invalid_values(self):
        self.assertEqual(scan_proxy.normalize_ip("127.0.0.1"), "")
        self.assertEqual(scan_proxy.normalize_ip("::1"), "")
        self.assertEqual(scan_proxy.normalize_ip("not-an-ip"), "")
        self.assertEqual(scan_proxy.normalize_ip("192.0.2.10"), "192.0.2.10")

    def test_destination_keeps_existing_name_for_copy(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            target = Path(temporary_directory)
            existing = target / "document.pdf"
            existing.write_bytes(b"existing")
            result = scan_proxy.destination(target, Path("document.pdf"), "copy")
            self.assertEqual(result, existing)

    def test_destination_creates_unique_name_for_move(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            target = Path(temporary_directory)
            existing = target / "document.pdf"
            existing.write_bytes(b"existing")
            result = scan_proxy.destination(target, Path("document.pdf"), "move")
            self.assertNotEqual(result, existing)
            self.assertEqual(result.suffix, ".pdf")
            self.assertFalse(result.exists())

    def test_load_rules_reads_english_schema(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            workbook_path = Path(temporary_directory) / "scan-proxy-config.xlsx"
            workbook = Workbook()
            worksheet = workbook.active
            worksheet.title = "Rules"
            worksheet.append([
                "Identifier", "Source", "Destination", "Mode",
                "Enabled", "Action", "Scanner",
            ])
            worksheet.append([
                "FINANCE", r"\\SCAN-SERVER\scan", r"\\FILE-SERVER\finance\scan",
                "identifier", True, "move", "FrontDesk",
            ])
            workbook.save(workbook_path)
            original_config_path = scan_proxy.CONFIG_PATH
            scan_proxy.CONFIG_PATH = workbook_path
            try:
                sheet, rules = scan_proxy.load_rules()
            finally:
                scan_proxy.CONFIG_PATH = original_config_path
            self.assertEqual(sheet, "Rules")
            self.assertEqual(len(rules), 1)
            self.assertEqual(rules[0][1], "FINANCE")
            self.assertEqual(rules[0][4], "identifier")
            self.assertEqual(rules[0][6], "move")
            self.assertEqual(rules[0][7], "FrontDesk")

    def test_pending_retry_delay_uses_backoff(self):
        self.assertEqual(scan_proxy.pending_retry_delay(0), 30)
        self.assertEqual(scan_proxy.pending_retry_delay(1), 120)
        self.assertEqual(scan_proxy.pending_retry_delay(999), 43200)

    def test_public_defaults_are_neutral(self):
        self.assertEqual(scan_proxy.SMB_USER, "scanner-service")
        self.assertEqual(scan_proxy.SMB_IGNORED_NETWORKS, ())


if __name__ == "__main__":
    unittest.main()
