"""Cross-platform tests for the Scan Proxy routing and privacy defaults."""

from __future__ import annotations

import importlib.util
import logging
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from openpyxl import Workbook

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPOSITORY_ROOT / "src" / "scan_proxy.py"
SPEC = importlib.util.spec_from_file_location("scan_proxy", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
scan_proxy = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = scan_proxy
SPEC.loader.exec_module(scan_proxy)


class FakeSmbResolver:
    snapshot_wall_time = 0.0

    def __init__(self, *, is_open=False):
        self.is_open = is_open
        self.refresh_count = 0
        self.forgotten = []

    def refresh_open_snapshot(self, force=False):
        self.refresh_count += 1
        return 0.0

    def resolve(self, file, relative="", mtime="", reference=""):
        result = scan_proxy.SmbResolver.empty()
        result["is_open"] = self.is_open
        return result

    def resolve_batch(self, rows):
        return {
            str(row["id"]): {
                "client": "192.0.2.21",
                "source": "Security-5145",
                "reason": "Exact event match",
                "confidence": "ExactPathRecent",
                "record_id": 123,
            }
            for row in rows
        }

    def forget(self, file):
        self.forgotten.append(file)


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.log = logging.getLogger("scan_proxy_tests")
        self.log.addHandler(logging.NullHandler())

    def test_enabled_values(self):
        for value in (True, "true", "1", "yes", "on", "x"):
            with self.subTest(value=value):
                self.assertTrue(scan_proxy.is_enabled(value))
        for value in (False, "false", "0", "no", "off", ""):
            with self.subTest(value=value):
                self.assertFalse(scan_proxy.is_enabled(value))

    def test_normalize_ip(self):
        for value in ("", "not-an-ip", "127.0.0.1", "::1", "0.0.0.0"):
            self.assertEqual(scan_proxy.normalize_ip(value), "")
        self.assertEqual(scan_proxy.normalize_ip("192.0.2.10"), "192.0.2.10")
        self.assertEqual(scan_proxy.normalize_ip("::ffff:192.0.2.10"), "192.0.2.10")

    def test_load_rules_reads_english_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            workbook_path = Path(directory) / "rules.xlsx"
            workbook = Workbook()
            sheet = workbook.active
            sheet.title = "Rules"
            sheet.append(["Identifier", "Source", "Destination", "Mode", "Enabled", "Action", "Scanner"])
            sheet.append(["DOC", "incoming", "outgoing", "identifier", True, "move", "unused"])
            workbook.save(workbook_path)
            with mock.patch.object(scan_proxy, "CONFIG_PATH", workbook_path):
                name, raw_rules = scan_proxy.load_rules()
            self.assertEqual(name, "Rules")
            self.assertEqual(len(raw_rules), 1)
            self.assertEqual(raw_rules[0][1:7], ("DOC", "incoming", "outgoing", "identifier", True, "move"))
            self.assertEqual(len(raw_rules[0]), 7)

    def test_duplicate_rules_are_ignored(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            target = Path(directory) / "target"
            raw = [
                (2, "DOC", source, target, "identifier", True, "move"),
                (3, "DOC", source, target, "identifier", True, "move"),
                (4, "DOC", source, target, "identifier", False, "move"),
            ]
            groups, active_count = scan_proxy.compile_rules(raw, self.log)
            self.assertEqual(active_count, 1)
            self.assertEqual(len(groups[0].identifiers["doc"]), 1)

    def test_recursive_target_inside_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            groups, count = scan_proxy.compile_rules(
                [(2, "", root, root / "child", "subfolders", True, "copy")],
                self.log,
            )
            self.assertEqual((groups, count), ([], 0))

    def test_copy_destination_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            existing = target / "document.txt"
            existing.write_text("existing")
            self.assertEqual(scan_proxy.destination(target, Path(existing.name), "copy"), existing)
            self.assertEqual(existing.read_text(), "existing")

    def test_move_destination_avoids_collisions(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / "document.txt").write_text("existing")
            result = scan_proxy.destination(target, Path("document.txt"), "move")
            self.assertNotEqual(result.name, "document.txt")
            self.assertFalse(result.exists())
            self.assertEqual(result.suffix, ".txt")


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source_dir = self.root / "incoming"
        self.target_dir = self.root / "routed"
        self.source_dir.mkdir()
        self.target_dir.mkdir()
        self.log = logging.getLogger("scan_proxy_transfer_tests")
        self.log.addHandler(logging.NullHandler())
        analytics_root = self.root / "analytics"
        paths = {
            "ROOT": self.root,
            "ANALYTICS": analytics_root,
            "STATE": analytics_root / "_state",
            "DB": analytics_root / "_state" / "scan-proxy.db",
            "REPORT": analytics_root / "analytics.html",
            "DAILY": analytics_root / "daily",
            "WEEKLY": analytics_root / "weekly",
            "MONTHLY": analytics_root / "monthly",
            "YEARLY": analytics_root / "yearly",
            "SMB_USER": "",
        }
        patcher = mock.patch.multiple(scan_proxy, **paths)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.analytics = scan_proxy.Analytics(self.log)
        self.analytics.init()
        self.addCleanup(self.analytics.close)
        self.smb = FakeSmbResolver()

    def create_file(self, name="DOC-file.txt", contents="sample"):
        path = self.source_dir / name
        path.write_text(contents)
        old = time.time() - 90
        os.utime(path, (old, old))
        return path

    def test_identifier_move_and_local_analytics(self):
        file = self.create_file()
        groups, count = scan_proxy.compile_rules(
            [(2, "DOC", self.source_dir, self.target_dir, "identifier", True, "move")],
            self.log,
        )
        self.assertEqual(count, 1)
        stats = scan_proxy.process_rules(groups, self.smb, self.analytics, self.log)
        self.assertEqual(stats["transfers"], 1)
        self.assertEqual(self.smb.refresh_count, 1)
        self.assertFalse(file.exists())
        self.assertEqual((self.target_dir / file.name).read_text(), "sample")
        row = self.analytics.connect().execute(
            "SELECT resolution_state, original_path, relative_path, completed_path, pages FROM scans"
        ).fetchone()
        self.assertEqual(tuple(row), ("unresolved", "", "", "", 1))
        self.analytics.refresh_reports()
        self.assertTrue(scan_proxy.REPORT.is_file())
        self.assertIn("Total files", scan_proxy.REPORT.read_text())

    def test_subfolder_copy_preserves_directory_structure(self):
        nested = self.source_dir / "nested"
        nested.mkdir()
        file = nested / "file.txt"
        file.write_text("content")
        old = time.time() - 90
        os.utime(file, (old, old))
        groups, _ = scan_proxy.compile_rules(
            [(2, "", self.source_dir, self.target_dir, "subfolders", True, "copy")],
            self.log,
        )
        first = scan_proxy.process_rules(groups, self.smb, self.analytics, self.log)
        second = scan_proxy.process_rules(groups, self.smb, self.analytics, self.log)
        self.assertEqual(first["transfers"], 1)
        self.assertEqual(second["transfers"], 0)
        self.assertEqual((self.target_dir / "nested" / "file.txt").read_text(), "content")
        self.assertTrue(file.exists())

    def test_open_file_is_not_transferred(self):
        file = self.create_file()
        blocker = FakeSmbResolver(is_open=True)
        completed = scan_proxy.transfer(
            file, self.target_dir, Path(file.name), "move", "Excel row 2", "DOC",
            blocker, self.analytics, self.log,
        )
        self.assertFalse(completed)
        self.assertTrue(file.exists())
        self.assertEqual(list(self.target_dir.iterdir()), [])

    def test_recent_file_is_not_transferred(self):
        file = self.source_dir / "DOC-recent.txt"
        file.write_text("unfinished")
        completed = scan_proxy.transfer(
            file, self.target_dir, Path(file.name), "move", "Excel row 2", "DOC",
            self.smb, self.analytics, self.log,
        )
        self.assertFalse(completed)
        self.assertFalse((self.target_dir / file.name).exists())

    def test_copy_to_identical_path_is_prevented(self):
        file = self.create_file()
        completed = scan_proxy.transfer(
            file, self.source_dir, Path(file.name), "copy", "Excel row 2", "DOC",
            self.smb, self.analytics, self.log,
        )
        self.assertFalse(completed)
        self.assertEqual(file.read_text(), "sample")

    def test_pending_attribution_paths_are_erased_on_resolution(self):
        file = self.create_file()
        with mock.patch.object(scan_proxy, "SMB_USER", "configured-account"):
            self.analytics.add_scan(
                file, file.name, file, "DOC", scan_proxy.utc_now_iso(),
                scan_proxy.SmbResolver.empty(), page_count=1, size_bytes=6,
            )
            row = self.analytics.connect().execute("SELECT * FROM scans").fetchone()
            self.assertEqual(row["resolution_state"], "pending")
            self.assertIn("DOC-file.txt", row["original_path"])
            self.analytics.connect().execute("UPDATE scans SET next_resolve_epoch = 0")
            self.analytics.connect().commit()
            changed = self.analytics.resolve_pending(FakeSmbResolver())
            self.assertEqual(changed, 1)
        row = self.analytics.connect().execute("SELECT * FROM scans").fetchone()
        self.assertEqual(row["scanner_ip"], "192.0.2.21")
        self.assertEqual(row["resolution_state"], "resolved")
        self.assertEqual((row["original_path"], row["relative_path"], row["completed_path"]), ("", "", ""))

    def test_embedded_report_data_cannot_inject_script_tags(self):
        file = self.create_file()
        resolved = scan_proxy.SmbResolver.empty()
        resolved["client"] = "192.0.2.40"
        with mock.patch.object(scan_proxy, "SMB_USER", "configured-account"):
            self.analytics.add_scan(
                file, file.name, file, "DOC", scan_proxy.utc_now_iso(),
                resolved, page_count=1, size_bytes=6,
            )
            with mock.patch.object(self.analytics, "refresh_hostnames", return_value=set()):
                with mock.patch.object(self.analytics, "hostnames", return_value={
                    "192.0.2.40": "</script><script>alert(1)</script>",
                }):
                    self.analytics.refresh_reports(force=True)
        html = scan_proxy.REPORT.read_text(encoding="utf-8")
        self.assertNotIn("</script><script>alert(1)</script>", html)
        self.assertIn("\\u003c/script\\u003e", html)

    def test_recovery_of_move_after_source_unlink_failure(self):
        file = self.create_file()
        source_stat = file.stat()
        destination = self.target_dir / file.name
        destination.write_text("sample")
        self.analytics.add_move(
            file, destination, file.name, "DOC", source_stat,
            scan_proxy.utc_now_iso(), scan_proxy.SmbResolver.empty(), "temporary error",
        )
        self.analytics.retry_moves()
        self.assertFalse(file.exists())
        self.assertEqual(self.analytics.connect().execute("SELECT COUNT(*) FROM pending_moves").fetchone()[0], 0)
        self.assertEqual(self.analytics.connect().execute("SELECT COUNT(*) FROM scans").fetchone()[0], 1)


class SmbSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.resolver = scan_proxy.SmbResolver(logging.getLogger("snapshot_tests"))

    def test_unique_open_file_is_blocked_and_then_cached(self):
        path = Path("example.txt")
        key = scan_proxy.normalize_path_key(path)
        self.resolver.snapshot_paths[key] = {"192.0.2.30"}
        result = self.resolver.resolve(path, "", "mtime-one")
        self.assertTrue(result["is_open"])
        self.assertEqual(result["client"], "192.0.2.30")
        self.resolver.snapshot_paths.clear()
        remembered = self.resolver.resolve(path, "", "mtime-one")
        self.assertFalse(remembered["is_open"])
        self.assertEqual(remembered["client"], "192.0.2.30")
        self.assertFalse(self.resolver.resolve(path, "", "mtime-two")["resolved"])

    def test_ambiguous_open_file_is_blocked(self):
        self.resolver.snapshot_relative["folder\\file.txt"] = {"192.0.2.1", "192.0.2.2"}
        result = self.resolver.resolve(Path("file.txt"), "folder/file.txt", "mtime")
        self.assertTrue(result["is_open"])
        self.assertEqual(result["confidence"], "Ambiguous")
        self.assertFalse(result["resolved"])

    def test_no_configured_account_skips_windows_helper(self):
        with mock.patch.object(scan_proxy, "SMB_USER", ""):
            self.assertEqual(self.resolver.resolve_batch([{"id": "x"}])["x"]["client"], "")


class ExampleWorkbookTests(unittest.TestCase):
    def test_example_rule_sheet_is_valid(self):
        from openpyxl import load_workbook
        path = REPOSITORY_ROOT / "config" / "scan-proxy-config.example.xlsx"
        workbook = load_workbook(path, read_only=True, data_only=True)
        try:
            self.assertEqual(workbook.active.title, "Rules")
            self.assertEqual(
                [cell.value for cell in workbook.active[1]],
                ["Identifier", "Source", "Destination", "Mode", "Enabled", "Action"],
            )
        finally:
            workbook.close()


if __name__ == "__main__":
    unittest.main()
