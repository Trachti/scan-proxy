from __future__ import annotations

import csv
import ctypes
import io
import ipaddress
import json
import logging
import os
import re
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from html import escape
from pathlib import Path

from openpyxl import load_workbook

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None


VERSION = "2.13.0"

# Maintainer: Trachti. No deployment-specific values are bundled.

BASE = (
    Path(sys.executable).resolve().parent
    if getattr(sys, "frozen", False)
    else Path(__file__).resolve().parent.parent
)
ROOT = Path(os.environ.get("SCAN_PROXY_ROOT", r"C:\scan"))
CONFIG_PATH = Path(os.environ.get(
    "SCAN_PROXY_CONFIG", str(BASE / "config" / "scan-proxy-config.xlsx")
))
SMB_HELPER_PATH = Path(os.environ.get(
    "SCAN_PROXY_SMB_HELPER", str(BASE / "scripts" / "scan-proxy-smb.ps1")
))


def environment_integer(name, default, minimum=1):
    """Read an integer environment setting and validate its minimum."""
    value = int(os.environ.get(name, str(default)))
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


FILE_SCAN_INTERVAL_SECONDS = environment_integer("SCAN_PROXY_FILE_SCAN_INTERVAL_SECONDS", 5)
REPORT_REFRESH_INTERVAL_SECONDS = environment_integer("SCAN_PROXY_REPORT_REFRESH_INTERVAL_SECONDS", 600)
PENDING_SWEEP_INTERVAL_SECONDS = environment_integer("SCAN_PROXY_PENDING_SWEEP_INTERVAL_SECONDS", 60)
PENDING_BATCH_SIZE = environment_integer("SCAN_PROXY_PENDING_BATCH_SIZE", 8)
PENDING_MAX_HOURS = environment_integer("SCAN_PROXY_PENDING_MAX_HOURS", 48)
SMB_EVENT_LOOKBACK_MINUTES = environment_integer("SCAN_PROXY_SMB_EVENT_LOOKBACK_MINUTES", 10)
SMB_BATCH_TIMEOUT = environment_integer("SCAN_PROXY_SMB_BATCH_TIMEOUT_SECONDS", 20)
SMB_SNAPSHOT_TIMEOUT = environment_integer("SCAN_PROXY_SMB_SNAPSHOT_TIMEOUT_SECONDS", 4)
SMB_SNAPSHOT_TTL_SECONDS = environment_integer("SCAN_PROXY_SMB_SNAPSHOT_TTL_SECONDS", 8)
MIN_AGE = environment_integer("SCAN_PROXY_MIN_FILE_AGE_SECONDS", 3)

SMB_USER = os.environ.get("SCAN_PROXY_SMB_USER", "").strip()
SMB_IGNORED_NETWORKS = tuple(
    network.strip()
    for network in os.environ.get("SCAN_PROXY_IGNORED_NETWORKS", "").replace(",", ";").split(";")
    if network.strip()
)
ENABLE_HOSTNAME_LOOKUP = os.environ.get("SCAN_PROXY_ENABLE_HOSTNAME_LOOKUP", "false").lower() in {"true", "1", "yes"}

LOG_ROOT = BASE / "logs"
SCANPROXY_LOG_DIR = LOG_ROOT / "scan-proxy"
ANALYTICS_LOG_DIR = LOG_ROOT / "analytics"
ANALYTICS = BASE / "analytics"
STATE = ANALYTICS / "_state"
REPORT = ANALYTICS / "analytics.html"
DB = STATE / "scan-proxy.db"
DAILY = ANALYTICS / "daily"
WEEKLY = ANALYTICS / "weekly"
MONTHLY = ANALYTICS / "monthly"
YEARLY = ANALYTICS / "yearly"

MAIN_LOOP_SLEEP_SECONDS = 1
PENDING_RETRY_DELAYS_SECONDS = (30, 120, 600, 3600, 21600, 43200)
SMB_EXACT_HINT_SECONDS = 3600
HOSTNAME_LOOKUP_TIMEOUT_SECONDS = 2
HOSTNAME_SUCCESS_TTL_SECONDS = 86400
HOSTNAME_FAILURE_TTL_SECONDS = 21600
HOSTNAME_BATCH_SIZE = 4
TARGET_DIR_CACHE_TTL_SECONDS = 600
PERFORMANCE_LOG_INTERVAL_SECONDS = 300
DAILY_RETENTION_DAYS = environment_integer("SCAN_PROXY_DAILY_RETENTION_DAYS", 90)
MOVE_RETRY_SECONDS = 5
PENDING_CACHE_SECONDS = 5
SMB_IGNORED_NETS = tuple(ipaddress.ip_network(value, strict=False) for value in SMB_IGNORED_NETWORKS)
STOP = threading.Event()

LOCAL_SCAN_SERVER_ALIASES = {
    name.split(".", 1)[0].strip().lower()
    for name in (
        os.environ.get("COMPUTERNAME", ""),
        socket.gethostname(),
        *os.environ.get("SCAN_PROXY_LOCAL_SERVER_ALIASES", "").replace(",", ";").split(";"),
    )
    if name.strip()
}
LOCAL_SCAN_SHARE = os.environ.get("SCAN_PROXY_LOCAL_SHARE", ROOT.name).strip().lower()
_TARGET_DIR_CACHE = {}

@dataclass(frozen=True, slots=True)
class Rule:
    row: int
    identifier: str
    source_excel: str
    source: Path
    target: Path
    mode: str
    action: str

@dataclass(slots=True)
class RuleGroup:
    source: Path
    source_excel: str
    identifiers: dict = field(default_factory=dict)
    subfolders: list = field(default_factory=list)
    error_until: float = 0.0

@dataclass(frozen=True, slots=True)
class FileCandidate:
    path: Path
    stat: object


def resolve_path(value):
    path = Path(str(value or ".").strip())
    if path.is_absolute():
        return path
    return ROOT / path


def localize_scan_source(path):
    """Access a local SMB share through the local disk when possible."""
    if os.name != "nt":
        return path
    text = str(path).strip().replace("/", "\\")
    match = re.match(r"^\\\\([^\\]+)\\([^\\]+)(?:\\(.*))?$", text)
    if not match:
        return path
    server, share, rest = match.groups()
    server = server.split(".", 1)[0].lower()
    if server not in LOCAL_SCAN_SERVER_ALIASES or share.lower() != LOCAL_SCAN_SHARE:
        return path
    if not rest:
        return ROOT
    return ROOT.joinpath(*[part for part in rest.split("\\") if part])


def normalize_path_key(path):
    return os.path.normcase(os.path.normpath(str(path)))


def normalize_relative_path(value):
    return str(value or "").strip().replace("/", "\\").strip("\\").lower()


def ensure_destination_directory(path):
    """Cache directory creation to avoid unnecessary remote filesystem calls."""
    now = time.monotonic()
    key = normalize_path_key(path)
    if _TARGET_DIR_CACHE.get(key, 0.0) > now:
        return
    path.mkdir(parents=True, exist_ok=True)
    _TARGET_DIR_CACHE[key] = now + TARGET_DIR_CACHE_TTL_SECONDS
    if len(_TARGET_DIR_CACHE) > 2048:
        _TARGET_DIR_CACHE.clear()

def is_enabled(value):
    return str(value).strip().lower() in {
        "true",
        "1",
        "yes",
        "on",
        "x",
    }

def normalize_ip(value):
    text = str(value or "").strip().strip("[]")
    try:
        addr = ipaddress.ip_address(text)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if str(addr) in {
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "::",
        }:
            return ""

        if any(
            addr.version == network.version and addr in network
            for network in SMB_IGNORED_NETS
        ):
            return ""
        return str(addr)
    except ValueError:
        return ""

def pending_retry_delay(attempts):
    """Return the backoff delay for a pending SMB attribution."""
    index = min(max(int(attempts), 0), len(PENDING_RETRY_DELAYS_SECONDS) - 1)
    return PENDING_RETRY_DELAYS_SECONDS[index]


def reverse_lookup(ip):
    """Look up a scanner hostname when explicitly enabled."""
    client = normalize_ip(ip)
    if not client:
        return "", "None"

    executable = "nslookup.exe" if os.name == "nt" else shutil.which("nslookup")
    if executable:
        try:
            result = subprocess.run(
                [executable, client],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=HOSTNAME_LOOKUP_TIMEOUT_SECONDS,
                creationflags=(
                    getattr(subprocess, "CREATE_NO_WINDOW", 0)
                    | getattr(subprocess, "BELOW_NORMAL_PRIORITY_CLASS", 0)
                ),
            )
            text = "\n".join((result.stdout or "", result.stderr or ""))
            matches = re.findall(
                r"(?im)^\s*name\s*[:=]\s*(\S.*?)\s*$",
                text,
            )
            for value in matches:
                hostname = value.strip().rstrip(".")
                if hostname and not normalize_ip(hostname) and hostname != client:
                    return hostname, "nslookup"
        except (OSError, subprocess.SubprocessError):
            pass
        return "", "None"

    try:
        hostname = socket.gethostbyaddr(client)[0].strip().rstrip(".")
        if hostname and hostname != client:
            return hostname, "socket"
    except (OSError, socket.herror, socket.gaierror):
        pass
    return "", "None"


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def parse_utc_iso(value):
    try:
        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        ).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def format_megabytes(size):
    value = Decimal(int(size or 0)) / Decimal(1048576)
    rounded = value.quantize(
        Decimal("0.01"),
        rounding=ROUND_HALF_UP,
    )
    return f"{rounded:.2f}"


def get_page_count(file, log):
    if file.suffix.lower() != ".pdf":
        return 1
    try:
        if PdfReader:
            reader = PdfReader(
                str(file),
                strict=False,
            )
            return max(1, len(reader.pages))
        content = file.read_bytes()
        return max(
            1,
            len(re.findall(rb"/Type\s*/Page\b", content)),
        )
    except Exception:
        log.warning("ANALYTICS WARNING | PDF page count could not be read")
        return 1


class DailyFileLogHandler(logging.Handler):
    def __init__(self, folder):
        super().__init__()
        self.folder = folder
        self.day = None
        self.stream = None
        folder.mkdir(
            parents=True,
            exist_ok=True,
        )

    def emit(self, record):
        try:
            day = datetime.now().strftime("%Y-%m-%d")
            if day != self.day:
                if self.stream:
                    self.stream.close()
                log_file = self.folder / f"{day}-scan-proxy.log"
                self.stream = log_file.open(
                    "a",
                    encoding="utf-8",
                )
                self.day = day
            self.stream.write(
                self.format(record) + "\n"
            )
            self.stream.flush()
        except Exception:
            self.handleError(record)
    def close(self):
        if self.stream:
            self.stream.close()
        super().close()

def get_logger(name, folder):
    log = logging.getLogger(name)
    log.setLevel(logging.INFO)
    log.propagate = False
    if not log.handlers:
        handler = DailyFileLogHandler(folder)
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s | %(levelname)s | %(message)s"
            )
        )
        log.addHandler(handler)
    return log


def get_logs():
    scanproxy_log = get_logger(
        "scan-proxy",
        SCANPROXY_LOG_DIR,
    )
    analytics_log = get_logger(
        "analytics",
        ANALYTICS_LOG_DIR,
    )
    return scanproxy_log, analytics_log


def load_rules():
    workbook = load_workbook(
        CONFIG_PATH,
        read_only=True,
        data_only=True,
    )
    try:
        worksheets = sorted(
            workbook.worksheets,
            key=lambda sheet: sheet.title.strip().lower() != "rules",
        )
        for worksheet in worksheets:
            header = next(
                worksheet.iter_rows(
                    min_row=1,
                    max_row=1,
                    values_only=True,
                ),
                (),
            )
            columns = {
                str(value).strip().lower(): index
                for index, value in enumerate(header)
                if value is not None
            }
            required = {
                "identifier",
                "source",
                "destination",
                "mode",
            }
            has_active_column = (
                "enabled" in columns
                or "status" in columns
            )
            if required <= columns.keys() and has_active_column:
                break
        else:
            raise ValueError(
                "No worksheet with Identifier, Source, Destination, Mode, "
                "and Enabled/Status columns was found"
            )
        columns["enabled"] = columns.get(
            "enabled",
            columns.get("status"),
        )
        def value_from_row(row, name, default=None):
            index = columns.get(name)
            if index is not None and index < len(row):
                return row[index]
            return default
        rules = []
        for row_number, row in enumerate(
            worksheet.iter_rows(
                min_row=2,
                values_only=True,
            ),
            2,
        ):
            if not any(value not in (None, "") for value in row):
                continue
            rules.append(
                (
                    row_number,
                    value_from_row(row, "identifier"),
                    value_from_row(row, "source"),
                    value_from_row(row, "destination"),
                    value_from_row(row, "mode"),
                    value_from_row(row, "enabled"),
                    value_from_row(row, "action", "move") or "move",
                )
            )
        return worksheet.title, rules
    finally:
        workbook.close()


def compile_rules(raw_rules, log):
    """Validate and compile routing rules on workbook reload."""
    groups = {}
    active_count = 0
    mapped_sources = set()
    seen_rules = {}

    for row, identifier, source, target, mode, enabled, action in raw_rules:
        if not is_enabled(enabled):
            continue
        if not source or not target:
            log.error("RULE ERROR | Row=%s | Source/Destination missing", row)
            continue

        source_excel = str(source).strip()
        src_excel_path = resolve_path(source_excel)
        src = localize_scan_source(src_excel_path)
        dst = resolve_path(target)
        mode = str(mode or "").strip().lower()
        action = str(action or "move").strip().lower()
        identifier_text = str(identifier or "").strip()

        if action not in {"move", "copy"}:
            log.error("RULE ERROR | Row=%s | Invalid action=%s", row, action)
            continue
        if mode not in {"identifier", "subfolder", "subfolders"}:
            log.error("RULE ERROR | Row=%s | Invalid mode=%s", row, mode)
            continue
        if mode == "identifier" and not identifier_text:
            log.error("RULE ERROR | Row=%s | Identifier missing", row)
            continue

        if mode in {"subfolder", "subfolders"}:
            dst_io = localize_scan_source(dst)
            try:
                if dst_io == src or dst_io.is_relative_to(src):
                    log.error("RULE ERROR | Destination is inside source | Row=%s", row)
                    continue
            except (OSError, ValueError):
                pass

        signature = (
            identifier_text.lower(), normalize_path_key(src), normalize_path_key(dst),
            mode, action,
        )
        if signature in seen_rules:
            log.warning(
                "DUPLICATE RULE SKIPPED | Row=%s | DuplicateOf=%s",
                row, seen_rules[signature],
            )
            continue
        seen_rules[signature] = row

        rule = Rule(
            row=row,
            identifier=identifier_text,
            source_excel=source_excel,
            source=src,
            target=dst,
            mode=mode,
            action=action,
        )
        key = normalize_path_key(src)
        group = groups.setdefault(key, RuleGroup(src, source_excel))
        if mode == "identifier":
            group.identifiers.setdefault(identifier_text.lower(), []).append(rule)
        else:
            group.subfolders.append(rule)
        active_count += 1

        if normalize_path_key(src) != normalize_path_key(src_excel_path) and key not in mapped_sources:
            mapped_sources.add(key)
            log.info("LOCAL SOURCE OPTIMIZED | Rule=%s", row)

    return list(groups.values()), active_count


def scan_source(root, recursive):
    """Scan a source tree once and retain file metadata."""
    files = []
    stack = [root]
    while stack:
        folder = stack.pop()
        with os.scandir(folder) as entries:
            for entry in entries:
                if entry.name.lower().endswith(".part"):
                    continue
                try:
                    if entry.is_file(follow_symlinks=False):
                        files.append(FileCandidate(Path(entry.path), entry.stat(follow_symlinks=False)))
                    elif recursive and entry.is_dir(follow_symlinks=False):
                        stack.append(Path(entry.path))
                except OSError:
                    continue
    return files


class SmbResolver:
    """Resolve SMB clients using one live snapshot and batched historical events."""

    def __init__(self, log):
        self.log = log
        self.exact_clients = {}
        self.snapshot_paths = {}
        self.snapshot_relative = {}
        self.snapshot_until = 0.0
        self.snapshot_wall_time = 0.0

    @staticmethod
    def empty(reason="No unambiguous SMB client IP could be resolved"):
        return {
            "client": "",
            "resolved": False,
            "source": "None",
            "reason": reason,
            "record_id": 0,
            "is_open": False,
            "confidence": "None",
        }

    def refresh_open_snapshot(self, force=False):
        """Fetch a shared SMB open-file snapshot for an entire scan cycle."""
        started = time.perf_counter()
        now = time.monotonic()
        if not force and self.snapshot_until > now:
            return 0.0
        self.snapshot_paths = {}
        self.snapshot_relative = {}
        self.snapshot_until = now + SMB_SNAPSHOT_TTL_SECONDS
        self.snapshot_wall_time = time.time()
        if os.name != "nt" or not SMB_HELPER_PATH.is_file() or not SMB_USER:
            return 0.0

        command = [
            "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-File", str(SMB_HELPER_PATH),
            "-Mode", "OpenSnapshot", "-UserName", SMB_USER,
            "-IgnoredNetworks", ";".join(SMB_IGNORED_NETWORKS),
        ]
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=SMB_SNAPSHOT_TIMEOUT,
                creationflags=(
                    getattr(subprocess, "CREATE_NO_WINDOW", 0)
                    | getattr(subprocess, "BELOW_NORMAL_PRIORITY_CLASS", 0)
                ),
            )
            if proc.returncode:
                raise RuntimeError((proc.stderr or f"ExitCode={proc.returncode}").strip())
            lines = [line.lstrip("\ufeff").strip() for line in proc.stdout.splitlines() if line.strip()]
            data = json.loads(lines[-1]) if lines else []
            if isinstance(data, dict):
                data = [data]
            for item in data:
                client = normalize_ip(item.get("Client"))
                if not client:
                    continue
                file_path = item.get("Path")
                relative = normalize_relative_path(item.get("RelativePath"))
                if file_path:
                    self.snapshot_paths.setdefault(normalize_path_key(file_path), set()).add(client)
                if relative:
                    self.snapshot_relative.setdefault(relative, set()).add(client)
        except Exception as exc:
            self.log.warning("SMB SNAPSHOT ERROR | ErrorType=%s", type(exc).__name__)
        return (time.perf_counter() - started) * 1000.0

    def resolve(self, file, relative="", mtime="", reference=""):
        """Match open files in memory without launching one process per file."""
        path_key = normalize_path_key(file)
        rel_key = normalize_relative_path(relative)
        now = time.monotonic()

        clients = self.snapshot_paths.get(path_key)
        if not clients and rel_key:
            clients = self.snapshot_relative.get(rel_key)
        if clients:
            if len(clients) == 1:
                client = next(iter(clients))
                result = {
                    "client": client,
                    "resolved": True,
                    "source": "Get-SmbOpenFile-Snapshot",
                    "reason": "Exact open SMB file from shared snapshot",
                    "record_id": 0,
                    "is_open": True,
                    "confidence": "ExactOpenFile",
                }
                cached = dict(result)
                cached["is_open"] = False
                cached["source"] = "Get-SmbOpenFile-Cache"
                cached["reason"] = "Previously matched open SMB file"
                cached["confidence"] = "ExactOpenFileCached"
                self.exact_clients[(path_key, mtime)] = (cached, now + SMB_EXACT_HINT_SECONDS)
                return result
            result = self.empty("Ambiguous open SMB file in snapshot")
            result["is_open"] = True
            result["confidence"] = "Ambiguous"
            return result

        hint = self.exact_clients.get((path_key, mtime))
        if hint:
            if hint[1] > now:
                return dict(hint[0])
            self.exact_clients.pop((path_key, mtime), None)
        return self.empty()

    def resolve_batch(self, rows):
        """Resolve pending files using a single PowerShell batch invocation."""
        rows = list(rows)
        if not rows:
            return {}
        empty = self.empty()
        if os.name != "nt" or not SMB_HELPER_PATH.is_file() or not SMB_USER:
            return {str(row["id"]): dict(empty) for row in rows}

        payload = [
            {
                "Id": str(row["id"]),
                "FilePath": str(row["original_path"]),
                "RelativePath": str(row["relative_path"] or ""),
                "ReferenceTimeUtc": str(row["file_mtime_utc"] or row["completed_at_utc"] or utc_now_iso()),
            }
            for row in rows
        ]
        command = [
            "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-File", str(SMB_HELPER_PATH),
            "-Mode", "ResolveBatch", "-UserName", SMB_USER,
            "-LookbackMinutes", str(SMB_EVENT_LOOKBACK_MINUTES),
            "-IgnoredNetworks", ";".join(SMB_IGNORED_NETWORKS),
        ]
        try:
            proc = subprocess.run(
                command,
                input=json.dumps(payload, ensure_ascii=False),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=SMB_BATCH_TIMEOUT,
                creationflags=(
                    getattr(subprocess, "CREATE_NO_WINDOW", 0)
                    | getattr(subprocess, "BELOW_NORMAL_PRIORITY_CLASS", 0)
                ),
            )
            if proc.returncode:
                raise RuntimeError((proc.stderr or f"ExitCode={proc.returncode}").strip())
            output = [line.lstrip("\ufeff").strip() for line in proc.stdout.splitlines() if line.strip()]
            data = json.loads(output[-1]) if output else []
            if isinstance(data, dict):
                data = [data]
            results = {}
            for item in data:
                row_id = str(item.get("Id") or "").strip()
                if not row_id:
                    continue
                client = normalize_ip(item.get("Client"))
                results[row_id] = {
                    "client": client,
                    "resolved": bool(client),
                    "source": str(item.get("Source") or "None"),
                    "reason": str(item.get("Reason") or empty["reason"]),
                    "record_id": int(item.get("RecordId") or 0),
                    "is_open": bool(item.get("Open")),
                    "confidence": str(item.get("Confidence") or "None"),
                }
            for row in rows:
                results.setdefault(str(row["id"]), dict(empty))
            return results
        except Exception as exc:
            self.log.warning("SMB BATCH ERROR | Count=%s | ErrorType=%s", len(rows), type(exc).__name__)
            failed = self.empty("SMB batch lookup failed")
            return {str(row["id"]): dict(failed) for row in rows}

    def forget(self, file):
        path_key = normalize_path_key(file)
        for cache_key in list(self.exact_clients):
            if cache_key[0] == path_key:
                self.exact_clients.pop(cache_key, None)


class Analytics:


    def __init__(self, log):
        self.log = log
        self.last_move_retry = 0.0
        self._pending_cache = set()
        self._pending_cache_until = 0.0
        self.db = None
        self._reports_dirty = True
        self._dirty_dates = set()
        self._last_maintenance_day = None

    def connect(self):
        """Reuse one SQLite connection for the serial routing process."""
        if self.db is None:
            self.db = sqlite3.connect(DB, timeout=10)
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA busy_timeout=10000")
            self.db.execute("PRAGMA synchronous=NORMAL")
            self.db.execute("PRAGMA temp_store=MEMORY")
        return self.db

    def close(self):
        if self.db is not None:
            try:
                self.db.close()
            finally:
                self.db = None

    def mark_dirty(self, completed_date=None):
        self._reports_dirty = True
        if completed_date:
            self._dirty_dates.add(str(completed_date))

    def init(self):
        for folder in (
            ANALYTICS,
            STATE,
            DAILY,
            WEEKLY,
            MONTHLY,
            YEARLY,
        ):
            folder.mkdir(
                parents=True,
                exist_ok=True,
            )
        with self.connect() as db:
            db.execute(
                "PRAGMA journal_mode=WAL"
            )
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    completed_at_utc TEXT NOT NULL,
                    completed_at_local TEXT NOT NULL,
                    completed_date TEXT NOT NULL,
                    original_path TEXT NOT NULL,
                    relative_path TEXT NOT NULL,
                    completed_path TEXT NOT NULL,
                    routing_label TEXT NOT NULL,
                    file_mtime_utc TEXT NOT NULL,
                    pages INTEGER NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    scanner_ip TEXT,
                    resolution_source TEXT NOT NULL,
                    resolution_reason TEXT NOT NULL,
                    resolution_confidence TEXT NOT NULL,
                    resolution_record_id INTEGER NOT NULL DEFAULT 0,
                    resolution_state TEXT NOT NULL,
                    resolve_attempts INTEGER NOT NULL DEFAULT 0,
                    next_resolve_epoch REAL NOT NULL DEFAULT 0,
                    resolve_deadline_utc TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    updated_at_utc TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_scans_pending
                    ON scans (
                        resolution_state,
                        next_resolve_epoch
                    );

                CREATE INDEX IF NOT EXISTS idx_scans_report
                    ON scans (
                        completed_date,
                        scanner_ip,
                        resolution_state
                    );

                CREATE INDEX IF NOT EXISTS idx_scans_resolved_report
                    ON scans (
                        resolution_state,
                        completed_date,
                        scanner_ip
                    );

                CREATE TABLE IF NOT EXISTS dns_cache (
                    scanner_ip TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT 'None',
                    last_lookup_utc TEXT NOT NULL,
                    next_lookup_epoch REAL NOT NULL DEFAULT 0,
                    failures INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_dns_cache_due
                    ON dns_cache (next_lookup_epoch);

                CREATE TABLE IF NOT EXISTS pending_moves (
                    id TEXT PRIMARY KEY,
                    source_norm TEXT NOT NULL,
                    source_path TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    relative_path TEXT NOT NULL,
                    routing_label TEXT NOT NULL,
                    source_size INTEGER NOT NULL,
                    source_mtime_ns INTEGER NOT NULL,
                    file_mtime_utc TEXT NOT NULL,
                    committed_at_utc TEXT NOT NULL,
                    resolution_json TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at_utc TEXT NOT NULL,
                    last_attempt_utc TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pending_moves_source
                    ON pending_moves (
                        source_norm,
                        state
                    );
                """
            )
        self.refresh_reports(force=True)


    def pending_move(self, source):
        now = time.monotonic()
        if now >= self._pending_cache_until:
            with self.connect() as db:
                rows = db.execute(
                    """
                    SELECT source_norm
                    FROM pending_moves
                    WHERE state IN ('pending', 'blocked')
                    """
                ).fetchall()
            self._pending_cache = {
                row["source_norm"]
                for row in rows
            }
            self._pending_cache_until = (
                now + PENDING_CACHE_SECONDS
            )
        key = os.path.normcase(
            os.path.normpath(
                str(source)
            )
        )
        return key in self._pending_cache
    def add_move(
        self,
        source,
        target,
        relative,
        label,
        stat,
        mtime,
        resolution,
        reason,
    ):
        

        now = utc_now_iso()
        move_id = uuid.uuid4().hex
        source_norm = os.path.normcase(
            os.path.normpath(
                str(source)
            )
        )
        values = (
            move_id,
            source_norm,
            str(source),
            str(target),
            str(relative),
            label,
            int(stat.st_size),
            int(stat.st_mtime_ns),
            mtime,
            now,
            json.dumps(resolution),
            type(reason).__name__,
            "pending",
            now,
            now,
        )
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO pending_moves
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
        self._pending_cache.add(source_norm)
    def add_scan(
        self,
        source,
        relative,
        target,
        label,
        mtime,
        resolution,
        scan_id=None,
        completed=None,
        page_count=None,
        size_bytes=None,
    ):
        

        done = (
            parse_utc_iso(completed)
            or datetime.now(timezone.utc)
        )
        local = done.astimezone()
        now = utc_now_iso()

        client = normalize_ip(
            (resolution or {}).get("client")
        )
        state = ("resolved" if client else "pending" if SMB_USER else "unresolved")
        deadline = (
            datetime.now(timezone.utc)
            + timedelta(hours=PENDING_MAX_HOURS)
        ).isoformat().replace(
            "+00:00",
            "Z",
        )
        values = (
            scan_id or uuid.uuid4().hex,
            done.isoformat().replace("+00:00", "Z"),
            local.isoformat(timespec="seconds"),
            local.date().isoformat(),
            str(source) if state == "pending" else "",
            str(relative) if state == "pending" else "",
            str(target) if state == "pending" else "",
            str(label or ""),
            mtime,
            int(page_count) if page_count is not None else get_page_count(target, self.log),
            int(size_bytes) if size_bytes is not None else target.stat().st_size,
            client or None,
            str(
                (resolution or {}).get("source")
                or "None"
            ),
            str(
                (resolution or {}).get("reason")
                or ""
            ),
            str(
                (resolution or {}).get("confidence")
                or "None"
            ),
            int(
                (resolution or {}).get("record_id")
                or 0
            ),
            state,
            0,
            time.time() + pending_retry_delay(0),
            deadline,
            now,
            now,
        )
        with self.connect() as db:
            db.execute(
                """
                INSERT OR IGNORE INTO scans
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                values,
            )
        self.mark_dirty(local.date().isoformat())
        self.log.info(
            "ANALYTICS | State=%s | Pages=%s",
            state,
            page_count if page_count is not None else "unknown",
        )


    def retry_moves(self):
        now = time.monotonic()
        if now - self.last_move_retry < MOVE_RETRY_SECONDS:
            return
        self.last_move_retry = now
        

        self._pending_cache_until = 0.0
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT *
                FROM pending_moves
                WHERE state = 'pending'
                ORDER BY created_at_utc
                LIMIT 10
                """
            ).fetchall()
        for row in rows:
            src = Path(row["source_path"])
            dst = Path(row["target_path"])
            if not dst.exists():
                with self.connect() as db:
                    db.execute(
                        "DELETE FROM pending_moves WHERE id = ?",
                        (row["id"],),
                    )
                continue
            try:
                stat = src.stat()
            except FileNotFoundError:
                stat = None
            except OSError:
                continue
            source_changed = (
                stat
                and (
                    stat.st_size != row["source_size"]
                    or stat.st_mtime_ns != row["source_mtime_ns"]
                )
            )
            if source_changed:
                try:
                    dst.unlink()
                    state = None
                except OSError:
                    state = "blocked"
                with self.connect() as db:
                    if state:
                        db.execute(
                            """
                            UPDATE pending_moves
                            SET state = 'blocked',
                                last_attempt_utc = ?
                            WHERE id = ?
                            """,
                            (
                                utc_now_iso(),
                                row["id"],
                            ),
                        )
                    else:
                        db.execute(
                            "DELETE FROM pending_moves WHERE id = ?",
                            (row["id"],),
                        )
                continue
            if stat:
                try:
                    src.unlink()
                except OSError:
                    continue
            try:
                resolution = json.loads(
                    row["resolution_json"] or "{}"
                )
            except json.JSONDecodeError:
                resolution = {}
            self.add_scan(
                src,
                row["relative_path"],
                dst,
                row["routing_label"],
                row["file_mtime_utc"],
                resolution,
                row["id"],
                row["committed_at_utc"],
            )
            with self.connect() as db:
                db.execute(
                    "DELETE FROM pending_moves WHERE id = ?",
                    (row["id"],),
                )


    def resolve_pending(self, smb):
        """Process due pending SMB clients in a resource-efficient batch."""
        now = time.time()
        now_utc = datetime.now(timezone.utc)
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT * FROM scans
                WHERE resolution_state = 'pending' AND next_resolve_epoch <= ?
                ORDER BY next_resolve_epoch, completed_at_utc
                LIMIT ?
                """,
                (now, PENDING_BATCH_SIZE),
            ).fetchall()
        if not rows:
            return 0

        expired, active_rows = [], []
        for row in rows:
            deadline = parse_utc_iso(row["resolve_deadline_utc"])
            (expired if deadline and deadline <= now_utc else active_rows).append(row)

        changed = 0
        if expired:
            stamp = utc_now_iso()
            with self.connect() as db:
                db.executemany(
                    """UPDATE scans SET resolution_state='unresolved', original_path='',
                        relative_path='', completed_path='', updated_at_utc=? WHERE id=?""",
                    [(stamp, row["id"]) for row in expired],
                )
            for row in expired:
                self.mark_dirty(row["completed_date"])
                changed += 1
                self.log.warning(
                    "SMB ATTRIBUTION EXPIRED | Attempts=%s",
                    row["resolve_attempts"],
                )

        if not active_rows:
            return changed

        results = smb.resolve_batch(active_rows)
        resolved_logs = []
        stamp = utc_now_iso()
        retry_now = time.time()
        with self.connect() as db:
            for row in active_rows:
                result = results.get(str(row["id"]), {})
                client = normalize_ip(result.get("client"))
                attempts = int(row["resolve_attempts"] or 0) + 1
                reason = str(result.get("reason") or "No unambiguous SMB client IP could be resolved")[:1000]
                if client:
                    db.execute(
                        """
                        UPDATE scans SET scanner_ip=?, resolution_source=?, resolution_reason=?,
                            resolution_confidence=?, resolution_record_id=?, resolution_state='resolved',
                            original_path='', relative_path='', completed_path='',
                            resolve_attempts=?, updated_at_utc=? WHERE id=?
                        """,
                        (client, str(result.get("source") or "None"), reason,
                         str(result.get("confidence") or "None"), int(result.get("record_id") or 0),
                         attempts, stamp, row["id"]),
                    )
                    self.mark_dirty(row["completed_date"])
                    changed += 1
                    resolved_logs.append(str(result.get("source") or "None"))
                else:
                    db.execute(
                        """
                        UPDATE scans SET resolve_attempts=?, next_resolve_epoch=?,
                            resolution_reason=?, updated_at_utc=? WHERE id=?
                        """,
                        (attempts, retry_now + pending_retry_delay(attempts), reason, stamp, row["id"]),
                    )
        for source in resolved_logs:
            self.log.info("SMB ATTRIBUTION RESOLVED | Source=%s", source)
        return changed


    def refresh_hostnames(self, ips):
        if not ENABLE_HOSTNAME_LOOKUP:
            return set()
        candidates = sorted({normalize_ip(ip) for ip in ips if normalize_ip(ip)})
        changed_ips = set()
        if not candidates:
            return changed_ips

        with self.connect() as db:
            cached = {
                row["scanner_ip"]: row
                for row in db.execute(
                    "SELECT * FROM dns_cache"
                ).fetchall()
            }

        now = time.time()
        due = [
            ip for ip in candidates
            if ip not in cached or float(cached[ip]["next_lookup_epoch"] or 0) <= now
        ][:HOSTNAME_BATCH_SIZE]
        if not due:
            return changed_ips

        results = [reverse_lookup(ip) for ip in due]

        with self.connect() as db:
            for ip, (hostname, source) in zip(due, results):
                previous = cached.get(ip)
                previous_name = str(previous["hostname"] or "") if previous else ""
                failures = 0 if hostname else int(previous["failures"] or 0) + 1 if previous else 1
                effective_name = hostname or previous_name
                ttl = (
                    HOSTNAME_SUCCESS_TTL_SECONDS
                    if hostname
                    else HOSTNAME_FAILURE_TTL_SECONDS
                )
                db.execute(
                    """
                    INSERT INTO dns_cache (
                        scanner_ip, hostname, source, last_lookup_utc,
                        next_lookup_epoch, failures
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(scanner_ip) DO UPDATE SET
                        hostname = excluded.hostname,
                        source = excluded.source,
                        last_lookup_utc = excluded.last_lookup_utc,
                        next_lookup_epoch = excluded.next_lookup_epoch,
                        failures = excluded.failures
                    """,
                    (
                        ip,
                        effective_name,
                        source if hostname else (previous["source"] if previous else "None"),
                        utc_now_iso(),
                        now + ttl,
                        failures,
                    ),
                )
                if hostname and hostname != previous_name:
                    changed_ips.add(ip)
                    self.log.info("HOSTNAME RESOLVED | Source=%s", source)
        return changed_ips

    def hostnames(self):
        if not ENABLE_HOSTNAME_LOOKUP:
            return {}
        with self.connect() as db:
            rows = db.execute(
                "SELECT scanner_ip, hostname FROM dns_cache WHERE hostname <> ''"
            ).fetchall()
        return {row["scanner_ip"]: row["hostname"] for row in rows}

    def quality_data(self):
        """Return daily totals for resolved and unresolved attribution."""
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT
                    completed_date,
                    COUNT(*) AS total,
                    COALESCE(SUM(pages), 0) AS pages,
                    COALESCE(SUM(size_bytes), 0) AS bytes,
                    MIN(completed_at_local) AS first_scan,
                    MAX(completed_at_local) AS last_scan,
                    SUM(CASE WHEN resolution_state = 'resolved' THEN 1 ELSE 0 END) AS resolved,
                    SUM(CASE WHEN resolution_state = 'pending' THEN 1 ELSE 0 END) AS pending,
                    SUM(CASE WHEN resolution_state = 'unresolved' THEN 1 ELSE 0 END) AS unresolved
                FROM scans
                GROUP BY completed_date
                ORDER BY completed_date
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def data(self):
        if not SMB_USER:
            return []
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT
                    completed_date,
                    scanner_ip,
                    COUNT(*) AS files,
                    COALESCE(SUM(pages), 0) AS pages,
                    COALESCE(SUM(size_bytes), 0) AS bytes,
                    MIN(completed_at_local) AS first_scan,
                    MAX(completed_at_local) AS last_scan
                FROM scans
                WHERE resolution_state = 'resolved'
                  AND scanner_ip IS NOT NULL
                GROUP BY
                    completed_date,
                    scanner_ip
                ORDER BY
                    completed_date,
                    scanner_ip
                """
            ).fetchall()
        return [
            row
            for row in rows
            if normalize_ip(row["scanner_ip"])
        ]
    @staticmethod
    def write_csv(path, fields, rows):
        """Atomically update a CSV only when its content changes."""
        path.parent.mkdir(parents=True, exist_ok=True)
        buffer = io.StringIO(newline="")
        writer = csv.DictWriter(
            buffer,
            fieldnames=fields,
            delimiter=";",
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)
        payload = buffer.getvalue().encode("utf-8-sig")

        try:
            if path.read_bytes() == payload:
                return False
        except FileNotFoundError:
            pass

        tmp = path.with_suffix(path.suffix + ".tmp")
        with tmp.open("wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(tmp, path)
        return True

    @staticmethod
    def write_text(path, text):
        """Atomically update a text file only when its content changes."""
        payload = text.encode("utf-8")
        try:
            if path.read_bytes() == payload:
                return False
        except FileNotFoundError:
            pass
        tmp = path.with_suffix(path.suffix + ".tmp")
        with tmp.open("wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(tmp, path)
        return True
    def build_report_html(
        self,
        embedded,
        latest,
        interval_label,
    ):
        """Generate a standalone HTML report with embedded data."""
        return f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Scan Proxy Analytics</title>
    <style>
        :root {{ color-scheme: light; }}
        body {{
            font: 14px Segoe UI, Arial, sans-serif;
            background: #f3f5f8;
            color: #1f2937;
            margin: 0;
        }}
        main {{
            max-width: 1450px;
            margin: auto;
            padding: 24px;
        }}
        header {{
            display: flex;
            justify-content: space-between;
            gap: 16px;
            flex-wrap: wrap;
            align-items: end;
            margin-bottom: 18px;
        }}
        h1 {{ margin: 0 0 4px; }}
        .ctrl, .cards {{
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            align-items: end;
        }}
        .ctrl {{
            background: white;
            padding: 14px;
            border-radius: 12px;
            box-shadow: 0 2px 10px #0001;
            margin-bottom: 14px;
        }}
        .card, table {{
            background: white;
            box-shadow: 0 2px 10px #0001;
        }}
        .card {{
            padding: 14px;
            border-radius: 12px;
            min-width: 145px;
            flex: 1 1 145px;
        }}
        .v {{
            font-size: 23px;
            font-weight: 700;
            margin-top: 3px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 16px;
            border-radius: 12px;
            overflow: hidden;
        }}
        th, td {{
            padding: 11px;
            border-bottom: 1px solid #eee;
            text-align: left;
            white-space: nowrap;
        }}
        th {{ background: #fafafa; }}
        .n {{ text-align: right; }}
        select, input {{
            padding: 8px;
            border: 1px solid #cfd6df;
            border-radius: 7px;
            background: white;
        }}
        small, .muted {{ color: #667085; }}
        .warn {{ color: #9a6700; }}
        .bad {{ color: #b42318; }}
        @media (max-width: 800px) {{
            main {{ padding: 12px; }}
            table {{ display: block; overflow-x: auto; }}
        }}
    </style>
</head>
<body>
    <main>
        <header>
            <div>
                <h1>Scan Proxy Analytics</h1>
                <small>
                    Scanner attribution uses unambiguous SMB client IPs &middot;
                    Hostname lookup is optional &middot;
                    Scan Proxy {escape(VERSION)}
                </small>
            </div>
            <small>Report refresh: {interval_label}</small>
        </header>

        <div class="ctrl">
            <label>
                View<br>
                <select id="periodSelect">
                    <option value="day">Day</option>
                    <option value="week">Week</option>
                    <option value="month">Month</option>
                    <option value="year">Year</option>
                </select>
            </label>
            <label>
                Date<br>
                <input id="dateInput" type="date" value="{latest}">
            </label>
            <label>
                Filter scanner IP / hostname<br>
                <input id="searchInput" type="search" placeholder="e.g. scanner IP or hostname">
            </label>
            <b id="r"></b>
        </div>

        <div class="cards">
            <div class="card">Scanner<div class="v" id="c">0</div></div>
            <div class="card">Total files<div class="v" id="f">0</div></div>
            <div class="card">Pages<div class="v" id="p">0</div></div>
            <div class="card">Data<div class="v" id="b">0 MB</div></div>
            <div class="card">IP pending<div class="v warn" id="pn">0</div></div>
            <div class="card">IP unresolved<div class="v bad" id="u">0</div></div>
            <div class="card">First scan<div class="v" id="e">-</div></div>
            <div class="card">Last scan<div class="v" id="l">-</div></div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Scanner IP</th>
                    <th>Hostname</th>
                    <th class="n">Files</th>
                    <th class="n">Pages</th>
                    <th class="n">Avg. pages/file</th>
                    <th class="n">Data MB</th>
                    <th>Last scan</th>
                </tr>
            </thead>
            <tbody id="scannerTable"></tbody>
        </table>

        <p class="muted">
            The table includes only completed scans with an unambiguous scanner IP.
            Pending and unresolved attributions are reported separately; identities are never guessed.
        </p>
    </main>

    <script>
        const payload = {embedded};
        const resolvedRows = payload.data;
        const qualityRows = payload.quality;
        const periodSelect = document.getElementById('periodSelect');
        const dateInput = document.getElementById('dateInput');
        const searchInput = document.getElementById('searchInput');
        const scannerTable = document.getElementById('scannerTable');
        const escapeHtml = value => String(value).replace(/[&<>"']/g, ch =>
            ({{'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}})[ch]
        );
        const padNumber = n => String(n).padStart(2, '0');
        const formatIsoDate = x => `${{x.getFullYear()}}-${{padNumber(x.getMonth() + 1)}}-${{padNumber(x.getDate())}}`;
        const parseIsoDate = s => {{
            const a = s.split('-').map(Number);
            return new Date(a[0], a[1] - 1, a[2]);
        }};
        const formatDisplayDate = s => {{
            const x = parseIsoDate(s);
            return x.toLocaleDateString('en-US');
        }};
        const formatDateTime = s => s ? new Date(s).toLocaleString(
            'en-US', {{dateStyle: 'short', timeStyle: 'short'}}
        ) : '-';
        const formatNumber = x => Number(x || 0).toLocaleString('en-US');
        const formatMegabytes = x => (Number(x || 0) / 1048576).toLocaleString(
            'en-US', {{minimumFractionDigits: 2, maximumFractionDigits: 2}}
        );

        function getDateRange() {{
            const x = parseIsoDate(dateInput.value);
            let a = new Date(x);
            let z = new Date(x);
            if (periodSelect.value === 'week') {{
                a.setDate(x.getDate() - ((x.getDay() + 6) % 7));
                z = new Date(a);
                z.setDate(a.getDate() + 6);
            }}
            if (periodSelect.value === 'month') {{
                a = new Date(x.getFullYear(), x.getMonth(), 1);
                z = new Date(x.getFullYear(), x.getMonth() + 1, 0);
            }}
            if (periodSelect.value === 'year') {{
                a = new Date(x.getFullYear(), 0, 1);
                z = new Date(x.getFullYear(), 11, 31);
            }}
            return [formatIsoDate(a), formatIsoDate(z)];
        }}

        function renderReport() {{
            const [startDate, endDate] = getDateRange();
            const rows = resolvedRows.filter(record => record.date >= startDate && record.date <= endDate);
            const quality = qualityRows.filter(record => record.date >= startDate && record.date <= endDate);
            const scanners = new Map();
            let files = 0, pages = 0, bytes = 0, pending = 0, unresolved = 0;
            let first = '', last = '';

            for (const record of quality) {{
                files += record.total;
                pages += record.pages;
                bytes += record.bytes;
                pending += record.pending;
                unresolved += record.unresolved;
                first = !first || (record.first && record.first < first) ? record.first : first;
                last = !last || (record.last && record.last > last) ? record.last : last;
            }}

            for (const record of rows) {{
                const scannerStats = scanners.get(record.scanner) || {{
                    hostname: record.hostname || '', files: 0, pages: 0, bytes: 0, lastScan: ''
                }};
                if (!scannerStats.hostname && record.hostname) scannerStats.hostname = record.hostname;
                scannerStats.files += record.files;
                scannerStats.pages += record.pages;
                scannerStats.bytes += record.bytes;
                scannerStats.lastScan = !scannerStats.lastScan || record.last > scannerStats.lastScan ? record.last : scannerStats.lastScan;
                scanners.set(record.scanner, scannerStats);
            }}

            document.getElementById('r').textContent = `${{formatDisplayDate(startDate)}} to ${{formatDisplayDate(endDate)}}`;
            document.getElementById('c').textContent = formatNumber(scanners.size);
            document.getElementById('f').textContent = formatNumber(files);
            document.getElementById('p').textContent = formatNumber(pages);
            document.getElementById('b').textContent = formatMegabytes(bytes) + ' MB';
            document.getElementById('pn').textContent = formatNumber(pending);
            document.getElementById('u').textContent = formatNumber(unresolved);
            document.getElementById('e').textContent = formatDateTime(first);
            document.getElementById('l').textContent = formatDateTime(last);

            const filter = searchInput.value.trim().toLowerCase();
            const visible = [...scanners]
                .filter(([ip, scannerStats]) => !filter || ip.toLowerCase().includes(filter) ||
                    (scannerStats.hostname || '').toLowerCase().includes(filter))
                .sort((a, b) => a[0].localeCompare(b[0], undefined, {{numeric: true}}));

            scannerTable.innerHTML = visible.map(([ip, scannerStats]) => `
                <tr>
                    <td>${{escapeHtml(ip)}}</td>
                    <td>${{scannerStats.hostname ? escapeHtml(scannerStats.hostname) : '<span class="muted">-</span>'}}</td>
                    <td class="n">${{formatNumber(scannerStats.files)}}</td>
                    <td class="n">${{formatNumber(scannerStats.pages)}}</td>
                    <td class="n">${{scannerStats.files ? (scannerStats.pages / scannerStats.files).toLocaleString('en-US', {{maximumFractionDigits: 1}}) : '-'}}</td>
                    <td class="n">${{formatMegabytes(scannerStats.bytes)}}</td>
                    <td>${{formatDateTime(scannerStats.lastScan)}}</td>
                </tr>
            `).join('') || '<tr><td colspan="7">No data</td></tr>';
        }}

        periodSelect.onchange = renderReport;
        dateInput.onchange = renderReport;
        searchInput.oninput = renderReport;
        renderReport();
    </script>
</body>
</html>
"""


    def refresh_reports(self, force=False):
        """Refresh affected report periods while keeping the HTML history complete."""
        today = date.today()
        maintenance_due = self._last_maintenance_day != today
        if not force and not self._reports_dirty and not maintenance_due:
            return 0

        full_refresh = bool(force or maintenance_due)
        dirty_dates = set(self._dirty_dates)
        data = self.data()
        scanner_ips = [row["scanner_ip"] for row in data]
        changed_ips = self.refresh_hostnames(scanner_ips)

        if changed_ips and not full_refresh:
            placeholders = ",".join("?" for _ in changed_ips)
            with self.connect() as db:
                rows = db.execute(
                    f"SELECT DISTINCT completed_date FROM scans WHERE scanner_ip IN ({placeholders})",
                    tuple(sorted(changed_ips)),
                ).fetchall()
            dirty_dates.update(row["completed_date"] for row in rows)

        hostnames = self.hostnames()
        quality = self.quality_data()
        cutoff = today - timedelta(days=DAILY_RETENTION_DAYS)

        def periods_for(day):
            week_start = day - timedelta(days=day.weekday())
            iso_week = week_start.isocalendar()
            month_start = date(day.year, day.month, 1)
            next_month = date(day.year + (day.month == 12), (day.month % 12) + 1, 1)
            return (
                ("week", f"{iso_week.year}-W{iso_week.week:02d}-scan-proxy.csv", week_start, week_start + timedelta(days=6)),
                ("month", f"{day.year:04d}-{day.month:02d}-scan-proxy.csv", month_start, next_month - timedelta(days=1)),
                ("year", f"{day.year:04d}-scan-proxy.csv", date(day.year, 1, 1), date(day.year, 12, 31)),
            )

        affected_periods = {"week": set(), "month": set(), "year": set()}
        if not full_refresh:
            for value in dirty_dates:
                try:
                    day = date.fromisoformat(value)
                except ValueError:
                    continue
                for report_type, name, start, finish in periods_for(day):
                    if finish < today:
                        affected_periods[report_type].add((name, start, finish))

        by_day = {}
        groups = {"week": {}, "month": {}, "year": {}}
        for row in data:
            completed_date = date.fromisoformat(row["completed_date"])
            day_key = completed_date.isoformat()
            if full_refresh or day_key in dirty_dates:
                by_day.setdefault(completed_date, []).append(row)

            item = {
                "scanner": row["scanner_ip"],
                "files": row["files"],
                "pages": row["pages"],
                "bytes": row["bytes"],
                "last": row["last_scan"],
            }
            for report_type, name, start, finish in periods_for(completed_date):
                if finish >= today:
                    continue
                period_key = (name, start, finish)
                if not full_refresh and period_key not in affected_periods[report_type]:
                    continue
                period = groups[report_type].setdefault(period_key, {})
                bucket = period.setdefault(
                    item["scanner"],
                    {"files": 0, "pages": 0, "bytes": 0, "last": ""},
                )
                bucket["files"] += item["files"]
                bucket["pages"] += item["pages"]
                bucket["bytes"] += item["bytes"]
                bucket["last"] = max(bucket["last"], item["last"])

        changed = 0
        for completed_date, same_day in by_day.items():
            if completed_date < cutoff:
                continue
            rows = [
                {
                    "Date": completed_date.isoformat(),
                    "Scanner": row["scanner_ip"],
                    "Hostname": hostnames.get(row["scanner_ip"], ""),
                    "Files": row["files"],
                    "Pages": row["pages"],
                    "Data_MB": format_megabytes(row["bytes"]),
                    "Last_Scan": str(row["last_scan"])[11:16],
                }
                for row in same_day
            ]
            changed += self.write_csv(
                DAILY / f"{completed_date.isoformat()}-scan-proxy.csv",
                ("Date", "Scanner", "Hostname", "Files", "Pages", "Data_MB", "Last_Scan"),
                rows,
            )

        for report_type, folder in (("week", WEEKLY), ("month", MONTHLY), ("year", YEARLY)):
            for (name, start, finish), scanners in groups[report_type].items():
                rows = [
                    {
                        "From": start.isoformat(),
                        "To": finish.isoformat(),
                        "Scanner": scanner,
                        "Hostname": hostnames.get(scanner, ""),
                        "Files": values["files"],
                        "Pages": values["pages"],
                        "Data_MB": format_megabytes(values["bytes"]),
                        "Last_Scan": str(values["last"])[0:16].replace("T", " "),
                    }
                    for scanner, values in sorted(scanners.items())
                ]
                changed += self.write_csv(
                    folder / name,
                    ("From", "To", "Scanner", "Hostname", "Files", "Pages", "Data_MB", "Last_Scan"),
                    rows,
                )

        if full_refresh:
            for report_file in DAILY.glob("*-scan-proxy.csv"):
                try:
                    report_date = date.fromisoformat(report_file.name[:10])
                    if report_date < cutoff:
                        report_file.unlink()
                        changed += 1
                        self.log.info("CLEANUP | Old daily report removed")
                except ValueError:
                    pass

            week_start = today - timedelta(days=today.weekday())
            iso_week = week_start.isocalendar()
            incomplete = (
                WEEKLY / f"{iso_week.year}-W{iso_week.week:02d}-scan-proxy.csv",
                MONTHLY / f"{today.year:04d}-{today.month:02d}-scan-proxy.csv",
                YEARLY / f"{today.year:04d}-scan-proxy.csv",
            )
            for report_file in incomplete:
                if report_file.exists():
                    report_file.unlink()
                    changed += 1
                    self.log.info("CLEANUP | Incomplete period report removed")

        embedded_data = [
            {
                "date": row["completed_date"],
                "scanner": row["scanner_ip"],
                "hostname": hostnames.get(row["scanner_ip"], ""),
                "files": row["files"],
                "pages": row["pages"],
                "bytes": row["bytes"],
                "first": row["first_scan"],
                "last": row["last_scan"],
            }
            for row in data
        ]
        embedded_quality = [
            {
                "date": row["completed_date"],
                "total": int(row["total"] or 0),
                "pages": int(row["pages"] or 0),
                "bytes": int(row["bytes"] or 0),
                "first": row["first_scan"] or "",
                "last": row["last_scan"] or "",
                "resolved": int(row["resolved"] or 0),
                "pending": int(row["pending"] or 0),
                "unresolved": int(row["unresolved"] or 0),
            }
            for row in quality
        ]
        # Escape HTML-sensitive characters before embedding JSON in a script element.
        embedded = json.dumps(
            {"data": embedded_data, "quality": embedded_quality},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        # Prevent embedded JSON from introducing script tags into the report.
        for character, escaped in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026")):
            embedded = embedded.replace(character, escaped)
        latest = quality[-1]["completed_date"] if quality else today.isoformat()
        interval_label = (
            f"{REPORT_REFRESH_INTERVAL_SECONDS // 60} minutes"
            if REPORT_REFRESH_INTERVAL_SECONDS % 60 == 0
            else f"{REPORT_REFRESH_INTERVAL_SECONDS} seconds"
        )
        html = self.build_report_html(embedded, latest, interval_label)
        changed += int(self.write_text(REPORT, html))

        if changed:
            self.log.info(
                "ANALYTICS UPDATED | Changed=%s | Full=%s | DirtyDays=%s",
                changed, full_refresh, len(dirty_dates),
            )
        self._reports_dirty = False
        self._dirty_dates.clear()
        self._last_maintenance_day = today
        return changed


def destination(target, relative, action):
    """Create a collision-free destination path for moves."""
    dst = target / relative
    ensure_destination_directory(dst.parent)
    if action == "copy":
        return dst
    if not dst.exists():
        return dst
    stamp = time.strftime("%Y%m%d_%H%M%S")
    number = 1
    while True:
        suffix = "" if number == 1 else f"_{number}"
        candidate = dst.with_name(f"{dst.stem}_{stamp}{suffix}{dst.suffix}")
        if not candidate.exists():
            return candidate
        number += 1


def transfer(src, target, route_relative, action, reason, label, smb, analytics, log, initial_stat=None):
    """Copy to a temporary target and publish only after source stability checks."""
    tmp = None
    dst = None
    try:
        before = initial_stat or src.stat()
        if analytics.pending_move(src):
            return False
        try:
            smb_relative = str(src.relative_to(ROOT))
        except ValueError:
            smb_relative = src.name
        mtime = datetime.fromtimestamp(before.st_mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z")

        resolution = smb.resolve(src, smb_relative, mtime, utc_now_iso())
        if resolution.get("is_open"):
            return False
        if time.time() - before.st_mtime < MIN_AGE:
            return False

        current = src.stat()
        if (before.st_size, before.st_mtime_ns) != (current.st_size, current.st_mtime_ns):
            return False

        dst = destination(target, route_relative, action)
        if normalize_path_key(dst) == normalize_path_key(src):
            log.error("TRANSFER SKIPPED | Source and destination are identical")
            return False
        if action == "copy" and dst.exists():
            return False

        page_count = get_page_count(src, analytics.log)
        tmp = dst.with_name(dst.name + "." + uuid.uuid4().hex + ".part")
        shutil.copy2(src, tmp)
        after = src.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            tmp.unlink(missing_ok=True)
            return False
        os.replace(tmp, dst)
        committed = utc_now_iso()

        if action == "move":
            try:
                src.unlink()
            except OSError as exc:
                try:
                    analytics.add_move(src, dst, smb_relative, label, before, mtime, resolution, exc)
                except Exception:
                    try:
                        dst.unlink()
                    except OSError:
                        log.error("CRITICAL | Cannot roll back destination after move failure")
                return False

        analytics.add_scan(
            src, smb_relative, dst, label, mtime, resolution,
            completed=committed, page_count=page_count, size_bytes=before.st_size,
        )
        log.info("TRANSFER COMPLETE | Action=%s | Rule=%s", action, reason)
        smb.forget(src)
        return True
    except FileNotFoundError:
        return False
    except Exception as exc:
        log.error("TRANSFER ERROR | ErrorType=%s", type(exc).__name__)
        return False
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)


def process_rules(groups, smb, analytics, log):
    """Read each source once and process matching transfers serially."""
    started = time.perf_counter()
    tasks = []
    scanned = 0
    source_errors = set()

    for group in groups:
        if STOP.is_set():
            break
        now = time.monotonic()
        if group.error_until > now:
            continue
        recursive = bool(group.subfolders)
        try:
            candidates = scan_source(group.source, recursive)
            group.error_until = 0.0
        except OSError as exc:
            group.error_until = now + 30.0
            key = normalize_path_key(group.source)
            if key not in source_errors:
                source_errors.add(key)
                log.error(
                    "RULE ERROR | Source unreadable | Retry=30s | ErrorType=%s",
                    type(exc).__name__,
                )
            continue
        scanned += len(candidates)

        for candidate in candidates:
            if STOP.is_set():
                break
            try:
                relative = candidate.path.relative_to(group.source)
            except ValueError:
                continue

            if group.identifiers and len(relative.parts) == 1:
                stem = candidate.path.stem.lower()
                name = candidate.path.name.lower()
                for key, matching_rules in group.identifiers.items():
                    if stem == key or name.startswith(key + "-"):
                        for rule in matching_rules:
                            tasks.append((candidate, rule, Path(candidate.path.name)))

            for rule in group.subfolders:
                tasks.append((candidate, rule, relative))

    force_snapshot = bool(tasks) and any(
        candidate.stat.st_mtime >= smb.snapshot_wall_time
        for candidate, _, _ in tasks
    )
    snapshot_ms = smb.refresh_open_snapshot(force=force_snapshot) if tasks else 0.0
    transfers = 0
    for candidate, rule, relative in tasks:
        if STOP.is_set():
            break
        # Rule identifiers are used in memory but not persisted in analytics.
        label = ""
        if transfer(
            candidate.path,
            rule.target,
            relative,
            rule.action,
            f"Excel row {rule.row}",
            label,
            smb,
            analytics,
            log,
            initial_stat=candidate.stat,
        ):
            transfers += 1

    return {
        "ms": (time.perf_counter() - started) * 1000.0,
        "snapshot_ms": snapshot_ms,
        "sources": len(groups),
        "scanned": scanned,
        "matched": len(tasks),
        "transfers": transfers,
    }


def single_instance(log):
    if os.name != "nt":
        return True
    kernel32 = ctypes.WinDLL(
        "kernel32",
        use_last_error=True,
    )
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CreateMutexW.argtypes = (
        ctypes.c_void_p,
        ctypes.c_bool,
        ctypes.c_wchar_p,
    )
    kernel32.CloseHandle.argtypes = (
        ctypes.c_void_p,
    )
    ctypes.set_last_error(0)
    handle = kernel32.CreateMutexW(
        None,
        False,
        "Global\\Trachti-ScanProxy",
    )
    already_running = (
        ctypes.get_last_error() == 183
    )
    if not handle or already_running:
        if handle:
            kernel32.CloseHandle(handle)
        log.error(
            "ABORT | Scan Proxy is already running"
        )
        return False
    return handle


def main():
    log, analytics_log = get_logs()
    mutex = single_instance(log)
    if mutex is False:
        return

    def request_stop(signum, _frame):
        log.info("STOP REQUESTED | Signal=%s", signum)
        STOP.set()

    for signal_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        stop_signal = getattr(signal, signal_name, None)
        if stop_signal is not None:
            try:
                signal.signal(stop_signal, request_stop)
            except (OSError, ValueError):
                pass

    analytics = Analytics(analytics_log)
    smb = SmbResolver(log)
    analytics.init()
    last_config_mtime = None
    groups = []
    sheet = ""
    next_file_scan = 0.0
    next_pending = time.monotonic() + PENDING_SWEEP_INTERVAL_SECONDS
    next_reports = time.monotonic() + REPORT_REFRESH_INTERVAL_SECONDS
    next_perf = time.monotonic() + PERFORMANCE_LOG_INTERVAL_SECONDS
    perf = {"cycles": 0, "scan_ms": 0.0, "snapshot_ms": 0.0, "scanned": 0,
            "matched": 0, "transfers": 0, "pending_ms": 0.0, "report_ms": 0.0}

    log.info(
        "START | Version=%s | FileScan=%ss | PendingSweep=%ss | "
        "ReportRefresh=%ss | SMB-Snapshot=%ss | SMB-Lookback=%smin",
        VERSION, FILE_SCAN_INTERVAL_SECONDS, PENDING_SWEEP_INTERVAL_SECONDS,
        REPORT_REFRESH_INTERVAL_SECONDS, SMB_SNAPSHOT_TTL_SECONDS,
        SMB_EVENT_LOOKBACK_MINUTES,
    )
    analytics_log.info(
        "START | Version=%s | PendingSweep=%ss | ReportRefresh=%ss",
        VERSION, PENDING_SWEEP_INTERVAL_SECONDS, REPORT_REFRESH_INTERVAL_SECONDS,
    )
    print(f"Scan Proxy {VERSION} is running. Press Ctrl+C to stop.", flush=True)

    try:
        while not STOP.is_set():
            try:
                now = time.monotonic()
                transfers_this_loop = 0

                if now >= next_file_scan:
                    config_mtime = CONFIG_PATH.stat().st_mtime_ns
                    if config_mtime != last_config_mtime:
                        sheet, raw_rules = load_rules()
                        groups, active_count = compile_rules(raw_rules, log)
                        last_config_mtime = config_mtime
                        log.info(
                            "WORKBOOK LOADED | Sheet=%s | Rules=%s | Active=%s | Sources=%s",
                            sheet, len(raw_rules), active_count, len(groups),
                        )

                    stats = process_rules(groups, smb, analytics, log)
                    transfers_this_loop = stats["transfers"]
                    perf["cycles"] += 1
                    perf["scan_ms"] += stats["ms"]
                    perf["snapshot_ms"] += stats["snapshot_ms"]
                    perf["scanned"] += stats["scanned"]
                    perf["matched"] += stats["matched"]
                    perf["transfers"] += stats["transfers"]
                    next_file_scan = time.monotonic() + FILE_SCAN_INTERVAL_SECONDS

                if not transfers_this_loop:
                    analytics.retry_moves()

                    if now >= next_pending:
                        t0 = time.perf_counter()
                        analytics.resolve_pending(smb)
                        perf["pending_ms"] += (time.perf_counter() - t0) * 1000.0
                        next_pending = time.monotonic() + PENDING_SWEEP_INTERVAL_SECONDS

                    if now >= next_reports:
                        t0 = time.perf_counter()
                        analytics.refresh_reports()
                        perf["report_ms"] += (time.perf_counter() - t0) * 1000.0
                        next_reports = time.monotonic() + REPORT_REFRESH_INTERVAL_SECONDS

                if now >= next_perf:
                    cycles = max(1, perf["cycles"])
                    log.info(
                        "PERFORMANCE | ScanAvg=%.1fms | SMB-Snapshot=%.1fms | "
                        "Sources=%s | Files=%s | Matches=%s | Transfers=%s | "
                        "Pending=%.1fms | Reports=%.1fms",
                        perf["scan_ms"] / cycles,
                        perf["snapshot_ms"] / cycles,
                        len(groups), perf["scanned"], perf["matched"], perf["transfers"],
                        perf["pending_ms"], perf["report_ms"],
                    )
                    perf = {"cycles": 0, "scan_ms": 0.0, "snapshot_ms": 0.0, "scanned": 0,
                            "matched": 0, "transfers": 0, "pending_ms": 0.0, "report_ms": 0.0}
                    next_perf = time.monotonic() + PERFORMANCE_LOG_INTERVAL_SECONDS

            except Exception as exc:
                log.error("SCAN CYCLE ERROR | ErrorType=%s", type(exc).__name__)
            STOP.wait(MAIN_LOOP_SLEEP_SECONDS)

    finally:
        try:
            analytics.resolve_pending(smb)
            analytics.refresh_reports(force=True)
        except Exception as exc:
            analytics_log.error("ANALYTICS ERROR | Shutdown | ErrorType=%s", type(exc).__name__)
        analytics.close()
        if os.name == "nt" and mutex not in (True, False):
            ctypes.WinDLL("kernel32").CloseHandle(ctypes.c_void_p(mutex))
        analytics_log.info("STOP")
        log.info("STOP")
        print("Scan Proxy stopped.", flush=True)

if __name__ == "__main__":
    main()
