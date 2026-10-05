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
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from html import escape
from pathlib import Path

from openpyxl import load_workbook

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None


VERSION = "2.12.0"

# Public changelog
# 2026-09-18 | Trachti | Added low-CPU batched SMB resolution for pending files.
# 2026-09-18 | Trachti | Added grouped Event 5145 queries, DNS caching, and change-only reports.
# 2026-08-14 | Trachti | Improved readability, split logs, and configurable SMB intervals.

if getattr(sys, "frozen", False):
    BASE = Path(sys.executable).resolve().parent
else:
    BASE = Path(__file__).resolve().parent.parent

ROOT = Path(os.environ.get("SCAN_PROXY_ROOT", r"E:\scan"))
CONFIG_PATH = Path(
    os.environ.get(
        "SCAN_PROXY_CONFIG",
        str(BASE / "config" / "scan-proxy-config.xlsx"),
    )
)
SMB_HELPER_PATH = Path(
    os.environ.get(
        "SCAN_PROXY_SMB_HELPER",
        str(BASE / "scripts" / "scan-proxy-smb.ps1"),
    )
)

FILE_SCAN_INTERVAL_SECONDS = int(
    os.environ.get("SCAN_PROXY_FILE_SCAN_INTERVAL_SECONDS", "5")
)
REPORT_REFRESH_INTERVAL_SECONDS = int(
    os.environ.get(
        "SCAN_PROXY_REPORT_REFRESH_INTERVAL_SECONDS",
        os.environ.get("SCAN_PROXY_SMB_QUERY_INTERVAL_SECONDS", "600"),
    )
)
PENDING_SWEEP_INTERVAL_SECONDS = int(
    os.environ.get("SCAN_PROXY_PENDING_SWEEP_INTERVAL_SECONDS", "60")
)
PENDING_BATCH_SIZE = int(
    os.environ.get("SCAN_PROXY_PENDING_BATCH_SIZE", "8")
)
PENDING_RETRY_DELAYS_SECONDS = (30, 120, 600, 3600, 21600, 43200)

SMB_LIVE_LOOKBACK_MINUTES = int(
    os.environ.get("SCAN_PROXY_SMB_LIVE_LOOKBACK_MINUTES", "2")
)
SMB_EVENT_LOOKBACK_MINUTES = int(
    os.environ.get("SCAN_PROXY_SMB_EVENT_LOOKBACK_MINUTES", "10")
)
SMB_IGNORED_NETWORKS = tuple(
    value.strip()
    for value in os.environ.get("SCAN_PROXY_IGNORED_NETWORKS", "")
    .replace(",", ";")
    .split(";")
    if value.strip()
)
SMB_USER = os.environ.get("SCAN_PROXY_SMB_USER", "scanner-service")

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

MIN_AGE = 3
MAIN_LOOP_SLEEP_SECONDS = 1
SMB_TIMEOUT = int(os.environ.get("SCAN_PROXY_SMB_TIMEOUT_SECONDS", "5"))
SMB_BATCH_TIMEOUT = int(os.environ.get("SCAN_PROXY_SMB_BATCH_TIMEOUT_SECONDS", "20"))
PENDING_MAX_HOURS = int(os.environ.get("SCAN_PROXY_PENDING_MAX_HOURS", "48"))
SMB_OPEN_CACHE_SECONDS = 2
SMB_RESOLVED_CACHE_SECONDS = 300
SMB_MISS_CACHE_SECONDS = 30
SMB_EXACT_HINT_SECONDS = 3600
HOSTNAME_LOOKUP_TIMEOUT_SECONDS = 2
HOSTNAME_SUCCESS_TTL_SECONDS = 86400
HOSTNAME_FAILURE_TTL_SECONDS = 21600
HOSTNAME_BATCH_SIZE = 4
DAILY_RETENTION_DAYS = 90
MOVE_RETRY_SECONDS = 5
PENDING_CACHE_SECONDS = 5
SMB_IGNORED_NETS = tuple(
    ipaddress.ip_network(network, strict=False)
    for network in SMB_IGNORED_NETWORKS
)
STOP = threading.Event()

def resolve_path(value):
    path = Path(str(value or ".").strip())
    if path.is_absolute():
        return path
    return ROOT / path
def is_enabled(value):
    return str(value).strip().lower() in {
        "true",
        "on",
        "1",
        "enabled",
        "yes",
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
    """Return the retry delay for a scanner whose client IP is still unresolved."""
    index = min(max(int(attempts), 0), len(PENDING_RETRY_DELAYS_SECONDS) - 1)
    return PENDING_RETRY_DELAYS_SECONDS[index]


def reverse_lookup(ip):
    """Resolve a scanner IP with nslookup first and socket DNS as a fallback."""
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
                r"(?im)^\s*(?:name|name)\s*[:=]\s*(\S.*?)\s*$",
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


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def parse_utc(value):
    try:
        return datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        ).astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None

def mb(size):
    value = Decimal(int(size or 0)) / Decimal(1048576)
    rounded = value.quantize(
        Decimal("0.01"),
        rounding=ROUND_HALF_UP,
    )
    return f"{rounded:.2f}".replace(".", ",")

def pages(file, log):
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
        log.warning(
            "ANALYTICS WARNING | "
            "PDF page count could not be read | "
            "File=%s",
            file,
        )
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
        "scanproxy",
        SCANPROXY_LOG_DIR,
    )
    analytics_log = get_logger(
        "analytics",
        ANALYTICS_LOG_DIR,
    )
    return scanproxy_log, analytics_log

def load_rules():
    """Load routing rules from the English public workbook schema."""
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
                worksheet.iter_rows(min_row=1, max_row=1, values_only=True),
                (),
            )
            columns = {
                str(value).strip().lower(): index
                for index, value in enumerate(header)
                if value is not None
            }
            required = {"identifier", "source", "destination", "mode"}
            has_enabled_column = "enabled" in columns or "status" in columns
            if required <= columns.keys() and has_enabled_column:
                break
        else:
            raise ValueError(
                "No worksheet with Identifier, Source, Destination, Mode "
                "and Enabled/Status columns was found"
            )

        columns["enabled"] = columns.get("enabled", columns.get("status"))

        def value_from_row(row, name, default=None):
            index = columns.get(name)
            if index is not None and index < len(row):
                return row[index]
            return default

        rules = []
        for row_number, row in enumerate(
            worksheet.iter_rows(min_row=2, values_only=True),
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
                    value_from_row(row, "scanner"),
                )
            )
        return worksheet.title, rules
    finally:
        workbook.close()


class SmbResolver:
    def __init__(self, log):
        self.log = log
        self.cache = {}
        self.exact_clients = {}
    def resolve(
        self,
        file,
        relative="",
        mtime="",
        reference="",
    ):

        path_key = os.path.normcase(os.path.normpath(str(file)))
        key = (path_key, str(mtime))
        now = time.monotonic()
        cached = self.cache.get(key)
        if cached and cached[1] > now:
            return dict(cached[0])
        exact_hint = self.exact_clients.get(path_key)
        if exact_hint and exact_hint[1] <= now:
            self.exact_clients.pop(path_key, None)
            exact_hint = None
        empty = {
            "client": "",
            "resolved": False,
            "source": "None",
            "reason": "No unambiguous SMB client IP could be resolved",
            "record_id": 0,
            "is_open": False,
            "confidence": "None",
        }
        if os.name != "nt" or not SMB_HELPER_PATH.is_file():
            return empty
        if not relative:
            try:
                relative = str(file.relative_to(ROOT))
            except ValueError:
                relative = file.name
        command = [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SMB_HELPER_PATH),
            "-Mode",
            "Resolve",
            "-FilePath",
            str(file),
            "-RelativePath",
            relative,
            "-UserName",
            SMB_USER,
            "-LookbackMinutes",
            str(SMB_LIVE_LOOKBACK_MINUTES),
            "-ReferenceTimeUtc",
            reference or utc_now(),
            "-IgnoredNetworks",
            ";".join(SMB_IGNORED_NETWORKS),
        ]
        try:
            completed_process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=SMB_TIMEOUT,
                creationflags=getattr(
                    subprocess,
                    "CREATE_NO_WINDOW",
                    0,
                ),
            )
            if completed_process.returncode:
                error_text = (
                    completed_process.stderr
                    or f"ExitCode={completed_process.returncode}"
                ).strip()
                raise RuntimeError(error_text)
            data = next(
                (
                    json.loads(line.lstrip("\ufeff"))
                    for line in reversed(
                        completed_process.stdout.splitlines()
                    )
                    if line.strip().startswith("{")
                ),
                {},
            )
            client = normalize_ip(
                data.get("Client")
            )
            result = {
                "client": client,
                "resolved": bool(client),
                "source": str(
                    data.get("Source") or "None"
                ),
                "reason": str(
                    data.get("Reason") or empty["reason"]
                ),
                "record_id": int(
                    data.get("RecordId") or 0
                ),
                "is_open": bool(
                    client and data.get("Open")
                ),
                "confidence": str(
                    data.get("Confidence") or "None"
                ),
            }
        except Exception as exc:
            self.log.info(
                "SMB CLIENT NOT RESOLVED | "
                "File=%s | Reason=%s",
                file,
                exc,
            )
            result = dict(empty)
        if (
            result.get("client")
            and result.get("source") == "Get-SmbOpenFile"
            and result.get("confidence") == "ExactOpenFile"
        ):
            saved = dict(result)
            saved["is_open"] = False
            saved["source"] = "Get-SmbOpenFile-Cache"
            saved["reason"] = "Previously observed exact open SMB file"
            saved["confidence"] = "ExactOpenFileCached"
            self.exact_clients[path_key] = (saved, now + SMB_EXACT_HINT_SECONDS)
            exact_hint = self.exact_clients[path_key]
        if exact_hint and not result.get("is_open"):
            hinted = dict(exact_hint[0])
            if not result.get("resolved") or result.get("client") != hinted["client"]:
                result = hinted

        if result["is_open"]:
            ttl = SMB_OPEN_CACHE_SECONDS
        elif result["resolved"]:
            ttl = SMB_RESOLVED_CACHE_SECONDS
        else:
            ttl = SMB_MISS_CACHE_SECONDS

        self.cache[key] = (
            dict(result),
            now + ttl,
        )
        if len(self.cache) > 2000:
            self.cache = {
                cache_key: cache_value
                for cache_key, cache_value in self.cache.items()
                if cache_value[1] > now
            }
        if len(self.exact_clients) > 2000:
            self.exact_clients = {
                hint_key: hint_value
                for hint_key, hint_value in self.exact_clients.items()
                if hint_value[1] > now
            }
        return result

    def resolve_batch(self, rows):
        """Resolve multiple pending files through a single PowerShell process.

        The PowerShell helper reads JSON jobs from STDIN and groups Security Event
        5145 queries. This substantially reduces process overhead on small systems.
        """
        rows = list(rows)
        if not rows:
            return {}

        empty = {
            "client": "",
            "resolved": False,
            "source": "None",
            "reason": "No unambiguous SMB client IP could be resolved",
            "record_id": 0,
            "is_open": False,
            "confidence": "None",
        }
        if os.name != "nt" or not SMB_HELPER_PATH.is_file():
            return {str(row["id"]): dict(empty) for row in rows}

        payload = [
            {
                "Id": str(row["id"]),
                "FilePath": str(row["original_path"]),
                "RelativePath": str(row["relative_path"] or ""),
                "ReferenceTimeUtc": str(
                    row["file_mtime_utc"] or row["completed_at_utc"] or utc_now()
                ),
            }
            for row in rows
        ]
        command = [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SMB_HELPER_PATH),
            "-Mode",
            "ResolveBatch",
            "-UserName",
            SMB_USER,
            "-LookbackMinutes",
            str(SMB_EVENT_LOOKBACK_MINUTES),
            "-IgnoredNetworks",
            ";".join(SMB_IGNORED_NETWORKS),
        ]
        try:
            completed_process = subprocess.run(
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
            if completed_process.returncode:
                error_text = (
                    completed_process.stderr
                    or f"ExitCode={completed_process.returncode}"
                ).strip()
                raise RuntimeError(error_text)

            output = [
                line.lstrip("\ufeff").strip()
                for line in completed_process.stdout.splitlines()
                if line.strip()
            ]
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
                    "is_open": bool(client and item.get("Open")),
                    "confidence": str(item.get("Confidence") or "None"),
                }

            for row in rows:
                results.setdefault(str(row["id"]), dict(empty))
            return results
        except Exception as exc:
            self.log.warning(
                "SMB BATCH ERROR | Files=%s | Reason=%s",
                len(rows),
                exc,
            )
            failed = dict(empty)
            failed["reason"] = f"SMB batch failed: {exc}"
            return {str(row["id"]): dict(failed) for row in rows}

    def forget(self, file):
        """Remove file-specific SMB caches after a completed transfer."""
        path_key = os.path.normcase(os.path.normpath(str(file)))
        self.exact_clients.pop(path_key, None)
        for cache_key in tuple(self.cache):
            if cache_key[0] == path_key:
                self.cache.pop(cache_key, None)


class Analytics:

    def __init__(self, log):
        self.log = log
        self.last_move_retry = 0.0
        self._pending_cache = set()
        self._pending_cache_until = 0.0

    def connect(self):
        db = sqlite3.connect(
            DB,
            timeout=10,
        )
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=10000")
        db.execute("PRAGMA synchronous=NORMAL")
        db.execute("PRAGMA temp_store=MEMORY")
        return db

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
        self.refresh_reports()

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

        now = utc_now()
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
            str(reason),
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
            parse_utc(completed)
            or datetime.now(timezone.utc)
        )
        local = done.astimezone()
        now = utc_now()

        client = normalize_ip(
            (resolution or {}).get("client")
        )
        state = (
            "resolved"
            if client
            else "pending"
        )
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
            str(source),
            str(relative),
            str(target),
            str(label or ""),
            mtime,
            int(page_count) if page_count is not None else pages(target, self.log),
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
        self.log.info(
            "ANALYTICS | Scanner=%s | File=%s | Status=%s",
            client or "pending",
            target,
            state,
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
                                utc_now(),
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
        """Process due pending client IP lookups in a small low-CPU batch."""
        now = time.time()
        now_utc = datetime.now(timezone.utc)
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT *
                FROM scans
                WHERE resolution_state = 'pending'
                  AND next_resolve_epoch <= ?
                ORDER BY next_resolve_epoch, completed_at_utc
                LIMIT ?
                """,
                (now, PENDING_BATCH_SIZE),
            ).fetchall()

        if not rows:
            return

        expired = []
        active_rows = []
        for row in rows:
            deadline = parse_utc(row["resolve_deadline_utc"])
            if deadline and deadline <= now_utc:
                expired.append(row)
            else:
                active_rows.append(row)
        if expired:
            stamp = utc_now()
            with self.connect() as db:
                db.executemany(
                    """
                    UPDATE scans
                    SET resolution_state = 'unresolved',
                        updated_at_utc = ?
                    WHERE id = ?
                    """,
                    [(stamp, row["id"]) for row in expired],
                )
            for row in expired:
                self.log.warning(
                    "SMB RESOLUTION EXPIRED | File=%s | Attempts=%s",
                    row["completed_path"],
                    row["resolve_attempts"],
                )

        if not active_rows:
            return
        results = smb.resolve_batch(active_rows)
        resolved_logs = []
        stamp = utc_now()
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
                        UPDATE scans
                        SET scanner_ip = ?,
                            resolution_source = ?,
                            resolution_reason = ?,
                            resolution_confidence = ?,
                            resolution_record_id = ?,
                            resolution_state = 'resolved',
                            resolve_attempts = ?,
                            updated_at_utc = ?
                        WHERE id = ?
                        """,
                        (
                            client,
                            str(result.get("source") or "None"),
                            reason,
                            str(result.get("confidence") or "None"),
                            int(result.get("record_id") or 0),
                            attempts,
                            stamp,
                            row["id"],
                        ),
                    )
                    resolved_logs.append(
                        (client, str(result.get("source") or "None"), row["completed_path"])
                    )
                else:
                    db.execute(
                        """
                        UPDATE scans
                        SET resolve_attempts = ?,
                            next_resolve_epoch = ?,
                            resolution_reason = ?,
                            updated_at_utc = ?
                        WHERE id = ?
                        """,
                        (
                            attempts,
                            retry_now + pending_retry_delay(attempts),
                            reason,
                            stamp,
                            row["id"],
                        ),
                    )

        for client, source, completed_path in resolved_logs:
            self.log.info(
                "SMB RESOLVED LATER | Scanner=%s | Source=%s | File=%s",
                client,
                source,
                completed_path,
            )

    def refresh_hostnames(self, ips):
        candidates = sorted({normalize_ip(ip) for ip in ips if normalize_ip(ip)})
        if not candidates:
            return

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
            return
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
                        utc_now(),
                        now + ttl,
                        failures,
                    ),
                )
                if hostname and hostname != previous_name:
                    self.log.info(
                        "HOSTNAME RESOLVED | Scanner=%s | Hostname=%s | Source=%s",
                        ip,
                        hostname,
                        source,
                    )

    def hostnames(self):
        with self.connect() as db:
            rows = db.execute(
                "SELECT scanner_ip, hostname FROM dns_cache WHERE hostname <> ''"
            ).fetchall()
        return {row["scanner_ip"]: row["hostname"] for row in rows}

    def quality_data(self):
        """Return daily resolved, pending, and unresolved counts for the local report."""
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
        """Write a CSV atomically, but only when its content changed."""
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
        """Write text atomically with change detection to reduce I/O."""
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
        """Build the local serverless HTML analytics report with embedded data."""
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
                    Only unambiguous SMB client IP addresses &middot;
                    Reverse DNS prefers nslookup &middot;
                    Scanproxy {escape(VERSION)}
                </small>
            </div>
            <small>Report refresh: {interval_label}</small>
        </header>

        <div class="ctrl">
            <label>
                View<br>
                <select id="m">
                    <option value="day">Day</option>
                    <option value="week">Week</option>
                    <option value="month">Month</option>
                    <option value="year">Year</option>
                </select>
            </label>
            <label>
                Date<br>
                <input id="d" type="date" value="{latest}">
            </label>
            <label>
                Filter scanner / hostname<br>
                <input id="q" type="search" placeholder="e.g. 192.0.2.10 or scanner01">
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
                    <th class="n">Avg pages/file</th>
                    <th class="n">Data MB</th>
                    <th>Last scan</th>
                </tr>
            </thead>
            <tbody id="t"></tbody>
        </table>

        <p class="muted">
            The table contains only successfully transferred scans with an unambiguously resolved
            scanner IP. Pending and permanently unresolved mappings are shown separately
            and are never assigned to an identifier or guessed client.
        </p>
    </main>

    <script>
        const P = {embedded};
        const D = P.data;
        const Q = P.quality;
        const m = document.getElementById('m');
        const d = document.getElementById('d');
        const q = document.getElementById('q');
        const t = document.getElementById('t');
        const pad = n => String(n).padStart(2, '0');
        const iso = x => `${{x.getFullYear()}}-${{pad(x.getMonth() + 1)}}-${{pad(x.getDate())}}`;
        const pd = s => {{
            const a = s.split('-').map(Number);
            return new Date(a[0], a[1] - 1, a[2]);
        }};
        const fd = s => {{
            const x = pd(s);
            return `${{pad(x.getDate())}}.${{pad(x.getMonth() + 1)}}.${{x.getFullYear()}}`;
        }};
        const dt = s => s ? new Date(s).toLocaleString(
            'en-GB', {{dateStyle: 'short', timeStyle: 'short'}}
        ) : '-';
        const num = x => Number(x || 0).toLocaleString('en-GB');
        const mb = x => (Number(x || 0) / 1048576).toLocaleString(
            'en-GB', {{minimumFractionDigits: 2, maximumFractionDigits: 2}}
        );

        function range() {{
            const x = pd(d.value);
            let a = new Date(x);
            let z = new Date(x);
            if (m.value === 'week') {{
                a.setDate(x.getDate() - ((x.getDay() + 6) % 7));
                z = new Date(a);
                z.setDate(a.getDate() + 6);
            }}
            if (m.value === 'month') {{
                a = new Date(x.getFullYear(), x.getMonth(), 1);
                z = new Date(x.getFullYear(), x.getMonth() + 1, 0);
            }}
            if (m.value === 'year') {{
                a = new Date(x.getFullYear(), 0, 1);
                z = new Date(x.getFullYear(), 11, 31);
            }}
            return [iso(a), iso(z)];
        }}

        function render() {{
            const [A, Z] = range();
            const rows = D.filter(v => v.date >= A && v.date <= Z);
            const quality = Q.filter(v => v.date >= A && v.date <= Z);
            const scanners = new Map();
            let files = 0, pages = 0, bytes = 0, pending = 0, unresolved = 0;
            let first = '', last = '';

            for (const v of quality) {{
                files += v.total;
                pages += v.pages;
                bytes += v.bytes;
                pending += v.pending;
                unresolved += v.unresolved;
                first = !first || (v.first && v.first < first) ? v.first : first;
                last = !last || (v.last && v.last > last) ? v.last : last;
            }}

            for (const v of rows) {{
                const o = scanners.get(v.scanner) || {{
                    hostname: v.hostname || '', f: 0, p: 0, b: 0, l: ''
                }};
                if (!o.hostname && v.hostname) o.hostname = v.hostname;
                o.f += v.files;
                o.p += v.pages;
                o.b += v.bytes;
                o.l = !o.l || v.last > o.l ? v.last : o.l;
                scanners.set(v.scanner, o);
            }}

            document.getElementById('r').textContent = `${{fd(A)}} bis ${{fd(Z)}}`;
            document.getElementById('c').textContent = num(scanners.size);
            document.getElementById('f').textContent = num(files);
            document.getElementById('p').textContent = num(pages);
            document.getElementById('b').textContent = mb(bytes) + ' MB';
            document.getElementById('pn').textContent = num(pending);
            document.getElementById('u').textContent = num(unresolved);
            document.getElementById('e').textContent = dt(first);
            document.getElementById('l').textContent = dt(last);

            const filter = q.value.trim().toLowerCase();
            const visible = [...scanners]
                .filter(([ip, o]) => !filter || ip.toLowerCase().includes(filter) ||
                    (o.hostname || '').toLowerCase().includes(filter))
                .sort((a, b) => a[0].localeCompare(b[0], undefined, {{numeric: true}}));

            t.innerHTML = visible.map(([ip, o]) => `
                <tr>
                    <td>${{ip}}</td>
                    <td>${{o.hostname || '<span class="muted">-</span>'}}</td>
                    <td class="n">${{num(o.f)}}</td>
                    <td class="n">${{num(o.p)}}</td>
                    <td class="n">${{o.f ? (o.p / o.f).toLocaleString('en-GB', {{maximumFractionDigits: 1}}) : '-'}}</td>
                    <td class="n">${{mb(o.b)}}</td>
                    <td>${{dt(o.l)}}</td>
                </tr>
            `).join('') || '<tr><td colspan="7">No data</td></tr>';
        }}

        m.onchange = render;
        d.onchange = render;
        q.oninput = render;
        render();
    </script>
</body>
</html>
"""

    def refresh_reports(self):
        """Generate reports idempotently and only for completed reporting periods."""
        data = self.data()
        scanner_ips = [row["scanner_ip"] for row in data]
        self.refresh_hostnames(scanner_ips)
        hostnames = self.hostnames()
        quality = self.quality_data()

        today = date.today()
        cutoff = today - timedelta(days=DAILY_RETENTION_DAYS)
        by_day = {}
        groups = {"week": {}, "month": {}, "year": {}}

        for row in data:
            completed_date = date.fromisoformat(row["completed_date"])
            by_day.setdefault(completed_date, []).append(row)
            item = {
                "scanner": row["scanner_ip"],
                "files": row["files"],
                "pages": row["pages"],
                "bytes": row["bytes"],
                "last": row["last_scan"],
            }
            week_start = completed_date - timedelta(days=completed_date.weekday())
            iso_week = week_start.isocalendar()
            month_start = date(completed_date.year, completed_date.month, 1)
            next_month = date(
                completed_date.year + (completed_date.month == 12),
                (completed_date.month % 12) + 1,
                1,
            )
            month_end = next_month - timedelta(days=1)
            periods = (
                (
                    "week",
                    f"{iso_week.year}-W{iso_week.week:02d}-scan-proxy.csv",
                    week_start,
                    week_start + timedelta(days=6),
                ),
                (
                    "month",
                    f"{completed_date.year:04d}-{completed_date.month:02d}-scan-proxy.csv",
                    month_start,
                    month_end,
                ),
                (
                    "year",
                    f"{completed_date.year:04d}-scan-proxy.csv",
                    date(completed_date.year, 1, 1),
                    date(completed_date.year, 12, 31),
                ),
            )
            for report_type, name, start, end in periods:
                if end >= today:
                    continue
                period = groups[report_type].setdefault((name, start, end), {})
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
                    "Data_MB": mb(row["bytes"]),
                    "Last_Scan": str(row["last_scan"])[11:16],
                }
                for row in same_day
            ]
            changed += self.write_csv(
                DAILY / f"{completed_date.isoformat()}-scan-proxy.csv",
                (
                    "Date", "Scanner", "Hostname", "Files",
                    "Pages", "Data_MB", "Last_Scan",
                ),
                rows,
            )

        report_folders = (("week", WEEKLY), ("month", MONTHLY), ("year", YEARLY))
        for report_type, folder in report_folders:
            for (name, start, end), scanners in groups[report_type].items():
                rows = [
                    {
                        "From": start.isoformat(),
                        "To": end.isoformat(),
                        "Scanner": scanner,
                        "Hostname": hostnames.get(scanner, ""),
                        "Files": values["files"],
                        "Pages": values["pages"],
                        "Data_MB": mb(values["bytes"]),
                        "Last_Scan": str(values["last"])[0:16].replace("T", " "),
                    }
                    for scanner, values in sorted(scanners.items())
                ]
                changed += self.write_csv(
                    folder / name,
                    (
                        "From", "To", "Scanner", "Hostname", "Files",
                        "Pages", "Data_MB", "Last_Scan",
                    ),
                    rows,
                )
        for report_file in DAILY.glob("*-scan-proxy.csv"):
            try:
                report_date = datetime.strptime(report_file.name[:10], "%Y-%m-%d").date()
                if report_date < cutoff:
                    report_file.unlink()
                    changed += 1
                    self.log.info(
                        "CLEANUP | daily analytics file deleted | File=%s",
                        report_file,
                    )
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
                self.log.info(
                    "CLEANUP | incomplete period report removed | File=%s",
                    report_file,
                )

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
        embedded = json.dumps(
            {"data": embedded_data, "quality": embedded_quality},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        latest = (
            quality[-1]["completed_date"]
            if quality
            else today.isoformat()
        )
        interval_label = (
            f"{REPORT_REFRESH_INTERVAL_SECONDS // 60} minutes"
            if REPORT_REFRESH_INTERVAL_SECONDS % 60 == 0
            else f"{REPORT_REFRESH_INTERVAL_SECONDS} seconds"
        )
        html = self.build_report_html(embedded, latest, interval_label)
        html_changed = self.write_text(REPORT, html)
        changed += int(html_changed)

        if changed:
            self.log.info(
                "ANALYTICS UPDATED | Files_changed=%s | HTML=%s",
                changed,
                REPORT,
            )

def destination(target, relative, action):
    dst = target / relative
    dst.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    if not dst.exists() or action == "copy":
        return dst
    stamp = time.strftime("%Y%m%d_%H%M%S")
    number = 1
    while True:
        suffix = (
            ""
            if number == 1
            else f"_{number}"
        )
        candidate = dst.with_name(
            f"{dst.stem}_{stamp}{suffix}{dst.suffix}"
        )
        if not candidate.exists():
            return candidate
        number += 1

def transfer(
    src,
    dst,
    action,
    reason,
    label,
    smb,
    analytics,
    log,
):
    tmp = dst.with_name(
        dst.name
        + "."
        + uuid.uuid4().hex
        + ".part"
    )
    try:
        before = src.stat()
        if action == "copy" and dst.exists():
            return False
        if analytics.pending_move(src):
            return False
        try:
            relative = str(src.relative_to(ROOT))
        except ValueError:
            relative = src.name
        mtime = datetime.fromtimestamp(
            before.st_mtime,
            tz=timezone.utc,
        ).isoformat().replace("+00:00", "Z")
        resolution = smb.resolve(src, relative, mtime, utc_now())
        if resolution.get("is_open"):
            return False
        if time.time() - before.st_mtime < MIN_AGE:
            return False

        current = src.stat()
        if (
            before.st_size,
            before.st_mtime_ns,
        ) != (
            current.st_size,
            current.st_mtime_ns,
        ):
            return False
        page_count = pages(src, analytics.log)
        shutil.copy2(
            src,
            tmp,
        )
        after = src.stat()
        if (
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_size,
            after.st_mtime_ns,
        ):
            tmp.unlink(
                missing_ok=True
            )
            return False
        os.replace(
            tmp,
            dst,
        )
        committed = utc_now()
        if action == "move":
            try:
                src.unlink()
            except OSError as exc:
                try:
                    analytics.add_move(
                        src,
                        dst,
                        relative,
                        label,
                        before,
                        mtime,
                        resolution,
                        exc,
                    )
                except Exception:
                    try:
                        dst.unlink()
                    except OSError:
                        log.exception(
                            "CRITICAL | Destination could not be rolled back "
                            "after a failed move | Destination=%s",
                            dst,
                        )
                return False
        analytics.add_scan(
            src,
            relative,
            dst,
            label,
            mtime,
            resolution,
            completed=committed,
            page_count=page_count,
            size_bytes=before.st_size,
        )
        log.info(
            "SUCCESS | File=%s | Destination=%s | "
            "Action=%s | Reason=%s",
            src,
            dst,
            action,
            reason,
        )
        smb.forget(src)
        return True
    except FileNotFoundError:
        return False
    except Exception:
        log.exception(
            "ERROR | File=%s | Destination=%s",
            src,
            dst,
        )
        return False
    finally:
        tmp.unlink(
            missing_ok=True
        )

def process_rules(
    rules,
    smb,
    analytics,
    log,
):
    """
    Process enabled Excel rules while listing each source only once per cycle.
    This keeps SMB directory enumeration inexpensive when many rules share a source.
    """
    listing_cache = {}
    directory_cache = {}
    source_errors = set()

    def source_key(path):
        return os.path.normcase(os.path.normpath(str(path)))

    def is_directory(path):
        key = source_key(path)
        if key not in directory_cache:
            try:
                directory_cache[key] = path.is_dir()
            except OSError:
                directory_cache[key] = False
        return directory_cache[key]

    def files_for(path, recursive):
        key = (source_key(path), bool(recursive))
        if key in listing_cache:
            return listing_cache[key]
        try:
            if recursive:
                files = tuple(
                    Path(folder) / name
                    for folder, _, names in os.walk(path)
                    for name in names
                    if not name.lower().endswith(".part")
                )
            else:
                with os.scandir(path) as entries:
                    files = tuple(
                        Path(entry.path)
                        for entry in entries
                        if entry.is_file(follow_symlinks=False)
                        and not entry.name.lower().endswith(".part")
                    )
        except OSError as exc:
            files = ()
            if key not in source_errors:
                source_errors.add(key)
                log.error(
                    "RULE ERROR | Source cannot be read | Source=%s | Reason=%s",
                    path,
                    exc,
                )
        listing_cache[key] = files
        return files

    for (
        row,
        code,
        source,
        target,
        mode,
        enabled,
        action,
        scanner,
    ) in rules:
        if STOP.is_set():
            return
        if not is_enabled(enabled):
            continue
        if not source or not target:
            log.error("RULE ERROR | Row=%s | Source or destination is missing", row)
            continue

        src = resolve_path(source)
        dst = resolve_path(target)
        mode = str(mode or "").strip().lower()
        action = str(action or "move").strip().lower()

        if action not in {"move", "copy"}:
            log.error("RULE ERROR | Row=%s | Action=%s is invalid", row, action)
            continue
        if not is_directory(src):
            key = source_key(src)
            if key not in source_errors:
                source_errors.add(key)
                log.error("RULE ERROR | Source is not a directory | Source=%s", src)
            continue

        if mode == "identifier":
            key = str(code or "").strip().lower()
            if not key:
                log.error("RULE ERROR | Row=%s | Identifier is missing", row)
                continue
            files = (
                file
                for file in files_for(src, False)
                if file.stem.lower() == key
                or file.name.lower().startswith(key + "-")
            )
        elif mode in {"subfolder", "subfolders"}:
            if dst == src or dst.is_relative_to(src):
                log.error("RULE ERROR | Destination is inside source | Row=%s", row)
                continue
            files = files_for(src, True)
        else:
            log.error("RULE ERROR | Row=%s | Mode=%s", row, mode)
            continue

        for file in files:
            if STOP.is_set():
                return
            relative = Path(file.name) if mode == "identifier" else file.relative_to(src)
            label = str(
                scanner
                or code
                or (relative.parts[0] if len(relative.parts) > 1 else "")
            )
            transfer(
                file,
                destination(dst, relative, action),
                action,
                f"Excel row {row}",
                label,
                smb,
                analytics,
                log,
            )

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
        "Global\\ScanProxy",
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
    rules = []
    sheet = ""
    next_file_scan = 0.0
    next_pending = time.monotonic() + PENDING_SWEEP_INTERVAL_SECONDS
    next_reports = time.monotonic() + REPORT_REFRESH_INTERVAL_SECONDS

    log.info(
        "START | Version=%s | Root=%s | FileScan=%ss | "
        "PendingSweep=%ss | Report refresh=%ss | SMBLive=%smin | "
        "SMBPending=%smin | IgnoredNetworks=%s",
        VERSION,
        ROOT,
        FILE_SCAN_INTERVAL_SECONDS,
        PENDING_SWEEP_INTERVAL_SECONDS,
        REPORT_REFRESH_INTERVAL_SECONDS,
        SMB_LIVE_LOOKBACK_MINUTES,
        SMB_EVENT_LOOKBACK_MINUTES,
        ",".join(SMB_IGNORED_NETWORKS),
    )
    analytics_log.info(
        "START | Version=%s | Analytics=%s | PendingSweep=%ss | Report refresh=%ss",
        VERSION,
        ANALYTICS,
        PENDING_SWEEP_INTERVAL_SECONDS,
        REPORT_REFRESH_INTERVAL_SECONDS,
    )
    print(f"Scan Proxy {VERSION} is running. Press Ctrl+C to stop.", flush=True)

    try:
        while not STOP.is_set():
            try:
                analytics.retry_moves()
                now = time.monotonic()
                config_mtime = CONFIG_PATH.stat().st_mtime_ns
                if config_mtime != last_config_mtime:
                    sheet, rules = load_rules()
                    last_config_mtime = config_mtime
                    next_file_scan = 0.0
                    log.info("CONFIG LOADED | Sheet=%s | Rules=%s", sheet, len(rules))
                if now >= next_file_scan:
                    process_rules(rules, smb, analytics, log)
                    next_file_scan = time.monotonic() + FILE_SCAN_INTERVAL_SECONDS
                if now >= next_pending:
                    analytics.resolve_pending(smb)
                    next_pending = time.monotonic() + PENDING_SWEEP_INTERVAL_SECONDS
                if now >= next_reports:
                    analytics.refresh_reports()
                    next_reports = time.monotonic() + REPORT_REFRESH_INTERVAL_SECONDS

            except Exception:
                log.exception("LOOP ERROR")
            STOP.wait(MAIN_LOOP_SLEEP_SECONDS)

    finally:
        try:
            analytics.resolve_pending(smb)
            analytics.refresh_reports()
        except Exception:
            analytics_log.exception("ANALYTICS ERROR | shutdown")
        if os.name == "nt" and mutex not in (True, False):
            ctypes.WinDLL("kernel32").CloseHandle(ctypes.c_void_p(mutex))
        analytics_log.info("STOP")
        log.info("STOP")
        print("Scan Proxy stopped.", flush=True)

if __name__ == "__main__":
    main()