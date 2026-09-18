from __future__ import annotations

import csv
import ctypes
import ipaddress
import json
import logging
import os
import re
import shutil
import signal
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


VERSION = "2.11.0-english-repository"

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
SMB_QUERY_INTERVAL_SECONDS = int(
    os.environ.get("SCAN_PROXY_SMB_QUERY_INTERVAL_SECONDS", "600")
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
SMB_TIMEOUT = 8
PENDING_MAX_HOURS = 48
SMB_OPEN_CACHE_SECONDS = 15
SMB_RESOLVED_CACHE_SECONDS = 300
SMB_MISS_CACHE_SECONDS = 30
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
    application_log = get_logger(
        "scan-proxy",
        SCANPROXY_LOG_DIR,
    )
    analytics_log = get_logger(
        "analytics",
        ANALYTICS_LOG_DIR,
    )
    return application_log, analytics_log


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
            has_enabled_column = (
                "enabled" in columns
                or "status" in columns
            )
            if required <= columns.keys() and has_enabled_column:
                break
        else:
            raise ValueError(
                "No worksheet with Identifier, Source, Destination, Mode "
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
    def resolve(
        self,
        file,
        relative="",
        mtime="",
        reference="",
    ):


        key = (
            str(file).lower(),
            str(mtime),
        )
        now = time.monotonic()
        cached = self.cache.get(key)
        if cached and cached[1] > now:
            return dict(cached[0])
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
            str(SMB_EVENT_LOOKBACK_MINUTES),
            "-ReferenceTimeUtc",
            reference or utc_now_iso(),
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
            result = empty
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
        return result


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
            db.execute(
                "PRAGMA synchronous=NORMAL"
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
            get_page_count(target, self.log),
            target.stat().st_size,
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
            time.time() + SMB_QUERY_INTERVAL_SECONDS,
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
        now = time.time()
        with self.connect() as db:
            rows = db.execute(
                """
                SELECT *
                FROM scans
                WHERE resolution_state = 'pending'
                  AND next_resolve_epoch <= ?
                ORDER BY completed_at_utc
                LIMIT 50
                """,
                (now,),
            ).fetchall()
        for row in rows:
            deadline = parse_utc_iso(
                row["resolve_deadline_utc"]
            )
            if deadline and deadline <= datetime.now(timezone.utc):
                with self.connect() as db:
                    db.execute(
                        """
                        UPDATE scans
                        SET resolution_state = 'unresolved',
                            updated_at_utc = ?
                        WHERE id = ?
                        """,
                        (
                            utc_now_iso(),
                            row["id"],
                        ),
                    )
                continue
            result = smb.resolve(
                Path(row["original_path"]),
                row["relative_path"],
                row["file_mtime_utc"],
                row["completed_at_utc"],
            )
            client = normalize_ip(
                result.get("client")
            )
            attempts = row["resolve_attempts"] + 1
            with self.connect() as db:
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
                            result["source"],
                            result["reason"],
                            result["confidence"],
                            result["record_id"],
                            attempts,
                            utc_now_iso(),
                            row["id"],
                        ),
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
                            time.time() + SMB_QUERY_INTERVAL_SECONDS,
                            result["reason"],
                            utc_now_iso(),
                            row["id"],
                        ),
                    )


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


        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        tmp = path.with_suffix(
            path.suffix + ".tmp"
        )
        with tmp.open(
            "w",
            encoding="utf-8-sig",
            newline="",
        ) as csv_file:
            writer = csv.DictWriter(
                csv_file,
                fieldnames=fields,
                delimiter=";",
                extrasaction="ignore",
            )
            writer.writeheader()
            writer.writerows(rows)
            csv_file.flush()
            os.fsync(csv_file.fileno())
        os.replace(
            tmp,
            path,
        )
    def build_report_html(
        self,
        embedded,
        latest,
        interval_label,
    ):
        generated = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        return f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Scan Proxy Analytics</title>
    <style>
        body {{
            font: 14px Segoe UI, Arial;
            background: #f3f5f8;
            color: #1f2937;
            margin: 0;
        }}
        main {{
            max-width: 1200px;
            margin: auto;
            padding: 24px;
        }}
        header, .ctrl, .cards {{
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            align-items: end;
        }}
        .card, table {{
            background: white;
            box-shadow: 0 2px 10px #0001;
        }}
        .card {{
            padding: 14px;
            border-radius: 12px;
            min-width: 140px;
        }}
        .v {{
            font-size: 23px;
            font-weight: 700;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 16px;
        }}
        th, td {{
            padding: 11px;
            border-bottom: 1px solid #eee;
            text-align: left;
        }}
        .n {{
            text-align: right;
        }}
        select, input {{
            padding: 8px;
        }}
        small {{
            color: #667085;
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
                    Scan Proxy {escape(VERSION)}
                </small>
            </div>
        </header>

        <div class="ctrl">
            <label>
                View
                <select id="m">
                    <option value="day">Day</option>
                    <option value="week">Week</option>
                    <option value="month">Month</option>
                    <option value="year">Year</option>
                </select>
            </label>
            <label>
                Date
                <input id="d" type="date" value="{latest}">
            </label>
            <b id="r"></b>
        </div>

        <div class="cards">
            <div class="card">Scanner<div class="v" id="c">0</div></div>
            <div class="card">Files<div class="v" id="f">0</div></div>
            <div class="card">Pages<div class="v" id="p">0</div></div>
            <div class="card">Data<div class="v" id="b">0 MB</div></div>
            <div class="card">First scan<div class="v" id="e">-</div></div>
            <div class="card">Last scan<div class="v" id="l">-</div></div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Scanner IP</th>
                    <th class="n">Files</th>
                    <th class="n">Pages</th>
                    <th class="n">Data MB</th>
                    <th>Last scan</th>
                </tr>
            </thead>
            <tbody id="t"></tbody>
        </table>

        <small>
            Batched refresh every {interval_label}.
            Generated: {generated}
        </small>
    </main>

    <script>
        const D = {embedded};
        const m = document.getElementById('m');
        const d = document.getElementById('d');
        const t = document.getElementById('t');
        const pad = n => String(n).padStart(2, '0');
        const iso = x =>
            `${{x.getFullYear()}}-${{pad(x.getMonth() + 1)}}-${{pad(x.getDate())}}`;
        const pd = s => {{
            const a = s.split('-').map(Number);
            return new Date(a[0], a[1] - 1, a[2]);
        }};
        const fd = s => {{
            const x = pd(s);
            return `${{pad(x.getDate())}}/${{pad(x.getMonth() + 1)}}/${{x.getFullYear()}}`;
        }};
        const dt = s =>
            s
                ? new Date(s).toLocaleString(
                    'en-GB',
                    {{dateStyle: 'short', timeStyle: 'short'}}
                )
                : '-';

        function rr() {{
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

            const A = iso(a);
            const Z = iso(z);
            const q = D.filter(v => v.date >= A && v.date <= Z);
            const m0 = new Map();
            let F = 0;
            let P = 0;
            let B = 0;
            let L = '';
            let E = '';

            for (const v of q) {{
                F += v.files;
                P += v.pages;
                B += v.bytes;
                L = !L || v.last > L ? v.last : L;
                E = !E || v.first < E ? v.first : E;
                const o = m0.get(v.scanner) || {{f: 0, p: 0, b: 0, l: ''}};
                o.f += v.files;
                o.p += v.pages;
                o.b += v.bytes;
                o.l = !o.l || v.last > o.l ? v.last : o.l;
                m0.set(v.scanner, o);
            }}

            document.getElementById('r').textContent = `${{fd(A)}} to ${{fd(Z)}}`;
            document.getElementById('c').textContent = m0.size;
            document.getElementById('f').textContent = F;
            document.getElementById('p').textContent = P;
            document.getElementById('b').textContent =
                (B / 1048576).toLocaleString(
                    'en-GB',
                    {{minimumFractionDigits: 2, maximumFractionDigits: 2}}
                ) + ' MB';
            document.getElementById('e').textContent = dt(E);
            document.getElementById('l').textContent = dt(L);

            t.innerHTML = [...m0]
                .sort()
                .map(([s, o]) => `
                    <tr>
                        <td>${{s}}</td>
                        <td class="n">${{o.f}}</td>
                        <td class="n">${{o.p}}</td>
                        <td class="n">${{
                            (o.b / 1048576).toLocaleString(
                                'en-GB',
                                {{minimumFractionDigits: 2, maximumFractionDigits: 2}}
                            )
                        }}</td>
                        <td>${{dt(o.l)}}</td>
                    </tr>
                `)
                .join('') || '<tr><td colspan="5">No data</td></tr>';
        }}

        m.onchange = rr;
        d.onchange = rr;
        rr();
    </script>
</body>
</html>
"""

    def refresh_reports(self):
        data = self.data()
        cutoff = (
            date.today()
            - timedelta(days=DAILY_RETENTION_DAYS)
        )
        by_day = {}
        groups = {
            "week": {},
            "month": {},
            "year": {},
        }
        for row in data:
            completed_date = date.fromisoformat(
                row["completed_date"]
            )
            by_day.setdefault(
                completed_date,
                [],
            ).append(row)
            item = {
                "scanner": row["scanner_ip"],
                "files": row["files"],
                "pages": row["pages"],
                "bytes": row["bytes"],
                "last": row["last_scan"],
            }
            week_start = (
                completed_date
                - timedelta(days=completed_date.weekday())
            )
            iso_week = week_start.isocalendar()

            month_start = date(
                completed_date.year,
                completed_date.month,
                1,
            )
            next_month = date(
                completed_date.year + (completed_date.month == 12),
                (completed_date.month % 12) + 1,
                1,
            )
            month_end = (
                next_month
                - timedelta(days=1)
            )
            keys = (
                (
                    "week",
                    f"{iso_week.year}-W{iso_week.week:02d}-scan-proxy.csv",
                    week_start,
                    week_start + timedelta(days=6),
                ),
                (
                    "month",
                    (
                        f"{completed_date.year:04d}-"
                        f"{completed_date.month:02d}-scan-proxy.csv"
                    ),
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
            for report_type, name, start, end in keys:
                period = groups[report_type].setdefault(
                    (
                        name,
                        start,
                        end,
                    ),
                    {},
                )
                bucket = period.setdefault(
                    item["scanner"],
                    {
                        "files": 0,
                        "pages": 0,
                        "bytes": 0,
                        "last": "",
                    },
                )
                bucket["files"] += item["files"]
                bucket["pages"] += item["pages"]
                bucket["bytes"] += item["bytes"]
                bucket["last"] = max(
                    bucket["last"],
                    item["last"],
                )
        for completed_date, same_day in by_day.items():
            if completed_date < cutoff:
                continue
            rows = [
                {
                    "Date": completed_date.isoformat(),
                    "Scanner": row["scanner_ip"],
                    "Files": row["files"],
                    "Pages": row["pages"],
                    "Data_MB": format_megabytes(row["bytes"]),
                    "Last_Scan": str(row["last_scan"])[11:16],
                }
                for row in same_day
            ]
            self.write_csv(
                DAILY
                / f"{completed_date.isoformat()}-scan-proxy.csv",
                (
                    "Date",
                    "Scanner",
                    "Files",
                    "Pages",
                    "Data_MB",
                    "Last_Scan",
                ),
                rows,
            )
        report_folders = (
            ("week", WEEKLY),
            ("month", MONTHLY),
            ("year", YEARLY),
        )
        for report_type, folder in report_folders:
            for (
                name,
                start,
                end,
            ), scanners in groups[report_type].items():
                rows = [
                    {
                        "From": start.isoformat(),
                        "To": end.isoformat(),
                        "Scanner": scanner,
                        "Files": values["files"],
                        "Pages": values["pages"],
                        "Data_MB": format_megabytes(values["bytes"]),
                        "Last_Scan": str(
                            values["last"]
                        )[0:16].replace("T", " "),
                    }
                    for scanner, values in sorted(
                        scanners.items()
                    )
                ]
                self.write_csv(
                    folder / name,
                    (
                        "From",
                        "To",
                        "Scanner",
                        "Files",
                        "Pages",
                        "Data_MB",
                        "Last_Scan",
                    ),
                    rows,
                )
        for report_file in DAILY.glob("*-scan-proxy.csv"):
            try:
                report_date = datetime.strptime(
                    report_file.name[:10],
                    "%Y-%m-%d",
                ).date()
                if report_date < cutoff:
                    report_file.unlink()
            except ValueError:
                pass
        embedded_data = [
            {
                "date": row["completed_date"],
                "scanner": row["scanner_ip"],
                "files": row["files"],
                "pages": row["pages"],
                "bytes": row["bytes"],
                "first": row["first_scan"],
                "last": row["last_scan"],
            }
            for row in data
        ]
        embedded = json.dumps(
            embedded_data,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        latest = (
            data[-1]["completed_date"]
            if data
            else date.today().isoformat()
        )
        if SMB_QUERY_INTERVAL_SECONDS % 60 == 0:
            interval_label = (
                f"{SMB_QUERY_INTERVAL_SECONDS // 60} minutes"
            )
        else:
            interval_label = (
                f"{SMB_QUERY_INTERVAL_SECONDS} seconds"
            )
        html = self.build_report_html(
            embedded,
            latest,
            interval_label,
        )
        tmp = REPORT.with_suffix(".tmp")
        tmp.write_text(
            html,
            encoding="utf-8",
        )
        os.replace(
            tmp,
            REPORT,
        )
        self.log.info(
            "ANALYTICS UPDATED | "
            "Interval=%ss | HTML=%s",
            SMB_QUERY_INTERVAL_SECONDS,
            REPORT,
        )


def destination(target, relative, action):
    destination_path = target / relative
    destination_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )
    if not destination_path.exists() or action == "copy":
        return destination_path

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    number = 1
    while True:
        suffix = "" if number == 1 else f"_{number}"
        candidate = destination_path.with_name(
            f"{destination_path.stem}_{timestamp}{suffix}{destination_path.suffix}"
        )
        if not candidate.exists():
            return candidate
        number += 1


def transfer(
    source_path,
    destination_path,
    action,
    reason,
    routing_label,
    smb,
    analytics,
    log,
):
    temporary_path = destination_path.with_name(
        destination_path.name + "." + uuid.uuid4().hex + ".part"
    )
    try:
        before = source_path.stat()
        if time.time() - before.st_mtime < MIN_AGE:
            return False
        if action == "copy" and destination_path.exists():
            return False
        if analytics.pending_move(source_path):
            return False

        try:
            relative = str(source_path.relative_to(ROOT))
        except ValueError:
            relative = source_path.name

        modified_at = datetime.fromtimestamp(
            before.st_mtime,
            tz=timezone.utc,
        ).isoformat().replace("+00:00", "Z")

        resolution = smb.resolve(
            source_path,
            relative,
            modified_at,
            utc_now_iso(),
        )
        if resolution.get("is_open"):
            return False

        current = source_path.stat()
        if (before.st_size, before.st_mtime_ns) != (
            current.st_size,
            current.st_mtime_ns,
        ):
            return False

        shutil.copy2(source_path, temporary_path)
        after = source_path.stat()
        if (before.st_size, before.st_mtime_ns) != (
            after.st_size,
            after.st_mtime_ns,
        ):
            temporary_path.unlink(missing_ok=True)
            return False

        os.replace(temporary_path, destination_path)
        committed_at = utc_now_iso()

        if action == "move":
            try:
                source_path.unlink()
            except OSError as exc:
                try:
                    analytics.add_move(
                        source_path,
                        destination_path,
                        relative,
                        routing_label,
                        before,
                        modified_at,
                        resolution,
                        exc,
                    )
                except Exception:
                    try:
                        destination_path.unlink()
                    except OSError:
                        log.exception(
                            "CRITICAL | Destination could not be rolled back "
                            "after a failed move | Destination=%s",
                            destination_path,
                        )
                return False

        analytics.add_scan(
            source_path,
            relative,
            destination_path,
            routing_label,
            modified_at,
            resolution,
            completed=committed_at,
        )
        log.info(
            "SUCCESS | File=%s | Destination=%s | Action=%s | Reason=%s",
            source_path,
            destination_path,
            action,
            reason,
        )
        return True
    except FileNotFoundError:
        return False
    except Exception:
        log.exception(
            "ERROR | File=%s | Destination=%s",
            source_path,
            destination_path,
        )
        return False
    finally:
        temporary_path.unlink(missing_ok=True)


def process_rules(
    rules,
    smb,
    analytics,
    log,
):
    """Route files for all enabled rules and transfer matching files safely."""
    for (
        row_number,
        identifier,
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
            log.error(
                "RULE ERROR | Row=%s | Source or destination is missing",
                row_number,
            )
            continue

        source_root = resolve_path(source)
        destination_root = resolve_path(target)
        mode = str(mode or "").strip().lower()
        action = str(action or "move").strip().lower()

        if action not in {"move", "copy"} or not source_root.is_dir():
            log.error(
                "RULE ERROR | Row=%s | Source or action is invalid",
                row_number,
            )
            continue

        if mode == "identifier":
            identifier_key = str(identifier or "").strip().lower()
            files = (
                file_path
                for file_path in source_root.iterdir()
                if file_path.is_file()
                and not file_path.name.endswith(".part")
                and (
                    file_path.stem.lower() == identifier_key
                    or file_path.name.lower().startswith(identifier_key + "-")
                )
            )
        elif mode in {"subfolder", "subfolders"}:
            if (
                destination_root == source_root
                or destination_root.is_relative_to(source_root)
            ):
                log.error(
                    "RULE ERROR | Destination is inside source | Row=%s",
                    row_number,
                )
                continue
            files = (
                file_path
                for file_path in source_root.rglob("*")
                if file_path.is_file()
                and not file_path.name.endswith(".part")
            )
        else:
            log.error(
                "RULE ERROR | Row=%s | Unsupported mode=%s",
                row_number,
                mode,
            )
            continue

        for file_path in files:
            if mode == "identifier":
                relative = Path(file_path.name)
            else:
                relative = file_path.relative_to(source_root)

            routing_label = str(
                scanner
                or identifier
                or (
                    relative.parts[0]
                    if len(relative.parts) > 1
                    else ""
                )
            )
            transfer(
                file_path,
                destination(
                    destination_root,
                    relative,
                    action,
                ),
                action,
                f"Excel row {row_number}",
                routing_label,
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
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    ctypes.set_last_error(0)
    handle = kernel32.CreateMutexW(
        None,
        False,
        "Global\\ScanProxy",
    )
    already_running = ctypes.get_last_error() == 183
    if not handle or already_running:
        if handle:
            kernel32.CloseHandle(handle)
        log.error("ABORT | Scan Proxy is already running")
        return False
    return handle


def main():
    log, analytics_log = get_logs()
    mutex = single_instance(log)
    if mutex is False:
        return

    signal.signal(signal.SIGINT, lambda *_: STOP.set())
    analytics = Analytics(analytics_log)
    smb = SmbResolver(log)
    analytics.init()

    last_config_mtime = None
    rules = []
    next_file_scan = 0.0
    next_analytics = time.monotonic() + SMB_QUERY_INTERVAL_SECONDS

    log.info(
        "START | Version=%s | Root=%s | FileScan=%ss | "
        "SMBQuery=%ss | SMBLookback=%smin | IgnoredNetworks=%s",
        VERSION,
        ROOT,
        FILE_SCAN_INTERVAL_SECONDS,
        SMB_QUERY_INTERVAL_SECONDS,
        SMB_EVENT_LOOKBACK_MINUTES,
        ",".join(SMB_IGNORED_NETWORKS),
    )
    analytics_log.info(
        "START | Version=%s | Analytics=%s | SMBQuery=%ss",
        VERSION,
        ANALYTICS,
        SMB_QUERY_INTERVAL_SECONDS,
    )
    print(
        f"Scan Proxy {VERSION} is running. Press Ctrl+C to stop.",
        flush=True,
    )

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
                    log.info(
                        "CONFIG LOADED | Sheet=%s | Rules=%s",
                        sheet,
                        len(rules),
                    )

                if now >= next_file_scan:
                    process_rules(
                        rules,
                        smb,
                        analytics,
                        log,
                    )
                    next_file_scan = (
                        time.monotonic() + FILE_SCAN_INTERVAL_SECONDS
                    )

                if now >= next_analytics:
                    analytics.resolve_pending(smb)
                    analytics.refresh_reports()
                    next_analytics = (
                        time.monotonic() + SMB_QUERY_INTERVAL_SECONDS
                    )
            except Exception:
                log.exception("PROCESSING CYCLE ERROR")

            STOP.wait(MAIN_LOOP_SLEEP_SECONDS)
    finally:
        try:
            analytics.resolve_pending(smb)
            analytics.refresh_reports()
        except Exception:
            analytics_log.exception("ANALYTICS ERROR | Shutdown refresh")

        if os.name == "nt" and mutex not in (True, False):
            ctypes.WinDLL("kernel32").CloseHandle(
                ctypes.c_void_p(mutex)
            )

        analytics_log.info("STOP")
        log.info("STOP")
        print("Scan Proxy stopped.", flush=True)


if __name__ == "__main__":
    main()
