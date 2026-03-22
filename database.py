#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AbuseIPDB Checker — SQLite Database Layer
Provides local caching and historical lookup storage.
"""

import sqlite3
import datetime
import logging
import threading
from pathlib import Path

DB_PATH = Path("abuseipdb.db")

# Thread-local storage for per-thread connections
_local = threading.local()

# Fields stored per IP check
RESULT_FIELDS = [
    "ip", "risk", "confidence", "reports", "country", "isp",
    "usage_type", "asn", "domain", "hostnames", "city",
    "first_report_utc", "last_report_utc", "link", "found",
    "duration", "attempts", "session_type", "error",
]

# Mapping from result dict keys to DB column names
_KEY_TO_COL = {
    "IP": "ip",
    "Risk": "risk",
    "Confidence": "confidence",
    "Reports": "reports",
    "Country": "country",
    "ISP": "isp",
    "Usage Type": "usage_type",
    "ASN": "asn",
    "Domain": "domain",
    "Hostname(s)": "hostnames",
    "City": "city",
    "First Report UTC": "first_report_utc",
    "Last Report UTC": "last_report_utc",
    "Link": "link",
    "Found": "found",
    "Duration": "duration",
    "Attempts": "attempts",
    "SessionType": "session_type",
    "error": "error",
}

_COL_TO_KEY = {v: k for k, v in _KEY_TO_COL.items()}


def _get_conn() -> sqlite3.Connection:
    """Get a thread-local SQLite connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        _local.conn = sqlite3.connect(str(DB_PATH), timeout=10)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


def init_db():
    """Create tables if they don't exist."""
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ip_checks (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ip            TEXT    NOT NULL,
            risk          TEXT,
            confidence    INTEGER,
            reports       INTEGER,
            country       TEXT,
            isp           TEXT,
            usage_type    TEXT,
            asn           TEXT,
            domain        TEXT,
            hostnames     TEXT,
            city          TEXT,
            first_report_utc TEXT,
            last_report_utc  TEXT,
            link          TEXT,
            found         INTEGER,
            duration      REAL,
            attempts      INTEGER,
            session_type  TEXT,
            error         TEXT,
            checked_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_ip_checks_ip ON ip_checks(ip)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_ip_checks_checked_at ON ip_checks(checked_at)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_ip_checks_risk ON ip_checks(risk)
    """)
    conn.commit()
    logging.info("Database initialized at %s", DB_PATH)


def _result_to_row(result: dict) -> dict:
    """Convert a result dict (with display keys) to DB column dict."""
    row = {}
    for display_key, col_name in _KEY_TO_COL.items():
        val = result.get(display_key)
        if col_name == "found" and val is not None:
            val = 1 if val else 0
        row[col_name] = val
    return row


def _row_to_result(row: sqlite3.Row) -> dict:
    """Convert a DB row back to a result dict (with display keys)."""
    result = {}
    for col_name in RESULT_FIELDS:
        display_key = _COL_TO_KEY.get(col_name, col_name)
        val = row[col_name]
        if col_name == "found":
            val = bool(val) if val is not None else None
        result[display_key] = val
    result["checked_at"] = row["checked_at"]
    result["db_id"] = row["id"]
    return result


def store_result(result: dict):
    """Store a single check result in the database."""
    conn = _get_conn()
    row = _result_to_row(result)
    cols = ", ".join(row.keys())
    placeholders = ", ".join(["?"] * len(row))
    try:
        conn.execute(
            f"INSERT INTO ip_checks ({cols}) VALUES ({placeholders})",
            list(row.values())
        )
        conn.commit()
    except Exception:
        logging.exception("Failed to store result for %s", result.get("IP"))


def get_cached(ip: str, ttl_hours: float = 24.0) -> dict | None:
    """
    Return the most recent cached result for an IP if it's within the TTL.
    Returns None if no valid cache entry exists.
    """
    conn = _get_conn()
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(hours=ttl_hours)
    cursor = conn.execute(
        """SELECT * FROM ip_checks
           WHERE ip = ? AND checked_at >= ? AND error IS NULL
           ORDER BY checked_at DESC LIMIT 1""",
        (ip, cutoff.strftime("%Y-%m-%d %H:%M:%S"))
    )
    row = cursor.fetchone()
    if row is None:
        return None
    result = _row_to_result(row)
    result["_cached"] = True
    logging.debug("Cache hit for %s (checked_at=%s)", ip, row["checked_at"])
    return result


def get_history(
    ip_filter: str = "",
    risk_filter: str = "",
    limit: int = 500,
    offset: int = 0,
) -> list[dict]:
    """Query historical results with optional filters."""
    conn = _get_conn()
    clauses = []
    params = []

    if ip_filter:
        clauses.append("ip LIKE ?")
        params.append(f"%{ip_filter}%")
    if risk_filter and risk_filter != "All":
        clauses.append("risk = ?")
        params.append(risk_filter)

    where = ""
    if clauses:
        where = "WHERE " + " AND ".join(clauses)

    cursor = conn.execute(
        f"SELECT * FROM ip_checks {where} ORDER BY checked_at DESC LIMIT ? OFFSET ?",
        params + [limit, offset]
    )
    return [_row_to_result(row) for row in cursor.fetchall()]


def get_history_count(ip_filter: str = "", risk_filter: str = "") -> int:
    """Count historical records matching filters."""
    conn = _get_conn()
    clauses = []
    params = []

    if ip_filter:
        clauses.append("ip LIKE ?")
        params.append(f"%{ip_filter}%")
    if risk_filter and risk_filter != "All":
        clauses.append("risk = ?")
        params.append(risk_filter)

    where = ""
    if clauses:
        where = "WHERE " + " AND ".join(clauses)

    cursor = conn.execute(f"SELECT COUNT(*) FROM ip_checks {where}", params)
    return cursor.fetchone()[0]


def get_stats() -> dict:
    """Return summary statistics from the database."""
    conn = _get_conn()

    total = conn.execute("SELECT COUNT(*) FROM ip_checks").fetchone()[0]
    unique_ips = conn.execute("SELECT COUNT(DISTINCT ip) FROM ip_checks").fetchone()[0]
    errors = conn.execute("SELECT COUNT(*) FROM ip_checks WHERE error IS NOT NULL").fetchone()[0]

    risk_counts = {}
    for row in conn.execute(
        "SELECT risk, COUNT(*) as cnt FROM ip_checks WHERE error IS NULL GROUP BY risk ORDER BY cnt DESC"
    ):
        risk_counts[row["risk"] or "Unknown"] = row["cnt"]

    top_countries = []
    for row in conn.execute(
        "SELECT country, COUNT(*) as cnt FROM ip_checks WHERE country != '' AND country IS NOT NULL "
        "GROUP BY country ORDER BY cnt DESC LIMIT 10"
    ):
        top_countries.append({"country": row["country"], "count": row["cnt"]})

    recent = None
    row = conn.execute("SELECT checked_at FROM ip_checks ORDER BY checked_at DESC LIMIT 1").fetchone()
    if row:
        recent = row["checked_at"]

    return {
        "total_checks": total,
        "unique_ips": unique_ips,
        "errors": errors,
        "risk_counts": risk_counts,
        "top_countries": top_countries,
        "last_check": recent,
    }


def delete_old_records(days: int = 90) -> int:
    """Delete records older than the given number of days. Returns count deleted."""
    conn = _get_conn()
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=days)
    cursor = conn.execute(
        "DELETE FROM ip_checks WHERE checked_at < ?",
        (cutoff.strftime("%Y-%m-%d %H:%M:%S"),)
    )
    conn.commit()
    deleted = cursor.rowcount
    logging.info("Purged %d records older than %d days", deleted, days)
    return deleted


def get_ip_timeline(ip: str) -> list[dict]:
    """Get all historical checks for a specific IP, ordered by date."""
    conn = _get_conn()
    cursor = conn.execute(
        "SELECT * FROM ip_checks WHERE ip = ? ORDER BY checked_at ASC",
        (ip,)
    )
    return [_row_to_result(row) for row in cursor.fetchall()]
