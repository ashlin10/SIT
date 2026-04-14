"""
Persistent dashboard metrics storage using SQLite.
All metrics are global (not per-user) and survive app reboots.
"""

import os
import sqlite3
import time
import threading
import psutil
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DB_DIR, "dashboard_metrics.db")

_local = threading.local()


def _get_conn() -> sqlite3.Connection:
    """Thread-local SQLite connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        os.makedirs(DB_DIR, exist_ok=True)
        _local.conn = sqlite3.connect(DB_PATH, timeout=10)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA busy_timeout=5000")
    return _local.conn


def init_db():
    """Create tables if they don't exist."""
    conn = _get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS request_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            method TEXT,
            path TEXT,
            status_code INTEGER,
            response_time_ms REAL,
            username TEXT,
            is_error INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS system_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            cpu_percent REAL,
            memory_percent REAL,
            memory_used_mb REAL,
            memory_total_mb REAL,
            disk_percent REAL,
            uptime_seconds REAL
        );

        CREATE TABLE IF NOT EXISTS user_activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT
        );

        CREATE TABLE IF NOT EXISTS active_user_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            active_count INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_request_log_ts ON request_log(ts);
        CREATE INDEX IF NOT EXISTS idx_system_snapshots_ts ON system_snapshots(ts);
        CREATE INDEX IF NOT EXISTS idx_user_activity_ts ON user_activity_log(ts);
        CREATE INDEX IF NOT EXISTS idx_active_user_ts ON active_user_snapshots(ts);
    """)
    conn.commit()


# ── Write helpers ──

def record_request(method: str, path: str, status_code: int,
                   response_time_ms: float, username: Optional[str] = None):
    """Record an HTTP request for RPM, error rate, response time metrics."""
    try:
        conn = _get_conn()
        is_error = 1 if status_code >= 400 else 0
        conn.execute(
            "INSERT INTO request_log (ts, method, path, status_code, response_time_ms, username, is_error) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), method, path, status_code,
             response_time_ms, username, is_error)
        )
        conn.commit()
    except Exception:
        pass


def record_system_snapshot():
    """Capture current CPU, memory, disk, uptime and store it."""
    try:
        conn = _get_conn()
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        uptime = time.time() - psutil.boot_time()
        conn.execute(
            "INSERT INTO system_snapshots (ts, cpu_percent, memory_percent, memory_used_mb, memory_total_mb, disk_percent, uptime_seconds) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), cpu, mem.percent,
             mem.used / (1024 * 1024), mem.total / (1024 * 1024),
             disk.percent, uptime)
        )
        conn.commit()
    except Exception:
        pass


def record_activity(username: str, action: str, details: Optional[str] = None):
    """Persist a user activity event."""
    try:
        conn = _get_conn()
        conn.execute(
            "INSERT INTO user_activity_log (ts, username, action, details) VALUES (?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), username, action, details)
        )
        conn.commit()
    except Exception:
        pass


def record_active_user_count(count: int):
    """Snapshot of how many users are currently online."""
    try:
        conn = _get_conn()
        conn.execute(
            "INSERT INTO active_user_snapshots (ts, active_count) VALUES (?, ?)",
            (datetime.now(timezone.utc).isoformat(), count)
        )
        conn.commit()
    except Exception:
        pass


# ── Read helpers ──

def _cutoff(range_key: str) -> str:
    """Return ISO timestamp for the given range key."""
    now = datetime.now(timezone.utc)
    deltas = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7)}
    d = deltas.get(range_key, timedelta(hours=1))
    return (now - d).isoformat()


def get_key_metrics(range_key: str = "1h") -> Dict[str, Any]:
    """Active Users, RPM, Error Rate %, Avg Response Time ms."""
    conn = _get_conn()
    cutoff = _cutoff(range_key)

    # Active users (latest snapshot)
    row = conn.execute(
        "SELECT active_count FROM active_user_snapshots ORDER BY ts DESC LIMIT 1"
    ).fetchone()
    active_users = row["active_count"] if row else 0

    # Previous snapshot for trend
    prev_row = conn.execute(
        "SELECT active_count FROM active_user_snapshots WHERE ts < ? ORDER BY ts DESC LIMIT 1",
        (cutoff,)
    ).fetchone()
    prev_active = prev_row["active_count"] if prev_row else active_users

    # Request metrics in range
    req = conn.execute(
        "SELECT COUNT(*) as cnt, SUM(is_error) as errs, AVG(response_time_ms) as avg_rt "
        "FROM request_log WHERE ts >= ?", (cutoff,)
    ).fetchone()

    total_requests = req["cnt"] or 0
    total_errors = req["errs"] or 0
    avg_response_time = round(req["avg_rt"] or 0, 1)

    # RPM
    range_minutes = {"1h": 60, "24h": 1440, "7d": 10080}.get(range_key, 60)
    rpm = round(total_requests / max(range_minutes, 1), 1)

    # Error rate
    error_rate = round((total_errors / max(total_requests, 1)) * 100, 2)

    return {
        "active_users": active_users,
        "active_users_prev": prev_active,
        "rpm": rpm,
        "error_rate": error_rate,
        "avg_response_time": avg_response_time,
        "total_requests": total_requests,
        "total_errors": int(total_errors),
    }


def get_request_timeseries(range_key: str = "1h", buckets: int = 30) -> List[Dict[str, Any]]:
    """Bucketed requests-over-time and error counts for chart."""
    conn = _get_conn()
    cutoff = _cutoff(range_key)
    now = datetime.now(timezone.utc)
    delta = now - datetime.fromisoformat(cutoff.replace("Z", "+00:00") if cutoff.endswith("Z") else cutoff)
    bucket_seconds = max(delta.total_seconds() / buckets, 1)

    rows = conn.execute(
        "SELECT ts, is_error, response_time_ms FROM request_log WHERE ts >= ? ORDER BY ts",
        (cutoff,)
    ).fetchall()

    result = []
    for i in range(buckets):
        bucket_start = datetime.fromisoformat(cutoff.replace("Z", "+00:00") if cutoff.endswith("Z") else cutoff) + timedelta(seconds=i * bucket_seconds)
        bucket_end = bucket_start + timedelta(seconds=bucket_seconds)
        bucket_rows = [r for r in rows if bucket_start.isoformat() <= r["ts"] < bucket_end.isoformat()]
        count = len(bucket_rows)
        errors = sum(1 for r in bucket_rows if r["is_error"])
        avg_rt = round(sum(r["response_time_ms"] for r in bucket_rows) / max(count, 1), 1) if count else 0
        result.append({
            "time": bucket_start.strftime("%H:%M"),
            "requests": count,
            "errors": errors,
            "avg_rt": avg_rt,
        })
    return result


def get_user_activity_timeseries(range_key: str = "1h", buckets: int = 30) -> List[Dict[str, Any]]:
    """Bucketed active user count over time for chart."""
    conn = _get_conn()
    cutoff = _cutoff(range_key)
    now = datetime.now(timezone.utc)
    delta = now - datetime.fromisoformat(cutoff.replace("Z", "+00:00") if cutoff.endswith("Z") else cutoff)
    bucket_seconds = max(delta.total_seconds() / buckets, 1)

    rows = conn.execute(
        "SELECT ts, active_count FROM active_user_snapshots WHERE ts >= ? ORDER BY ts",
        (cutoff,)
    ).fetchall()

    result = []
    for i in range(buckets):
        bucket_start = datetime.fromisoformat(cutoff.replace("Z", "+00:00") if cutoff.endswith("Z") else cutoff) + timedelta(seconds=i * bucket_seconds)
        bucket_end = bucket_start + timedelta(seconds=bucket_seconds)
        bucket_rows = [r for r in rows if bucket_start.isoformat() <= r["ts"] < bucket_end.isoformat()]
        avg_count = round(sum(r["active_count"] for r in bucket_rows) / max(len(bucket_rows), 1), 1) if bucket_rows else 0
        time_fmt = "%b %d %H:%M" if range_key == "7d" else "%H:%M"
        result.append({
            "time": bucket_start.strftime(time_fmt),
            "users": avg_count,
        })
    return result


def get_system_health() -> Dict[str, Any]:
    """Latest system snapshot + server status classification."""
    conn = _get_conn()
    row = conn.execute(
        "SELECT * FROM system_snapshots ORDER BY ts DESC LIMIT 1"
    ).fetchone()
    if not row:
        return {
            "cpu_percent": 0, "memory_percent": 0,
            "memory_used_mb": 0, "memory_total_mb": 0,
            "disk_percent": 0, "uptime_seconds": 0,
            "status": "unknown",
        }

    cpu = row["cpu_percent"]
    mem = row["memory_percent"]
    status = "healthy"
    if cpu > 90 or mem > 90:
        status = "critical"
    elif cpu > 70 or mem > 70:
        status = "warning"

    return {
        "cpu_percent": round(cpu, 1),
        "memory_percent": round(mem, 1),
        "memory_used_mb": round(row["memory_used_mb"], 0),
        "memory_total_mb": round(row["memory_total_mb"], 0),
        "disk_percent": round(row["disk_percent"], 1),
        "uptime_seconds": round(row["uptime_seconds"], 0),
        "status": status,
    }


def get_system_timeseries(range_key: str = "1h", buckets: int = 30) -> List[Dict[str, Any]]:
    """CPU + memory over time for sparklines."""
    conn = _get_conn()
    cutoff = _cutoff(range_key)
    now = datetime.now(timezone.utc)
    delta = now - datetime.fromisoformat(cutoff.replace("Z", "+00:00") if cutoff.endswith("Z") else cutoff)
    bucket_seconds = max(delta.total_seconds() / buckets, 1)

    rows = conn.execute(
        "SELECT ts, cpu_percent, memory_percent FROM system_snapshots WHERE ts >= ? ORDER BY ts",
        (cutoff,)
    ).fetchall()

    result = []
    for i in range(buckets):
        bucket_start = datetime.fromisoformat(cutoff.replace("Z", "+00:00") if cutoff.endswith("Z") else cutoff) + timedelta(seconds=i * bucket_seconds)
        bucket_end = bucket_start + timedelta(seconds=bucket_seconds)
        bucket_rows = [r for r in rows if bucket_start.isoformat() <= r["ts"] < bucket_end.isoformat()]
        avg_cpu = round(sum(r["cpu_percent"] for r in bucket_rows) / max(len(bucket_rows), 1), 1) if bucket_rows else 0
        avg_mem = round(sum(r["memory_percent"] for r in bucket_rows) / max(len(bucket_rows), 1), 1) if bucket_rows else 0
        result.append({
            "time": bucket_start.strftime("%H:%M"),
            "cpu": avg_cpu,
            "memory": avg_mem,
        })
    return result


def get_recent_activities(limit: int = 50) -> List[Dict[str, Any]]:
    """Get recent activities from persistent store."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT ts, username, action, details FROM user_activity_log ORDER BY ts DESC LIMIT ?",
        (limit,)
    ).fetchall()
    return [dict(r) for r in rows]


def get_top_active_users(range_key: str = "1h", limit: int = 10) -> List[Dict[str, Any]]:
    """Top users by activity count in the given range."""
    conn = _get_conn()
    cutoff = _cutoff(range_key)
    rows = conn.execute(
        "SELECT username, COUNT(*) as actions FROM user_activity_log "
        "WHERE ts >= ? GROUP BY username ORDER BY actions DESC LIMIT ?",
        (cutoff, limit)
    ).fetchall()
    return [dict(r) for r in rows]


def cleanup_old_data(days: int = 30):
    """Remove data older than N days to keep DB lean."""
    try:
        conn = _get_conn()
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        conn.execute("DELETE FROM request_log WHERE ts < ?", (cutoff,))
        conn.execute("DELETE FROM system_snapshots WHERE ts < ?", (cutoff,))
        conn.execute("DELETE FROM user_activity_log WHERE ts < ?", (cutoff,))
        conn.execute("DELETE FROM active_user_snapshots WHERE ts < ?", (cutoff,))
        conn.commit()
    except Exception:
        pass
