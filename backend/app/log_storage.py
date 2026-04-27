"""Request log persistence and retrieval backed by SQLite."""

from __future__ import annotations

import asyncio
import ast
import json
import sqlite3
import math
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(val) for key, val in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    return repr(value)


def _normalize_details(details: Dict[str, Any] | None) -> Dict[str, Any] | None:
    if details is None:
        return None
    if not isinstance(details, dict):
        return {"_raw": repr(details)}
    try:
        return _json_safe(details)
    except Exception:
        return {"_raw": repr(details)}


@dataclass
class LogEntry:
    """Structured log entry for LNURL interactions."""

    timestamp: str
    username: str
    ip: str
    event: str
    domain: str | None = None
    amount_msat: int | None = None
    status: str = "ok"
    message: str | None = None
    details: Dict[str, Any] | None = None

    @classmethod
    def create(
        cls,
        *,
        username: str,
        ip: str,
        event: str,
        domain: str | None = None,
        amount_msat: int | None = None,
        status: str = "ok",
        message: str | None = None,
        details: Dict[str, Any] | None = None,
    ) -> "LogEntry":
        return cls(
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            username=username,
            ip=ip,
            event=event,
            domain=domain,
            amount_msat=amount_msat,
            status=status,
            message=message,
            details=_normalize_details(details),
        )


@dataclass
class InvoiceEvent:
    id: int
    username: str
    domain: str | None
    ip: str | None
    amount_msat: int
    payment_hash: str | None
    payment_request: str | None
    request_log_id: int | None
    created_at: str
    next_check_at: str | None
    check_interval_seconds: int
    expires_at: str | None
    settled: bool
    expired: bool
    details: Dict[str, Any] | None
    settled_at: str | None


class RequestLogStorage:
    """Handles storage and retrieval of request logs using SQLite."""

    def __init__(
        self,
        path: Path,
        *,
        max_recent: int = 50,
        retention_days: int = 30,
    ) -> None:
        self._path = path
        self._max_recent = max_recent
        self._retention_days = max(1, retention_days)
        self._recent: Deque[Dict[str, object]] = deque(maxlen=max_recent)
        self._lock = asyncio.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._load_recent()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS request_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    username TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    event TEXT NOT NULL,
                    domain TEXT,
                    amount_msat INTEGER,
                    status TEXT NOT NULL,
                    message TEXT,
                    details TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS invoice_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    username TEXT NOT NULL,
                    domain TEXT,
                    ip TEXT,
                    amount_msat INTEGER NOT NULL,
                    payment_hash TEXT,
                    payment_request TEXT,
                    details TEXT,
                    request_log_id INTEGER,
                    settled INTEGER NOT NULL DEFAULT 0,
                    expired INTEGER NOT NULL DEFAULT 0,
                    last_checked_at TEXT,
                    next_check_at TEXT,
                    expires_at TEXT,
                    settled_at TEXT,
                    check_interval_seconds INTEGER NOT NULL DEFAULT 60
                )
                """
            )
            self._ensure_invoice_event_columns(conn)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(timestamp)")
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_invoice_events_payment_hash ON invoice_events(payment_hash)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_invoice_events_next_check ON invoice_events(next_check_at)"
            )

    def _ensure_invoice_event_columns(self, conn: sqlite3.Connection) -> None:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(invoice_events)")}
        alterations = {
            "request_log_id": "INTEGER",
            "settled": "INTEGER NOT NULL DEFAULT 0",
            "expired": "INTEGER NOT NULL DEFAULT 0",
            "last_checked_at": "TEXT",
            "next_check_at": "TEXT",
            "expires_at": "TEXT",
            "settled_at": "TEXT",
            "check_interval_seconds": "INTEGER NOT NULL DEFAULT 60",
        }
        for column, ddl in alterations.items():
            if column not in columns:
                conn.execute(f"ALTER TABLE invoice_events ADD COLUMN {column} {ddl}")

    def _load_recent(self) -> None:
        try:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT id, timestamp, username, ip, event, domain, amount_msat, status, message, details
                    FROM request_logs
                    ORDER BY datetime(timestamp) DESC
                    LIMIT ?
                    """,
                    (self._max_recent,),
                ).fetchall()
        except sqlite3.Error:
            return
        for row in reversed(rows):
            payload = self._row_to_payload(row)
            self._recent.append(payload)

    def _row_to_payload(self, row: sqlite3.Row) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "username": row["username"],
            "ip": row["ip"],
            "event": row["event"],
            "domain": row["domain"],
            "amount_msat": row["amount_msat"],
            "status": row["status"],
            "message": row["message"],
            "details": self._deserialize_details(row["details"]),
        }
        payload.setdefault("domain", None)
        return payload

    def _row_to_invoice_event(self, row: sqlite3.Row) -> InvoiceEvent:
        return InvoiceEvent(
            id=row["id"],
            username=row["username"],
            domain=row["domain"],
            ip=row["ip"],
            amount_msat=row["amount_msat"],
            payment_hash=row["payment_hash"],
            payment_request=row["payment_request"],
            request_log_id=row["request_log_id"],
            created_at=row["created_at"],
            next_check_at=row["next_check_at"],
            check_interval_seconds=row["check_interval_seconds"],
            expires_at=row["expires_at"],
            settled=bool(row["settled"]),
            expired=bool(row["expired"]),
            details=self._deserialize_details(row["details"]),
            settled_at=row["settled_at"],
        )

    def _serialize_details(self, details: Any) -> Optional[str]:
        if details is None:
            return None
        try:
            safe = _json_safe(details)
            return json.dumps(safe)
        except (TypeError, ValueError):
            return json.dumps({"_raw": repr(details)})

    def _deserialize_details(self, payload: Any) -> Any:
        if payload is None:
            return None
        if isinstance(payload, str):
            try:
                data = json.loads(payload)
                return data
            except json.JSONDecodeError:
                try:
                    data = ast.literal_eval(payload)
                    if isinstance(data, (dict, list)):
                        return _json_safe(data)
                except (ValueError, SyntaxError):
                    pass
                return {"_raw": payload}
        return payload

    def _parse_timestamp(self, value: Any) -> Optional[datetime]:
        if not isinstance(value, str):
            return None
        candidate = value.strip()
        if not candidate:
            return None
        if candidate.endswith("Z"):
            candidate = f"{candidate[:-1]}+00:00"
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            return None

    async def append(self, entry: LogEntry) -> Optional[int]:
        payload = asdict(entry)
        row_id: Optional[int] = None
        async with self._lock:
            try:
                with self._connect() as conn:
                    cursor = conn.execute(
                        """
                        INSERT INTO request_logs (
                            timestamp, username, ip, event, domain, amount_msat, status, message, details
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            payload["timestamp"],
                            payload["username"],
                            payload["ip"],
                            payload["event"],
                            payload.get("domain"),
                            payload.get("amount_msat"),
                            payload.get("status"),
                            payload.get("message"),
                            self._serialize_details(payload.get("details")),
                        ),
                    )
                    row_id = cursor.lastrowid
            except sqlite3.Error:
                pass
            payload.setdefault("domain", None)
            payload.setdefault("id", row_id)
            self._recent.append(payload)
        await self.cleanup()
        return row_id

    async def get_recent(self, limit: int | None = None) -> List[Dict[str, object]]:
        async with self._lock:
            recent_items = list(self._recent)
        if limit is not None:
            return recent_items[-limit:]
        return recent_items

    async def clear(self) -> None:
        async with self._lock:
            self._recent.clear()
            try:
                with self._connect() as conn:
                    conn.execute("DELETE FROM request_logs")
            except sqlite3.Error:
                return

    async def cleanup(self) -> None:
        cutoff = datetime.now(tz=timezone.utc) - timedelta(days=self._retention_days)
        async with self._lock:
            try:
                with self._connect() as conn:
                    conn.execute(
                        "DELETE FROM request_logs WHERE timestamp < ?",
                        (cutoff.isoformat(),),
                    )
            except sqlite3.Error:
                return
            filtered = deque(maxlen=self._max_recent)
            for entry in self._recent:
                ts = self._parse_timestamp(entry.get("timestamp"))
                if ts and ts >= cutoff:
                    filtered.append(entry)
            self._recent = filtered

    def _update_recent_entry(
        self,
        log_id: Optional[int],
        *,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        if log_id is None:
            return
        for entry in self._recent:
            if entry.get("id") == log_id:
                if details is not None:
                    entry["details"] = _normalize_details(details)
                break

    async def log_invoice_event(
        self,
        *,
        username: str,
        domain: str | None,
        amount_msat: int,
        ip: str | None = None,
        payment_hash: str | None = None,
        payment_request: str | None = None,
        details: Dict[str, Any] | None = None,
        request_log_id: int | None = None,
        expires_at: str | None = None,
    ) -> None:
        created_at = datetime.now(tz=timezone.utc).isoformat()
        next_check_at = created_at
        async with self._lock:
            try:
                with self._connect() as conn:
                    conn.execute(
                        """
                        INSERT INTO invoice_events (
                            created_at,
                            username,
                            domain,
                            ip,
                            amount_msat,
                            payment_hash,
                            payment_request,
                            details,
                            request_log_id,
                            settled,
                            expired,
                            last_checked_at,
                            next_check_at,
                            expires_at,
                            settled_at,
                            check_interval_seconds
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, NULL, ?, ?, NULL, 60)
                        """,
                        (
                            created_at,
                            username,
                            domain,
                            ip,
                            amount_msat,
                            payment_hash,
                            payment_request,
                            self._serialize_details(details),
                            request_log_id,
                            next_check_at,
                            expires_at,
                        ),
                    )
            except sqlite3.Error:
                return

    async def get_due_invoice_events(self, limit: int = 50) -> List[InvoiceEvent]:
        now_iso = datetime.now(tz=timezone.utc).isoformat()
        async with self._lock:
            try:
                with self._connect() as conn:
                    rows = conn.execute(
                        """
                        SELECT
                            id,
                            username,
                            domain,
                            ip,
                            amount_msat,
                            payment_hash,
                            payment_request,
                            details,
                            request_log_id,
                            created_at,
                            next_check_at,
                            check_interval_seconds,
                            expires_at,
                            settled,
                            expired,
                            settled_at
                        FROM invoice_events
                        WHERE settled = 0
                          AND expired = 0
                          AND (next_check_at IS NULL OR next_check_at <= ?)
                        ORDER BY COALESCE(next_check_at, created_at)
                        LIMIT ?
                        """,
                        (now_iso, limit),
                    ).fetchall()
            except sqlite3.Error:
                return []
        return [self._row_to_invoice_event(row) for row in rows]

    async def get_invoice_event_by_hash(self, payment_hash: str) -> Optional[InvoiceEvent]:
        normalized = (payment_hash or "").strip().lower()
        if not normalized:
            return None
        async with self._lock:
            try:
                with self._connect() as conn:
                    row = conn.execute(
                        """
                        SELECT
                            id,
                            username,
                            domain,
                            ip,
                            amount_msat,
                            payment_hash,
                            payment_request,
                            details,
                            request_log_id,
                            created_at,
                            next_check_at,
                            check_interval_seconds,
                            expires_at,
                            settled,
                            expired,
                            settled_at
                        FROM invoice_events
                        WHERE LOWER(payment_hash) = ?
                        LIMIT 1
                        """,
                        (normalized,),
                    ).fetchone()
            except sqlite3.Error:
                return None
        if not row:
            return None
        return self._row_to_invoice_event(row)

    async def get_unsettled_invoice_events(
        self,
        *,
        limit: int = 50,
        min_id: int | None = None,
    ) -> List[InvoiceEvent]:
        limit = max(1, limit)
        params: List[Any] = []
        where = "WHERE settled = 0 AND expired = 0"
        if min_id is not None:
            where += " AND id > ?"
            params.append(int(min_id))
        params.append(limit)
        async with self._lock:
            try:
                with self._connect() as conn:
                    rows = conn.execute(
                        f"""
                        SELECT
                            id,
                            username,
                            domain,
                            ip,
                            amount_msat,
                            payment_hash,
                            payment_request,
                            details,
                            request_log_id,
                            created_at,
                            next_check_at,
                            check_interval_seconds,
                            expires_at,
                            settled,
                            expired,
                            settled_at
                        FROM invoice_events
                        {where}
                        ORDER BY id
                        LIMIT ?
                        """,
                        tuple(params),
                    ).fetchall()
            except sqlite3.Error:
                return []
        return [self._row_to_invoice_event(row) for row in rows]

    async def apply_invoice_event_update(
        self,
        *,
        event: InvoiceEvent,
        details: Dict[str, Any] | None,
        settled: bool,
        expired: bool,
        next_check: Optional[datetime],
        expires_at: Optional[datetime],
        interval_seconds: int,
        settled_at: Optional[datetime],
    ) -> None:
        serialized_details = self._serialize_details(details)
        now_iso = datetime.now(tz=timezone.utc).isoformat()
        next_check_iso = next_check.isoformat() if next_check else None
        expires_at_iso = (
            expires_at.isoformat() if expires_at else (event.expires_at if event.expires_at else None)
        )
        settled_at_iso = (
            settled_at.isoformat()
            if settled_at
            else (event.settled_at if event.settled_at else None)
        )
        async with self._lock:
            try:
                with self._connect() as conn:
                    conn.execute(
                        """
                        UPDATE invoice_events
                        SET
                            details = ?,
                            settled = ?,
                            expired = ?,
                            last_checked_at = ?,
                            next_check_at = ?,
                            expires_at = COALESCE(?, expires_at),
                            settled_at = COALESCE(?, settled_at),
                            check_interval_seconds = ?
                        WHERE id = ?
                        """,
                        (
                            serialized_details,
                            1 if settled else 0,
                            1 if expired else 0,
                            now_iso,
                            next_check_iso,
                            expires_at_iso,
                            settled_at_iso,
                            interval_seconds,
                            event.id,
                        ),
                    )
                    if event.request_log_id is not None and serialized_details is not None:
                        conn.execute(
                            """
                            UPDATE request_logs
                            SET details = ?
                            WHERE id = ?
                            """,
                            (serialized_details, event.request_log_id),
                        )
            except sqlite3.Error:
                return
            if event.request_log_id is not None and isinstance(details, dict):
                self._update_recent_entry(event.request_log_id, details=details)

    async def list_invoice_events(
        self,
        *,
        page: int = 1,
        page_size: int = 20,
        query: str = "",
    ) -> Dict[str, Any]:
        page = max(1, page)
        normalized_size = max(1, min(100, page_size))
        offset = (page - 1) * normalized_size
        search = query.strip().lower()
        where_clause = ""
        params: List[Any] = []
        if search:
            like = f"%{search}%"
            where_clause = """
                WHERE LOWER(username) LIKE ?
                   OR LOWER(domain) LIKE ?
                   OR LOWER(COALESCE(payment_hash, '')) LIKE ?
                   OR LOWER(COALESCE(payment_request, '')) LIKE ?
                   OR LOWER(COALESCE(details, '')) LIKE ?
            """
            params.extend([like, like, like, like, like])

        async with self._lock:
            try:
                with self._connect() as conn:
                    total_row = conn.execute(
                        f"SELECT COUNT(*) FROM invoice_events {where_clause}",
                        tuple(params),
                    ).fetchone()
                    total_items = int(total_row[0]) if total_row else 0
                    query_params = list(params)
                    query_params.extend([normalized_size, offset])
                    rows = conn.execute(
                        f"""
                        SELECT
                            id,
                            created_at,
                            username,
                            domain,
                            ip,
                            amount_msat,
                            payment_hash,
                            payment_request,
                            settled,
                            expired,
                            details,
                            next_check_at,
                            last_checked_at,
                            expires_at,
                            request_log_id,
                            settled_at
                        FROM invoice_events
                        {where_clause}
                        ORDER BY datetime(created_at) DESC, id DESC
                        LIMIT ? OFFSET ?
                        """,
                        tuple(query_params),
                    ).fetchall()
            except sqlite3.Error:
                total_items = 0
                rows = []

        items: List[Dict[str, Any]] = []
        for row in rows:
            amount_msat = row["amount_msat"]
            if not isinstance(amount_msat, int):
                amount_msat = None
            details = self._deserialize_details(row["details"])
            settled = bool(row["settled"])
            expired = bool(row["expired"])
            forwarded = isinstance(details, dict) and bool(details.get("forwarded"))
            items.append(
                {
                    "id": row["id"],
                    "created_at": row["created_at"],
                    "username": row["username"],
                    "domain": row["domain"],
                    "ip": row["ip"],
                    "amount_msat": amount_msat,
                    "amount_sat": amount_msat // 1000 if isinstance(amount_msat, int) else None,
                    "payment_hash": row["payment_hash"],
                    "payment_request": row["payment_request"],
                    "settled": settled,
                    "expired": expired,
                    "status": "forwarded" if forwarded else ("settled" if settled else ("expired" if expired else "pending")),
                    "next_check_at": row["next_check_at"],
                    "last_checked_at": row["last_checked_at"],
                    "expires_at": row["expires_at"],
                    "details": details,
                    "request_log_id": row["request_log_id"],
                    "settled_at": row["settled_at"],
                }
            )

        total_pages = math.ceil(total_items / normalized_size) if total_items else 0
        current_page = page if total_pages else 1

        return {
            "items": items,
            "page": current_page,
            "page_size": normalized_size,
            "total_items": total_items,
            "total_pages": total_pages,
            "has_next": current_page < total_pages,
            "has_prev": total_pages > 0 and current_page > 1,
            "query": query,
        }

    async def get_invoice_summary(self) -> Dict[str, int]:
        cutoff_24h = (datetime.now(tz=timezone.utc) - timedelta(hours=24)).isoformat()
        cutoff_7d = (datetime.now(tz=timezone.utc) - timedelta(days=7)).isoformat()
        async with self._lock:
            try:
                with self._connect() as conn:
                    row = conn.execute(
                        """
                        SELECT
                            COUNT(*) AS total,
                            SUM(CASE WHEN settled = 1 THEN 1 ELSE 0 END) AS settled,
                            SUM(
                                CASE
                                    WHEN settled = 1
                                         AND COALESCE(settled_at, last_checked_at, created_at) >= ?
                                    THEN 1 ELSE 0
                                END
                            ) AS settled_24h,
                            SUM(
                                CASE WHEN settled = 1 THEN COALESCE(amount_msat, 0) ELSE 0 END
                            ) AS sats_total_msat,
                            SUM(
                                CASE
                                    WHEN settled = 1
                                         AND COALESCE(settled_at, last_checked_at, created_at) >= ?
                                    THEN COALESCE(amount_msat, 0)
                                    ELSE 0
                                END
                            ) AS sats_7d_msat
                        FROM invoice_events
                        """,
                        (cutoff_24h, cutoff_7d),
                    ).fetchone()
                    total = row["total"] if row else 0
                    settled = row["settled"] if row else 0
                    settled_24h = row["settled_24h"] if row else 0
                    sats_total_msat = row["sats_total_msat"] if row else 0
                    sats_7d_msat = row["sats_7d_msat"] if row else 0
            except sqlite3.Error:
                total = settled = settled_24h = 0
                sats_total_msat = sats_7d_msat = 0
        total = 0 if total is None else total
        settled = 0 if settled is None else settled
        settled_24h = 0 if settled_24h is None else settled_24h
        sats_total_msat = 0 if sats_total_msat is None else sats_total_msat
        sats_7d_msat = 0 if sats_7d_msat is None else sats_7d_msat
        return {
            "invoices_total": int(total),
            "invoices_paid": int(settled),
            "invoices_paid_24h": int(settled_24h),
            "sats_total_msat": int(sats_total_msat or 0),
            "sats_7d_msat": int(sats_7d_msat or 0),
        }

    async def get_invoice_activity(self, days: int = 14, tz_offset_minutes: int = 0) -> List[Dict[str, int]]:
        if days <= 0:
            return []
        offset_minutes = int(tz_offset_minutes or 0)
        offset_delta = timedelta(minutes=offset_minutes)
        now_utc = datetime.now(tz=timezone.utc)
        local_now = now_utc - offset_delta
        local_start = (local_now - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
        start_dt = local_start + offset_delta
        start_iso = start_dt.isoformat()
        async with self._lock:
            try:
                with self._connect() as conn:
                    rows = conn.execute(
                        """
                        SELECT
                            COALESCE(settled_at, last_checked_at, created_at) AS settled_ts,
                            amount_msat
                        FROM invoice_events
                        WHERE settled = 1
                          AND COALESCE(settled_at, last_checked_at, created_at) >= ?
                        """,
                        (start_iso,),
                    ).fetchall()
            except sqlite3.Error:
                rows = []
        local_series_start_date = local_start.date()
        totals: Dict[str, int] = {}
        counts: Dict[str, int] = {}
        for row in rows:
            ts = row["settled_ts"]
            if not isinstance(ts, str):
                continue
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                continue
            local_dt = dt - offset_delta
            if local_dt.date() < local_series_start_date:
                continue
            key = local_dt.date().isoformat()
            amount_msat = row["amount_msat"] or 0
            totals[key] = totals.get(key, 0) + int(amount_msat)
            counts[key] = counts.get(key, 0) + 1
        series: List[Dict[str, int]] = []
        for offset in range(days):
            day = (local_start + timedelta(days=offset)).date().isoformat()
            sats = totals.get(day, 0) // 1000
            paid = counts.get(day, 0)
            series.append({"date": day, "sats": sats, "paid": paid})
        return series
