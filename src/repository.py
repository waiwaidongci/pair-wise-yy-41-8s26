from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import (ID_PREFIX, READING_KIND, STATES, TRAFFIC_ANNOUNCEMENT_KIND,
                    reading_content_hash)


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        with self.conn:
            self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS gateway_batches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_no TEXT NOT NULL UNIQUE,
                    station TEXT NOT NULL,
                    seq_start INTEGER NOT NULL,
                    seq_end INTEGER NOT NULL,
                    reading_count INTEGER NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('accepted','rejected')),
                    result TEXT,
                    fail_reason TEXT,
                    fail_detail TEXT,
                    external_ref TEXT,
                    received_by TEXT NOT NULL,
                    received_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS gateway_readings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    batch_id INTEGER NOT NULL REFERENCES gateway_batches(id) ON DELETE CASCADE,
                    station TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    measured_at TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(station, seq)
                );
                CREATE INDEX IF NOT EXISTS ix_gateway_readings_station_seq
                    ON gateway_readings(station, seq);
            """)
        # 迁移：为既有 items 补充 alarm_count 列
        cols = [row[1] for row in self.conn.execute("PRAGMA table_info(items)").fetchall()]
        if "alarm_count" not in cols:
            with self.conn:
                self.conn.execute(
                    "ALTER TABLE items ADD COLUMN alarm_count INTEGER NOT NULL DEFAULT 0"
                )

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, actor, now, now),
                )
                item_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous = row["entry_hash"] if row else "GENESIS"
            event = make_entry(action, entity_type, entity_id, actor, detail, previous)
            cur = self.conn.execute(
                """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
                   previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (event["action"], event["entity_type"], event["entity_id"], event["actor"],
                 json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
                 event["previous_hash"], event["entry_hash"], event["created_at"]),
            )
            event_id = int(cur.lastrowid)
        event["id"] = event_id
        return event

    def list_audit(self, entity_id: Optional[int] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: tuple = ()
        if entity_id is not None:
            sql += " WHERE entity_id=?"
            params = (entity_id,)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def verify_audit_chain(self) -> bool:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            payload = {
                "action": row["action"], "entity_type": row["entity_type"],
                "entity_id": row["entity_id"], "actor": row["actor"],
                "detail": json.loads(row["detail"]), "created_at": row["created_at"],
            }
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True

    # ---- 网关批次 ----

    def get_gateway_batch(self, batch_no: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM gateway_batches WHERE batch_no=?", (batch_no,)
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        for key in ("result", "fail_detail"):
            if item.get(key):
                item[key] = json.loads(item[key])
        return item

    def create_gateway_batch(self, batch_no: str, station: str, seq_start: int,
                             seq_end: int, reading_count: int, status: str,
                             result: Optional[dict], fail_reason: Optional[str],
                             fail_detail: Optional[dict], external_ref: Optional[str],
                             actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            self.conn.execute(
                """INSERT INTO gateway_batches(batch_no, station, seq_start, seq_end,
                   reading_count, status, result, fail_reason, fail_detail, external_ref,
                   received_by, received_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (batch_no, station, seq_start, seq_end, reading_count, status,
                 json.dumps(result, ensure_ascii=False, sort_keys=True) if result is not None else None,
                 fail_reason,
                 json.dumps(fail_detail, ensure_ascii=False, sort_keys=True) if fail_detail is not None else None,
                 external_ref, actor, now),
            )
        return self.get_gateway_batch(batch_no)

    def update_gateway_batch_result(self, batch_no: str, result: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            self.conn.execute(
                "UPDATE gateway_batches SET result=? WHERE batch_no=?",
                (json.dumps(result, ensure_ascii=False, sort_keys=True), batch_no),
            )
        return self.get_gateway_batch(batch_no)

    def get_station_hwm(self, station: str) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COALESCE(MAX(seq),0) AS hwm FROM gateway_readings WHERE station=?",
                (station,),
            ).fetchone()
        return int(row["hwm"])

    def get_reading(self, station: str, seq: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM gateway_readings WHERE station=? AND seq=?",
                (station, seq),
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["payload"] = json.loads(item["payload"])
        return item

    def list_gateway_readings(self, station: str) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM gateway_readings WHERE station=? ORDER BY seq",
                (station,),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item["payload"])
            result.append(item)
        return result

    def add_gateway_reading(self, batch_id: int, batch_no: str, item_id: int,
                            station: str, seq: int, reading: Dict[str, Any],
                            actor: str) -> bool:
        """写入一条网关读数，并同步生成一条监测记录。返回是否为新增。"""
        now = utc_now()
        payload = json.dumps(reading, ensure_ascii=False, sort_keys=True)
        content_hash = reading_content_hash(reading)
        with self._lock, self.conn:
            cur = self.conn.execute(
                """INSERT OR IGNORE INTO gateway_readings(batch_id, station, seq, payload,
                   content_hash, measured_at, created_at) VALUES(?,?,?,?,?,?,?)""",
                (batch_id, station, seq, payload, content_hash,
                 reading.get("measured_at"), now),
            )
            inserted = cur.rowcount > 0
            if inserted:
                self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, READING_KIND, payload, "closed",
                     f"{batch_no}:{seq}", actor, now),
                )
        return inserted

    def update_item_recalc(self, item_id: int, severity: str, quantity: float,
                           threshold: float, alarm_count: int,
                           status: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            self.conn.execute(
                """UPDATE items SET severity=?, quantity=?, threshold=?, alarm_count=?,
                   status=?, version=version+1, updated_at=? WHERE id=?""",
                (severity, quantity, threshold, alarm_count, status, now, item_id),
            )
        return self.get_item(item_id)

    def close_record(self, item_id: int, record_id: int) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                "UPDATE records SET status='closed' WHERE id=? AND item_id=?",
                (record_id, item_id),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute(
                    "SELECT 1 FROM records WHERE id=? AND item_id=?",
                    (record_id, item_id),
                ).fetchone()
                if exists is None:
                    raise NotFoundError("记录不存在")
                raise ConflictError("记录已关闭")
            row = self.conn.execute(
                "SELECT * FROM records WHERE id=?", (record_id,)
            ).fetchone()
        return dict(row)

    def count_open_records(self, item_id: int, kind: Optional[str] = None) -> int:
        sql = "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'"
        params: list = [item_id]
        if kind is not None:
            sql += " AND kind=?"
            params.append(kind)
        with self._lock:
            row = self.conn.execute(sql, params).fetchone()
        return int(row["n"])

    def get_open_traffic_announcement(self, item_id: int,
                                      traffic_ref: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                """SELECT * FROM records WHERE item_id=? AND external_ref=?
                   AND kind=? AND status='open'""",
                (item_id, traffic_ref, TRAFFIC_ANNOUNCEMENT_KIND),
            ).fetchone()
        return dict(row) if row else None

    def close(self) -> None:
        with self._lock:
            self.conn.close()
