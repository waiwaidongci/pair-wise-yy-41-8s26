from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import ENTITY, ID_PREFIX, STATES, status_after_notice_revoked


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
                CREATE TABLE IF NOT EXISTS batches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    batch_no TEXT NOT NULL,
                    status TEXT NOT NULL
                        CHECK(status IN ('accepted','duplicate','rejected','late')),
                    reason TEXT,
                    detail TEXT NOT NULL,
                    submitted_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, batch_no)
                );
                CREATE TABLE IF NOT EXISTS readings (
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    seq INTEGER NOT NULL,
                    value REAL NOT NULL,
                    alarm INTEGER NOT NULL,
                    batch_id INTEGER NOT NULL REFERENCES batches(id),
                    recorded_at TEXT,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(item_id, seq)
                );
            """)

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

    def open_record_count_by_kind(self, item_id: int, kind: str) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND kind=? AND status='open'",
                (item_id, kind),
            ).fetchone()
        return int(row["n"])

    def frontier_seq(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COALESCE(MAX(seq),0) AS n FROM readings WHERE item_id=?",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def get_readings(self, item_id: int, seqs) -> Dict[int, Dict[str, Any]]:
        seqs = list(seqs)
        if not seqs:
            return {}
        marks = ",".join("?" for _ in seqs)
        with self._lock:
            rows = self.conn.execute(
                f"SELECT * FROM readings WHERE item_id=? AND seq IN ({marks})",
                (item_id, *seqs),
            ).fetchall()
        return {int(row["seq"]): {"seq": int(row["seq"]), "value": float(row["value"]),
                                  "alarm": bool(row["alarm"]),
                                  "recorded_at": row["recorded_at"]} for row in rows}

    def alarm_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM readings WHERE item_id=? AND alarm=1",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def get_batch(self, item_id: int, batch_no: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM batches WHERE item_id=? AND batch_no=?",
                (item_id, batch_no),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["detail"] = json.loads(result["detail"])
        return result

    def list_batches(self, item_id: int) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM batches WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def _insert_audit_locked(self, conn, action: str, entity_type: str, entity_id: int,
                           actor: str, detail: dict) -> int:
        row = conn.execute(
            "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous = row["entry_hash"] if row else "GENESIS"
        event = make_entry(action, entity_type, entity_id, actor, detail, previous)
        cur = conn.execute(
            """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
               previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
            (event["action"], event["entity_type"], event["entity_id"], event["actor"],
             json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
             event["previous_hash"], event["entry_hash"], event["created_at"]),
        )
        return int(cur.lastrowid)

    def accept_batch_with_recompute(self, item_id: int, batch_no: str, readings: list,
                                 overlapped: list, actor: str,
                                 severity_for: callable) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """INSERT INTO batches(item_id, batch_no, status, reason, detail,
                   submitted_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                (item_id, batch_no, "accepted", None,
                 json.dumps({"inserted": [r["seq"] for r in readings]},
                            ensure_ascii=False, sort_keys=True), actor, now),
            )
            batch_id = int(cur.lastrowid)
            for reading in readings:
                self.conn.execute(
                    """INSERT INTO readings(item_id, seq, value, alarm, batch_id,
                       recorded_at, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, reading["seq"], reading["value"],
                     1 if reading["alarm"] else 0, batch_id,
                     reading.get("recorded_at"), now),
                )
            stats = self.conn.execute(
                """SELECT COALESCE(MAX(seq),0) AS frontier,
                          COALESCE(SUM(alarm),0) AS alarms
                   FROM readings WHERE item_id=?""",
                (item_id,),
            ).fetchone()
            frontier, alarm_count = int(stats["frontier"]), int(stats["alarms"])
            item_row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            old_severity = item_row["severity"]
            new_severity = severity_for(old_severity, alarm_count)
            changed = new_severity != old_severity
            if changed:
                self.conn.execute(
                    """UPDATE items SET severity=?, quantity=?, version=version+1, updated_at=?
                       WHERE id=?""",
                    (new_severity, float(alarm_count), now, item_id),
                )
            accept_detail = {"batch_no": batch_no,
                            "inserted": [reading["seq"] for reading in readings],
                            "overlapped": overlapped}
            recompute_detail = {"frontier": frontier, "alarm_count": alarm_count,
                              "from_severity": old_severity, "to_severity": new_severity,
                              "from_quantity": float(item_row["quantity"]),
                              "trigger_batch": batch_no, "severity_changed": changed}
            accept_id = self._insert_audit_locked(
                self.conn, "batch_accept", ENTITY, item_id, actor, accept_detail)
            recompute_id = self._insert_audit_locked(
                self.conn, "recompute", ENTITY, item_id, actor, recompute_detail)
        return {"batch_id": batch_id, "accept_audit_id": accept_id,
                "recompute_audit_id": recompute_id, "frontier": frontier,
                "alarm_count": alarm_count, "from_severity": old_severity,
                "to_severity": new_severity, "severity_changed": changed,
                "inserted": [reading["seq"] for reading in readings],
                "overlapped": overlapped}

    def reject_batch_with_audit(self, item_id: int, batch_no: str, reason: str,
                              detail: dict, actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """INSERT INTO batches(item_id, batch_no, status, reason, detail,
                   submitted_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                (item_id, batch_no, "rejected", reason,
                 json.dumps(detail, ensure_ascii=False, sort_keys=True), actor, now),
            )
            batch_id = int(cur.lastrowid)
            audit_detail = {"batch_no": batch_no, "reason": reason,
                           "conflict_seqs": [c["seq"] for c in detail.get("conflicts", [])],
                           "missing": detail.get("missing", [])}
            audit_id = self._insert_audit_locked(
                self.conn, "batch_reject", ENTITY, item_id, actor, audit_detail)
        return {"batch_id": batch_id, "audit_id": audit_id}

    def late_batch_with_monitoring(self, item_id: int, batch_no: str, frontier: int,
                                  actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            record_cur = self.conn.execute(
                """INSERT INTO records(item_id, kind, detail, status, external_ref,
                   created_by, created_at) VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(item_id, external_ref) DO NOTHING""",
                (item_id, "monitoring", f"迟到批次{batch_no}仅留存监测记录", "closed",
                 f"BATCH:{batch_no}", actor, now),
            )
            record_id = int(record_cur.lastrowid or 0)
            cur = self.conn.execute(
                """INSERT INTO batches(item_id, batch_no, status, reason, detail,
                   submitted_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                (item_id, batch_no, "late", "late_only",
                 json.dumps({"frontier": frontier, "record_id": record_id},
                            ensure_ascii=False, sort_keys=True), actor, now),
            )
            batch_id = int(cur.lastrowid)
            audit_id = self._insert_audit_locked(
                self.conn, "batch_late", ENTITY, item_id, actor,
                {"batch_no": batch_no, "frontier": frontier, "record_id": record_id})
        return {"batch_id": batch_id, "audit_id": audit_id, "record_id": record_id,
                "frontier": frontier}

    def duplicate_batch_audit(self, item_id: int, batch_no: str, previous: dict,
                           actor: str) -> int:
        with self._lock, self.conn:
            return self._insert_audit_locked(
                self.conn, "batch_duplicate", ENTITY, item_id, actor,
                {"batch_no": batch_no, "first_status": previous["status"],
                 "first_result": previous["detail"]})

    def revoke_notice_tx(self, item_id: int, notice_ref: str, actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            record_row = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? AND kind=? AND external_ref=?",
                (item_id, "traffic_notice", notice_ref),
            ).fetchone()
            if record_row is None:
                raise NotFoundError("交通通告记录不存在")
            if record_row["status"] == "closed":
                return {"already_closed": True, "record_id": int(record_row["id"])}
            self.conn.execute(
                "UPDATE records SET status='closed' WHERE id=?", (record_row["id"],))
            revoke_audit = self._insert_audit_locked(
                self.conn, "notice_revoke", ENTITY, item_id, actor,
                {"notice_ref": notice_ref, "record_id": int(record_row["id"])})
            open_row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND kind=? AND status='open'",
                (item_id, "traffic_notice"),
            ).fetchone()
            open_notices = int(open_row["n"])
            all_open_row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
            open_records = int(all_open_row["n"])
            item_row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
            old_status = item_row["status"]
            new_status = status_after_notice_revoked(old_status, open_notices, open_records)
            recompute_audit = None
            if new_status != old_status:
                self.conn.execute(
                    """UPDATE items SET status=?, version=version+1, updated_at=? WHERE id=?""",
                    (new_status, now, item_id),
                )
                recompute_audit = self._insert_audit_locked(
                    self.conn, "recompute", ENTITY, item_id, actor,
                    {"reason": "notice_revoked", "notice_ref": notice_ref,
                     "from": old_status, "to": new_status,
                     "open_notices": open_notices,
                     "open_records": open_records})
        return {"already_closed": False, "record_id": int(record_row["id"]),
                "revoke_audit_id": revoke_audit, "recompute_audit_id": recompute_audit,
                "open_notices": open_notices, "from": old_status, "to": new_status}

    def apply_recompute(self, item_id: int, quantity: float, severity: str) -> None:
        now = utc_now()
        with self._lock, self.conn:
            self.conn.execute(
                """UPDATE items SET quantity=?, severity=?, version=version+1, updated_at=?
                   WHERE id=?""",
                (quantity, severity, now, item_id),
            )

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

    def close(self) -> None:
        with self._lock:
            self.conn.close()
