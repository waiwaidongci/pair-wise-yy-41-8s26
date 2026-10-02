from __future__ import annotations

import threading
from typing import Any, Dict, Optional

from .domain import (BatchRejected, ensure_role, normalize_severity, require_number,
                     require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CREATE_ROLES, ENTITY, GATEWAY_ROLES,
                    NOTICE_REVOKE_ROLES, NOTICE_ROLES, RECORD_ROLES, TITLE,
                    TRAFFIC_NOTICE_KIND, VIEW_ROLES, completion_blockers,
                    escalation_required, notice_blockers, priority_score,
                    recompute_severity, response_deadline_hours,
                    role_for_transition, validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository
        self._ingest_guard = threading.Lock()
        self._ingest_locks: Dict[int, threading.RLock] = {}

    def _ingest_lock(self, item_id: int) -> threading.RLock:
        with self._ingest_guard:
            lock = self._ingest_locks.get(item_id)
            if lock is None:
                lock = threading.RLock()
                self._ingest_locks[item_id] = lock
            return lock

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "priority": priority_score(severity, quantity, threshold),
        })
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        if kind == TRAFFIC_NOTICE_KIND:
            ensure_role(role, NOTICE_ROLES)
        else:
            ensure_role(role, RECORD_ROLES)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if kind == TRAFFIC_NOTICE_KIND:
            external_ref = require_text(external_ref, "external_ref", 100)
        elif external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
            "external_ref": external_ref,
        })
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str, notice_ref: Optional[str] = None) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            from .domain import ConflictError
            raise ConflictError("；".join(blockers))
        bound_notice = None
        notice_block = notice_blockers(
            target, self.repository.open_record_count_by_kind(item_id, TRAFFIC_NOTICE_KIND))
        if notice_block:
            from .domain import ConflictError
            raise ConflictError("；".join(notice_block))
        if target in ("restricted", "closed"):
            notice_ref = require_text(notice_ref, "notice_ref", 100)
            record = self._find_notice(item_id, notice_ref)
            if record is None or record["status"] != "open":
                from .domain import ConflictError
                raise ConflictError("限行或封闭必须绑定处于生效中的交通通告记录")
            bound_notice = {"notice_ref": notice_ref, "record_id": record["id"]}
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        audit_detail = {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        }
        if bound_notice:
            audit_detail.update(bound_notice)
        self.repository.append_audit("transition", ENTITY, item_id, actor, audit_detail)
        return self.enrich(updated)

    def _find_notice(self, item_id: int, notice_ref: str) -> Optional[Dict[str, Any]]:
        for record in self.repository.list_records(item_id):
            if record["kind"] == TRAFFIC_NOTICE_KIND and record["external_ref"] == notice_ref:
                return record
        return None

    @staticmethod
    def _canonical_reading(raw: Any, index: int) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            from .domain import ValidationError
            raise ValidationError(f"readings[{index}]必须是对象")
        seq = raw.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
            from .domain import ValidationError
            raise ValidationError(f"readings[{index}].seq必须是正整数")
        value = require_number(raw.get("value"), f"readings[{index}].value")
        alarm = raw.get("alarm")
        if not isinstance(alarm, bool):
            from .domain import ValidationError
            raise ValidationError(f"readings[{index}].alarm必须是布尔值")
        recorded_at = raw.get("recorded_at")
        if recorded_at is not None:
            recorded_at = require_text(recorded_at, f"readings[{index}].recorded_at", 100)
        return {"seq": seq, "value": float(value), "alarm": alarm,
                "recorded_at": recorded_at}

    def ingest_batch(self, item_id: int, payload: Dict[str, Any],
                     actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, GATEWAY_ROLES)
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        batch_no = require_text(payload.get("batch_no"), "batch_no", 100)
        raw_readings = payload.get("readings")
        if not isinstance(raw_readings, list) or not raw_readings:
            from .domain import ValidationError
            raise ValidationError("readings必须是非空数组")
        readings = sorted((self._canonical_reading(raw, i)
                           for i, raw in enumerate(raw_readings)),
                          key=lambda reading: reading["seq"])
        if len({reading["seq"] for reading in readings}) != len(readings):
            from .domain import ValidationError
            raise ValidationError("批次内序列不能重复")
        with self._ingest_lock(item_id):
            return self._ingest_batch_locked(item_id, batch_no, readings, actor, item)

    def _ingest_batch_locked(self, item_id: int, batch_no: str,
                             readings: list, actor: str,
                             item: Dict[str, Any]) -> Dict[str, Any]:
        previous = self.repository.get_batch(item_id, batch_no)
        if previous is not None:
            self.repository.duplicate_batch_audit(item_id, batch_no, previous, actor)
            return {"batch_no": batch_no, "status": "duplicate",
                    "first_status": previous["status"], "result": previous["detail"]}
        seqs = [reading["seq"] for reading in readings]
        stored = self.repository.get_readings(item_id, seqs)
        conflicts = []
        for reading in readings:
            old = stored.get(reading["seq"])
            if old is None:
                continue
            fields = []
            if old["value"] != reading["value"]:
                fields.append("value")
            if old["alarm"] != reading["alarm"]:
                fields.append("alarm")
            if old["recorded_at"] != reading["recorded_at"]:
                fields.append("recorded_at")
            if fields:
                conflicts.append({"seq": reading["seq"], "fields": fields,
                                "stored": old, "incoming": reading})
        frontier = self.repository.frontier_seq(item_id)
        missing = self._missing_seqs(seqs, stored, frontier)
        if conflicts or missing:
            reason = "gap"
            if conflicts and missing:
                reason = "overlap_conflict_and_gap"
            elif conflicts:
                reason = "overlap_conflict"
            detail = {"batch_no": batch_no, "conflicts": conflicts, "missing": missing}
            self.repository.reject_batch_with_audit(item_id, batch_no, reason, detail, actor)
            if conflicts:
                message = "批次序列重叠但内容不一致，整批拒绝"
            else:
                message = "读数序列存在缺口，缺口未补齐不能跳过"
            raise BatchRejected(message, reason=reason, conflicts=conflicts, missing=missing)
        extends_frontier = any(seq > frontier for seq in seqs)
        if not extends_frontier:
            outcome = self.repository.late_batch_with_monitoring(
                item_id, batch_no, frontier, actor)
            return {"batch_no": batch_no, "status": "late",
                    "frontier": outcome["frontier"], "record_id": outcome["record_id"]}
        new_readings = [reading for reading in readings if reading["seq"] > frontier]
        overlapped = [seq for seq in seqs if seq <= frontier]
        outcome = self.repository.accept_batch_with_recompute(
            item_id, batch_no, new_readings, overlapped, actor, recompute_severity)
        return {"batch_no": batch_no, "status": "accepted",
                "inserted": outcome["inserted"], "overlapped": overlapped,
                "frontier_before": frontier,
                "recompute": {"frontier": outcome["frontier"],
                               "alarm_count": outcome["alarm_count"],
                               "from_severity": outcome["from_severity"],
                               "to_severity": outcome["to_severity"],
                               "severity_changed": outcome["severity_changed"]}}

    @staticmethod
    def _missing_seqs(seqs, stored, frontier):
        needed = {seq for seq in seqs if seq > frontier}
        covered = set(stored) | set(seqs)
        if not needed:
            return []
        upper = max(needed)
        return [seq for seq in range(frontier + 1, upper + 1) if seq not in covered]

    def recompute(self, item_id: int, actor: str, trigger_batch: Optional[str] = None) -> Dict[str, Any]:
        item = self.repository.get_item(item_id)
        alarm_count = self.repository.alarm_count(item_id)
        frontier = self.repository.frontier_seq(item_id)
        new_severity = recompute_severity(item["severity"], alarm_count)
        changed = new_severity != item["severity"]
        if changed:
            self.repository.apply_recompute(item_id, float(alarm_count), new_severity)
        detail = {
            "frontier": frontier, "alarm_count": alarm_count,
            "from_severity": item["severity"], "to_severity": new_severity,
            "from_quantity": item["quantity"], "trigger_batch": trigger_batch,
            "severity_changed": changed,
        }
        self.repository.append_audit("recompute", ENTITY, item_id, actor, detail)
        return detail

    def revoke_notice(self, item_id: int, payload: Dict[str, Any],
                      actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, NOTICE_REVOKE_ROLES)
        actor = require_text(actor, "actor", 100)
        notice_ref = require_text(payload.get("notice_ref"), "notice_ref", 100)
        self.repository.get_item(item_id)
        with self._ingest_lock(item_id):
            outcome = self.repository.revoke_notice_tx(item_id, notice_ref, actor)
        if outcome.get("already_closed"):
            return {"notice_ref": notice_ref, "already_closed": True,
                    "record_id": outcome["record_id"]}
        return {"notice_ref": notice_ref, "already_closed": False,
                "record_id": outcome["record_id"],
                "open_notices": outcome["open_notices"],
                "status": outcome["from"], "status_after": outcome["to"]}

    def list_batches(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_batches(item_id)

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None) -> list:
        ensure_role(role, AUDIT_ROLES)
        return self.repository.list_audit(item_id)

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result
