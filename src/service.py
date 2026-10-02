from __future__ import annotations

import json
import threading
from typing import Any, Dict, Optional

from .domain import (ConflictError, PermissionDenied, ValidationError,
                     ensure_role, normalize_severity, require_number, require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, CLOSURE_BIND_STATES, CREATE_ROLES, ENTITY,
                    RECORD_ROLES, TITLE, TRAFFIC_ANNOUNCEMENT_KIND, VIEW_ROLES,
                    completion_blockers, escalation_required, gap_positions,
                    priority_score, reading_field_diff, recalc_readings,
                    response_deadline_hours, role_for_transition, validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository
        # 网关可能并发补传，批次接收与重算在进程内串行化
        self._batch_lock = threading.RLock()

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
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
        })
        return record

    def _validate_readings(self, raw: Any) -> list:
        if not isinstance(raw, list) or not raw:
            raise ValidationError("readings必须是非空数组")
        readings = []
        for entry in raw:
            if not isinstance(entry, dict):
                raise ValidationError("每条读数必须是对象")
            seq = entry.get("seq")
            if not isinstance(seq, int) or seq < 1:
                raise ValidationError("seq必须是正整数")
            severity = normalize_severity(entry.get("severity"))
            quantity = require_number(entry.get("quantity", 0), "quantity")
            threshold = require_number(entry.get("threshold", 1), "threshold", 0.000001)
            kind = entry.get("kind")
            if kind is not None:
                kind = require_text(kind, "kind", 100)
            detail = entry.get("detail")
            if detail is not None:
                detail = require_text(detail, "detail")
            measured_at = entry.get("measured_at")
            if measured_at is not None:
                measured_at = require_text(measured_at, "measured_at", 100)
            readings.append({
                "seq": seq, "severity": severity, "quantity": quantity,
                "threshold": threshold, "kind": kind, "detail": detail,
                "measured_at": measured_at,
            })
        return readings

    def receive_gateway_batch(self, payload: Dict[str, Any], actor: str,
                              role: str) -> Dict[str, Any]:
        """网关批次补传：幂等接收、重叠比对、缺口拦截、按最新连续序列重算告警。"""
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        batch_no = require_text(payload.get("batch_no"), "batch_no", 100)
        station = require_text(payload.get("station"), "station", 100)
        item_id = payload.get("item_id")
        if not isinstance(item_id, int) or item_id < 1:
            raise ValidationError("item_id必须是正整数")
        self.repository.get_item(item_id)
        readings = self._validate_readings(payload.get("readings"))
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)

        with self._batch_lock:
            # 同一个批次号重复提交沿用第一次结果
            existing = self.repository.get_gateway_batch(batch_no)
            if existing is not None:
                self.repository.append_audit("duplicate", ENTITY, item_id, actor, {
                    "batch_no": batch_no, "station": station,
                    "first_status": existing["status"],
                })
                return existing.get("result") or {
                    "batch_no": batch_no, "status": existing["status"]}

            hwm = self.repository.get_station_hwm(station)
            # 序列重叠：逐条比对，内容不同整批拒绝并指出冲突位置
            conflicts = []
            new_seqs = []
            for reading in readings:
                old = self.repository.get_reading(station, reading["seq"])
                if old is None:
                    new_seqs.append(reading["seq"])
                else:
                    mismatches = reading_field_diff(old["payload"], reading)
                    if mismatches:
                        conflicts.append({"seq": reading["seq"], "mismatches": mismatches})
            if conflicts:
                fail_detail = {"conflicts": conflicts}
                self.repository.create_gateway_batch(
                    batch_no, station, min(r["seq"] for r in readings),
                    max(r["seq"] for r in readings), len(readings), "rejected",
                    None, "conflict", fail_detail, external_ref, actor)
                self.repository.append_audit("reject", ENTITY, item_id, actor, {
                    "batch_no": batch_no, "station": station, "reason": "conflict",
                    "positions": conflicts,
                })
                raise ConflictError(
                    "序列内容冲突，整批拒绝："
                    + json.dumps(conflicts, ensure_ascii=False))

            # 缺口未补齐不能跳过
            missing = gap_positions(hwm, new_seqs)
            if missing:
                fail_detail = {"missing_seqs": missing, "hwm": hwm}
                self.repository.create_gateway_batch(
                    batch_no, station, min(r["seq"] for r in readings),
                    max(r["seq"] for r in readings), len(readings), "rejected",
                    None, "gap", fail_detail, external_ref, actor)
                self.repository.append_audit("reject", ENTITY, item_id, actor, {
                    "batch_no": batch_no, "station": station, "reason": "gap",
                    "missing_seqs": missing, "hwm": hwm,
                })
                raise ConflictError(
                    "序列存在缺口未补齐，不能跳过："
                    + json.dumps(missing, ensure_ascii=False))

            # 接收并落库
            result = {
                "batch_no": batch_no, "station": station, "status": "accepted",
                "seq_start": min(r["seq"] for r in readings),
                "seq_end": max(r["seq"] for r in readings),
                "reading_count": len(readings),
            }
            batch = self.repository.create_gateway_batch(
                batch_no, station, result["seq_start"], result["seq_end"],
                len(readings), "accepted", result, None, None, external_ref, actor)
            new_count = 0
            for reading in readings:
                if self.repository.add_gateway_reading(
                        batch["id"], batch_no, item_id, station,
                        reading["seq"], reading, actor):
                    new_count += 1

            # 按最新连续序列重算告警数量与状态
            all_readings = [
                {"seq": x["seq"], **x["payload"]}
                for x in self.repository.list_gateway_readings(station)
            ]
            recalc = recalc_readings(all_readings)
            item = self.repository.get_item(item_id)
            if recalc is not None:
                new_status = item["status"]
                if recalc["alarm_count"] > 0 and new_status == "normal":
                    new_status = "warning"
                updated = self.repository.update_item_recalc(
                    item_id, recalc["severity"], recalc["quantity"],
                    recalc["threshold"], recalc["alarm_count"], new_status)
            else:
                updated = item

            result["new_readings"] = new_count
            result["recalc"] = recalc
            result["item"] = self.enrich(updated)
            self.repository.update_gateway_batch_result(batch_no, result)
            self.repository.append_audit("receive", ENTITY, item_id, actor, {
                "batch_no": batch_no, "station": station,
                "seq_start": result["seq_start"], "seq_end": result["seq_end"],
                "reading_count": len(readings), "new_readings": new_count,
            })
            if recalc is not None:
                self.repository.append_audit("recalculate", ENTITY, item_id, actor, {
                    "batch_no": batch_no, "station": station,
                    "severity": recalc["severity"], "quantity": recalc["quantity"],
                    "threshold": recalc["threshold"], "alarm_count": recalc["alarm_count"],
                    "continuous_through_seq": recalc["continuous_through_seq"],
                })
            return result

    def close_record(self, item_id: int, record_id: int, actor: str,
                     role: str) -> Dict[str, Any]:
        """关闭记录；交通通告撤销后按未关闭事项重算状态。"""
        ensure_role(role, set(["traffic_authority", "bridge_engineer"]))
        actor = require_text(actor, "actor", 100)
        record = self.repository.close_record(item_id, record_id)
        self.repository.append_audit("revoke", ENTITY, item_id, actor, {
            "record_id": record_id, "kind": record["kind"],
        })
        if record["kind"] == TRAFFIC_ANNOUNCEMENT_KIND:
            item = self.repository.get_item(item_id)
            if item["status"] in CLOSURE_BIND_STATES:
                open_announcements = self.repository.count_open_records(
                    item_id, TRAFFIC_ANNOUNCEMENT_KIND)
                open_others = self.repository.count_open_records(item_id) - open_announcements
                # 通告撤销后按未关闭事项重算：仍有未关闭事项则保持警示，全部结清则恢复
                new_status = "warning" if open_others > 0 else "restored"
                if new_status != item["status"]:
                    updated = self.repository.update_item_recalc(
                        item_id, item["severity"], item["quantity"],
                        item["threshold"], item["alarm_count"], new_status)
                    self.repository.append_audit("recalculate", ENTITY, item_id, actor, {
                        "from": item["status"], "to": new_status,
                        "reason": "traffic_announcement_revoked",
                        "open_other_records": open_others,
                    })
                    return {"record": record, "item": self.enrich(updated)}
        return {"record": record}

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str, traffic_ref: Optional[str] = None) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            raise ConflictError("；".join(blockers))
        traffic_announcement = None
        if target in CLOSURE_BIND_STATES:
            if not traffic_ref:
                raise ValidationError("限行或封闭必须绑定对应的交通通告记录(traffic_ref)")
            traffic_ref = require_text(traffic_ref, "traffic_ref", 100)
            traffic_announcement = self.repository.get_open_traffic_announcement(
                item_id, traffic_ref)
            if traffic_announcement is None:
                raise ConflictError("未找到有效的交通通告记录，限行/封闭必须绑定交通通告")
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        audit_detail = {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        }
        if traffic_announcement is not None:
            audit_detail["traffic_ref"] = traffic_ref
            audit_detail["traffic_record_id"] = traffic_announcement["id"]
        self.repository.append_audit("transition", ENTITY, item_id, actor, audit_detail)
        return self.enrich(updated)

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
