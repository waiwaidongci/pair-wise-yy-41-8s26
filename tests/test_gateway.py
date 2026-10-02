import tempfile, unittest, threading
from pathlib import Path
from src.domain import ConflictError, ValidationError
from src.repository import Repository
from src.service import Service
from src.rules import STATES, TRANSITION_ROLES


def batch(batch_no, station, item_id, readings, external_ref=None):
    payload = {"batch_no": batch_no, "station": station, "item_id": item_id,
               "readings": readings}
    if external_ref:
        payload["external_ref"] = external_ref
    return payload


def reading(seq, severity="normal", quantity=1.0, threshold=10.0, **extra):
    r = {"seq": seq, "severity": severity, "quantity": quantity,
         "threshold": threshold}
    r.update(extra)
    return r


class GatewayBatchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.item = self.service.create_item(
            {"title": "bridge alarm", "description": "gateway feed",
             "severity": "normal", "quantity": 0, "threshold": 10,
             "external_ref": "BR-1"}, "creator", "sensor_operator")

    def tearDown(self):
        self.repo.close(); self.tmp.cleanup()

    def test_accept_batch_recalc_and_audit(self):
        result = self.service.receive_gateway_batch(
            batch("B001", "GW-01", self.item["id"], [
                reading(1, "normal", 1, 10),
                reading(2, "warning", 12, 10),
            ]), "gw", "sensor_operator")
        self.assertEqual(result["status"], "accepted")
        recalc = result["recalc"]
        self.assertEqual(recalc["severity"], "warning")
        self.assertEqual(recalc["quantity"], 12.0)
        self.assertEqual(recalc["alarm_count"], 1)
        self.assertEqual(recalc["continuous_through_seq"], 2)
        self.assertEqual(result["item"]["status"], "warning")
        # 监测记录已进入现有 records
        records = self.service.list_records(self.item["id"], "viewer")
        self.assertEqual(len(records), 2)
        self.assertTrue(all(r["kind"] == "sensor_reading" for r in records))
        # 审计链接入接收与重算
        actions = [e["action"] for e in self.service.audit("viewer", self.item["id"])]
        self.assertIn("receive", actions)
        self.assertIn("recalculate", actions)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_duplicate_batch_no_uses_first_result(self):
        payload = batch("B001", "GW-01", self.item["id"], [reading(1)])
        first = self.service.receive_gateway_batch(payload, "gw", "sensor_operator")
        second = self.service.receive_gateway_batch(payload, "gw", "sensor_operator")
        self.assertEqual(first["status"], "accepted")
        self.assertEqual(second["status"], "accepted")
        self.assertEqual(second["recalc"]["continuous_through_seq"], 1)
        # 重复提交只留一条监测记录，不重复计数
        self.assertEqual(len(self.service.list_records(self.item["id"], "viewer")), 1)
        dup_events = [e for e in self.service.audit("viewer", self.item["id"])
                      if e["action"] == "duplicate"]
        self.assertEqual(len(dup_events), 1)

    def test_overlap_content_conflict_rejects_with_positions(self):
        self.service.receive_gateway_batch(
            batch("B001", "GW-01", self.item["id"], [reading(1, "normal", 1, 10)]),
            "gw", "sensor_operator")
        with self.assertRaises(ConflictError) as ctx:
            self.service.receive_gateway_batch(
                batch("B002", "GW-01", self.item["id"], [
                    reading(1, "critical", 99, 10),  # 与已接收内容冲突
                    reading(2, "normal", 2, 10),
                ]), "gw", "sensor_operator")
        msg = str(ctx.exception)
        self.assertIn("整批拒绝", msg)
        self.assertIn("1", msg)  # 指出冲突序号
        # 冲突批次不落库、不重算
        self.assertEqual(self.repo.get_station_hwm("GW-01"), 1)
        reject_events = [e for e in self.service.audit("viewer", self.item["id"])
                         if e["action"] == "reject"]
        self.assertEqual(len(reject_events), 1)
        self.assertEqual(reject_events[0]["detail"]["reason"], "conflict")
        self.assertTrue(self.repo.verify_audit_chain())

    def test_overlap_identical_content_is_kept_no_downgrade(self):
        # 先接收高危读数，告警升级
        self.service.receive_gateway_batch(
            batch("B001", "GW-01", self.item["id"], [
                reading(1, "critical", 50, 10),
            ]), "gw", "sensor_operator")
        item = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(item["status"], "warning")
        self.assertEqual(item["severity"], "critical")
        # 迟到旧批（序号落后、内容一致）只留监测记录，不降级
        result = self.service.receive_gateway_batch(
            batch("B002", "GW-01", self.item["id"], [
                reading(1, "critical", 50, 10),  # 与序号1一致
            ]), "gw", "sensor_operator")
        self.assertEqual(result["status"], "accepted")
        item = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(item["status"], "warning")  # 未降级
        self.assertEqual(item["severity"], "critical")

    def test_gap_cannot_be_skipped(self):
        self.service.receive_gateway_batch(
            batch("B001", "GW-01", self.item["id"], [
                reading(1), reading(2), reading(3),
            ]), "gw", "sensor_operator")
        # 缺序号4，直接传5-6 -> 拒绝
        with self.assertRaises(ConflictError) as ctx:
            self.service.receive_gateway_batch(
                batch("B002", "GW-01", self.item["id"], [
                    reading(5), reading(6),
                ]), "gw", "sensor_operator")
        msg = str(ctx.exception)
        self.assertIn("缺口", msg)
        self.assertIn("4", msg)  # 指出缺失序号
        self.assertEqual(self.repo.get_station_hwm("GW-01"), 3)
        # 补齐4后可继续
        self.service.receive_gateway_batch(
            batch("B003", "GW-01", self.item["id"], [reading(4)]),
            "gw", "sensor_operator")
        self.assertEqual(self.repo.get_station_hwm("GW-01"), 4)

    def test_concurrent_batches_serialized(self):
        errors = []

        def accept(batch_no, seqs):
            try:
                self.service.receive_gateway_batch(
                    batch(batch_no, "GW-01", self.item["id"],
                          [reading(s) for s in seqs]),
                    "gw", "sensor_operator")
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        # 不同批次按序补传，串行化后不应出现缺口或重复计数
        for batch_no, seqs in (("B001", [1, 2, 3]),
                               ("B002", [4, 5, 6]),
                               ("B003", [7, 8])):
            accept(batch_no, seqs)
        self.assertEqual(errors, [])
        self.assertEqual(self.repo.get_station_hwm("GW-01"), 8)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_concurrent_same_batch_no_idempotent(self):
        payload = batch("B001", "GW-01", self.item["id"], [reading(1)])
        results = []

        def accept():
            results.append(self.service.receive_gateway_batch(
                payload, "gw", "sensor_operator"))

        threads = [threading.Thread(target=accept) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(results), 5)
        self.assertTrue(all(r["status"] == "accepted" for r in results))
        self.assertEqual(len(self.service.list_records(self.item["id"], "viewer")), 1)

    def test_closure_requires_traffic_announcement(self):
        self.service.receive_gateway_batch(
            batch("B001", "GW-01", self.item["id"], [reading(1, "critical", 50, 10)]),
            "gw", "sensor_operator")
        current = self.service.get_item(self.item["id"], "viewer")
        # 无交通通告 -> 422
        with self.assertRaises(ValidationError):
            self.service.transition(current["id"], "restricted", current["version"],
                                    "reviewer", "bridge_engineer")
        # 伪造通告 -> 409
        with self.assertRaises(ConflictError):
            self.service.transition(current["id"], "restricted", current["version"],
                                    "reviewer", "bridge_engineer", "TA-99")
        # 建立有效通告后可限行
        self.service.add_record(self.item["id"], {
            "kind": "traffic_announcement", "detail": "control",
            "status": "open", "external_ref": "TA-1"}, "recorder", "bridge_engineer")
        current = self.service.get_item(self.item["id"], "viewer")
        updated = self.service.transition(current["id"], "restricted", current["version"],
                                          "reviewer", "bridge_engineer", "TA-1")
        self.assertEqual(updated["status"], "restricted")

    def test_revoke_announcement_recalculates_status(self):
        self.service.receive_gateway_batch(
            batch("B001", "GW-01", self.item["id"], [reading(1, "critical", 50, 10)]),
            "gw", "sensor_operator")
        ta = self.service.add_record(self.item["id"], {
            "kind": "traffic_announcement", "detail": "control",
            "status": "open", "external_ref": "TA-1"}, "recorder", "bridge_engineer")
        current = self.service.get_item(self.item["id"], "viewer")
        current = self.service.transition(current["id"], "restricted", current["version"],
                                          "reviewer", "bridge_engineer", "TA-1")
        current = self.service.transition(current["id"], "closed", current["version"],
                                          "reviewer", "traffic_authority", "TA-1")
        self.assertEqual(current["status"], "closed")
        # 通告撤销 -> 无未关闭事项 -> 重算为恢复
        result = self.service.close_record(self.item["id"], ta["id"],
                                           "reviewer", "traffic_authority")
        self.assertEqual(result["item"]["status"], "restored")
        rec_events = [e for e in self.service.audit("viewer", self.item["id"])
                      if e["action"] == "recalculate"]
        self.assertTrue(any(e["detail"].get("reason") ==
                            "traffic_announcement_revoked" for e in rec_events))
        self.assertTrue(self.repo.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
