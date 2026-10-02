import tempfile, unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from src.domain import BatchRejected, ConflictError, PermissionDenied
from src.repository import Repository
from src.service import Service


def reading(seq, value, alarm=False, recorded_at=None):
    data = {"seq": seq, "value": value, "alarm": alarm}
    if recorded_at is not None:
        data["recorded_at"] = recorded_at
    return data


class GatewayTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.item = self.service.create_item(
            {"title": "gateway bridge", "description": "batch ingestion",
             "severity": "normal", "quantity": 0, "threshold": 10,
             "external_ref": "GW-1"}, "creator", "sensor_operator")

    def tearDown(self):
        self.repo.close(); self.tmp.cleanup()

    def ingest(self, batch_no, readings):
        return self.service.ingest_batch(
            self.item["id"], {"batch_no": batch_no, "readings": readings},
            "gateway", "sensor_operator")

    def test_accepts_contiguous_and_recomputes(self):
        result = self.ingest("B1", [reading(1, 1.0), reading(2, 2.0, True),
                                     reading(3, 3.0, True)])
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["inserted"], [1, 2, 3])
        self.assertEqual(result["recompute"]["frontier"], 3)
        self.assertEqual(result["recompute"]["alarm_count"], 2)
        item = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(item["quantity"], 2.0)
        self.assertEqual(item["severity"], "watch")
        self.assertGreater(item["version"], 1)

    def test_alarm_count_recomputes_to_warning_and_critical(self):
        readings = [reading(i, float(i), alarm=i >= 2) for i in range(1, 7)]
        self.ingest("B1", readings[:3])
        item = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(item["severity"], "watch")
        self.ingest("B2", readings[3:])
        item = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(item["severity"], "warning")
        more = [reading(i, 0.0, alarm=True) for i in range(7, 10)]
        self.ingest("B3", more)
        item = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(item["severity"], "critical")
        self.assertEqual(item["quantity"], 8.0)

    def test_duplicate_batch_keeps_first_result(self):
        first = self.ingest("B1", [reading(1, 1.0, True)])
        duplicate = self.service.ingest_batch(
            self.item["id"],
            {"batch_no": "B1", "readings": [reading(1, 9.9, True)]},
            "gateway", "sensor_operator")
        self.assertEqual(duplicate["status"], "duplicate")
        self.assertEqual(duplicate["first_status"], "accepted")
        self.assertEqual(duplicate["result"]["inserted"], [1])
        item = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(item["quantity"], 1.0)
        self.assertEqual(self.repo.frontier_seq(self.item["id"]), 1)
        batches = self.service.list_batches(self.item["id"], "viewer")
        self.assertEqual(len(batches), 1)
        audit = self.service.audit("viewer", self.item["id"])
        self.assertIn("batch_duplicate", [event["action"] for event in audit])

    def test_overlap_conflict_rejects_whole_batch_with_position(self):
        self.ingest("B1", [reading(1, 1.0), reading(2, 2.0, True, "2026-01-01T00:00:00Z")])
        with self.assertRaises(BatchRejected) as caught:
            self.ingest("B2", [reading(2, 2.5, True, "2026-01-01T00:00:00Z"),
                                 reading(3, 3.0, True)])
        rejected = caught.exception
        self.assertEqual(rejected.reason, "overlap_conflict")
        self.assertEqual(rejected.conflicts[0]["seq"], 2)
        self.assertEqual(rejected.conflicts[0]["fields"], ["value"])
        self.assertEqual(self.repo.frontier_seq(self.item["id"]), 2)
        self.assertEqual(self.repo.alarm_count(self.item["id"]), 1)
        batch = self.repo.get_batch(self.item["id"], "B2")
        self.assertEqual(batch["status"], "rejected")

    def test_gap_is_not_skippable_and_then_filled(self):
        with self.assertRaises(BatchRejected) as caught:
            self.ingest("B1", [reading(1, 1.0), reading(3, 3.0, True)])
        self.assertEqual(caught.exception.reason, "gap")
        self.assertEqual(caught.exception.missing, [2])
        self.assertEqual(self.repo.frontier_seq(self.item["id"]), 0)
        self.assertEqual(self.repo.alarm_count(self.item["id"]), 0)
        self.ingest("B1-HEAD", [reading(1, 1.0)])
        self.ingest("B1-GAP", [reading(2, 2.0)])
        self.assertEqual(self.repo.frontier_seq(self.item["id"]), 2)
        self.ingest("B3", [reading(3, 3.0, True)])
        self.assertEqual(self.repo.frontier_seq(self.item["id"]), 3)

    def test_out_of_order_in_batch_is_accepted_when_contiguous(self):
        result = self.ingest("B1", [reading(3, 3.0, True), reading(1, 1.0),
                                      reading(2, 2.0)])
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["inserted"], [1, 2, 3])

    def test_late_old_batch_keeps_monitoring_only_and_does_not_downgrade(self):
        self.ingest("B1", [reading(i, 0.0, alarm=True) for i in range(1, 7)])
        item = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(item["severity"], "critical")
        late = self.ingest("OLD", [reading(1, 0.0, True), reading(2, 0.0, True)])
        self.assertEqual(late["status"], "late")
        self.assertIn("record_id", late)
        item = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(item["severity"], "critical")
        self.assertEqual(item["quantity"], 6.0)
        records = self.service.list_records(self.item["id"], "viewer")
        self.assertTrue(any(record["kind"] == "monitoring" for record in records))

    def test_concurrent_batches_are_serialized_without_gap_or_loss(self):
        def send(pair):
            batch_no, seqs, value = pair
            try:
                return self.ingest(
                    batch_no, [reading(seq, value, alarm=True) for seq in seqs])
            except BatchRejected as rejected:
                return {"status": "rejected", "reason": rejected.reason}
        jobs = [("B1", [1, 2, 3], 1.0), ("B2", [1, 2, 3], 1.0),
                ("B3", [1, 2, 3], 1.0), ("B4", [3, 4], 9.9)]
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(send, jobs))
        statuses = sorted(result["status"] for result in results)
        self.assertEqual(statuses.count("accepted"), 1)
        self.assertEqual(statuses.count("late"), 2)
        self.assertEqual(statuses.count("rejected"), 1)
        self.assertEqual(self.repo.frontier_seq(self.item["id"]), 3)
        self.assertEqual(self.repo.alarm_count(self.item["id"]), 3)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_concurrent_same_batch_returns_single_accepted_result(self):
        payload = {"batch_no": "B1", "readings": [reading(1, 1.0, True)]}
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: self.service.ingest_batch(
                self.item["id"], payload, "gateway", "sensor_operator"), range(2)))
        self.assertEqual(sorted(o["status"] for o in outcomes), ["accepted", "duplicate"])

    def test_gateway_role_required(self):
        with self.assertRaises(PermissionDenied):
            self.service.ingest_batch(
                self.item["id"],
                {"batch_no": "B1", "readings": [reading(1, 1.0)]},
                "viewer", "viewer")

    def test_every_outcome_is_in_audit_chain(self):
        self.ingest("B1", [reading(1, 1.0, True)])
        with self.assertRaises(BatchRejected):
            self.ingest("B2", [reading(3, 3.0)])
        with self.assertRaises(BatchRejected):
            self.ingest("B3", [reading(1, 9.0)])
        self.ingest("OLD", [reading(1, 1.0, True)])
        actions = {event["action"] for event in
                   self.service.audit("viewer", self.item["id"])}
        self.assertIn("batch_accept", actions)
        self.assertIn("batch_reject", actions)
        self.assertIn("batch_late", actions)
        self.assertIn("recompute", actions)
        self.assertTrue(self.repo.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
