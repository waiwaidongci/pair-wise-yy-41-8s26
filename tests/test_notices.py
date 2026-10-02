import tempfile, unittest
from pathlib import Path
from src.domain import ConflictError, PermissionDenied
from src.repository import Repository
from src.service import Service


class NoticeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        self.item = self.service.create_item(
            {"title": "notice bridge", "description": "traffic measures",
             "severity": "warning", "quantity": 0, "threshold": 10,
             "external_ref": "N-1"}, "creator", "sensor_operator")

    def tearDown(self):
        self.repo.close(); self.tmp.cleanup()

    def advance(self):
        current = self.service.get_item(self.item["id"], "viewer")
        if current["status"] == "normal":
            current = self.service.transition(current["id"], "warning", current["version"],
                                          "sensor", "sensor_operator")
        return self.service.transition(current["id"], "restricted", current["version"],
                                  "engineer", "bridge_engineer",
                                  notice_ref="NOTICE-1")

    def add_notice(self, ref="NOTICE-1", status="open"):
        return self.service.add_record(
            self.item["id"],
            {"kind": "traffic_notice", "detail": "measure", "status": status,
             "external_ref": ref}, "ta", "traffic_authority")

    def test_restricted_requires_open_notice_binding(self):
        with self.assertRaises(ConflictError):
            current = self.service.get_item(self.item["id"], "viewer")
            self.service.transition(current["id"], "restricted", current["version"],
                                  "engineer", "bridge_engineer",
                                  notice_ref="NOTICE-1")
        self.add_notice("NOTICE-OLD", status="closed")
        with self.assertRaises(ConflictError):
            self.advance()
        self.add_notice()
        current = self.advance()
        self.assertEqual(current["status"], "restricted")
        audit = self.service.audit("viewer", self.item["id"])
        bound = [event for event in audit if event["action"] == "transition"][-1]
        self.assertEqual(bound["detail"]["notice_ref"], "NOTICE-1")

    def test_notice_requires_traffic_authority(self):
        with self.assertRaises(PermissionDenied):
            self.service.add_record(
                self.item["id"],
                {"kind": "traffic_notice", "detail": "x", "external_ref": "X"},
                "sensor", "sensor_operator")
        with self.assertRaises(PermissionDenied):
            self.service.revoke_notice(
                self.item["id"], {"notice_ref": "NOTICE-1"},
                "engineer", "bridge_engineer")

    def test_revoke_restricted_notice_recomputes_to_warning_when_items_open(self):
        self.add_notice()
        self.service.add_record(
            self.item["id"],
            {"kind": "inspection", "detail": "pending repair", "status": "open",
             "external_ref": "JOB-1"}, "engineer", "bridge_engineer")
        self.advance()
        result = self.service.revoke_notice(
            self.item["id"], {"notice_ref": "NOTICE-1"}, "ta",
            "traffic_authority")
        self.assertEqual(result["status"], "restricted")
        self.assertEqual(result["status_after"], "warning")
        current = self.service.get_item(self.item["id"], "viewer")
        self.assertEqual(current["status"], "warning")

    def test_revoke_closed_notice_restores_when_no_open_items(self):
        self.add_notice()
        current = self.advance()
        current = self.service.transition(current["id"], "closed", current["version"],
                                      "ta", "traffic_authority",
                                      notice_ref="NOTICE-1")
        result = self.service.revoke_notice(
            self.item["id"], {"notice_ref": "NOTICE-1"}, "ta",
            "traffic_authority")
        self.assertEqual(result["status"], "closed")
        self.assertEqual(result["status_after"], "restored")
        self.assertEqual(
            self.service.get_item(self.item["id"], "viewer")["status"], "restored")
        self.assertTrue(self.repo.verify_audit_chain())

    def test_revoking_one_of_two_notices_keeps_measure_active(self):
        self.add_notice("NOTICE-1")
        self.add_notice("NOTICE-2")
        self.advance()
        result = self.service.revoke_notice(
            self.item["id"], {"notice_ref": "NOTICE-1"}, "ta",
            "traffic_authority")
        self.assertEqual(result["status_after"], "restricted")
        result = self.service.revoke_notice(
            self.item["id"], {"notice_ref": "NOTICE-2"}, "ta",
            "traffic_authority")
        self.assertEqual(result["status_after"], "restored")


if __name__ == "__main__":
    unittest.main()
