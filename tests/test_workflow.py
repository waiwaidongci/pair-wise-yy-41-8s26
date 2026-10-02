import tempfile, unittest
from pathlib import Path
from src.repository import Repository
from src.service import Service
from src.rules import STATES, TRANSITION_ROLES
class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.repo=Repository(str(Path(self.tmp.name)/"test.db")); self.service=Service(self.repo)
    def tearDown(self): self.repo.close(); self.tmp.cleanup()
    def test_complete_workflow_and_audit(self):
        item=self.service.create_item({"title":"workflow item","description":"complete business flow","severity":'warning',"quantity":12,"threshold":6,"external_ref":"WF-1"},"creator",'sensor_operator')
        self.assertEqual(item["status"],STATES[0])
        self.service.add_record(item["id"],{"kind":"evidence","detail":"evidence registered","status":"closed","external_ref":"EV-1"},"recorder",'sensor_operator')
        self.service.add_record(item["id"],{"kind":"traffic_notice","detail":"restriction notice","status":"open","external_ref":"NOTICE-1"},"ta",'traffic_authority')
        current=item
        for target in STATES[1:-1]:
            notice_ref="NOTICE-1" if target in ("restricted","closed") else None
            current=self.service.transition(current["id"],target,current["version"],"reviewer",TRANSITION_ROLES[target][0],notice_ref=notice_ref)
        self.assertEqual(current["status"],"closed")
        self.service.revoke_notice(current["id"],{"notice_ref":"NOTICE-1"},"ta",'traffic_authority')
        current=self.service.get_item(current["id"],"viewer")
        self.assertEqual(current["status"],STATES[-1])
        self.assertEqual(len(self.service.list_records(current["id"],"viewer")),2)
        events=self.service.audit("viewer",current["id"]); self.assertGreaterEqual(len(events),len(STATES)+2); self.assertTrue(self.repo.verify_audit_chain())
if __name__=="__main__": unittest.main()
