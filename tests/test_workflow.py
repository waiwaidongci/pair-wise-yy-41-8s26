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
        ta=self.service.add_record(item["id"],{"kind":"traffic_announcement","detail":"traffic control in force","status":"open","external_ref":"TA-1"},"recorder",'bridge_engineer')
        current=item
        for target in STATES[1:-1]:
            traffic_ref="TA-1" if target in ("restricted","closed") else None
            current=self.service.transition(current["id"],target,current["version"],"reviewer",TRANSITION_ROLES[target][0],traffic_ref)
        self.assertEqual(current["status"],'closed')
        # 通告撤销后按未关闭事项重算：证据已结清、通告已撤销，全部结清即恢复
        current=self.service.close_record(item["id"],ta["id"],"reviewer",'traffic_authority')["item"]
        self.assertEqual(current["status"],STATES[-1])
        self.assertEqual(len(self.service.list_records(current["id"],"viewer")),2)
        events=self.service.audit("viewer",current["id"]); self.assertGreaterEqual(len(events),len(STATES)+1); self.assertTrue(self.repo.verify_audit_chain())
if __name__=="__main__": unittest.main()
