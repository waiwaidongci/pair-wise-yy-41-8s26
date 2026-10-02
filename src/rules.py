from __future__ import annotations
from .domain import ConflictError, ValidationError
TITLE='桥梁结构监测与限行决策'; ENTITY='桥梁告警'; ID_PREFIX='BM'
SEVERITIES=['normal', 'watch', 'warning', 'critical']; STATES=['normal', 'warning', 'restricted', 'closed', 'restored']; TRANSITIONS={'normal': ['warning'], 'warning': ['restricted'], 'restricted': ['closed'], 'closed': ['restored'], 'restored': []}; TRANSITION_ROLES={'warning': ['sensor_operator'], 'restricted': ['bridge_engineer'], 'closed': ['traffic_authority'], 'restored': ['bridge_engineer']}
CREATE_ROLES=set(['sensor_operator']); RECORD_ROLES=set(['sensor_operator', 'bridge_engineer']); AUDIT_ROLES=set(['bridge_engineer', 'viewer']); VIEW_ROLES=set(['sensor_operator', 'bridge_engineer', 'traffic_authority', 'viewer'])
GATEWAY_ROLES=set(['sensor_operator']); NOTICE_ROLES=set(['traffic_authority']); NOTICE_REVOKE_ROLES=set(['traffic_authority'])
TRAFFIC_NOTICE_KIND='traffic_notice'; MONITORING_KIND='monitoring'; TRAFFIC_MEASURE_STATES=set(['restricted','closed'])
SEVERITY_WEIGHT={'normal': 1.0, 'watch': 3.0, 'warning': 6.0, 'critical': 9.0}; DEADLINE_HOURS={'normal': 72, 'watch': 24, 'warning': 8, 'critical': 4}; TERMINAL_STATES=set(['restored'])
def priority_score(severity,quantity=0.0,threshold=1.0,open_records=0):
    if severity not in SEVERITY_WEIGHT: raise ValidationError("unknown severity")
    ratio=quantity/threshold if threshold>0 else 1.0
    return max(0,min(10,int(round(SEVERITY_WEIGHT[severity]+min(4.0,ratio*4.0)+min(3.0,float(open_records))))))
def response_deadline_hours(severity,quantity=0.0,threshold=1.0):
    if severity not in DEADLINE_HOURS: raise ValidationError("unknown severity")
    ratio=quantity/threshold if threshold>0 else 1.0
    return max(1,int(DEADLINE_HOURS[severity]/max(1.0,ratio)))
def escalation_required(severity,quantity=0.0,threshold=1.0):
    return severity==SEVERITIES[-1] or (threshold>0 and quantity>=threshold)
def can_transition(current,target): return target in TRANSITIONS.get(current,[])
def validate_transition(current,target):
    if current not in STATES or target not in STATES: raise ValidationError("未知状态")
    if not can_transition(current,target): raise ConflictError(f"不能从{current}转换到{target}")
def completion_blockers(target,open_records): return ["仍有未关闭事项"] if target in TERMINAL_STATES and open_records>0 else []
def role_for_transition(target): return set(TRANSITION_ROLES.get(target,[]))
WARNING_ALARM_COUNT=3; CRITICAL_ALARM_COUNT=6
SEVERITY_ORDER={name:index for index,name in enumerate(SEVERITIES)}
def recompute_severity(current,alarm_count):
    if alarm_count>=CRITICAL_ALARM_COUNT: computed=SEVERITIES[3]
    elif alarm_count>=WARNING_ALARM_COUNT: computed=SEVERITIES[2]
    elif alarm_count>=1: computed=SEVERITIES[1]
    else: computed=SEVERITIES[0]
    if SEVERITY_ORDER[computed]>SEVERITY_ORDER[current]: return computed
    return current
def notice_blockers(target,open_notice_count):
    return ["限行或封闭必须绑定有效的交通通告记录"] if target in TRAFFIC_MEASURE_STATES and open_notice_count<=0 else []
def status_after_notice_revoked(current,open_notice_count,open_record_count=None):
    if current not in TRAFFIC_MEASURE_STATES or open_notice_count>0: return current
    if open_record_count is not None and open_record_count<=0: return 'restored'
    return 'warning' if current=='restricted' else 'restricted'
