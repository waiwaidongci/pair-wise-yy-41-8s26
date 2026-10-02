from __future__ import annotations

import hashlib
import json

from .domain import ConflictError, ValidationError
TITLE='桥梁结构监测与限行决策'; ENTITY='桥梁告警'; ID_PREFIX='BM'
SEVERITIES=['normal', 'watch', 'warning', 'critical']; STATES=['normal', 'warning', 'restricted', 'closed', 'restored']; TRANSITIONS={'normal': ['warning'], 'warning': ['restricted'], 'restricted': ['closed'], 'closed': ['restored'], 'restored': []}; TRANSITION_ROLES={'warning': ['sensor_operator'], 'restricted': ['bridge_engineer'], 'closed': ['traffic_authority'], 'restored': ['bridge_engineer']}
CREATE_ROLES=set(['sensor_operator']); RECORD_ROLES=set(['sensor_operator', 'bridge_engineer']); AUDIT_ROLES=set(['bridge_engineer', 'viewer']); VIEW_ROLES=set(['sensor_operator', 'bridge_engineer', 'traffic_authority', 'viewer'])
SEVERITY_WEIGHT={'normal': 1.0, 'watch': 3.0, 'warning': 6.0, 'critical': 9.0}; DEADLINE_HOURS={'normal': 72, 'watch': 24, 'warning': 8, 'critical': 4}; TERMINAL_STATES=set(['restored'])

# 网关批次与交通通告
BATCH_STATUSES=['accepted', 'rejected']
READING_KIND='sensor_reading'
TRAFFIC_ANNOUNCEMENT_KIND='traffic_announcement'
CLOSURE_BIND_STATES=set(['restricted', 'closed'])
READING_FIELDS=('severity', 'quantity', 'threshold', 'kind', 'detail', 'measured_at')


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


def reading_content_hash(reading):
    """对读数的有效载荷做规范哈希，用于重叠批次的逐条比对。"""
    payload={k: reading.get(k) for k in READING_FIELDS}
    raw=json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def reading_field_diff(existing, incoming):
    """逐条比对重叠读数的字段，返回不一致位置列表。"""
    mismatches=[]
    for field in READING_FIELDS:
        ev=existing.get(field); iv=incoming.get(field)
        if ev!=iv:
            mismatches.append({'field': field, 'existing': ev, 'incoming': iv})
    return mismatches


def gap_positions(hwm, new_seqs):
    """新读数必须恰好连续接在 hwm 之后，返回缺失的序号。"""
    new_set=set(int(s) for s in new_seqs)
    expected=list(range(int(hwm)+1, int(hwm)+1+len(new_set)))
    missing=[s for s in expected if s not in new_set]
    return sorted(missing)


def recalc_readings(readings):
    """按最新连续序列重算告警：严重度取峰值、数量取峰值、告警数取越界条数。"""
    if not readings:
        return None
    peak=max(readings, key=lambda r: SEVERITY_WEIGHT.get(r.get('severity'), 0))
    quantity=max(float(r.get('quantity', 0)) for r in readings)
    latest=max(readings, key=lambda r: int(r.get('seq', 0)))
    threshold=float(latest.get('threshold', 1))
    alarm_count=sum(
        1 for r in readings
        if r.get('severity') in ('warning', 'critical')
        or float(r.get('quantity', 0)) >= float(r.get('threshold', 1))
    )
    return {
        'severity': peak['severity'],
        'quantity': quantity,
        'threshold': threshold,
        'alarm_count': alarm_count,
        'continuous_through_seq': int(latest['seq']),
    }
