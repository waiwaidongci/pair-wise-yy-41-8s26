# 桥梁结构监测与限行决策

融合传感、巡检、交通荷载和天气数据，生成限载限行或恢复建议。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量。
- `src/repository.py`：SQLite建表、事务、版本控制和审计链。
- `src/service.py`：权限检查、用例编排、并发控制和审计。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则和失败测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8318
```

默认端口为`8318`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/transition`，必须提交`expected_version`，进入限行/封闭还须提交`notice_ref`
- `POST /api/items/{id}/batches`，网关批次补传（`sensor_operator`）
- `GET /api/items/{id}/batches`，批次处理结果
- `POST /api/items/{id}/revoke-notice`，撤销交通通告（`traffic_authority`）
- `GET /api/audit`

允许角色：sensor_operator, bridge_engineer, traffic_authority, viewer。监测偏差与预警阈值之比和多条异常记录决定告警等级；限行与封闭决策必须绑定交通通告记录。

### 网关批次规则

- 报文：`{"batch_no": "...", "readings": [{"seq": 1, "value": 1.2, "alarm": false, "recorded_at": "..."}]}`，批次内按`seq`排序，`seq`为从1开始的连续整数。
- 同一批次号重复提交：沿用第一次处理结果（accepted/rejected/late），不重复入库、不重算，返回`status=duplicate`并追加审计。
- 序列重叠：逐条比对`value/alarm/recorded_at`，任一不同即**整批拒绝**，409响应`reason=overlap_conflict`，`conflicts`指出冲突序列与字段；同时存在缺口时为`overlap_conflict_and_gap`。
- 缺口：前沿之后到本批最大序列之间若缺号（如已有1-2却传4），整批拒绝，`reason=gap`，`missing`列出缺失序列；缺口未补齐不能跳过。
- 并发补传：每桥梁串行处理，批次唯一约束兜底。
- 重算：按**最新连续序列**（1..前沿）统计`alarm=true`的读数数量，写入`quantity`；等级映射 0=normal、1-2=watch、3-5=warning、6+=critical，且只升不降（迟到旧批不能把已升级告警降级）。
- 迟到批（全部序列都在前沿之内且内容一致）：仅留存一条`monitoring`监测记录，不改变告警数量和等级。
- 每次接收、重算、拒绝、迟到、重复提交都写入哈希审计链。

### 交通通告绑定与撤销

- `kind=traffic_notice`的记录仅`traffic_authority`可登记，`external_ref`为通告编号。
- 进入`restricted/closed`必须提交处于`open`状态的通告编号，审计记录绑定的`notice_ref`。
- 撤销通告后按住来未关闭事项重算状态：仍有其他生效通告则维持限行/封闭；无生效通告但还有未关闭事项时，restricted退回warning、closed退回restricted；所有事项均已关闭时直接restored。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
