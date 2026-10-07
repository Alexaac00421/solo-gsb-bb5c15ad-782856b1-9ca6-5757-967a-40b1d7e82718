# 内网前缀委派 Web 平台

基于 **Node.js (Express) + PostgreSQL** 的内网 IPv4/IPv6 前缀（CIDR）委派管理台。
支持管理员与地址持有人两类本地账号，提供独立地址域、根前缀、自动选号分配、
管理员保留、释放/重用、前缀树展示与请求幂等等能力。

## 功能概览

- **账号**：本地用户名/密码（bcrypt 存储，JWT 登录）。分 `admin`（管理员）与 `holder`（地址持有人）。
- **地址域**：管理员创建互相独立的地址域；每个域分别管理 IPv4 与 IPv6 两棵前缀树。
- **根前缀**：管理员在域内创建 IPv4/IPv6 根前缀；**同域同族的有效根前缀不得重叠**（包含、交叉、完全相同均拒绝）。
- **申请分配**：管理员或父前缀持有人可在任意有效父前缀下申请更长的目标前缀长度与用途。
  系统自动选出父范围内 **数值最小、按 CIDR 边界对齐、且不与任何有效直属子前缀（分配/保留）重叠** 的子前缀，
  返回规范 CIDR、前缀编号与当前完整前缀树；空间不足返回 `409 NO_SPACE`。
  - 管理员可通过 `holder_id` 直接把前缀委派给指定持有人；持有人只能在自己持有的父前缀下继续细分。
- **保留**：管理员可保留指定 CIDR（必须边界对齐、位于某个有效根内、与现有有效前缀不重叠）。
- **释放**：管理员可释放任意前缀；持有人只能释放自己的前缀。存在有效下级时拒绝（`409 HAS_ACTIVE_CHILDREN`）。
  释放只是把记录标记为 `released`——**旧记录仍可追溯（含操作历史），地址立即可被重新分配**（重新分配生成新编号的新记录）。
- **并发安全**：同一 (地址域, 地址族) 上的分配/保留在数据库事务 + 咨询锁内串行选号，并发申请绝不会得到重叠前缀。
- **幂等**：所有写操作必须携带 `Idempotency-Key` 请求头。成功操作返回唯一 `request_no`；
  同用户、同 Key、同内容重试返回首次结果（含同一编号、同一 CIDR，响应带 `Idempotent-Replay: true`）；
  同 Key 异内容返回 `409 IDEMPOTENCY_CONFLICT`。
- **严格校验**：非法 CIDR、主机位非零、跨地址族混用、目标长度不大于父前缀、越出父/根范围、
  无权操作等一律以 4xx 拒绝且不改变任何状态。

## 一键启动（Docker Compose）

前置：已安装 Docker 与 Docker Compose 插件。

```bash
docker compose up --build -d
```

该命令会：

1. 构建应用镜像（`node:20-alpine`）并安装生产依赖；
2. 启动 PostgreSQL 16 容器并在数据卷中持久化；
3. 等待数据库健康后启动应用，**自动建表、初始化数据库结构、播种初始管理员账号**（schema 幂等，可重复执行）。

启动后访问：

- **Web 控制台地址端口**：<http://localhost:3000>
- 初始管理员：用户名 `admin`，密码 `admin12345`（请通过环境变量修改，见下）
- 数据库对外映射端口：`localhost:55432`

停止与清理：

```bash
docker compose down          # 停止（保留数据）
docker compose down -v       # 停止并删除数据库数据卷
```

## 本地裸机运行（不使用 Docker）

需要本机已有 Node.js ≥ 20 和可访问的 PostgreSQL。

```bash
npm install
# 指向你自己的 PostgreSQL（用户需有建表权限）
export DATABASE_URL="postgres://deleg:deleg@localhost:5432/delegation"
export JWT_SECRET="some-long-random-secret"
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD=admin12345
npm start
```

应用启动时会自动等待数据库就绪、执行 `db/schema.sql`（幂等）并播种管理员。
打开 <http://localhost:3000>。

## 配置（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PORT` | `3000` | 应用监听端口（容器内；宿主机映射由 `APP_PORT` 控制） |
| `APP_PORT` | `3000` | Compose 映射到宿主机的 Web 端口 |
| `DATABASE_URL` | `postgres://deleg:deleg@localhost:5432/delegation` | PostgreSQL 连接串 |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | `deleg` / `deleg` / `delegation` | Compose 中数据库的账号与库名 |
| `POSTGRES_PORT` | `55432` | Compose 数据库映射到宿主机的端口 |
| `JWT_SECRET` | `change-me-in-production` | JWT 签名密钥，**生产环境务必修改** |
| `JWT_TTL` | `12h` | 登录令牌有效期 |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | `admin` / `admin12345` | 首次启动播种的初始管理员 |
| `PG_POOL_MAX` | `10` | 数据库连接池大小 |

可复制 `.env.example` 为 `.env` 后由 Compose 自动读取。

## Web 界面用法

1. 浏览器打开 <http://localhost:3000>，用管理员登录（也可先自助注册“持有人”账号）。
2. 左侧**新建地址域**，选中域后在左下方**新建根前缀**（如 `10.0.0.0/8`、`2001:db8::/32`）。
3. 在中间前缀树中点击某个父前缀将其选中，右侧：
   - **申请子前缀**：填写目标长度（如 `26`）与用途，提交后自动分配最小对齐空闲块；
   - **保留指定子前缀**（管理员）：填写完整 CIDR；
   - **释放前缀**：对选中前缀执行释放。
4. 每次成功操作右下角提示中带唯一请求号；中间树实时刷新。顶部可切换 IPv4 / IPv6。

## HTTP API 摘要

除注册/登录/健康检查外均需 `Authorization: Bearer <token>`；所有写接口需 `Idempotency-Key` 请求头。

| 方法 | 路径 | 角色 | 说明 |
| --- | --- | --- | --- |
| POST | `/api/register` | 公开 | 自助注册持有人 |
| POST | `/api/login` | 公开 | 登录获取 JWT |
| GET | `/api/me` | 已登录 | 当前用户信息 |
| POST | `/api/users` | 管理员 | 创建账号（可指定 admin/holder） |
| GET | `/api/users` | 管理员 | 用户列表 |
| POST | `/api/domains` | 管理员 | 创建地址域 |
| GET | `/api/domains` | 已登录 | 地址域列表 |
| GET | `/api/domains/:id/tree?family=4\|6` | 已登录 | 当前有效前缀树 |
| POST | `/api/roots` | 管理员 | 创建根前缀 `{domain_id, cidr, purpose}` |
| POST | `/api/prefixes/allocate` | 管理员/父前缀持有人 | 自动分配 `{domain_id, parent_id, target_len, purpose, holder_id?}` |
| POST | `/api/prefixes/reserve` | 管理员 | 保留 `{domain_id, cidr, purpose}` |
| POST | `/api/prefixes/:id/release` | 管理员/持有人本人 | 释放 `{note?}` |
| GET | `/api/prefixes` | 已登录 | 前缀列表（可按 domain/family/status/type/holder 过滤） |
| GET | `/api/prefixes/:id` | 管理员/持有人本人 | 前缀详情及其关联请求号 |
| GET | `/api/prefixes/:id/history` | 管理员/持有人本人 | 同一规范 CIDR 的历代记录（含已释放） |
| GET | `/api/health` | 公开 | 健康检查 |

典型响应（分配）：

```json
{
  "prefix": {
    "id": 12,
    "domain_id": 1,
    "family": 4,
    "cidr": "10.0.0.192/26",
    "prefix_len": 26,
    "type": "allocation",
    "status": "active",
    "purpose": "dmz",
    "parent_id": 4,
    "holder_id": 7,
    "created_by": 1
  },
  "tree": [ /* 该域该族完整的有效前缀树 */ ],
  "request_no": "REQ-9f86d081884c7d659a2feaa0c55ad015"
}
```

### curl 示例

```bash
# 登录
TOKEN=$(curl -s localhost:3000/api/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin12345"}' | jq -r .token)

# 建域
curl -s localhost:3000/api/domains -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: dom-1' \
  -d '{"name":"lab","description":"测试域"}'

# 建 IPv4 根
curl -s localhost:3000/api/roots -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: root-v4-1' \
  -d '{"domain_id":1,"cidr":"10.0.0.0/8","purpose":"corp"}'

# 在根 #2 下申请 /26（自动选号），重试同一命令即幂等返回首次结果
curl -s localhost:3000/api/prefixes/allocate -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: alloc-1' \
  -d '{"domain_id":1,"parent_id":2,"target_len":26,"purpose":"net-a"}'
```

## 数据模型要点

- `prefixes` 同时保存 `active` 与 `released` 行；地址以 NUMERIC(39,0) 数字区间
  `(start_ip, end_ip)` 存储，可容纳 IPv6 的 128 位值。
- `(domain_id, family, cidr)` 上存在仅针对有效行的唯一索引——同一规范 CIDR
  同一时刻只能有一条有效记录；释放后旧记录保留，地址方可重用。
- 选号在事务内对 `(domain_id, family)` 取 `pg_advisory_xact_lock`，配合区间重叠
  校验，保证并发分配/保留不会产生重叠结果。
- `requests` 表记录每个成功写操作的唯一 `request_no`、幂等键、请求体指纹与响应快照，
  支撑重试回放与冲突检测，也让每个前缀可追溯其来源请求。

## 测试

测试通过 `embedded-postgres` 自动拉起真实 PostgreSQL，无需外部依赖：

```bash
npm test                 # 运行全部（CIDR 单元 + 端到端 + 并发压力）
npm run test:cidr        # CIDR 解析/选号算法单元测试
npm run test:e2e         # 全流程 HTTP 端到端（权限、校验、幂等、释放/重用…）
npm run test:concurrency # 并发分配/保留不重叠 + 同键并发重试收敛为一次
```

## 项目结构

```
.
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── db/schema.sql           # 幂等建表脚本
├── src
│   ├── server.js           # Express 入口、建表与播种
│   ├── db.js               # 连接池、事务、类型解析
│   ├── auth.js             # JWT、bcrypt、角色中间件
│   ├── cidr.js             # CIDR 解析/规范化与最小对齐选号算法
│   ├── tree.js             # 扁平记录 -> 前缀树
│   ├── idempotency.js      # 请求号/指纹/同键互斥
│   ├── idempotent.js       # 幂等写操作包装
│   └── routes/             # auth / domains / prefixes 路由
├── public/                 # 单页 Web 控制台
└── test/                   # 单元、端到端、并发测试
```
