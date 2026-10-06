# 内网前缀委派 Web 平台

基于 **Node.js (Express) + PostgreSQL** 的内网 IPv4/IPv6 前缀委派管理台。

## 功能概览

- **本地账号**：管理员（`admin`）与地址持有人（`holder`），Session 登录。
- **地址域**：管理员创建相互独立的地址域，并在域下建立 IPv4/IPv6 **根前缀**；
  同地址域、同族的根前缀不得重叠（数据库触发器强制）。
- **前缀申请**：管理员或**父前缀持有人**在有效父前缀下，指定更长的目标前缀长度与用途；
  系统自动选出父范围内**数值最小、按 CIDR 边界对齐、且不与有效直属子分配/保留重叠**的子前缀，
  返回规范 CIDR、编号与当前完整前缀树；空间不足明确拒绝（`NO_FREE_SPACE`）。
- **保留**：管理员可在父前缀下保留任意指定的、边界对齐且不冲突的子前缀。
- **释放**：管理员可释放任意前缀；持有人只能释放自己名下分配；
  存在有效下级时拒绝（`HAS_ACTIVE_CHILDREN`）；释放后**旧记录保留可追溯、地址立即可重用**。
- **并发安全**：地址域行锁 + 数据库重叠约束双重保证，并发申请/保留绝不会分得重叠前缀。
- **幂等**：每个写操作必须携带 `X-Idempotency-Key: <UUID>`；
  成功响应带唯一**请求号** `request_no`；同内容重试返回首次结果（`replayed: true`），
  异内容返回 `409 IDEMPOTENCY_CONFLICT`。
- **严格校验**：非法 CIDR（含带主机位、前缀长度越界）、跨地址族、越出父范围、
  无权操作均返回 4xx 错误且不改变任何状态。

## 一键启动（推荐，Docker Compose）

前置：已安装 Docker 与 Docker Compose。

```bash
docker compose up --build
```

启动后：

- **Web 地址**：http://localhost:3000
- 首次启动会自动安装依赖、创建全部数据表，并写入初始管理员账号。
- 默认管理员：**admin / admin123**

停止：`Ctrl+C` 后 `docker compose down`（数据保留）；清除数据：`docker compose down -v`。

## 配置（环境变量）

在项目根目录创建 `.env`，或在启动前导出环境变量即可覆盖默认值：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `WEB_PORT` | `3000` | Web 对外端口 |
| `DB_PORT` | `5432` | PostgreSQL 对外端口 |
| `POSTGRES_USER` | `prefix` | 数据库用户 |
| `POSTGRES_PASSWORD` | `prefix` | 数据库密码 |
| `POSTGRES_DB` | `prefix_delegation` | 数据库名 |
| `ADMIN_USERNAME` | `admin` | 初始管理员用户名（仅空库时创建） |
| `ADMIN_PASSWORD` | `admin123` | 初始管理员密码 |
| `SESSION_SECRET` | `please-change-this-secret` | Session 签名密钥，生产请修改 |
| `COOKIE_SECURE` | `false` | 经 HTTPS 部署时设为 `true` |

## 本地裸机运行（可选）

需 Node.js ≥ 20 与可访问的 PostgreSQL 13+：

```bash
npm install
export DATABASE_URL="postgres://prefix:prefix@localhost:5432/prefix_delegation"
npm run init-db        # 建表 + 初始管理员
npm start              # 启动，访问 http://localhost:3000
```

## 测试

- `npm run test`：端到端测试。自动下载并启动一个**真实的嵌入式 PostgreSQL**
  （`embedded-postgres`，devDependency），再启动真实 HTTP 服务，覆盖登录鉴权、
  根前缀不重叠、最小选号、保留/释放权限、释放后重用、非法 CIDR/跨族/越界、
  幂等重放与异内容冲突、以及 30 路并发申请与混合并发保留的不重叠保证。
- `node test/iputil.test.js`：纯算法单元测试（CIDR 严格解析、BigInt 对齐、
  最小空闲块扫描），无需数据库。

## REST API 摘要

所有写操作需携带请求头 `X-Idempotency-Key: <UUID>` 与登录会话 Cookie。

| 方法 | 路径 | 权限 | 说明 |
| --- | --- | --- | --- |
| POST | `/api/auth/login` | 公开 | 登录 `{username,password}` |
| POST | `/api/auth/logout` | 登录 | 退出 |
| GET  | `/api/auth/me` | 登录 | 当前用户 |
| GET/POST | `/api/domains` | 登录 / 管理员 | 列表 / 创建地址域 |
| GET/POST | `/api/users` | 管理员 | 用户列表 / 创建用户 |
| POST | `/api/prefixes/roots` | 管理员 | 创建根前缀 `{domain,cidr,purpose?}` |
| POST | `/api/prefixes/allocate` | 管理员或父前缀持有人 | 申请 `{parentId,targetLength,purpose,holderId?}`（管理员可通过 `holderId` 委派给指定持有人） |
| POST | `/api/prefixes/reserve` | 管理员 | 保留 `{parentId,cidr,purpose?}` |
| POST | `/api/prefixes/:id/release` | 管理员或持有人本人 | 释放 |
| GET  | `/api/prefixes/tree?domain=&family=` | 登录 | 有效前缀树 |
| GET  | `/api/prefixes/history?domain=&family=` | 管理员 | 含已释放的全量历史 |
| GET  | `/api/prefixes/my` | 登录 | 我持有的前缀 |

写操作成功响应示例：

```json
{
  "request_no": "17",
  "prefix": { "id": "12", "cidr": "10.0.1.0/24", "kind": "allocation", "...": "..." },
  "number": "12",
  "tree": [ /* 当前域族完整有效前缀树 */ ]
}
```

典型错误（均为 4xx，且不改变状态）：

- `400 INVALID_CIDR`：CIDR 非法或带主机位
- `400 ADDRESS_FAMILY_MISMATCH`：跨 IPv4/IPv6 地址族
- `400 OUTSIDE_PARENT`：子前缀越出父范围
- `403 FORBIDDEN`：无权操作
- `409 NO_FREE_SPACE`：父前缀下无满足目标长度的连续对齐空间
- `409 PREFIX_OVERLAP`：与有效前缀重叠
- `409 HAS_ACTIVE_CHILDREN`：存在有效下级，不能释放
- `409 IDEMPOTENCY_CONFLICT`：同一幂等键用于不同内容

## 设计要点

- 地址统一表示为半开区间 `[start_addr, end_addr)`（`NUMERIC(39,0)`，足以容纳 128 位 IPv6），
  应用层用 BigInt 做边界对齐与最小空闲块搜索，IPv4/IPv6 同一套算法。
- 最小空闲子前缀搜索：取父范围内首个按目标长度对齐、且不与任一直属有效子区间相交的块，
  无需枚举最多 2^128 个候选。
- 分配/保留/建根在同一事务中先 `SELECT … FOR UPDATE` 锁住地址域行，
  叠加 `trg_prefix_no_invalid_overlap` 触发器作为最终防线。
- 幂等行与业务行同事务提交；失败整体回滚，不留脏请求号。
