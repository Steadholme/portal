# Portal — HOLDFAST 主权云入口

Portal 是 HOLDFAST 主权基础设施的**顶级入口（apex launcher / dashboard）**，部署在 `w33d.xyz`。
它坐落在 Sluice 网关的 `auth=sso` 路由之后，**自身不做任何登录**：网关完成 OIDC 浏览器登录后，
**剥离**入站 `X-Auth-*` 并注入可信身份头，Portal 直接读取 `X-Auth-Email` 显示「已登录为」。
仅内网可达（只能经 Sluice 在 `w33d.xyz` 主机上访问）。

技术栈与 keystone / keyward / beacon 一致：Rust + axum、env 驱动的 `Config`、`healthcheck` 子命令、
多阶段非 root Dockerfile（rustls + `ring`，不链接 OpenSSL）、内嵌 HOLDFAST 企业级设计令牌
（品牌渐变 `#0B1220→#0F172A`、靛蓝强调色 `#4F46E5`、12px 圆角、状态药丸、盾徽 + 字标应用栏）。

## 端点

| 方法 | 路径        | 鉴权             | 说明 |
|------|-------------|------------------|------|
| GET  | `/`         | SSO（网关注入）  | 仪表盘：标题 + 响应式服务磁贴网格 |
| GET  | `/healthz`  | 公开             | 存活探针（容器 HEALTHCHECK 使用） |

### 仪表盘 `GET /`

- 标题：`HOLDFAST · Sovereign Cloud` / `Welcome, <email>`。
- **服务磁贴网格**（响应式）。每块磁贴含：内联 SVG 图标、服务名、一行描述、**实时状态药丸**
  （`operational` / `degraded` / `down`，不可达时为 `unknown`），并链接到该服务的公开子域。
- 右上角：登录邮箱 + 指向 `https://id.w33d.xyz/_gw/auth/logout` 的退出链接（**绝对地址**，跨子域）。

### 实时状态

仪表盘以**短超时（2s）**拉取 Beacon 的内网 JSON `GET <BEACON_URL>/api/status`，把每个目录条目的
`component` 名映射到对应组件状态 → 磁贴药丸。结果**缓存数秒**（默认 5s）。

**韧性是契约**：Beacon 不可达 / 超时 / 非 200 / JSON 损坏，一律折叠为空映射，磁贴渲染为 `unknown`
药丸——**页面永不报错**。

## 服务目录（catalog）

默认目录（可经 `PORTAL_CATALOG` JSON 覆盖整张表）：

| 服务     | URL                        | Beacon 组件 | 备注 |
|----------|----------------------------|-------------|------|
| Identity | `https://id.w33d.xyz`      | `Identity`  | SSO / OIDC 签发方 |
| Status   | `https://status.w33d.xyz`  | `Gateway`   | Beacon 公共状态页 |
| Vitals   | `https://vitals.w33d.xyz`  | `Vitals`    | 主机指标仪表盘 |
| Audit    | `https://audit.w33d.xyz`   | `Audit`     | Watchtower 审计 |
| Mail     | `https://mail.w33d.xyz`    | `Mail`      | 预留给 Corvid（coming soon） |

> 目录条目的 `component` 名需与 Beacon 实际探测的组件名一致才能点亮实时药丸；未匹配则显示 `unknown`。
> Beacon 内置 seed 仅含 `Gateway` / `Identity` / `CA`，可通过 `BEACON_SEED` 扩展以覆盖 Vitals/Audit 等。

`PORTAL_CATALOG` 条目字段：`name`、`url`、`description?`、`component?`、`icon?`、`coming_soon?`。
`icon` 可选值：`identity` / `status` / `vitals` / `audit` / `mail`（其它回退为通用图标）。

## 配置（环境变量）

| 变量             | 默认                      | 说明 |
|------------------|---------------------------|------|
| `BIND_ADDR`      | `0.0.0.0:8600`            | 监听地址 |
| `BEACON_URL`     | `http://beacon:8400`      | 内网 Beacon 基址（拼 `/api/status` 拉取实时状态） |
| `PORTAL_CATALOG` | （内置默认目录）          | 覆盖整张目录的 JSON 数组 |

## 构建与冒烟

```bash
# 本地测试（无数据库、无外部服务，内置 fake Beacon）
cargo test

# 构建镜像
docker build -t holdfast/portal:dev .

# 冒烟：健康检查 + 仪表盘（Beacon 不可达时仍渲染，药丸为 unknown）
docker run --rm -p 8600:8600 holdfast/portal:dev &
curl -fsS http://127.0.0.1:8600/healthz          # -> ok
curl -fsS http://127.0.0.1:8600/ | head          # -> 渲染磁贴网格
```

## 网关接线

在 Sluice 路由表中新增（主机 `w33d.xyz`）：

```
host w33d.xyz -> http://portal:8600   auth=sso
```

Portal 仅内网可达；Sluice 是唯一公网入口。`/_gw/auth/callback` 与 `/_gw/auth/logout` 由 Sluice 自身
在 `id.w33d.xyz` 上提供，redirect_uri 保持 `https://id.w33d.xyz/_gw/auth/callback` 不变。
