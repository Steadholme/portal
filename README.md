# Portal — HOLDFAST 主权云指挥中心

Portal 是 HOLDFAST 主权基础设施的**顶级入口（apex command center / dashboard）**，部署在 `w33d.xyz`。
它坐落在 Sluice 网关的 `auth=sso` 路由之后，**自身不做任何登录**：网关完成 OIDC 浏览器登录后，
**剥离**入站 `X-Auth-*` 并注入可信身份头，Portal 直接读取 `X-Auth-Email` 显示「已登录为」。
仅内网可达（只能经 Sluice 在 `w33d.xyz` 主机上访问）。

技术栈与 keystone / keyward / beacon 一致：Rust + axum、env 驱动的 `Config`、`healthcheck` 子命令、
多阶段非 root Dockerfile（rustls + `ring`，不链接 OpenSSL）、内嵌 HOLDFAST 企业级设计令牌
（品牌渐变 `#0B1220→#0F172A`、靛蓝强调色 `#4F46E5`、圆角卡片、状态药丸、盾徽 + 字标应用栏）。

## 指挥中心仪表盘 `GET /`

现代化的运维指挥中心（server-rendered，CSS 内嵌），自上而下：

- **应用栏（sticky）**：左侧盾徽 + `HOLDFAST` 字标 + `Command Center` 标签；右侧登录邮箱（带首字母头像）+
  指向 `https://id.w33d.xyz/_gw/auth/logout` 的退出链接（**绝对地址**，跨子域）。
- **品牌渐变 Hero**：基于服务器时间的问候语（`Good morning/afternoon/evening, <Name>`，name 取邮箱
  local-part 首字母大写）+ 一行实时摘要（`N of M systems operational · K audit events sealed`）。
- **实时指标卡（live metric cards）**——悬浮于 Hero 下沿，大数字 + 标签 + 强调色：
  - **Systems online** `<up>/<total>` 运行中组件（来自 Beacon）+ All operational / Degraded 标签
  - **Host CPU** 最新 `cpu_pct`（来自 Vitals）+ 进度条 + Nominal/Elevated/Critical
  - **Host memory** 最新 `mem_pct`（来自 Vitals）+ 进度条
  - **Audit events** 审计链长度（来自 Watchtower `/api/verify`）+ `✓ Chain verified` / `⚠ Integrity broken`
  - **Load · 1m** 最新 `load1`（来自 Vitals）
- **服务网格（services grid）**：每个目录条目一张卡——内联 SVG 图标、服务名、一行描述、**实时状态药丸**
  （`operational` / `degraded` / `down`，不可达时 `unknown`），整卡链接到该服务公开子域。Mail 为 coming soon。
- **最近活动（recent activity）**：Watchtower 最近 ~8 条审计事件（action、actor、相对时间，按严重度着色圆点）。
- 响应式：窄屏下指标卡与双栏自动堆叠；WCAG AA 对比度。

## 实时数据（并发拉取 + 缓存）

一次页面加载所需的全部实时数据，由 `snapshot` 模块**一轮并发**（`tokio::join!`）拉取，**整体缓存数秒**（默认 5s）。
每路请求**短超时（2s）**且**各自独立容错**：

| 后端 | 内网端点 | 用途 |
|------|----------|------|
| Beacon | `GET <BEACON_URL>/api/status` | `components[].name/status` → systems-online 计数 + 每张磁贴药丸 |
| Vitals | `GET <VITALS_URL>/api/metrics?since=…` | 取各 metric 最新样本：`cpu_pct` / `mem_pct` / `load1` → 指标卡 |
| Watchtower | `GET <WATCHTOWER_URL>/api/verify` | `{ok,count}` → 审计事件数 + 链验证指示 |
| Watchtower | `GET <WATCHTOWER_URL>/api/events` | 最新审计事件数组（newest-first）→ 最近活动（取前 8） |

> Beacon 返回 `StatusView`；Vitals 返回 `{samples:[{host,metric,value,ts}]}`（`ts` 为 epoch 秒）；
> Watchtower 事件 `ts` 为 epoch **毫秒**（渲染相对时间时折算为秒）。

**韧性是契约**：任何后端不可达 / 超时 / 非 200 / JSON 损坏，只会把**自己那张卡 / 药丸 / 信息流**降级为
`—` / `unknown` / 空，**绝不报错或阻塞整页**，其余卡片照常并发渲染。

## 服务目录（catalog）

默认目录（可经 `PORTAL_CATALOG` JSON 覆盖整张表）共 **9 张磁贴**，`component` 名与部署 `BEACON_SEED` 对齐：

| 服务     | URL                        | Beacon 组件 | 备注 |
|----------|----------------------------|-------------|------|
| Identity | `https://id.w33d.xyz`      | `Identity`  | SSO / OIDC 签发方 |
| Status   | `https://status.w33d.xyz`  | `Gateway`   | Beacon 公共状态页 |
| Vitals   | `https://vitals.w33d.xyz`  | `Vitals`    | 主机指标仪表盘 |
| Audit    | `https://audit.w33d.xyz`   | `Audit`     | Watchtower 审计 |
| Blog     | `https://blog.w33d.xyz`    | `Blog`      | Inkwell 博客 |
| Forum    | `https://forum.w33d.xyz`   | `Forum`     | Agora 论坛 |
| Wiki     | `https://wiki.w33d.xyz`    | `Wiki`      | Lattice 知识库 |
| Paste    | `https://paste.w33d.xyz`   | `Pastefire` | Pastefire 代码分享 |
| Mail     | `https://mail.w33d.xyz`    | `Mail`      | 预留给 Corvid（coming soon） |

> 目录条目的 `component` 名需与 Beacon 实际探测的组件名一致才能点亮实时药丸；未匹配则显示 `unknown`。
> `PORTAL_CATALOG` 条目字段：`name`、`url`、`description?`、`component?`、`icon?`、`coming_soon?`。
> `icon` 可选值：`identity` / `status` / `vitals` / `audit` / `mail` / `blog` / `forum` / `wiki` / `paste`（其它回退为通用图标）。

## 配置（环境变量）

| 变量             | 默认                      | 说明 |
|------------------|---------------------------|------|
| `BIND_ADDR`      | `0.0.0.0:8600`            | 监听地址 |
| `BEACON_URL`     | `http://beacon:8400`      | 内网 Beacon 基址（拼 `/api/status`） |
| `VITALS_URL`     | `http://vitals:8300`      | 内网 Vitals 基址（拼 `/api/metrics`） |
| `WATCHTOWER_URL` | `http://watchtower:8500`  | 内网 Watchtower 基址（拼 `/api/verify`、`/api/events`） |
| `PORTAL_CATALOG` | （内置 9 张默认目录）     | 覆盖整张目录的 JSON 数组 |

## 构建与冒烟

```bash
# 本地测试（无数据库、无外部服务，内置 fake Beacon/Vitals/Watchtower）
cargo test
cargo clippy --all-targets -- -D warnings

# 构建镜像
docker build -t holdfast/portal:dev .

# 冒烟：健康检查 + 仪表盘（后端不可达时仍渲染，指标降级为 — / unknown）
docker run --rm -p 8600:8600 holdfast/portal:dev &
curl -fsS http://127.0.0.1:8600/healthz          # -> ok
curl -fsS http://127.0.0.1:8600/ | head          # -> 渲染指挥中心仪表盘
```

## 网关接线

在 Sluice 路由表中（主机 `w33d.xyz`）：

```
host w33d.xyz -> http://portal:8600   auth=sso
```

Portal 仅内网可达；Sluice 是唯一公网入口。`/_gw/auth/callback` 与 `/_gw/auth/logout` 由 Sluice 自身
在 `id.w33d.xyz` 上提供，redirect_uri 保持 `https://id.w33d.xyz/_gw/auth/callback` 不变。
