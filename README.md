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
  指向 `https://sso.w33d.xyz/_gw/auth/logout` 的退出链接（**绝对地址**，跨子域）。
- **品牌渐变 Hero**：基于服务器时间的问候语（`Good morning/afternoon/evening, <Name>`，name 取邮箱
  local-part 首字母大写）+ 一行实时摘要（`N of M systems operational · K audit events sealed`）。
- **实时指标卡（live metric cards）**——悬浮于 Hero 下沿，大数字 + 标签 + 强调色：
  - **Systems online** `<up>/<total>` 运行中组件（来自 Beacon）+ All operational / Degraded 标签
  - **Host CPU** 最新 `cpu_pct`（来自 Vitals）+ 进度条 + Nominal/Elevated/Critical
  - **Host memory** 最新 `mem_pct`（来自 Vitals）+ 进度条
  - **Audit events** 审计链长度（来自 Watchtower `/api/verify`）+ `✓ Chain verified` / `⚠ Integrity broken`
  - **Load · 1m** 最新 `load1`（来自 Vitals）
- **服务网格（services grid）**：每个目录条目一张卡——内联 SVG 图标、服务名、一行描述、**实时状态药丸**
  （`operational` / `degraded` / `down`，不可达时 `unknown`），整卡链接到对应产品 surface。
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

## Experience Manifest 驱动的 Estate

生产环境必须同时提供 canonical Experience Manifest 生成的两个严格 projection：

- `public`：仅包含可在 `w33d.xyz` 启动台发现的产品 surface；
- `estate`：仅包含额外的 WireGuard/internal 管理 surface，与 `public` 的 stable ID 和 URL 不得重叠。

Portal 在启动时一次性读取并验证两份文件。schema、未知字段、audience、strict SemVer release、未排序 ID、重复 ID/canonical URL、相同 fingerprint、非 HTTPS URL、空字段、未知 category 或任一文件缺失都会让启动失败，避免使用部分或含混的服务目录。顶层 contract 为：

```json
{
  "schemaVersion": "holdfast.experience-projection.v1",
  "release": "1.0.0",
  "fingerprint": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "audience": "public",
  "surfaces": [
    {
      "id": "mail-web",
      "name": "Mail",
      "description": "SSO webmail",
      "url": "https://mail.w33d.xyz",
      "category": "communication",
      "icon": "mail",
      "statusComponent": "Mail",
      "profile": "communication",
      "capabilities": ["launch"],
      "comingSoon": false
    }
  ]
}
```

category vocabulary 固定为 `communication`、`content`、`identity`、`observability`、`ai`、`developer`、`platform`。`profile` 必须是 Odyssey 支持的 14 个 profile 之一，并安全输出为 tile 的 `data-ody-profile`。surface ID 和 capability label 必须以 `[a-z]` 开头，后续仅使用 `[a-z0-9-]`；capabilities 必须唯一并严格升序。`statusComponent` 必须与 Beacon 实际探测的组件名一致。URL 必须位于 `w33d.xyz` 或其子域，使用 HTTPS 且不带 port、userinfo、query 或 fragment。URL 继续是浏览器 pin/recent 的 `data-app-id`，Manifest stable ID 单独输出为 `data-product-id`。

未配置 projection 的纯开发模式继续使用代码内置的 22 个 public 产品和 27 个 internal 管理 surface，并保留 `PORTAL_CATALOG` 对 public catalog 的兼容覆盖。配置 projection 后，`PORTAL_CATALOG` 不参与生产渲染。

外部请求只读取 `public` projection；只有精确的 `X-Gateway-Zone: internal`、匹配固定 host `w33d.xyz`，并通过独立 `X-Gateway-Zone-Sig` 验证后，服务端才组合 `public + estate`。Manifest metadata 只控制展示，绝不生成 Sluice route 或授权决策。

## 配置（环境变量）

| 变量             | 默认                      | 说明 |
|------------------|---------------------------|------|
| `BIND_ADDR`      | `0.0.0.0:8600`            | 监听地址 |
| `BEACON_URL`     | `http://beacon:8400`      | 内网 Beacon 基址（拼 `/api/status`） |
| `VITALS_URL`     | `http://vitals:8300`      | 内网 Vitals 基址（拼 `/api/metrics`） |
| `WATCHTOWER_URL` | `http://watchtower:8500`  | 内网 Watchtower 基址（拼 `/api/verify`、`/api/events`） |
| `EXPERIENCE_PUBLIC_PROJECTION` | 未设置 | production `public` projection 文件路径 |
| `EXPERIENCE_ESTATE_PROJECTION` | 未设置 | production `estate` projection 文件路径；必须与 public 成对设置 |
| `GATEWAY_ZONE_HMAC_KEY` | 未设置 | production projection 模式必填；只由 Sluice 与 Portal 持有 |
| `GATEWAY_HMAC_KEY` | 未设置 | 网关注入 identity headers 的独立 HMAC key；不得与 zone key 相同 |
| `PORTAL_CATALOG` | （内置 22 张 public 目录） | 仅无 projection 的 dev/legacy 模式覆盖 public catalog |

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
在 `sso.w33d.xyz` 上提供，redirect URI 保持 `https://sso.w33d.xyz/_gw/auth/callback` 不变。

内部 Estate attestation 使用独立的、host/route-bound payload：

```text
holdfast.gateway-zone.v1\nportal-root\nw33d.xyz\ninternal\n<epoch_minute>
```

Portal 接受 current/previous minute。签名缺失、伪造、过期、Host 不匹配或 zone 不精确匹配时，页面安静降级为 public projection，不返回内部 hostname、internal fingerprint 或审计 target。
