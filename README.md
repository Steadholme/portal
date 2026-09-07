# Portal — Steadholme 主权云指挥中心

Portal 是 Steadholme 主权基础设施的**顶级入口（apex command center / dashboard）**，部署在 `w33d.xyz`。
它坐落在 Sluice 网关的 `auth=sso` 路由之后，**自身不做任何登录**：网关完成 OIDC 浏览器登录后，
**剥离**入站 `X-Auth-*` 并注入可信身份头，Portal 直接读取 `X-Auth-Email` 显示「已登录为」。
仅内网可达（只能经 Sluice 在 `w33d.xyz` 主机上访问）。

技术栈与 keystone / keyward / beacon 一致：Rust + axum、env 驱动的 `Config`、`healthcheck` 子命令、
多阶段非 root Dockerfile（rustls + `ring`，不链接 OpenSSL）、内嵌 Portal 自己的设计令牌
（画布 `#F6F7F9`、强调蓝 `#2F5BD3`、8–16px 圆角、状态药丸、盾徽；Figma 源：w33d's team › Portal）。

## 启动台 `GET /`（v2 · Command canvas）

server-rendered，无 JS 也完整可用；页面上每个字符串只允许是**名称、数值或动作**（没有眉标、坐标、来源说明、只读提示或计数）。自上而下：

- **顶行**：盾徽（回到首页）、机队芯片 `N/M up`（Beacon 有数据时才出现）、账号弹层（Account / All services / Sign out，退出指向 `https://sso.w33d.xyz/_gw/auth/logout`）。
- **命令框**：唯一入口。`?q=` 服务端过滤；有 JS 时就地过滤簇，`⌘K` / `/` 打开命令面板（模糊匹配、键盘导航）。下方是本机记住的 **最近 / 已置顶** 胶囊（localStorage，键名冻结为 `holdfast.portal.*.v1`）。
- **便当区左列（`#estate-live`，Wire 可整体刷新）**：
  - **Fleet** 卡：环形图每个点是一个 Beacon 组件，中心 `up/total`；非 operational 的组件按名字 + 状态药丸列出；`Refresh`（`X-Wire: 1` 片段替换）与 `Status` 链接。
  - **Host** 卡：CPU / Memory / Load 三条竖表（Vitals）、24h 事件数、`N sealed · chain verified`（Watchtower）。
- **便当区右列**：按类别成簇的图标 + 名称瓦片（Communication、Content & Knowledge、Identity & Security、Observability、AI & Assistants、Developer & Platform、Platform & Tools）。降级 / 宕机在图标角上显示状态环，`Soon` 标记未上线。点击瓦片打开抽屉（状态 / 地址 / 访问面 + Open / Pin）。
- **Internal 簇**：只在网关签名 attested 的 internal zone 出现，虚线下沉、带 `VPN` 药丸，内部按 Observe / Protect / Ship / Network / Recover 分组。

外部视图只读取 Beacon public projection；组件名、机队汇总与审计事件永远不会从 operator projection 泄漏到外部 HTML（见测试 `beacon_scopes_*`、`dashboard_external_wire_fragment_*`）。

## 操作台 `GET /ops`（v2 · Sealed stream）

管理员（`X-Auth-Groups` ∩ {admins, infra-admins}）专用，只读：

- **顶行**：盾徽 + `Audit · Host` 分段控件 + 账号弹层。
- **摘要条**：Chain（链长 + 验证结论）、Fleet（operator projection 的 `up/total`，非 operational 组件名）、CPU、Memory、Load、Events（匹配当前筛选的事件数）。
- **审计流**：按 Today / Yesterday / 日期分组的事件行（时间、严重度色轨、mono 动作、目标、来源、操作者）；筛选是 GET 表单——动作搜索框 + Source / Actor / Range 三个 `<details>` 芯片（无 JS 亦可用，激活时显示值与 Clear 链接）；分页链接保留全部筛选。每行内含 `<details>` 密封记录（Seq / Timestamp / … / Prev hash / Hash），有 JS 时折叠进右侧**检视器**（记录字段 + prev → hash 链可视化 + Verified 药丸 + Open in Watchtower / Copy hash）。
- **Host**：Vitals 主机指标块。服务健康属于 Beacon，不在 Portal 出现。

## 实时数据（并发拉取 + 缓存）

一次页面加载所需的全部实时数据，由 `snapshot` 模块以固定 5 路、**有界并发**（`tokio::join!`）拉取，
**整体缓存数秒**（默认 5s）。每路请求**短超时（2s）**且**各自独立容错**：

| 后端 | 内网端点 | 用途 |
|------|----------|------|
| Beacon public projection | `GET <BEACON_PUBLIC_URL>/api/status` | external full/Wire 的 systems-online、incident banner 与 public 磁贴状态 |
| Beacon operator projection | `GET <BEACON_URL>/api/status` | 签名 internal Estate 与 admin `/ops` 的完整组件状态 |
| Vitals | `GET <VITALS_URL>/api/metrics?since=…` | 取各 metric 最新样本：`cpu_pct` / `mem_pct` / `load1` → 指标卡 |
| Watchtower | `GET <WATCHTOWER_URL>/api/verify` | `{ok,count}` → 审计事件数 + 链验证指示 |
| Watchtower | `GET <WATCHTOWER_URL>/api/events` | 最新审计事件数组（newest-first）→ 最近活动（取前 8） |

> Beacon 返回 `StatusView`；Vitals 返回 `{samples:[{host,metric,value,ts}]}`（`ts` 为 epoch 秒）；
> Watchtower 事件 `ts` 为 epoch **毫秒**（渲染相对时间时折算为秒）。

两份 Beacon projection 同时进入同一个短期 snapshot，但渲染边界严格按 trust scope 选择：external full 与
`X-Wire: 1` 只读取 public projection；只有通过 gateway-zone 签名验证的 internal Estate 和 admin `/ops`
才读取 operator projection。external HTML 不会从共享 cache 的 operator rollup、组件名、总数或 incident banner
中取值。

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
| `BEACON_PUBLIC_URL` | `http://beacon:8400`   | Beacon public projection 基址（拼 `/api/status`）；只用于 external full/Wire |
| `BEACON_URL`     | `http://beacon:8401`      | Beacon operator projection 基址（拼 `/api/status`）；只用于 internal Estate 与 `/ops` |
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
docker build -t steadholme/portal:dev .

# 冒烟：健康检查 + 仪表盘（后端不可达时仍渲染，指标降级为 — / unknown）
docker run --rm -p 8600:8600 steadholme/portal:dev &
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
