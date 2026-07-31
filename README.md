# Camellia Nexus Management Server

## 中文

Camellia Nexus Management Server 是 Camellia Nexus 桌面客户端的生产授权服务。服务端是账号、授权、设备、刷新会话、授权码、挑战、审计事件和 entitlement 签发状态的权威中心。客户端只保存设备本地密钥、刷新会话和短期 entitlement 租约。

客户端与服务端的联合生产就绪结论由两仓库各自的审计文档和精确版本发布证据共同维护。

### 生产模型

生产环境要求：

- PostgreSQL 持久化存储
- 稳定的 entitlement 签发配置
- HTTPS issuer URL
- 显式配置的桌面 OAuth client 与 redirect URI allow-list
- 通过 Admin CLI 发放和管理授权码
- JSON 日志，便于平台采集和审计
- 与业务入口分离的私有 Prometheus 指标监听器
- 数据库迁移在受控环境中执行，迁移、公开 API、Admin Web 与 Worker 使用四个独立数据库身份

最小环境变量示例：

```bash
CAMELLIA_NEXUS_LICENSE_ENV=production
CAMELLIA_NEXUS_LICENSE_BIND=0.0.0.0:8088
CAMELLIA_NEXUS_LICENSE_STORAGE=postgres
DATABASE_URL=postgres://nexus_public:replace-with-url-safe-secret@postgres:5432/nexus
CAMELLIA_NEXUS_LICENSE_ISSUER=https://license.example.com
CAMELLIA_NEXUS_LICENSE_AUDIENCE=camellia-nexus-desktop
CAMELLIA_NEXUS_LICENSE_KEY_ID=entitlement-2026-00
CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM_PATH=/run/secrets/entitlement-es256-private.pem
CAMELLIA_NEXUS_WORKSPACE_KEYRING_PATH=/run/secrets/workspace_keyring.json
CAMELLIA_NEXUS_WEBHOOK_KEYRING_PATH=/run/secrets/webhook_keyring.json
CAMELLIA_NEXUS_OAUTH_CLIENT_ID=camellia-nexus-desktop
CAMELLIA_NEXUS_OAUTH_REDIRECT_URIS=camellia-nexus://auth/callback
CAMELLIA_NEXUS_CLIENT_MINIMUM_VERSION=1.0.0
CAMELLIA_NEXUS_CLIENT_RECOMMENDED_VERSION=1.0.0
CAMELLIA_NEXUS_CLIENT_VERSION_ENFORCE_AFTER=2030-01-01T00:00:00Z
CAMELLIA_NEXUS_CORS_ALLOWED_ORIGINS=camellia-nexus://localhost
CAMELLIA_NEXUS_LOG_FORMAT=json
CAMELLIA_NEXUS_LOG_LEVEL=info
CAMELLIA_NEXUS_HTTP_LOG_LEVEL=info
CAMELLIA_NEXUS_HTTP_FAILURE_LOG_LEVEL=warn
CAMELLIA_NEXUS_DATABASE_MIGRATE=false
CAMELLIA_NEXUS_DATABASE_MAX_CONNECTIONS=8
CAMELLIA_NEXUS_DATABASE_ACQUIRE_TIMEOUT_SECONDS=5
CAMELLIA_NEXUS_TIME_MAX_FORWARD_JUMP_SECONDS=86400
CAMELLIA_NEXUS_HTTP_REQUEST_TIMEOUT_SECONDS=15
CAMELLIA_NEXUS_HTTP_MAX_IN_FLIGHT=256
CAMELLIA_NEXUS_METRICS_BIND=0.0.0.0:9091
CAMELLIA_NEXUS_METRICS_ALLOW_NON_LOOPBACK=true
CAMELLIA_NEXUS_MAINTENANCE_INTERVAL_SECONDS=3600
CAMELLIA_NEXUS_CLEANUP_BATCH_SIZE=1000
```

授权码在 PostgreSQL 中以哈希形式保存，并通过 Admin CLI 管理。生产环境硬性拒绝静态环境变量授权码；`CAMELLIA_NEXUS_LICENSE_ACTIVATION_CODES` 仅供开发环境使用。

### 容器镜像与部署

服务端以根 `Cargo.toml` 为唯一版本真源，并与客户端独立演进。`main` 门禁通过后，`Release Manager` 自动提出版本与变更日志；只有最终 head 获得人工批准且按规定 squash 合并后，才会在复核仓库策略与不可变 Release 设置后创建 tag 和 draft Release，镜像以 digest 校验和签名后发布。手动运行只验证按提交 SHA 标识的候选镜像，不推送。

镜像位置由组织审核后的 `CONTAINER_REGISTRY_MAP` 决定。GHCR 和 Docker Hub
分别按配置发布；未配置的目标会明确跳过，不允许由凭据或手工输入隐式启用。

服务端与客户端分别维护独立的版本序列。服务端只发布规范的稳定语义化版本；发布前绑定最高的已完成兼容客户端正式版，审批前冻结并扫描 OCI 字节，审批后仅把同一 digest 复制到已配置的注册表。完成不可变 Release、证据与公开回读后，`latest` 才指向最高已完成稳定版；发布 tag 和版本镜像 tag 不得覆盖。该仓库只使用绑定 OCI digest 的无密钥 Cosign/OIDC 身份，不保存桌面或移动端证书/密钥。完整流程见 [发布规范](docs/releasing.md)。

容器部署要点：

- 当前生产镜像契约仅支持 `linux/amd64`；ClamAV 依赖与正式构建均显式采用该架构，不承诺未经验证的兼容架构
- 使用 `docker-compose.yml` 作为生产部署模板，并替换镜像 owner、数据库密码、issuer URL 和 OAuth redirect URI allow-list
- 将签发 PEM 放入 compose secret 指向的位置，默认示例为 `./secrets/entitlement-es256-private.pem`
- Compose 的本地文件型 secret 会保留宿主机所有权；应用镜像以 `10001:10001` 运行，因此所有私密 secret 文件必须由 `10001:10001` 持有并设为 `0400`，`secrets/` 目录应仅允许部署账号访问（`0700`）。不得以全局可读的 `0444` 规避权限错误
- PostgreSQL 使用固定到不可变摘要的 `postgres:18-alpine`，数据卷挂载到 `/var/lib/postgresql`
- 服务默认只暴露到本机地址，生产入口应由反向代理提供 HTTPS
- `docker-compose.yml` 显式关闭应用启动迁移；先执行受控的一次性迁移，再启动或滚动替换服务
- 启动后使用 `GET /healthz` 与 `GET /readyz` 检查服务状态；容器内可执行 `camellia-nexus-management-server healthcheck http://127.0.0.1:<port>/readyz`，并给 SIGTERM 至少 30 秒退出窗口

### 数据库迁移策略

服务端使用 SQLx 管理 PostgreSQL schema。尚未发布的完整数据模型已压缩为唯一的
`migrations/0001_prelaunch_baseline.sql`；此前的开发数据库没有升级兼容路径，必须删除并从该基线
重建。首次正式发布后，已发布迁移不可修改、重排或删除，后续 schema 演进只能通过新的递增
migration 表达。

`CAMELLIA_NEXUS_DATABASE_MIGRATE` 的默认值取决于 `CAMELLIA_NEXUS_LICENSE_ENV`：开发环境为 `true`，生产环境为 `false`。常驻服务在生产环境必须保持 `false`；发布前由同一镜像的专用 `migrate` 角色一次性应用迁移并验证 readiness：

```bash
docker compose run --rm migrate
```

迁移成功退出后，Compose 才会启动公开授权服务、管理控制台和任务 Worker。服务在绑定监听端口前仍会执行 schema readiness 检查；该检查不替代完整 migration/checksum 发布门禁。

SQLx 会校验数据库中已应用 migration 的 checksum。校验失败表示运行工件与数据库迁移历史不一致，
应停止发布并恢复二者的一致状态，再通过新的 migration 交付结构变更。不得手动改写
`_sqlx_migrations`。当前基线会一次性建立授权、管理员身份、批处理、对象存储、付款证据、Team、云
工作区和 Webhook 结构，并初始化可信时间单例；任一必要结构缺失时 readiness 会失败。

### 管理控制台

同一镜像包含三个相互隔离的运行角色：

- `serve`：公开授权 API，只监听公开授权端口。
- `admin-web`：私有管理 WebUI 与 `/api/v1` 管理 API，使用独立 origin、监听端口和会话 Cookie。
- `admin-worker`：执行持久化批量任务、过期敏感交付清理和后台维护。

管理界面可以通过浏览器原生入口安装为名为 **Camellia Console** 的在线型 PWA：桌面与 Android
使用浏览器提供的安装入口，iOS 使用系统“添加到主屏幕”。除本机开发 origin 外，安装要求 HTTPS；
站内不提供安装按钮。Service Worker 只预缓存带内容哈希的前端资源、自托管字体和版本化图标，不缓存
导航、`index.html`、fallback、manifest、外观初始化脚本、`/api/v1`、认证响应、Cookie 或任何管理
数据。安装后仍必须在线连接并完成正常登录和会话校验，断网时不提供离线管理能力。

首次部署：

```bash
./scripts/generate-keyring.sh admin
./scripts/generate-keyring.sh workspace
./scripts/generate-keyring.sh webhook
./scripts/generate-proxy-secret.sh
sudo chmod 0700 secrets
sudo chown 10001:10001 \
  secrets/entitlement-es256-private.pem secrets/*-keyring.json \
  secrets/admin-proxy-secret
sudo chmod 0400 \
  secrets/entitlement-es256-private.pem secrets/*-keyring.json \
  secrets/admin-proxy-secret
docker compose run --rm migrate
docker compose run --rm admin-web admin operator bootstrap owner \
  --display-name "Primary owner" \
  --actor deployment \
  --reason "initial control-plane bootstrap"
docker compose up -d
```

引导命令只输出十分钟有效的登记令牌。管理员首次打开控制台后设置密码并登记 TOTP；密码使用 Argon2id，TOTP 密钥和敏感交付使用独立派生密钥加密。激活码批次和 Team 邀请令牌不会直接出现在普通 API 响应或日志中，而是绑定当前管理员会话，通过十分钟领取令牌查看，并在确认后销毁密文。

管理会话采用 30 分钟空闲时限和 8 小时不可延长的绝对时限；敏感操作仍要求最近 10 分钟内再次验证密码与 TOTP。控制台仅在页面可见且检测到近期键盘、指针或重新聚焦操作时，以低频 `/auth/me` 检查延续活跃会话；后台标签页或无人操作不会被保活。这样可避免管理员持续工作时因纯前端查看或筛选而意外退出，同时仍会让真正闲置的会话自动失效。页脚显示当前会话的绝对结束时间，密码修改、身份禁用及服务端撤销仍会立即终止会话。

管理端创建 Team 邀请、更新成员和撤销邀请均在数据库事务内认领幂等键。若创建邀请的响应在网络中丢失，控制台会保留原操作键，重新取得同一条邀请的短期加密交付，而不会重复占用席位或生成第二名成员；修改了请求内容却复用旧操作键会得到冲突响应。

账户、授权、设备、激活码、账单、批量任务取消和付款凭证也使用相同的持久幂等契约：资源变更、审计和公开响应在一个事务内提交，控制台仅在确认收到业务错误后更换操作键。最终提交事务会锁定并重新验证管理员身份状态、会话、凭据代际、角色和所需权限；并发撤权要么先使写入失败，要么等待该次已获授权的提交结束。批量 Worker 对每个条目执行同样检查。激活码密文交付可由原操作键重新取得；付款凭证还以声明与文件摘要去重，并由 worker 回收崩溃留下的孤立对象。秘密领取本身由会话绑定领取令牌保护，领取与确认也在提交事务内重新验证对应权限。

完成首次引导后，Platform Owner 可在私有控制台的“管理员身份”页面新增、分配角色、禁用和重置控制面身份。新身份在完成一次性令牌登记密码与 TOTP 前保持 `pending`；禁用会立即撤销全部会话并作废未使用的登记令牌；重置会先移除旧密码、TOTP 和恢复码，再签发新的十分钟登记令牌。身份变更必须具备近期二次验证、操作原因、幂等键和 `If-Match` 行版本；服务端拒绝自我禁用、自我重置以及移除最后一名活跃 Platform Owner。

管理员用户名是创建后不可修改的登录与审计标识；每名活跃管理员均可在个人菜单中修改自己的显示名称和密码，无需获得身份管理权限，但仍须通过近期二次验证、操作原因、幂等键与 `If-Match` 行版本保护。密码修改会原子推进凭据代际并撤销该身份的全部管理会话；即使并发登录已完成旧密码校验，也无法在新代际提交后创建或提升会话。若全部在线管理路径不可用，可从受控终端执行 `admin operator recover-owner` 恢复一名 Platform Owner；命令要求精确确认规范化用户名，清除原密码、TOTP、恢复码和会话，将身份置为 `pending`，并只输出一个十分钟有效的重置令牌。若令牌未能交付，可对尚无认证因子的 `pending` Owner 重新执行恢复；新令牌会使此前所有登记令牌失效。该离线命令仅用于恢复控制面访问，不授予产品 Team 权益。

创建客户账户时会建立唯一且稳定的内部 Team Owner 占位身份，首台注册设备自动绑定到该 Owner。私有控制面可在 Team 工作区中一次性完善其邮箱与显示名称；操作受二次验证、幂等键和 row version 保护，只替换占位资料，不会新建成员、额外占用席位、改变 Owner 角色或改动设备绑定。产品 Team 角色与控制面管理员角色是彼此独立的身份域，Team Owner 不会因此获得 Admin UI 登录能力。

管理端生产变量：

```bash
CAMELLIA_NEXUS_ADMIN_BIND=0.0.0.0:8090
CAMELLIA_NEXUS_ADMIN_PUBLIC_ORIGIN=https://console.example.com
CAMELLIA_NEXUS_ADMIN_REQUEST_TIMEOUT_SECONDS=180
CAMELLIA_NEXUS_ADMIN_MAX_IN_FLIGHT=64
CAMELLIA_NEXUS_ADMIN_KEYRING_PATH=/run/secrets/admin_keyring
CAMELLIA_NEXUS_ADMIN_FORWARDED_FOR_SECRET_PATH=/run/secrets/admin_proxy_secret
CAMELLIA_NEXUS_OBJECT_STORAGE=database
CAMELLIA_NEXUS_OBJECT_HARD_LIMIT_BYTES=21474836480
CAMELLIA_NEXUS_EVIDENCE_SCANNER=clamav
CAMELLIA_NEXUS_CLAMAV_ADDRESS=clamav:3310
```

`CAMELLIA_NEXUS_CLAMAV_ADDRESS` 使用 `host:port` 格式，host 可为 DNS 名称、IPv4 或带方括号的 IPv6，并在每次建立扫描连接时解析。Compose 部署应保留服务名 `clamav:3310`，不要固定容器的临时 IP。

转发来源地址默认不受信任。需要记录客户端地址时，反向代理必须先删除外部传入的 `X-Forwarded-For` 与 `X-Camellia-Proxy-Auth`，再写入已验证地址和 32–256 个可见 ASCII 字符的共享密钥；服务端通过 `CAMELLIA_NEXUS_ADMIN_FORWARDED_FOR_SECRET_PATH` 从有界常规文件读取同一密钥并以常量时间校验。未通过认证或不是合法 IP 的转发值不会进入审计记录。管理 origin 只能包含 HTTP(S) scheme 与 authority，不得包含用户名或密码；生产环境必须使用 HTTPS，且不应直接暴露到互联网。

对象存储提供三档统一接口并始终执行对象级 XChaCha20-Poly1305 加密、SHA-256 完整性验证和配额控制：`filesystem` 适合单机小规模，`database` 通过 1 MiB PostgreSQL 分块支持中等规模，`s3` 适合大规模与多副本部署。外部后端写入先持久化 staging 元数据；即使上传响应不确定，worker 也会通过有界 HEAD/GET、密文长度、解密与摘要对账后完成提交或清理，绝不丢失唯一恢复记录。外部读取在分配内存前验证数据库与对象元数据，并在流式读取中执行绝对大小上限。付款证据只接受签名匹配的 PNG、JPEG、PDF，先进入隔离区；生产环境强制启用 ClamAV，扫描不可用时保持隔离并拒绝付款通过。

### API

浏览器激活：

- `GET /oauth/authorize`
- `POST /oauth/authorize`

授权 API：

- `GET /healthz`
- `GET /readyz`
- `POST /v1/devices/register`
- `POST /v1/activations/verify`
- `POST /v1/activations/confirm`
- `POST /v1/entitlements/challenge`
- `POST /v1/entitlements/refresh`
- `POST /v1/entitlements/status`
- `POST /v1/session/recovery/challenge`
- `POST /v1/session/recovery`
- `GET /v1/devices?cursor={device_id}&pageSize={1..100}`
- `DELETE /v1/devices/{device_id}`
- `GET /v1/devices/{device_id}/removals/{operation_id}`
- `POST /v1/session/logout`
- `GET /v1/billing/summary`
- `POST /v1/billing/payment-claims`
- `GET /v1/team/profile`
- `GET /v1/team/members`
- `PATCH /v1/team/members/{member_id}`
- `POST /v1/team/members/{member_id}/device-enrollments`
- `POST /v1/team/invitations`
- `POST /v1/team/invitations/accept`
- `POST /v1/team/device-enrollments`
- `POST /v1/team/device-enrollments/accept`
- `POST /v1/team/leave`
- `POST /v1/team/ownership-transfer`
- `GET /v1/team/operations/{operation_id}`
- `GET /v1/workspace/configurations`
- `POST /v1/workspace/configurations`
- `GET /v1/workspace/configurations/{document_id}`
- `DELETE /v1/workspace/configurations/{document_id}`
- `POST /v1/workspace/configurations/{document_id}/revisions`
- `POST /v1/workspace/configurations/{document_id}/publish`
- `POST /v1/workspace/configurations/{document_id}/restore`
- `POST /v1/workspace/configurations/{document_id}/purge`
- `GET /v1/workspace/sync/changes`
- `GET /v1/workspace/sync/checkpoint`
- `POST /v1/workspace/sync/checkpoint`
- `GET /v1/workspace/alerts/rules`
- `POST /v1/workspace/alerts/rules`
- `PATCH /v1/workspace/alerts/rules/{rule_id}`
- `DELETE /v1/workspace/alerts/rules/{rule_id}`
- `GET /v1/workspace/alerts/incidents`
- `POST /v1/workspace/alerts/incidents/{incident_id}/acknowledge`
- `POST /v1/workspace/alerts/incidents/{incident_id}/resolve`
- `GET /v1/workspace/audit/event-types`
- `GET /v1/workspace/audit/events`
- `GET /v1/workspace/audit/export`
- `GET /v1/workspace/webhooks`
- `POST /v1/workspace/webhooks`
- `GET /v1/workspace/webhooks/deliveries`
- `PATCH /v1/workspace/webhooks/{endpoint_id}`
- `DELETE /v1/workspace/webhooks/{endpoint_id}`
- `POST /v1/workspace/webhooks/{endpoint_id}/rotate-secret`

账单、Team 与 Workspace API 仍要求有效且已完成设备证明的 refresh session。Team 账单读取对 `owner`、`admin`、`billing` 开放，提交付款凭证仅允许 `owner`、`billing`；成员列表允许 `owner`、`admin`、`operator`、`viewer`、`auditor`，采用默认 100、最大 200 的键集分页，成员管理仅允许 `owner`、`admin` 且 Admin 不能修改同级 Admin。每个公开 Team 写入请求必须携带规范 UUIDv4 `operationId`。服务端把业务变更、审计与使用 Workspace keyring 独立域派生密钥加密的精确响应放在同一事务提交；同一设备以相同命令和规范请求重试会取得原响应，包括原邀请或设备入组秘密，修改任一绑定内容却复用操作标识会返回冲突。操作记录保留 37 天后由有界维护清理；令牌本身到期后仍保持到期，响应重放不会重新授权。`GET /v1/team/operations/{operation_id}` 仅用于主动离组恢复：只有原 refresh session 与原设备，并且查询中的成员 ID、row version 与已存 `leave_workspace` 请求全部一致时才返回已提交；即使离组已撤销该会话也不扩大查询范围，其他 Team 操作不能冒充离组结果。新工作区自动建立唯一 Owner，并且只有首台设备获得引导绑定；七天邀请仅可激活首台成员设备，追加设备必须使用已绑定设备签发的一次性 15 分钟入组令牌。无效、过期、已消费或类型错误的 Team 令牌只返回可恢复的专用业务错误，不会使有效设备会话失效。已完成关联的同一设备重复提交已接受的邀请或入组请求属于幂等成功，即使令牌随后到期，也可以从响应丢失中安全恢复且不会建立重复绑定。设备移除会原子撤销会话并删除成员绑定；重新激活不会恢复旧绑定。Owner/Admin 可为仍为 Active 且已无绑定设备的成员签发恢复入组令牌，Admin 不能操作 Owner。Suspended 终止会话但保留可恢复绑定；Removed/主动离组会在同一事务中终止会话、将设备标记为 Removed、释放席位并撤销未使用令牌，但不会删除用户本地配置。完整职责矩阵、云能力边界、并发冲突与密钥轮换规则见 [Team 工作区生产契约](docs/team-workspace.md)。

浏览器授权是 Camellia Nexus 第一方 OAuth authorization-code 流程，不是 OIDC，也不签发 ID token。请求的 `scope` 必须逐字等于唯一单 token `camellia.nexus.license`；空值、旧的 `openid`/`offline_access`、未知或重复 scope 以及首尾空白一律拒绝。PKCE 只允许 `S256`，challenge 必须恰好是 43 个无 padding 的 base64url 字符。`state` 必须是 32–128 字节的 RFC 3986 unreserved 字符。`response_type`、`client_id`、redirect URI 和所有协议字段均有固定值或长度上限，未知 query/form 字段也会被拒绝。GET 在显示授权码输入框前调用与 POST 相同的纯协议校验；非法 GET/POST 只显示不可提交的错误页，用户必须回到桌面客户端重新开始授权。

OAuth authorization code 由服务端签发，短期有效，并绑定 PKCE challenge、redirect URI、设备 ID 与设备公钥。它只在首次成功注册事务中消费；若响应在网络中丢失，完全相同的设备、密钥、PKCE 与 redirect 请求可在首次消费后的 10 分钟固定窗口内取回同一已提交结果，重试不会延长窗口。数据库授权码在设备注册时只建立待激活绑定；设备完成私钥持有证明并调用 activation confirm 后，服务端才在事务中增加 redemption 计数，并在达到 `max_redemptions` 时将授权码标为 `consumed`。

生产环境必须配置严格规范的 SemVer `CAMELLIA_NEXUS_CLIENT_MINIMUM_VERSION`、`CAMELLIA_NEXUS_CLIENT_RECOMMENDED_VERSION`（不得低于 minimum）以及统一时间格式的 `CAMELLIA_NEXUS_CLIENT_VERSION_ENFORCE_AFTER`。注册和设备 proof 中的 `appVersion` 也必须是逐字规范的 SemVer。执行时间到达后，低于最低版本的请求在消费授权码、创建/轮换会话或签发 entitlement 前返回 HTTP 426 `client_upgrade_required`，错误 JSON 顶层携带 camelCase `clientVersionPolicy`。执行时间之前签发的 entitlement 会把 `refreshAfter` 和 `exp` 同时截断到执行边界；所有 entitlement 都签入同一 policy，客户端无需依赖可缓存的额外配置端点。有效设备 proof 会更新已登记设备的版本与 last-seen，已激活设备再次登录只更新平台、版本、显示名等非密钥元数据。

`POST /v1/entitlements/status` 不能只凭 bearer 会话读取状态。客户端必须先获取 scope 为 `entitlement:status` 的一次性 challenge，再提交由当前设备签名且包含当前 `appVersion` 的 proof。服务端原子消费 challenge、验证设备私钥持有关系、记录当前版本并执行最低版本策略后，才返回设备状态和授权 epoch。状态查询不轮换刷新会话，HTTP 426 或其他拒绝也不会使同一有效会话失效，但每次查询都必须使用新的 challenge。

版本策略是诚实客户端的升级协调与服务端协议兼容门禁，不是二进制远程证明。设备签名只证明请求者持有已登记私钥；能够修改客户端并控制该私钥的攻击者也能够伪报 `appVersion`。因此服务端不得把版本字符串当成反作弊或授权边界，付费能力仍须由签名 entitlement、服务端状态和服务端权限检查保护；若威胁模型要求证明实际运行工件，还需独立的代码签名、可信更新与平台 attestation 方案。

刷新会话丢失但设备私钥仍在时，客户端可先向 `POST /v1/session/recovery/challenge` 提交 `deviceId`，再将 scope 为 `session:recover` 的一次性 challenge 签名后提交到 `POST /v1/session/recovery`。对任意规范 UUID，challenge 端点均返回相同 HTTP 状态和 JSON 结构：已注册设备与未知设备的挑战都通过同一短期持久化、原子消费和过期清理路径，未知设备使用不可认证的合成主体。恢复端点消费并绑定 challenge 后，对缺失设备使用固定虚拟公钥执行同形态签名校验；不存在、伪造、过期、重放或无效 proof 对外统一为 `invalid_challenge`，只有完成真实设备私钥持有证明后才会返回设备、账户或授权的可操作业务状态。匿名阶段只受全局熔断和入口按来源限流保护，设备维度的恢复桶在 proof 成功后才消耗，因此仅知道设备 UUID 的攻击者不能耗尽该设备的恢复配额。恢复允许 `active` 设备，也允许尚未超过 30 分钟待激活期限的 `pending_activation` 设备继续完成一次响应不明确的注册；成功后服务端废止该设备的旧刷新会话，并签发一个已经过设备证明的新会话。此接口不能恢复过期待激活、`removed`、`revoked` 或 `suspicious` 设备，也不等同于管理员修改设备状态。

`GET /v1/devices` 返回 `{ "devices": [...], "nextCursor": string | null }`，不返回无界数组。`pageSize` 默认 50，必须位于 1–100；`cursor` 省略时读取第一页，后续请求原样传回上一页的 `nextCursor`。游标是不可变设备 ID 的规范小写连字符 UUID，客户端应将其视为不透明值；非规范游标、未知 query 字段及越界页大小均返回 `invalid_request`。仓储层先按当前 `license_id` 过滤，再以 C locale 的 `device_id` 字典序执行 keyset 查询和 `limit + 1` 探测，因此不会把同账号下其他授权的设备加载到内存或计入分页窗口。

`DELETE /v1/devices/{device_id}` 同时要求 bearer refresh session、规范 UUIDv4 `operationId` 与发起设备针对 `device:remove:{device_id}` scope 的签名 proof。服务端再校验目标设备与请求设备属于同一账号和授权；Team 授权还会按成员绑定与角色限制跨成员移除，并禁止移除唯一活跃 Owner 设备。设备状态、会话撤销、Team 绑定删除、审计与幂等结果在同一事务内提交。成功后客户设备列表不再返回该 Removed 设备，重新激活也不会恢复旧成员绑定。客户端可先查询 `GET /v1/devices/{device_id}/removals/{operation_id}`；即使自移除已撤销原会话，该精确原 bearer 仍只能查询自身同一操作的提交状态，从而在响应丢失后完成本地身份切换。复用操作 ID 但改变发起会话、发起设备或目标设备会返回幂等冲突。

### 授权状态语义

| 对象 | 状态 | 服务端语义 |
| --- | --- | --- |
| 账号 | `active` | 允许激活、刷新与会话恢复。 |
| 账号 | `suspended` | 临时停用并撤销账号下设备会话；新激活、刷新和恢复返回 `account_suspended`。可由带审计信息的 Admin 命令恢复为 `active`。 |
| 账号 | `denylisted` | 禁用并撤销账号下设备会话；新激活、刷新和恢复返回 `account_denylisted`。 |
| 授权 | `active` | `expires_at` 为空或仍在未来时可用；到期后返回 `license_expired`。 |
| 授权 | `past_due` / `canceled` | 只有在 `expires_at` 明确位于未来时继续作为宽限期授权；时间到达或未设置时分别返回 `license_past_due` / `license_canceled`。 |
| 设备 | `pending_activation` | 仅允许完成 activation proof/confirm，不可刷新 entitlement。 |
| 设备 | `active` | 可刷新 entitlement、恢复会话，并作为已激活设备计入上限。 |
| 设备 | `removed` | 会话被撤销；同一已登记设备身份和私钥可使用新授权码重新走正常激活流程。 |
| 设备 | `revoked` / `suspicious` | 会话被撤销且注册/刷新被拒绝；不能由 Admin 直接设为 `active`。如需重新登记同一设备身份，先通过有审计的状态操作改为 `removed`，再走新授权码激活；密钥已泄露时应使用新的设备身份和密钥。 |
| 授权码 | `active` | 还必须未过 `expires_at` 且有剩余 redemption 才可用。 |
| 授权码 | `consumed` / `revoked` | 分别表示 redemption 已用尽或被管理员撤销；`expires_at` 是独立约束。`restore` 会重置 redemption 记录，但不会自动延长已到期的 `expires_at`。 |

账号、授权或设备状态变化会阻止后续在线刷新，但已经签发的短期 entitlement 是离线租约，在自身 `exp` 到达前不会被服务端主动收回。

管理能力同时由 Admin CLI 与独立部署的 `admin-web` 控制面提供。公共授权服务不挂载管理路由；管理 WebUI/API 使用独立监听地址、HTTPS origin、管理员身份、权限、CSRF、幂等、版本前置条件和审计边界。

### Admin CLI

服务端二进制内置生产管理命令。Admin 命令需要 `DATABASE_URL`。所有会改变账号、授权、授权码或设备的命令都要求可追责的操作者和原因；发码使用 `--issued-by` 作为 actor，其余变更使用 `--actor`，并统一要求 `--reason`。

二进制提供中英双语的分层帮助。帮助处理发生在配置、日志和数据库初始化之前，因此即使尚未准备生产环境变量或 PostgreSQL，也可以安全查看：

```bash
camellia-nexus-management-server --help
camellia-nexus-management-server serve --help
camellia-nexus-management-server migrate --help
camellia-nexus-management-server healthcheck --help
camellia-nexus-management-server admin-web --help
camellia-nexus-management-server admin-worker --help
camellia-nexus-management-server admin --help
camellia-nexus-management-server admin account --help
camellia-nexus-management-server admin code issue --help
camellia-nexus-management-server help admin license create
camellia-nexus-management-server --version
```

每个顶层运行角色和每项 Admin 操作均有独立帮助。`admin <命令组>` 显示该组的可用操作，`admin <命令组> <操作> --help` 进一步显示准确用法、参数约束、选项说明和示例。`-h` 与 `--help` 等价；根命令还支持 `-V` 与 `--version`。未知命令或多余的位置参数会以用法错误退出，不会被静默忽略并意外启动服务。

账号：

```bash
camellia-nexus-management-server admin account list
camellia-nexus-management-server admin account show <account-id>
camellia-nexus-management-server admin account create acct_customer_001 --note "Customer 001" --actor operator_001 --reason "customer created"
camellia-nexus-management-server admin account set-state acct_customer_001 active --actor operator_001 --reason "support review complete"
camellia-nexus-management-server admin account set-state acct_customer_001 suspended --actor operator_001 --reason "billing review"
camellia-nexus-management-server admin account set-state acct_customer_001 denylisted --actor operator_001 --reason "fraud confirmed"
```

授权：

```bash
camellia-nexus-management-server admin license list
camellia-nexus-management-server admin license list --account acct_customer_001
camellia-nexus-management-server admin license show lic_customer_001
camellia-nexus-management-server admin license create lic_customer_001 --account acct_customer_001 --plan pro --actor operator_001 --reason "purchase provisioned"
camellia-nexus-management-server admin license set-status lic_customer_001 active --actor operator_001 --reason "payment received"
camellia-nexus-management-server admin license set-status lic_customer_001 past_due --actor operator_001 --reason "invoice overdue"
camellia-nexus-management-server admin license set-status lic_customer_001 canceled --actor operator_001 --reason "subscription canceled"
camellia-nexus-management-server admin license set-plan lic_customer_001 team --seats 3 --actor operator_001 --reason "team upgrade"
camellia-nexus-management-server admin license set-seats lic_customer_001 5 --actor operator_001 --reason "seat expansion"
camellia-nexus-management-server admin license set-expires-at lic_customer_001 2027-01-01T00:00:00Z --actor operator_001 --reason "renewal term"
```

Free 与 Pro 授权的购买席位恒为零，创建时应省略 `--seats`；Team 授权必须为 3 至 10,000 席。首次进入 Team 时必须显式提供席位数，已是 Team 时省略席位会保留当前数量，离开 Team 会自动清零；`set-seats` 仅适用于 Team。套餐或席位实际发生变化时，服务端只推进一次 license epoch 与 row version。

控制面 Owner 的离线恢复：

```bash
camellia-nexus-management-server admin operator recover-owner owner \
  --actor recovery-operator \
  --reason "restore control-plane access" \
  --confirm owner
```

`--confirm` 必须与规范化后的目标用户名完全一致。此命令会使现有认证材料立即失效，每次新令牌只在当前输出中显示；若交付失败，可对尚无认证因子的 `pending` Owner 重新执行，新令牌会立即作废此前令牌。命令应只在受控终端执行并安全交付。

人工账单先从报价快照创建 Invoice，再由用户提交付款信息，最后由运营人员审核。只有 `billing payment approve` 的数据库事务成功后才会更新套餐、期限与 license epoch；`submitted`、`needs_information` 或 `rejected` 均不会授予权益。商业报价仅用于 Pro 与 Team。Invoice 席位必须与报价套餐一致：Team 必须显式指定 3 至 10,000 席，Pro 必须为零；服务端会拒绝矛盾输入，不会静默更正商业数据。账单和付款声明采用默认 50、最大 100 的不透明键集分页；Admin UI 可继续加载，CLI 返回带 `nextCursor` 的页面并接受 `--cursor`、`--page-size` 与 `--query`。

```bash
camellia-nexus-management-server admin billing offer create pro-yearly --plan pro --duration-days 365 --currency USD --amount 99 --name-en "Pro yearly" --name-zh "专业版年付" --actor finance_001 --reason "2026 catalog"
camellia-nexus-management-server admin billing method create bank-sgd --name-en "Bank transfer" --name-zh "银行转账" --instructions-en "Use the invoice reference." --instructions-zh "请填写账单付款附言。" --asset SGD --destination-hint "Account ending 1234" --actor finance_001 --reason "manual settlement channel"
camellia-nexus-management-server admin billing invoice create inv_001 --account acct_customer_001 --license lic_customer_001 --offer pro-yearly --due-at 7d --actor finance_001 --reason "customer order"
camellia-nexus-management-server admin billing payment list --status submitted
camellia-nexus-management-server admin billing payment approve claim_001 --row-version 1 --actor reviewer_001 --reason "bank receipt verified" --operation-id review_claim_001_v1
```

付款批准要求金额和结算资产与 Invoice 完全一致。CLI 的三种审核操作必须传入最近一次读取所得的正整数 `--row-version`；Admin UI 使用等价的 `If-Match`，过期版本会被拒绝并要求重新读取。仅 BillingAdmin 可在独立审查后使用 `--allow-amount-override true`，并必须提供审计原因。相同 `operation-id`、row version 与相同请求可安全重试；用同一 ID 提交不同内容会被拒绝。

管理授权码：

```bash
camellia-nexus-management-server admin code issue --account acct_customer_001 --license lic_customer_001 --issued-by operator_001 --reason "customer purchase" --operation-id order_001-issue-01 --count 3 --max-redemptions 1 --channel direct --ttl-days 365
camellia-nexus-management-server admin code list --account acct_customer_001
camellia-nexus-management-server admin code list --status active
camellia-nexus-management-server admin code show <code-or-prefix-or-hash>
camellia-nexus-management-server admin code revoke <code-or-prefix-or-hash> --actor operator_001 --reason "order refunded"
camellia-nexus-management-server admin code restore <code-or-prefix-or-hash> --actor operator_001 --reason "refund reversed" --max-redemptions 1
camellia-nexus-management-server admin code expire <code-or-prefix-or-hash> --actor operator_001 --reason "contract ended" --expires-at 2027-01-01
```

`code issue` 将整批授权码、对应审计事件和 `operation-id` 在一个数据库事务中写入。`operation-id` 必须对发码操作全局唯一；重复值会被拒绝，从而避免自动化重试重复发码。明文只在首次成功提交后输出一次，重复请求不能恢复明文；若首次输出丢失，应根据 operation id 派生的 `order_id` 与审计记录找到并逐一撤销该批授权码，再用新的 operation id 重新发放。

时间输入支持 RFC3339（例如 `2027-01-01T00:00:00Z`）、UTC 日期（`2027-01-01`）、UTC 日期时间（`2027-01-01 00:00:00`）、相对有效期（`30d`、`12h`、`2w`）以及适合机器调用的 Unix 秒。Admin JSON 输出保留规范的 Unix 字段，并补充对应的 UTC ISO 字段，方便人工核对。

Admin 默认使用人类友好输出。若自动化脚本需要严格保持原始字段，使用 `--raw` 或 `--output raw`：

```bash
camellia-nexus-management-server admin --raw license show lic_customer_001
camellia-nexus-management-server admin code list --output raw --status active
```

设备：

```bash
camellia-nexus-management-server admin device list --account acct_customer_001
camellia-nexus-management-server admin device show <device-id>
camellia-nexus-management-server admin device set-state <device-id> removed --actor operator_001 --reason "user removed device"
camellia-nexus-management-server admin device set-state <device-id> suspicious --actor operator_001 --reason "risk signal"
camellia-nexus-management-server admin device revoke <device-id> --actor operator_001 --reason "key compromise"
```

审计：

```bash
camellia-nexus-management-server admin audit list
camellia-nexus-management-server admin audit list --account acct_customer_001 --limit 100
```

账号、授权、设备和授权码都是持久审计实体。Admin CLI 会拒绝其 `delete` 命令，也会拒绝 `device restore` 或把设备直接设为 `active`；请分别使用账号状态、`canceled` 授权状态、`removed`/`revoked` 设备状态和授权码撤销表达业务结果。授权码 `restore` 是经过 actor/reason 审计的 redemption 重置操作，不是物理恢复已删除数据。

明文授权码只在发放时输出一次。新授权码采用 `CNX1-xxxxx-xxxxx-xxxxx-xxxxx-xxxxx` 格式并包含 125 位随机性；输入不区分大小写和连字符。未指定有效期时默认 30 天，`--ttl-days` 必须在 1 至 3650 天之间，且不能和 `--expires-at` 同时使用。数据库只保存哈希、短前缀、redemption 计数和管理元数据。Admin CLI 严格拒绝未知、重复或缺少值的选项，避免自动化脚本因拼写错误静默采用默认值。

### 部署资产

- `Dockerfile`：无运行时软件源安装、数值型非 root UID 的生产镜像
- `.github/workflows/ci.yml`：PR/main 的 Rust、PostgreSQL、管理 UI、浏览器与候选镜像质量门禁
- `.github/workflows/publish-release.yml`：受管 tag 的正式镜像构建、扫描、Cosign 签名、GHCR/GitHub Release 发布与回读
- `.github/dependabot.yml`：Cargo、独立容器输入和 GitHub Actions 依赖更新；耦合工具链与镜像由 `scripts/update-toolchains.sh` 原子更新
- `docs/dependency-management.md`：工具链、依赖、镜像固定和例外治理规范
- `SECURITY.md`、`docs/runbooks/incident-response.md`、`docs/runbooks/key-rotation.md`：安全披露、事件响应与密钥/凭据轮换
- `docs/runbooks/backup-restore.md`、`docs/runbooks/release-rollback.md`：联合恢复点、恢复验收与按摘要发布/回滚
- `docker-compose.yml`：容器部署模板
- `.env.example`：容器环境变量示例
- `deploy/systemd/`：非容器 Linux 的 migrate、公开服务、Admin Web 和 Worker 独立 unit
- `deploy/*.env.example`：按角色分离的非容器生产环境变量模板
- `docs/systemd-deployment.md`：systemd 安装、升级、回滚与指标契约
- `migrations/`：SQLx 管理的 PostgreSQL schema
- `scripts/generate-entitlement-key.sh`：签发 PEM 生成工具
- `scripts/start-local.sh`：本地联调启动脚本

### 日志与运维

entitlement 签发材料应由部署环境统一管理，轮换策略由发布流程控制。

签发材料提示：

- 新环境可使用 `scripts/generate-entitlement-key.sh <private.pem> <public.pem>` 生成 P-256/ES256 PEM。若生产密钥由 KMS、HSM 或平台 secret store 托管，外部部署适配器必须以只读文件挂载服务可读取的 PEM；服务本身不包含原生 KMS/HSM 驱动
- 生产环境仅接受 `CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM_PATH` 指向的只读 PEM 文件；`CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM` 内联值只允许开发环境
- 所有 PEM 与 keyring 挂载必须解析为服务可读的常规文件且不超过 64 KiB；每个 keyring 必须包含 1–64 个 key，以便轮换历史保持显式且有界
- `CAMELLIA_NEXUS_LICENSE_KEY_ID` 标识当前签发版本，并应随发布流程明确管理
- 生产环境还必须配置 `CAMELLIA_NEXUS_WORKSPACE_KEYRING_PATH`。该只读 JSON 使用 `activeKeyId` 选择 `keys` 中一个 URL-safe、无 padding Base64 编码的 32 字节根密钥；Workspace 修订与公开 Team 操作响应使用彼此域分离的派生密钥，轮换时须保留仍被任一历史修订或 Team 操作记录引用的旧密钥
- 生产环境还必须配置独立的 `CAMELLIA_NEXUS_WEBHOOK_KEYRING_PATH`。其 JSON 格式与上述 keyring 相同，但不得复用 Admin 或 Workspace 根密钥；所有服务副本须同时保留仍被端点引用的旧 key id
- 三类 keyring 使用 `scripts/generate-keyring.sh <admin|workspace|webhook> [output]` 独立创建；Team keyring 的两阶段轮换、引用核验和同恢复点备份/恢复流程见 [Team 工作区生产契约](docs/team-workspace.md#team-keyring-operations--team-密钥环运维)
- 客户端信任配置应随桌面版本发布，issuer、audience 和 key id 必须与服务端发布配置一致
- 轮换时先发布包含新信任配置的客户端，再切换服务端签发版本，并保留旧签发配置直到旧租约自然过期

日志配置：

- `CAMELLIA_NEXUS_LOG_FORMAT`：`json` 或 `compact`。生产默认 `json`
- `CAMELLIA_NEXUS_LOG_LEVEL`：应用日志等级，支持 `error`、`warn`、`info`、`debug`、`trace`
- `CAMELLIA_NEXUS_HTTP_LOG_LEVEL`：HTTP request/response access log 等级
- `CAMELLIA_NEXUS_HTTP_FAILURE_LOG_LEVEL`：HTTP failure log 等级
- `CAMELLIA_NEXUS_LOG_FILTER`：可选完整 tracing filter 表达式

运行与维护配置：

- `GET /healthz` 是不访问外部依赖的进程存活检查；公开/Admin `GET /readyz` 最多等待 2 秒检查 repository、必需 schema、所需密钥、Admin 恶意软件扫描器与持久时间权威，并在依赖不可用时返回 `503 not ready` 与 `Cache-Control: no-store`
- `CAMELLIA_NEXUS_HTTP_REQUEST_TIMEOUT_SECONDS`（默认 `15`）限制业务请求总时间；`CAMELLIA_NEXUS_HTTP_MAX_IN_FLIGHT`（默认 `256`）限制进程内并发，超时返回 504，过载返回 503，并附带 `Retry-After: 1`
- `CAMELLIA_NEXUS_ADMIN_REQUEST_TIMEOUT_SECONDS`（默认 `180`）与 `CAMELLIA_NEXUS_ADMIN_MAX_IN_FLIGHT`（默认 `64`）只限制 `admin-web` 的 `/api/v1`；健康检查和静态资源不占用该预算。超时返回机器可读的 504，过载返回 503，二者均附带 `Retry-After: 1`
- `CAMELLIA_NEXUS_DATABASE_ACQUIRE_TIMEOUT_SECONDS`（默认 `5`）限制等待 PostgreSQL 连接的时间；`CAMELLIA_NEXUS_DATABASE_MAX_CONNECTIONS`（默认 `8`）限制连接池大小。`serve`、`admin-web` 与 `admin-worker` 对无效值或零值均直接拒绝启动，不会静默使用默认值
- 每个生产常驻角色都必须设置 `CAMELLIA_NEXUS_METRICS_BIND`。独立运维监听器提供 `/healthz` 与
  Prometheus 文本 `/metrics`；Admin Worker 还提供持续反映数据库、密钥、扫描器与工作循环状态的
  `/readyz`，其容器健康检查必须使用该端点。默认应绑定回环地址。非回环地址还必须显式设置
  `CAMELLIA_NEXUS_METRICS_ALLOW_NON_LOOPBACK=true` 并由私有防火墙/入口隔离。`serve`、`admin-web` 与
  `admin-worker` 使用不同端口；指标只含有界的角色、状态码类别与结果标签，绝不包含租户、设备、URL、
  token 或 operation ID。所有指标族使用兼容经典 Prometheus 命名规则的 `camellia_nexus_` 前缀
- `CAMELLIA_NEXUS_CLIENT_MINIMUM_VERSION`、`CAMELLIA_NEXUS_CLIENT_RECOMMENDED_VERSION` 与 `CAMELLIA_NEXUS_CLIENT_VERSION_ENFORCE_AFTER` 在生产环境均为必填；版本必须是规范 SemVer，执行时间必须是绝对的 RFC3339、UTC 日期/日期时间或 Unix 秒，不接受相对时长。相对时间只允许开发环境和 Admin 有效期输入，避免多副本按各自启动时刻产生不同执行边界
- PostgreSQL 模式以 `service_time_authority` 单例保存授权时间高水位。每个安全相关请求在写入 code、session 或 entitlement 前原子推进高水位，取数据库时间、持久高水位与进程单调时间的最大安全值；因此数据库或主机时钟回拨以及服务重启都不会让已过期对象重新有效。Admin 写命令遵循同一时间权威；内存模式仅用于开发和测试，不提供跨进程持久保证
- `CAMELLIA_NEXUS_TIME_MAX_FORWARD_JUMP_SECONDS`（默认 `86400`，即 24 小时）是数据库时间相对持久高水位允许的一次最大前跳。超过该值时服务记录结构化错误、拒绝全部依赖授权时间的操作并使 readiness 失败，且不会接受异常时间。先校正并确认 PostgreSQL UTC 时间；若前跳来自经过核验的长时间停机，可在受控维护窗口临时把该值提高到覆盖实际间隔，待一次成功 readiness 推进高水位后立即恢复默认并重启。不得直接改写时间权威表
- 生产 PostgreSQL repository 将 rate-limit bucket 持久化并原子更新，因此同一数据库上的所有服务副本共享限流计数；内存 repository 的 bucket 只用于单进程开发/测试
- 应用内匿名全局 bucket 只是集群熔断器，不是来源级防滥用边界。生产 HTTPS 入口必须在转发 `/oauth/*` 和 `/v1/*` 前按经过验证的客户端源地址执行 WAF/限流，并丢弃外部伪造的 forwarded-IP 头；已认证设备流量应使用独立策略，避免匿名攻击耗尽正常刷新容量。重复匿名拒绝的持久审计按事件/原因采样，完整请求计数应由入口指标和访问日志保存
- `CAMELLIA_NEXUS_MAINTENANCE_INTERVAL_SECONDS`（默认 `3600`）与 `CAMELLIA_NEXUS_CLEANUP_BATCH_SIZE`（默认 `1000`）控制清理任务。任务启动后立即运行一次，随后按间隔执行；过期 challenge 和 OAuth authorization code 保留 1 小时，refresh session 在 family 的绝对到期时间后再保留 7 天用于重放检测，rate-limit bucket 保留 2 小时，然后按表分批删除
- 清理任务不会删除账号、授权、设备、数据库授权码或审计事件；这些记录需按业务与合规政策保留
- 服务在 SIGTERM 或 Ctrl-C 后停止接收新连接、等待在途请求完成、停止维护任务并关闭 repository；Webhook Worker 最多用 20 秒排空已认领交付，超时后中止剩余任务并保留可重试状态。部署平台的停止宽限必须同时覆盖请求超时和 Worker 排空；示例 compose 与 systemd 配置使用 30 秒

### 本地验证

本地执行用于开发验证和 CI 等价检查，不是生产部署路径：

```bash
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
bash scripts/test-systemd-deployment.sh
# 需要可创建临时数据库的 TEST_DATABASE_URL
cargo test --locked --test postgres_repository -- --ignored
# 需要默认相邻路径中的客户端仓库，也可显式传入其路径
node scripts/check-cross-repo-contract.mjs
node scripts/test-cross-repo-contract.mjs
scripts/start-local.sh --help
```

最终容器、真实 Admin UI 与 Windows 原生客户端的分层验证范围、一次性 Compose 后端和安全清理要求见
[生产级验证](docs/testing.md)。
四角色 OS/数据库隔离、secret 所有权与迁移后显式授权见
[systemd 部署](docs/systemd-deployment.md)；Compose 使用同一数据库边界。

隔离实验可使用内存存储：

```bash
CAMELLIA_NEXUS_LICENSE_STORAGE=memory cargo run
```

### 许可证

Camellia Nexus Management Server 是需要 Camellia Computing 明确授权的专有软件。源代码可见性、仓库访问权或收到副本均不构成使用、复制、修改、分发、托管或再许可授权。完整条款见 [LICENSE](LICENSE)；第三方组件继续适用各自许可证，详见 [NOTICE](NOTICE)。

## English

Camellia Nexus Management Server is the production licensing service for Camellia Nexus desktop clients. The server is the authority for accounts, licenses, devices, refresh sessions, authorization codes, challenges, audit events and entitlement issuance. Desktop clients only keep device-local keys, refresh sessions and short-lived entitlement leases.

### Production model

Production deployments require:

- PostgreSQL persistent storage
- Stable entitlement issuance configuration
- HTTPS issuer URL
- Explicit desktop OAuth client and redirect URI allow-list
- Activation codes issued and managed through the Admin CLI
- JSON logs for platform ingestion and audit
- A private Prometheus metrics listener separate from product traffic
- Database migrations executed in a controlled environment, with separate migration, public API,
  Admin Web, and Worker database identities

Minimum environment:

```bash
CAMELLIA_NEXUS_LICENSE_ENV=production
CAMELLIA_NEXUS_LICENSE_BIND=0.0.0.0:8088
CAMELLIA_NEXUS_LICENSE_STORAGE=postgres
DATABASE_URL=postgres://nexus_public:replace-with-url-safe-secret@postgres:5432/nexus
CAMELLIA_NEXUS_LICENSE_ISSUER=https://license.example.com
CAMELLIA_NEXUS_LICENSE_AUDIENCE=camellia-nexus-desktop
CAMELLIA_NEXUS_LICENSE_KEY_ID=entitlement-2026-00
CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM_PATH=/run/secrets/entitlement-es256-private.pem
CAMELLIA_NEXUS_WORKSPACE_KEYRING_PATH=/run/secrets/workspace_keyring.json
CAMELLIA_NEXUS_WEBHOOK_KEYRING_PATH=/run/secrets/webhook_keyring.json
CAMELLIA_NEXUS_OAUTH_CLIENT_ID=camellia-nexus-desktop
CAMELLIA_NEXUS_OAUTH_REDIRECT_URIS=camellia-nexus://auth/callback
CAMELLIA_NEXUS_CLIENT_MINIMUM_VERSION=1.0.0
CAMELLIA_NEXUS_CLIENT_RECOMMENDED_VERSION=1.0.0
CAMELLIA_NEXUS_CLIENT_VERSION_ENFORCE_AFTER=2030-01-01T00:00:00Z
CAMELLIA_NEXUS_CORS_ALLOWED_ORIGINS=camellia-nexus://localhost
CAMELLIA_NEXUS_LOG_FORMAT=json
CAMELLIA_NEXUS_LOG_LEVEL=info
CAMELLIA_NEXUS_HTTP_LOG_LEVEL=info
CAMELLIA_NEXUS_HTTP_FAILURE_LOG_LEVEL=warn
CAMELLIA_NEXUS_DATABASE_MIGRATE=false
CAMELLIA_NEXUS_DATABASE_MAX_CONNECTIONS=8
CAMELLIA_NEXUS_DATABASE_ACQUIRE_TIMEOUT_SECONDS=5
CAMELLIA_NEXUS_TIME_MAX_FORWARD_JUMP_SECONDS=86400
CAMELLIA_NEXUS_HTTP_REQUEST_TIMEOUT_SECONDS=15
CAMELLIA_NEXUS_HTTP_MAX_IN_FLIGHT=256
CAMELLIA_NEXUS_METRICS_BIND=0.0.0.0:9091
CAMELLIA_NEXUS_METRICS_ALLOW_NON_LOOPBACK=true
CAMELLIA_NEXUS_MAINTENANCE_INTERVAL_SECONDS=3600
CAMELLIA_NEXUS_CLEANUP_BATCH_SIZE=1000
```

Activation codes are stored in PostgreSQL as hashes and are managed by the Admin CLI. Production
always rejects static environment activation codes; `CAMELLIA_NEXUS_LICENSE_ACTIVATION_CODES` is
reserved for development environments. The [systemd deployment contract](docs/systemd-deployment.md)
defines the same four OS/database trust boundaries used by Compose, including secret ownership and
post-migration grants.

### Container image and deployment

The server uses the root `Cargo.toml` as its sole version source and advances independently from the client. After `main` passes its gates, `Release Manager` proposes the version and changelog. Only an exact-head human-approved Release PR merged with the required squash policy can create the tag and draft Release after repository policy and immutable-Release checks; the image is verified and signed by digest before publication. Manual runs validate a candidate identified by commit SHA without pushing it.

Image locations come exclusively from the reviewed `CONTAINER_REGISTRY_MAP`.
GHCR and Docker Hub are published independently when configured; an absent
target is explicitly skipped and cannot be inferred from credentials or a
manual input.

Server and client versions advance independently. Before approval, the server binds the highest completed compatible client release and freezes and scans one OCI layout. After approval, only that digest is copied to configured registries. `latest` is reconciled to the highest completed stable release only after immutable Release evidence and public readback succeed. Release tags and versioned image tags must never be replaced. This repository uses only the keyless Cosign/OIDC identity bound to its OCI digest and does not store desktop or mobile signing credentials. See the [release policy](docs/releasing.md) for the complete procedure.

Container deployment notes:

- The current production image contract supports `linux/amd64` only. The ClamAV dependency and formal build both declare that architecture; unverified compatibility architectures are not promised.
- Use `docker-compose.yml` as the production deployment template and set independently generated
  migration, public, Admin Web, and Worker database passwords, plus the image coordinate, issuer URL,
  and OAuth redirect URI allow-list
- Place the issuance PEM at the compose secret path. The default example is `./secrets/entitlement-es256-private.pem`
- Local file-backed Compose secrets preserve host ownership. The application image runs as `10001:10001`, so every private secret file must be owned by `10001:10001` with mode `0400`; restrict the `secrets/` directory to the deployment account with mode `0700`. Never work around a permissions failure by making secrets globally readable with mode `0444`
- PostgreSQL uses `postgres:18-alpine` pinned to an immutable digest, with data mounted at
  `/var/lib/postgresql`; its first-start hook creates only the three unprivileged runtime logins, and
  the migration command applies the explicit per-table grants
- The service example binds only to localhost; production ingress should terminate HTTPS through a reverse proxy
- `docker-compose.yml` explicitly disables application-startup migrations; run a controlled one-shot migration before starting or rolling the service
- Use `GET /healthz` and `GET /readyz` after startup. Inside the container, run `camellia-nexus-management-server healthcheck http://127.0.0.1:<port>/readyz`. Give SIGTERM at least a 30-second stop window.

### Database migration policy

The server uses SQLx to manage the PostgreSQL schema. The complete unpublished data model is
squashed into the single `migrations/0001_prelaunch_baseline.sql`. Earlier development databases
have no supported upgrade path and must be recreated from that baseline. After the first formal
release, published migrations are immutable and subsequent schema evolution uses new incrementing
migrations.

The default for `CAMELLIA_NEXUS_DATABASE_MIGRATE` depends on `CAMELLIA_NEXUS_LICENSE_ENV`: it is `true` in development and `false` in production. Long-lived production roles must keep it disabled. Before rollout, the dedicated `migrate` role from the same image applies every pending migration and verifies readiness:

```bash
docker compose run --rm migrate
```

Compose starts the public service, private console and worker only after the migration role succeeds. Every long-lived role still performs a required-schema readiness check before serving work.

SQLx validates checksums for migrations already applied to the database. A checksum failure indicates
that the runtime artifact and database migration history are inconsistent. Stop the rollout, restore
consistency, then deliver schema changes through a new migration. Never rewrite `_sqlx_migrations`.
The baseline creates licensing, administrator identity, jobs, object storage, payment evidence, Team,
cloud workspace and Webhook structures and initializes trusted time; readiness fails when any required
part is absent.

### Administration console

The image exposes independent `serve`, `admin-web`, `admin-worker`, and one-shot `migrate` roles. `admin-web` uses a private listener and origin, server-side sessions, Argon2id passwords, mandatory TOTP, CSRF/origin enforcement, version preconditions, idempotency keys and immutable audit context.

The administration UI can be installed as an online-only PWA named **Camellia Console** through the
browser's native install entry. Desktop and Android use the browser installation affordance; iOS uses
Add to Home Screen. Installation requires HTTPS except on a local development origin, and the UI does
not add its own install button. Its service worker precaches only content-hashed frontend assets, the
self-hosted font, and versioned icons. It never caches navigations, `index.html`, the fallback,
manifest, appearance bootstrap, `/api/v1`, authentication responses, cookies, or administration data.
The installed console still requires an online connection plus normal sign-in and session validation;
it provides no offline administration capability.

Bootstrap the first Platform Owner with:

```bash
./scripts/generate-keyring.sh admin
./scripts/generate-keyring.sh workspace
./scripts/generate-keyring.sh webhook
./scripts/generate-proxy-secret.sh
sudo chmod 0700 secrets
sudo chown 10001:10001 \
  secrets/entitlement-es256-private.pem secrets/*-keyring.json \
  secrets/admin-proxy-secret
sudo chmod 0400 \
  secrets/entitlement-es256-private.pem secrets/*-keyring.json \
  secrets/admin-proxy-secret
docker compose run --rm migrate
docker compose run --rm admin-web admin operator bootstrap owner \
  --display-name "Primary owner" --actor deployment \
  --reason "initial control-plane bootstrap"
docker compose up -d
```

The bootstrap command emits a ten-minute enrollment token. Activation-code batches and Team invitation tokens are encrypted, bound to the current administrator session, exposed through a separate ten-minute claim token, and cryptographically erased after acknowledgement.

Administrator sessions have a 30-minute idle limit and a non-renewable eight-hour absolute limit; sensitive operations still require password and TOTP verification within the preceding ten minutes. The console performs a low-frequency `/auth/me` check only while the page is visible and recent keyboard, pointer, or refocus activity indicates that an administrator is present. Background or unattended tabs are not kept alive. This prevents an actively used client-side view or filter from causing an unexpected sign-in prompt while preserving idle expiry. The footer shows the absolute session end time, and password changes, identity disabling, or server-side revocation still terminate sessions immediately.

Administrative Team invitation creation, member updates and invitation revocation claim their idempotency keys inside the database transaction. If an invitation response is lost in transit, the console retains the original operation key and recovers the same short-lived encrypted delivery without consuming another seat or creating another member. Reusing that key with changed request data returns a conflict.

Accounts, licenses, devices, activation codes, billing records, bulk-job cancellation and payment evidence follow the same persistent operation contract: the resource change, audit record and public response commit atomically, and the console rotates an operation key only after a definite business error. The final commit transaction locks and rechecks administrator status, session, credential epoch, roles, and the exact permission. A concurrent revocation either wins and rejects the write or waits for the already-authorized commit; the bulk worker performs the same check for every item. Activation-code deliveries can be reconstructed from the original operation; evidence is additionally deduplicated by claim and digest, while the worker removes objects orphaned by a crash. Secret claim tokens are session-bound business keys, and both claim and acknowledgement recheck their corresponding permission in the committing transaction.

After bootstrap, Platform Owners manage additional control-plane identities from **Administrators** in the private console. New identities remain `pending` until their one-time enrollment token is delivered through the encrypted secret-delivery flow and they configure a password plus TOTP. Disabling an identity immediately revokes its sessions and outstanding enrollment tokens. Credential reset also removes the old password, TOTP and recovery codes before issuing a new ten-minute enrollment token. Identity mutations require recent step-up authentication, an audit reason, an idempotency key and an `If-Match` row version; self-disable/self-reset and removal of the final active Platform Owner are rejected.

An administrator username is an immutable sign-in and audit identifier. Every active administrator can change their own display name and password from the user menu without identity-management permission, while recent step-up, an audit reason, idempotency and an `If-Match` row version remain mandatory. A successful password change atomically advances the credential epoch and revokes every session for that identity; even a concurrent login that already verified the old password cannot create or elevate a session after the new epoch commits. If every online administration path is unavailable, a controlled terminal may run `admin operator recover-owner` for a Platform Owner. Exact normalized-username confirmation is required; the operation clears the password, TOTP, recovery codes and sessions, moves the identity to `pending`, and prints one ten-minute reset token. If delivery fails, recovery may be run again for a pending Owner with no authentication factors; the replacement invalidates every earlier enrollment token. This offline recovery restores control-plane access only and never grants a product Team entitlement.

Account creation establishes one stable internal Team Owner placeholder, and the first registered device is bound to that Owner. The private Team control plane can complete its email and display name once, guarded by step-up, idempotency and row version. Completion only replaces placeholder profile fields: it does not create a member, consume another seat, change the Owner role or alter device bindings. Product Team roles and private control-plane roles are independent identity domains; a Team Owner does not thereby receive Admin UI access.

Important control-plane settings:

```bash
CAMELLIA_NEXUS_ADMIN_BIND=0.0.0.0:8090
CAMELLIA_NEXUS_ADMIN_PUBLIC_ORIGIN=https://console.example.com
CAMELLIA_NEXUS_ADMIN_REQUEST_TIMEOUT_SECONDS=180
CAMELLIA_NEXUS_ADMIN_MAX_IN_FLIGHT=64
CAMELLIA_NEXUS_ADMIN_KEYRING_PATH=/run/secrets/admin_keyring
CAMELLIA_NEXUS_ADMIN_FORWARDED_FOR_SECRET_PATH=/run/secrets/admin_proxy_secret
CAMELLIA_NEXUS_OBJECT_STORAGE=database
CAMELLIA_NEXUS_EVIDENCE_SCANNER=clamav
CAMELLIA_NEXUS_CLAMAV_ADDRESS=clamav:3310
```

`CAMELLIA_NEXUS_CLAMAV_ADDRESS` uses `host:port`; the host may be a DNS name, IPv4 address, or bracketed IPv6 address and is resolved for each scan connection. Compose deployments should keep the service name `clamav:3310` instead of pinning an ephemeral container IP.

Forwarded addresses are ignored by default. To record them, the proxy must strip incoming `X-Forwarded-For` and `X-Camellia-Proxy-Auth`, inject a verified address and a shared secret of 32–256 visible ASCII characters, and the server must read that same secret from the bounded regular file named by `CAMELLIA_NEXUS_ADMIN_FORWARDED_FOR_SECRET_PATH`. Unauthenticated or malformed values never enter audit records. The Admin origin may contain only an HTTP(S) scheme and authority, never a username or password. It must use HTTPS in production and should remain private.

Object storage provides encrypted `filesystem`, PostgreSQL `database` (1 MiB chunks), and `s3` backends for small, medium and large deployments. Every object has a random data key, XChaCha20-Poly1305 encryption, SHA-256 validation and quota enforcement. External writes persist staging metadata first; even when an upload response is ambiguous, the worker retains the unique recovery record and uses bounded HEAD/GET, ciphertext length, decryption and digest checks to finalize or remove it. External reads validate database and object metadata before allocation and enforce an absolute cap while streaming. Payment evidence is signature-checked, quarantined and scanned; production refuses to start with scanning disabled, and payment approval fails closed unless every attachment is clean.

### API

Browser activation:

- `GET /oauth/authorize`
- `POST /oauth/authorize`

License API:

- `GET /healthz`
- `GET /readyz`
- `POST /v1/devices/register`
- `POST /v1/activations/verify`
- `POST /v1/activations/confirm`
- `POST /v1/entitlements/challenge`
- `POST /v1/entitlements/refresh`
- `POST /v1/entitlements/status`
- `POST /v1/session/recovery/challenge`
- `POST /v1/session/recovery`
- `GET /v1/devices?cursor={device_id}&pageSize={1..100}`
- `DELETE /v1/devices/{device_id}`
- `GET /v1/devices/{device_id}/removals/{operation_id}`
- `POST /v1/session/logout`
- `GET /v1/billing/summary`
- `POST /v1/billing/payment-claims`
- `GET /v1/team/profile`
- `GET /v1/team/members`
- `PATCH /v1/team/members/{member_id}`
- `POST /v1/team/members/{member_id}/device-enrollments`
- `POST /v1/team/invitations`
- `POST /v1/team/invitations/accept`
- `POST /v1/team/device-enrollments`
- `POST /v1/team/device-enrollments/accept`
- `POST /v1/team/leave`
- `POST /v1/team/ownership-transfer`
- `GET /v1/team/operations/{operation_id}`
- `GET /v1/workspace/configurations`
- `POST /v1/workspace/configurations`
- `GET /v1/workspace/configurations/{document_id}`
- `DELETE /v1/workspace/configurations/{document_id}`
- `POST /v1/workspace/configurations/{document_id}/revisions`
- `POST /v1/workspace/configurations/{document_id}/publish`
- `POST /v1/workspace/configurations/{document_id}/restore`
- `POST /v1/workspace/configurations/{document_id}/purge`
- `GET /v1/workspace/sync/changes`
- `GET /v1/workspace/sync/checkpoint`
- `POST /v1/workspace/sync/checkpoint`
- `GET /v1/workspace/alerts/rules`
- `POST /v1/workspace/alerts/rules`
- `PATCH /v1/workspace/alerts/rules/{rule_id}`
- `DELETE /v1/workspace/alerts/rules/{rule_id}`
- `GET /v1/workspace/alerts/incidents`
- `POST /v1/workspace/alerts/incidents/{incident_id}/acknowledge`
- `POST /v1/workspace/alerts/incidents/{incident_id}/resolve`
- `GET /v1/workspace/audit/event-types`
- `GET /v1/workspace/audit/events`
- `GET /v1/workspace/audit/export`
- `GET /v1/workspace/webhooks`
- `POST /v1/workspace/webhooks`
- `GET /v1/workspace/webhooks/deliveries`
- `PATCH /v1/workspace/webhooks/{endpoint_id}`
- `DELETE /v1/workspace/webhooks/{endpoint_id}`
- `POST /v1/workspace/webhooks/{endpoint_id}/rotate-secret`

Billing, Team, and Workspace APIs still require a valid device-proven refresh session. Team billing read access is limited to `owner`, `admin`, and `billing`, while payment-evidence submission is limited to `owner` and `billing`. Member lists are available to `owner`, `admin`, `operator`, `viewer`, and `auditor` through keyset pages of 100 by default and 200 at most; mutations remain limited to `owner` and `admin`, and an Admin cannot mutate a peer Admin. Every public Team write requires a canonical UUIDv4 `operationId`. The service commits the business change, audit, and exact response encrypted with a domain-separated Workspace-keyring derivation in one transaction. An identical device/command/canonical-request retry receives the original response, including the original invitation or enrollment secret; changing any bound content while reusing the identity returns a conflict. Operation records are removed by bounded maintenance after 37 days. Replaying a response never extends the underlying token expiry. `GET /v1/team/operations/{operation_id}` is limited to voluntary-leave recovery: it reports committed only when the exact original refresh session and device plus the queried member ID and row version match the stored `leave_workspace` request. Revocation of that session by leave does not widen the query, and another Team operation cannot masquerade as leave. A workspace receives one Owner automatically, and only its first device receives the bootstrap binding. A seven-day invitation activates one member device once; additional devices require a separate one-use 15-minute enrollment token created by an already bound device. Invalid, expired, consumed, or wrong-kind Team tokens return dedicated recoverable business errors without invalidating a valid device session. Repeating an accepted invitation or device-enrollment request from the device that was just linked is idempotent even after the token later expires, allowing a lost response to be recovered without creating another binding. Removing a device atomically revokes its sessions and deletes its member binding; reactivation does not restore that binding. Owner/Admin can issue a recovery enrollment for an Active member with zero devices, while Admin cannot recover Owner. Suspended revokes sessions but retains recoverable bindings. Removed or voluntary leave revokes sessions, marks bound devices Removed, releases the seat, and revokes outstanding tokens in one transaction without deleting local configuration. See the [Team workspace production contract](docs/team-workspace.md) for the complete role matrix, cloud boundaries, concurrency conflicts, and key-rotation rules.

Browser authorization is a first-party Camellia Nexus OAuth authorization-code flow, not OIDC, and it does not issue ID tokens. `scope` must exactly equal the single token `camellia.nexus.license`; empty values, the former `openid`/`offline_access` values, unknown or duplicate scopes, and surrounding whitespace are rejected. PKCE permits only `S256`, with an exactly 43-character unpadded base64url challenge. `state` must contain 32–128 bytes of RFC 3986 unreserved characters. `response_type`, `client_id`, the redirect URI, and every protocol field have fixed values or hard length limits, and unknown query/form fields are rejected. GET invokes the same pure protocol validation as POST before rendering an activation-code input. Invalid GET or POST requests show only a non-submittable error page and must be restarted from the desktop client.

OAuth authorization codes are server-issued, short-lived, and bound to the PKCE challenge, redirect URI, device ID, and device public key. The code is consumed only by the first successful registration transaction. If that response is lost, an identical device/key/PKCE/redirect request may retrieve the same committed result during a fixed ten-minute window measured from the original consumption; retries never extend the window. Registration only creates a pending binding to a database activation code. After the device proves possession of its private key and calls activation confirm, the server increments the redemption count transactionally and marks the code `consumed` when it reaches `max_redemptions`.

Production requires canonical SemVer values for `CAMELLIA_NEXUS_CLIENT_MINIMUM_VERSION` and `CAMELLIA_NEXUS_CLIENT_RECOMMENDED_VERSION` (recommended must not be lower), plus `CAMELLIA_NEXUS_CLIENT_VERSION_ENFORCE_AFTER` in the shared human-readable time format. Registration and every device proof also require a byte-for-byte canonical SemVer `appVersion`. At or after enforcement, an older client receives HTTP 426 `client_upgrade_required` before an authorization code is consumed, a session is created or rotated, or an entitlement is issued; the error JSON carries the camelCase `clientVersionPolicy` at the top level. Entitlements issued before the transition cap both `refreshAfter` and `exp` at the enforcement instant, and every entitlement signs the policy, avoiding a separate cacheable policy endpoint. A valid device proof updates the registered app version and last-seen time; a new login for an active device updates only mutable non-key metadata such as platform, version, and display name.

`POST /v1/entitlements/status` cannot read state from a bearer session alone. The client first obtains a one-time challenge scoped to `entitlement:status`, then submits proof signed by the current device and carrying its current `appVersion`. The server atomically consumes that challenge, verifies possession of the device key, observes the current version, and applies minimum-version policy before returning device state and license epoch. A status check does not rotate the refresh session, so HTTP 426 and other denials do not invalidate an otherwise valid session, but every check requires a fresh challenge.

This policy coordinates upgrades for honest clients and gates protocol compatibility; it is not binary attestation. A device signature proves possession of the registered private key, and an attacker who can modify the client while controlling that key can also misreport `appVersion`. Server-side paid capabilities must therefore remain protected by signed entitlements, authoritative state and server authorization checks. Threat models that require proof of the running artifact need a separate code-signing, trusted-update and platform-attestation design.

If a refresh session is lost while the device private key remains available, the client may submit its `deviceId` to `POST /v1/session/recovery/challenge`, sign the one-time challenge whose scope is `session:recover`, and submit that proof to `POST /v1/session/recovery`. Every canonical UUID receives the same HTTP status and JSON shape. Challenges for registered and unknown devices use the same short-lived persistence, atomic-consumption, and expiry-cleanup path; an unknown device uses a non-authenticating synthetic subject. After consumption, a missing device is checked with a fixed dummy public key so signature work has the same shape. Missing, forged, expired, replayed, or otherwise invalid proofs all return `invalid_challenge`; actionable device, account, and license state is returned only after proof of a real device key. The anonymous phase uses only the global circuit breaker plus source-aware ingress limits, and the per-device recovery bucket is consumed only after a valid proof, so knowledge of a device UUID cannot exhaust that device's quota. Recovery accepts an `active` device or an unexpired `pending_activation` device that must finish an ambiguously delivered registration. On success, the server revokes the device's old refresh sessions and issues a new device-proven session. It cannot recover an expired pending, `removed`, `revoked`, or `suspicious` device and is not an administrative state change.

`GET /v1/devices` returns `{ "devices": [...], "nextCursor": string | null }`, never an unbounded array. `pageSize` defaults to 50 and must be between 1 and 100. Omit `cursor` for the first page, then pass the previous `nextCursor` back unchanged. The cursor is the canonical lowercase hyphenated UUID of an immutable device ID and clients must treat it as opaque; noncanonical cursors, unknown query fields and out-of-range page sizes return `invalid_request`. The repository filters on the current `license_id` before applying a C-locale `device_id` keyset order and a `limit + 1` probe, so devices belonging to another license on the same account are neither loaded into memory nor counted in the page window.

`DELETE /v1/devices/{device_id}` requires a bearer refresh session, a canonical UUIDv4
`operationId`, and proof signed by the requesting device for the `device:remove:{device_id}` scope.
The service verifies that requester and target belong to the same account and license. Team
licenses additionally authorize cross-member removal from current bindings and roles and preserve
at least one active Owner device. Device state, session revocation, Team unbinding, audit, and the
idempotent result commit in one transaction. Reactivation never restores the old member binding.
The client may preflight `GET /v1/devices/{device_id}/removals/{operation_id}`; after a self-removal
revokes its session, only the exact original bearer can recover that exact committed result and
finish a local identity switch. Reusing an operation ID with a different requester session,
requester device, or target conflicts.

### Authorization-state semantics

| Entity | State | Server semantics |
| --- | --- | --- |
| Account | `active` | Activation, refresh and session recovery are allowed. |
| Account | `suspended` | Temporarily disabled and device sessions under the account are revoked; new activation, refresh and recovery return `account_suspended`. An audited Admin operation may set it back to `active`. |
| Account | `denylisted` | Disabled and device sessions under the account are revoked; new activation, refresh and recovery return `account_denylisted`. |
| License | `active` | Usable while `expires_at` is absent or in the future; an elapsed expiry returns `license_expired`. |
| License | `past_due` / `canceled` | Continues as a grace-period license only when `expires_at` is explicitly in the future; once reached, or when absent, requests return `license_past_due` / `license_canceled`. |
| Device | `pending_activation` | May only complete activation proof/confirm and cannot refresh an entitlement. |
| Device | `active` | May refresh entitlements and recover sessions, and counts against the active-device limit. |
| Device | `removed` | Sessions are revoked; the same registered device identity and private key may re-enter the normal activation flow with a new activation code. |
| Device | `revoked` / `suspicious` | Sessions are revoked and registration/refresh is denied; Admin cannot set the device directly to `active`. To re-enroll the same identity intentionally, first make an audited transition to `removed`, then use a new activation code. A compromised key requires a new device identity and key. |
| Activation code | `active` | It must also be before `expires_at` and have remaining redemptions to be usable. |
| Activation code | `consumed` / `revoked` | Redemptions are exhausted or an administrator revoked the code. `expires_at` is independent. `restore` resets redemption history but does not extend an already elapsed expiry. |

Account, license or device state changes prevent subsequent online refreshes, but an already issued short-lived entitlement is an offline lease and is not actively recalled before its own `exp`.

Administration is available through both the Admin CLI and the independently deployed `admin-web` control plane. The public licensing service mounts no administration routes; the administration WebUI/API has a separate listener, HTTPS origin, administrator identity, authorization, CSRF, idempotency, version-precondition, and audit boundaries.

Platform Owners can use the **Administrator identities** page to provision, role, disable and securely reset control-plane users. Enrollment material is never returned in an ordinary identity record: it is encrypted, bound to the initiating administrator session, available for ten minutes through the secret-delivery endpoints, and erased after acknowledgement. The service preserves at least one active Platform Owner and rejects self-disable and self-reset operations.

### Admin CLI

The service binary includes production administration commands. Admin commands require `DATABASE_URL`. Every command that changes an account, license, activation code or device requires an attributable operator and reason: issuance uses `--issued-by` as its actor, other mutations use `--actor`, and all require `--reason`.

The binary provides hierarchical bilingual help. Help is resolved before configuration, logging, or database initialization, so it remains safe to inspect without production environment variables or PostgreSQL:

```bash
camellia-nexus-management-server --help
camellia-nexus-management-server serve --help
camellia-nexus-management-server migrate --help
camellia-nexus-management-server healthcheck --help
camellia-nexus-management-server admin-web --help
camellia-nexus-management-server admin-worker --help
camellia-nexus-management-server admin --help
camellia-nexus-management-server admin account --help
camellia-nexus-management-server admin code issue --help
camellia-nexus-management-server help admin license create
camellia-nexus-management-server --version
```

Every top-level runtime role and Admin operation has dedicated help. `admin <group>` lists that group's operations, while `admin <group> <operation> --help` shows exact usage, constraints, option descriptions, and an example. `-h` is equivalent to `--help`; the root command also supports `-V` and `--version`. Unknown commands or extra positional arguments exit as usage errors instead of being ignored and accidentally starting a service.

Accounts:

```bash
camellia-nexus-management-server admin account list
camellia-nexus-management-server admin account show <account-id>
camellia-nexus-management-server admin account create acct_customer_001 --note "Customer 001" --actor operator_001 --reason "customer created"
camellia-nexus-management-server admin account set-state acct_customer_001 active --actor operator_001 --reason "support review complete"
camellia-nexus-management-server admin account set-state acct_customer_001 suspended --actor operator_001 --reason "billing review"
camellia-nexus-management-server admin account set-state acct_customer_001 denylisted --actor operator_001 --reason "fraud confirmed"
```

Licenses:

```bash
camellia-nexus-management-server admin license list
camellia-nexus-management-server admin license list --account acct_customer_001
camellia-nexus-management-server admin license show lic_customer_001
camellia-nexus-management-server admin license create lic_customer_001 --account acct_customer_001 --plan pro --actor operator_001 --reason "purchase provisioned"
camellia-nexus-management-server admin license set-status lic_customer_001 active --actor operator_001 --reason "payment received"
camellia-nexus-management-server admin license set-status lic_customer_001 past_due --actor operator_001 --reason "invoice overdue"
camellia-nexus-management-server admin license set-status lic_customer_001 canceled --actor operator_001 --reason "subscription canceled"
camellia-nexus-management-server admin license set-plan lic_customer_001 team --seats 3 --actor operator_001 --reason "team upgrade"
camellia-nexus-management-server admin license set-seats lic_customer_001 5 --actor operator_001 --reason "seat expansion"
camellia-nexus-management-server admin license set-expires-at lic_customer_001 2027-01-01T00:00:00Z --actor operator_001 --reason "renewal term"
```

Free and Pro licenses always have zero purchased seats and omit `--seats` on creation. Team licenses require 3 through 10,000 seats. Entering Team for the first time requires an explicit quantity, omission retains the current quantity when the license is already Team, and leaving Team clears it; `set-seats` is Team-only. When the authoritative plan or quantity actually changes, the service advances the license epoch and row version exactly once.

Offline control-plane Owner recovery:

```bash
camellia-nexus-management-server admin operator recover-owner owner \
  --actor recovery-operator \
  --reason "restore control-plane access" \
  --confirm owner
```

`--confirm` must exactly match the normalized target username. The command immediately invalidates existing authentication material and shows each new reset token only in that invocation. If delivery fails, it may be run again for a pending Owner with no authentication factors; the replacement immediately invalidates every earlier token. Run it only from a controlled terminal and deliver the token securely.

Manual billing creates an invoice from an immutable offer snapshot, accepts customer payment evidence, and then requires an operator review. Only a committed `billing payment approve` transaction changes the plan, term, and license epoch; submitted, needs-information, and rejected claims grant no entitlement. Commercial offers apply only to Pro and Team. Invoice seats must match the offer plan: Team requires an explicit quantity from 3 through 10,000, while Pro requires zero. The service rejects contradictory input instead of silently rewriting commercial data. Invoice and payment-claim lists use opaque keyset pages of 50 by default and 100 at most. The Admin UI loads subsequent pages explicitly; the CLI returns `nextCursor` and accepts `--cursor`, `--page-size`, and `--query`.

```bash
camellia-nexus-management-server admin billing offer create pro-yearly --plan pro --duration-days 365 --currency USD --amount 99 --name-en "Pro yearly" --name-zh "专业版年付" --actor finance_001 --reason "2026 catalog"
camellia-nexus-management-server admin billing method create bank-sgd --name-en "Bank transfer" --name-zh "银行转账" --instructions-en "Use the invoice reference." --instructions-zh "请填写账单付款附言。" --asset SGD --destination-hint "Account ending 1234" --actor finance_001 --reason "manual settlement channel"
camellia-nexus-management-server admin billing invoice create inv_001 --account acct_customer_001 --license lic_customer_001 --offer pro-yearly --due-at 7d --actor finance_001 --reason "customer order"
camellia-nexus-management-server admin billing payment list --status submitted
camellia-nexus-management-server admin billing payment approve claim_001 --row-version 1 --actor reviewer_001 --reason "bank receipt verified" --operation-id review_claim_001_v1
```

Approval requires the paid amount and settlement asset to match the invoice exactly. All three CLI review operations require the positive `--row-version` returned by the most recent read; the Admin UI sends the equivalent `If-Match`. A stale version is rejected, and the latest record must be reloaded and reviewed before retrying. A BillingAdmin may use `--allow-amount-override true` only after an independent review and with an audit reason. Retrying the same request with the same operation ID, row version, and content is safe; reusing that ID for different content is rejected.

Manage activation codes:

```bash
camellia-nexus-management-server admin code issue --account acct_customer_001 --license lic_customer_001 --issued-by operator_001 --reason "customer purchase" --operation-id order_001-issue-01 --count 3 --max-redemptions 1 --channel direct --ttl-days 365
camellia-nexus-management-server admin code list --account acct_customer_001
camellia-nexus-management-server admin code list --status active
camellia-nexus-management-server admin code show <code-or-prefix-or-hash>
camellia-nexus-management-server admin code revoke <code-or-prefix-or-hash> --actor operator_001 --reason "order refunded"
camellia-nexus-management-server admin code restore <code-or-prefix-or-hash> --actor operator_001 --reason "refund reversed" --max-redemptions 1
camellia-nexus-management-server admin code expire <code-or-prefix-or-hash> --actor operator_001 --reason "contract ended" --expires-at 2027-01-01
```

`code issue` writes the entire batch, its audit events and the `operation-id` in one database transaction. The operation ID must be globally unique for issuance; a duplicate is rejected, preventing automation retries from issuing another batch. Plaintext is printed only after the first successful commit and cannot be recovered by replaying the operation. If that output is lost, locate and revoke each code using the operation-ID-derived `order_id` values and audit records, then issue a replacement under a new operation ID.

Time inputs accept RFC3339 instants such as `2027-01-01T00:00:00Z`, UTC dates such as `2027-01-01`, UTC datetimes such as `2027-01-01 00:00:00`, relative expiry durations such as `30d`, `12h`, or `2w`, and Unix seconds for machine-operated workflows. Admin JSON output keeps canonical Unix fields and adds matching UTC ISO fields for operator review.

Admin uses human-friendly output by default. Use `--raw` or `--output raw` when automation needs the exact original JSON fields:

```bash
camellia-nexus-management-server admin --raw license show lic_customer_001
camellia-nexus-management-server admin code list --output raw --status active
```

Devices:

```bash
camellia-nexus-management-server admin device list --account acct_customer_001
camellia-nexus-management-server admin device show <device-id>
camellia-nexus-management-server admin device set-state <device-id> removed --actor operator_001 --reason "user removed device"
camellia-nexus-management-server admin device set-state <device-id> suspicious --actor operator_001 --reason "risk signal"
camellia-nexus-management-server admin device revoke <device-id> --actor operator_001 --reason "key compromise"
```

Audit:

```bash
camellia-nexus-management-server admin audit list
camellia-nexus-management-server admin audit list --account acct_customer_001 --limit 100
```

Accounts, licenses, devices and activation codes are durable audit entities. The Admin CLI rejects their `delete` commands, and it also rejects `device restore` or setting a device directly to `active`. Represent business outcomes with account states, a `canceled` license, `removed`/`revoked` device states and activation-code revocation. Activation-code `restore` is an actor/reason-audited redemption reset, not restoration of physically deleted data.

Plaintext activation codes are printed once when issued. New codes use the canonical `CNX1-xxxxx-xxxxx-xxxxx-xxxxx-xxxxx` format with 125 bits of randomness; input is case- and hyphen-insensitive. Issuance defaults to a 30-day expiry; `--ttl-days` must be between 1 and 3650 and cannot be combined with `--expires-at`. The database stores only hashes, short prefixes, redemption counters and management metadata. The Admin CLI rejects unknown, duplicate or valueless options so automation cannot silently fall back after a typo.

### Deployment assets

- `Dockerfile`: production image with no runtime package installation and a numeric non-root UID
- `.github/workflows/ci.yml`: PR/main Rust, PostgreSQL, administration UI, browser, and candidate-image quality gates
- `.github/workflows/publish-release.yml`: formal managed-tag image build, scan, Cosign signing, GHCR/GitHub Release publication, and readback
- `.github/dependabot.yml`: updates for Cargo, independent container inputs and GitHub Actions; `scripts/update-toolchains.sh` updates coupled toolchains and images atomically
- `docs/dependency-management.md`: toolchain, dependency, immutable-image and exception governance
- `SECURITY.md`, `docs/runbooks/incident-response.md`, and `docs/runbooks/key-rotation.md`: vulnerability reporting, incident response, and key/credential rotation
- `docs/runbooks/backup-restore.md` and `docs/runbooks/release-rollback.md`: joint recovery points, restore acceptance, and digest-pinned rollout/rollback
- `docker-compose.yml`: container deployment template
- `.env.example`: container environment example
- `deploy/systemd/`: explicit migrate, public, Admin Web and worker units for non-container Linux
- `deploy/*.env.example`: role-separated non-container production environment templates
- `docs/systemd-deployment.md`: systemd installation, upgrade, rollback and metrics contract
- `migrations/`: SQLx-managed PostgreSQL schema
- `scripts/generate-entitlement-key.sh`: issuance PEM generation helper
- `scripts/start-local.sh`: local integration startup helper

### Logging and operations

Entitlement issuance material should be managed by the deployment environment, with rotation controlled by the release process.

Issuance material notes:

- New environments may use `scripts/generate-entitlement-key.sh <private.pem> <public.pem>` to generate P-256/ES256 PEM files. When production keys live in a KMS, HSM, or platform secret store, an external deployment adapter must mount a read-only PEM file; the service has no native KMS/HSM driver
- Production accepts only a read-only PEM file referenced by `CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM_PATH`; inline `CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM` is development-only
- Every PEM and keyring mount must resolve to a service-readable regular file no larger than 64 KiB; each keyring must contain 1–64 keys so rotation history remains explicit and bounded
- `CAMELLIA_NEXUS_LICENSE_KEY_ID` identifies the active issuance version and should be managed through the release process
- Production also requires `CAMELLIA_NEXUS_WORKSPACE_KEYRING_PATH`. This read-only JSON uses `activeKeyId` to select a URL-safe, unpadded base64-encoded 32-byte root key from `keys`; Workspace revisions and public Team operation responses use domain-separated derived keys, and rotation must retain old keys while either stored revisions or Team operation records still reference them
- Production also requires an independent `CAMELLIA_NEXUS_WEBHOOK_KEYRING_PATH`. It uses the same JSON shape, but must not reuse Admin or Workspace root keys; every service replica must retain old key IDs while endpoints still reference them
- Create the three independent keyrings with `scripts/generate-keyring.sh <admin|workspace|webhook> [output]`. See the [Team workspace production contract](docs/team-workspace.md#team-keyring-operations--team-密钥环运维) for two-phase Team key rotation, reference inventory, and recovery-point backup/restore
- Client trust metadata should be shipped with the desktop release; issuer, audience and key ID must match the service release configuration
- For rotation, release the client trust update first, then switch the service issuance version and keep the old issuance configuration until existing leases expire

Logging configuration:

- `CAMELLIA_NEXUS_LOG_FORMAT`: `json` or `compact`. Production defaults to `json`
- `CAMELLIA_NEXUS_LOG_LEVEL`: application log level: `error`, `warn`, `info`, `debug`, or `trace`
- `CAMELLIA_NEXUS_HTTP_LOG_LEVEL`: HTTP request/response access-log level
- `CAMELLIA_NEXUS_HTTP_FAILURE_LOG_LEVEL`: HTTP failure-log level
- `CAMELLIA_NEXUS_LOG_FILTER`: optional full tracing filter expression

Runtime and maintenance configuration:

- `GET /healthz` is process liveness and does not touch external dependencies. Public/Admin `GET /readyz` waits at most two seconds for the repository, required schema, required key material, Admin malware scanner, and persistent-time checks, returning `503 not ready` with `Cache-Control: no-store` when a dependency is unavailable
- `CAMELLIA_NEXUS_HTTP_REQUEST_TIMEOUT_SECONDS` (default `15`) bounds total business-request time. `CAMELLIA_NEXUS_HTTP_MAX_IN_FLIGHT` (default `256`) bounds per-process concurrency. Timeouts return 504; overload returns 503; both include `Retry-After: 1`
- `CAMELLIA_NEXUS_ADMIN_REQUEST_TIMEOUT_SECONDS` (default `180`) and `CAMELLIA_NEXUS_ADMIN_MAX_IN_FLIGHT` (default `64`) apply only to `admin-web` `/api/v1`; health checks and static assets do not consume this budget. Timeout is a machine-readable 504 and overload a 503, both with `Retry-After: 1`
- `CAMELLIA_NEXUS_DATABASE_ACQUIRE_TIMEOUT_SECONDS` (default `5`) bounds PostgreSQL pool waits, while `CAMELLIA_NEXUS_DATABASE_MAX_CONNECTIONS` (default `8`) bounds pool size. `serve`, `admin-web`, and `admin-worker` all reject invalid or zero values at startup instead of silently using defaults
- `CAMELLIA_NEXUS_METRICS_BIND` is required for every production runtime role. The separate operations
  listener serves `/healthz` and Prometheus text at `/metrics`; the Admin Worker additionally exposes
  `/readyz` with its continuously observed database, keyring, scanner, and iteration state, and its
  container health check must use that endpoint. Loopback is the safe default;
  a non-loopback address also requires `CAMELLIA_NEXUS_METRICS_ALLOW_NON_LOOPBACK=true` and a private
  firewall/ingress. Use separate ports for `serve`, `admin-web`, and `admin-worker`. Metrics expose
  bounded role/status/outcome labels and never tenant, device, URL, token, or operation identifiers.
  Every metric family uses the classic-compatible `camellia_nexus_` prefix
- `CAMELLIA_NEXUS_CLIENT_MINIMUM_VERSION`, `CAMELLIA_NEXUS_CLIENT_RECOMMENDED_VERSION`, and `CAMELLIA_NEXUS_CLIENT_VERSION_ENFORCE_AFTER` are all required in production; versions must be canonical SemVer and the enforcement time must be an absolute RFC3339 instant, UTC date/date-time, or Unix second value. Relative durations are accepted only in development and for Admin expiry inputs, preventing replicas from resolving policy boundaries from different startup times
- PostgreSQL mode stores the licensing-time high-water mark in the `service_time_authority` singleton. Before a security-sensitive request writes a code, session or entitlement, it atomically advances that mark using the safe maximum of database time, the persisted high water and process-monotonic time. Database or host-clock rollback, including across a service restart, therefore cannot make expired objects valid again. Admin mutations use the same authority. Memory mode is development/test-only and has no cross-process persistence guarantee
- `CAMELLIA_NEXUS_TIME_MAX_FORWARD_JUMP_SECONDS` (default `86400`, or 24 hours) is the largest single database-time advance accepted beyond the persisted high water. A larger advance is logged, all operations that depend on licensing time fail closed, readiness fails, and the suspect value is not trusted. First correct and verify PostgreSQL UTC time. If a verified long outage caused the gap, temporarily raise the limit during a controlled maintenance window, wait for one successful readiness check to advance the high water, then restore the default and restart. Never edit the time-authority table directly
- The production PostgreSQL repository persists and atomically updates rate-limit buckets, so all service replicas sharing that database also share rate-limit counts. The memory repository's buckets are single-process development/test state
- The in-application anonymous global bucket is a cluster circuit breaker, not a source-level abuse boundary. Production HTTPS ingress must apply WAF/per-source limits to `/oauth/*` and `/v1/*` using a verified client address and must discard externally supplied forwarding headers before setting its own. Authenticated device traffic should use a separate policy so anonymous abuse cannot consume normal refresh capacity. Durable audits for repeated anonymous denials are sampled by event/reason; ingress metrics and access logs retain full request counts
- `CAMELLIA_NEXUS_MAINTENANCE_INTERVAL_SECONDS` (default `3600`) and `CAMELLIA_NEXUS_CLEANUP_BATCH_SIZE` (default `1000`) control cleanup. It runs once immediately after startup and then at the configured interval. Expired challenges and OAuth authorization codes are retained for one hour; refresh sessions are retained until seven days after the session family's absolute expiry for replay detection; rate-limit buckets are retained for two hours; records are then deleted in per-table batches
- Cleanup never deletes accounts, licenses, devices, database activation codes or audit events; retain those records according to business and compliance policy
- On SIGTERM or Ctrl-C, the service stops accepting new connections, drains in-flight requests, stops maintenance and closes the repository. The Webhook worker has up to 20 seconds to drain claimed deliveries, then aborts remaining tasks without marking them successful. The platform stop grace must cover both request timeout and worker drain; the sample compose and systemd configurations use 30 seconds

### Local verification

Local execution is for development validation and CI parity. It is not the deployment path:

```bash
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
bash scripts/test-systemd-deployment.sh
# Requires TEST_DATABASE_URL with permission to create temporary databases.
cargo test --locked --test postgres_repository -- --ignored
# Requires the desktop checkout at its default adjacent path, or pass its path explicitly.
node scripts/check-cross-repo-contract.mjs
node scripts/test-cross-repo-contract.mjs
scripts/start-local.sh --help
```

See [production verification](docs/testing.md) for the final-container, live Admin UI, native Windows
client, disposable Compose backend, and secure-cleanup test contracts.

For isolated experiments:

```bash
CAMELLIA_NEXUS_LICENSE_STORAGE=memory cargo run
```

### License

Camellia Nexus Management Server is proprietary software and requires express authorization from Camellia Computing. Source visibility, repository access, or possession of a copy does not grant rights to use, copy, modify, distribute, host, or sublicense it. See [LICENSE](LICENSE). Third-party components remain under their respective licenses as described in [NOTICE](NOTICE).
