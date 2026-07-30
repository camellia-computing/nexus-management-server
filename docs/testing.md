# Production verification / 生产级验证

The management server is verified as an authority, a deployable Linux image, and the backend of two user
interfaces. Tests are split by responsibility so UI fixtures never substitute for PostgreSQL or
server-side authorization.

授权服务需要同时作为业务权威、可部署 Linux 镜像以及两个用户界面的后端接受验证。测试按职责
分层，UI fixture 不能替代 PostgreSQL 或服务端授权判断。

## Required layers / 必要分层

| Layer / 层级 | Required proof / 必须证明 |
| --- | --- |
| Rust unit and service tests | Parsing, cryptography, state transitions, permissions, idempotency, pagination, errors, and bounded behavior |
| PostgreSQL integration | Transactions, row versions, trusted time, replica-safe rate limits, migrations, concurrency, jobs, and persistence |
| Deployment contracts | Four distinct OS and database identities, systemd ordering/hardening, private per-role metrics, denied public access to Admin data/DDL, and production configuration failure modes |
| Admin UI deterministic browser tests | Themes, localization, responsive/overflow states, dialogs, keyboard/focus, errors, PWA installation metadata, and interactions across fixed fixtures |
| Final-container runtime | Image metadata, migrations, CLI mutations, public and Admin roles, PWA/static headers, hardening, readiness, worker startup, real authentication, Team operations, and logout |
| Live Admin UI | The static UI embedded in the final image performs real authentication/step-up, account/license/code/Team/billing/bulk/support mutations, conflict recovery, audit/system checks, credential maintenance, accessibility/responsive checks, and logout |
| Cross-repository native desktop | OAuth/PKCE, device proof, signed entitlement, OS secure storage, offline/terminal lifecycle enforcement, billing, Team governance, and cloud resources through the actual Windows Tauri client |

## Commands / 命令

The normal local gates remain authoritative:

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
bash scripts/test-systemd-deployment.sh
node scripts/check-cross-repo-contract.mjs
node scripts/test-cross-repo-contract.mjs
pnpm --dir admin-ui install --frozen-lockfile
pnpm --dir admin-ui format:check
pnpm --dir admin-ui check
pnpm --dir admin-ui test:visual
pnpm --dir admin-ui test:visual:stability
```

Build an immutable candidate image and exercise its real runtime. Setting the live flag adds the real
browser/Admin API path and therefore requires the repository's exact Node.js/pnpm plus Playwright
Chromium installation:

```bash
CAMELLIA_NEXUS_RUN_ADMIN_UI_LIVE=1 scripts/test-container-runtime.sh <locally-loaded-image>
```

The runtime test creates an isolated PostgreSQL database with a schema owner plus three
least-privilege runtime logins, enrollment factors and sessions, accounts, Team licenses, one-time
deliveries, billing fixtures, a synthetic PDF, a pinned ClamAV scanner, worker, and hardened runtime
containers. It proves the public login cannot read Admin identities or create schema objects and the
Worker cannot read password credentials. A disposable pre-expired browser session proves the real step-up
dialog and retry retain one operation identity. The live browser also proves one-time secret
destruction, optimistic concurrency, evidence scanning and payment approval, bounded bulk work,
restricted support permissions, audit/system views, password rotation, session revocation, and logout.
All generated credentials live under a mode-0700 temporary directory and are removed by the exit
trap. Network traces are disabled and failure screenshots blur authentication and one-time values. Do
not add debug output that prints request bodies, cookies, TOTP material, delivery tokens, or plaintext
codes.

The deterministic browser gate also verifies the manifest, exact icon dimensions, service-worker
registration/update, and Cache Storage allow-list. Its offline check requires immutable application
assets to remain available while navigations, the manifest, appearance bootstrap, Admin API and
session data fail closed and never appear in Cache Storage. Rust and final-container checks separately
verify required PWA files, MIME types, CSP `worker-src`, and immutable/no-store cache headers.

Focused PostgreSQL Team tests force invitation and device-enrollment response replay, verify the
original one-time secret is recovered without a second member/binding, reject changed content and a
different device under the same operation identity, bind leave-status lookup to the exact original
session, command, member, and row version, and inspect stored bytes to prove the secret is not
plaintext. The desktop browser test injects a
post-commit lost response and proves the visible retry sends the same request and `operationId` and
recovers the original secret. These tests complement, rather than replace, final-container and native
Windows coverage.

运行时测试会创建隔离的 PostgreSQL 数据库、管理员注册因素与会话、账户、Team 授权、一次性交付、
账单夹具、合成 PDF、固定 ClamAV 扫描器、Worker 和加固容器。一次性预过期浏览器会话验证真实
step-up 对话框及重试沿用同一操作标识；真实浏览器还验证一次性密钥销毁、乐观并发、证据扫描与付款
批准、有界批处理、受限支持权限、审计/系统视图、密码轮换、会话撤销及退出。全部临时凭据只存在于
权限为 0700 的临时目录，并由退出清理器删除；网络 trace 被禁用，失败截图会模糊认证与一次性值。
不得增加会打印请求正文、Cookie、TOTP、交付令牌或明文激活码的调试输出。

确定性浏览器门禁还会验证 manifest、精确图标尺寸、Service Worker 注册/更新及 Cache Storage
白名单。断网检查要求带哈希的应用资源仍可读取，而导航、manifest、外观初始化脚本、管理 API 与
会话数据必须失败关闭且从不进入 Cache Storage。Rust 与最终容器门禁另行验证 PWA 必需文件、MIME、
CSP `worker-src` 以及 immutable/no-store 缓存头。

专项 PostgreSQL Team 测试会强制执行邀请与设备入组响应重放，验证原一次性秘密可恢复且不会产生
第二名成员或绑定，拒绝在同一操作标识下修改内容或设备，将离组状态查询绑定到精确原会话、命令、
成员与 row version，并检查持久化字节不含明文秘密。客户端浏览器测试会注入“事务已提交但响应丢失”，证明可见重试发送完全相同的
请求和 `operationId` 并恢复原秘密。这些测试是最终容器与真实 Windows 覆盖的补充，不能替代后者。

## Hosted cross-repository environment / 托管跨仓环境

`scripts/build-e2e-bundle.sh` exports the already verified final server image and the pinned PostgreSQL
image as root filesystem archives for a Windows hosted runner. It verifies the amd64 runtime files and
PostgreSQL 18 binary before emitting a manifest that requires x86_64 WSL2 with shared loopback
networking. The manifest includes image identity, version, revision, byte sizes, and SHA-256 digests
but no private key, database, or activation code. The Windows harness generates those values only
after verifying and importing the bundle into uniquely named WSL2 distributions.

`scripts/build-e2e-bundle.sh` 将已验证的最终服务端镜像及固定 PostgreSQL 镜像导出为 Windows 托管
Runner 可导入的根文件系统。它先验证 amd64 必要运行文件和 PostgreSQL 18 二进制，再生成要求
x86_64 WSL2 及共享回环网络的清单。清单只包含镜像身份、版本、提交、大小与 SHA-256，不包含私钥、
数据库或激活码；Windows Harness 验证并导入唯一命名的 WSL2 环境后才生成这些单次数据。

The server CI runs the full Windows native suite against the current final-image bundle and an
explicitly selected desktop ref. It covers controlled offline recovery, account suspension, payment,
three Team device identities, governance, shared revisions, sync, alert incidents, bounded audit, and
inactive Webhook secret lifecycle. The desktop repository runs full for standard validation, smoke in
parallel with candidate packages, and skips it for generated-only Release validation. A public
protocol change is complete only when both repositories' byte-identical wire/semantic checker and
mutation test, owning tests, final-container flow, and native cross-repository scenario pass.

服务端 CI 使用当前最终镜像 bundle 与显式客户端 ref 执行完整 Windows 原生套件，覆盖受控离线恢复、
账户暂停、付款、三套 Team 设备身份、治理、共享修订、同步、告警事件、有界审计及非活动 Webhook
密钥生命周期。客户端仓库在 standard 门禁执行 full，在 candidate 包并行构建时执行 smoke，并在仅含
生成差异的 Release 门禁跳过。公共协议修改只有在双仓字节一致的 wire/semantic 检查器与 mutation
test、权威层测试、最终容器流程和原生跨仓场景全部通过后才算完成。

## Cross-repository access / 跨仓库访问

The Windows native job and contract monitor resolve the sibling as
`${{ github.repository_owner }}/nexus`. The repository name is fixed while the owner follows
the repository executing the workflow, so an account transfer or same-name backup does not require a
workflow edit. The GitHub App display name is not an interface and may differ between owners.

Windows 原生任务与协议监控始终将同级仓库解析为
`${{ github.repository_owner }}/nexus`。仓库名固定，owner 跟随当前工作流所在仓库，因此账户
迁移或其他 owner 下的同名备份无需修改工作流。GitHub App 的显示名称不属于接口，不同 owner 可以
使用不同名称。

Cross-repository authentication has two supported modes:

- With neither credential configured, the workflow verifies that the sibling reports
  `private: false`, then checks it out with the job-scoped `github.token`. A missing, renamed, or
  private sibling fails before checkout with a configuration error.
- With both credentials configured in a trusted same-repository event, the workflow mints a
  short-lived installation token restricted to `nexus` with read-only Contents and Metadata
  access. Configure repository variable `CROSS_REPO_READ_APP_CLIENT_ID` and repository secret
  `CROSS_REPO_READ_APP_PRIVATE_KEY` together; a partial configuration fails.
- A fork or Dependabot pull request never receives or mints an App token. It can use only the public
  fallback, so a private sibling intentionally requires a trusted maintainer run.

跨仓认证支持两种模式：两个凭据均未配置时，工作流先确认同级仓库返回 `private: false`，再使用任务
级 `github.token` checkout；仓库缺失、改名或私有时会在 checkout 前给出配置错误。可信的同仓事件中，
两个凭据均已配置时才签发仅限 `nexus` 且只有 Contents/Metadata 只读权限的短期安装令牌。
仓库变量 `CROSS_REPO_READ_APP_CLIENT_ID` 与仓库 secret `CROSS_REPO_READ_APP_PRIVATE_KEY` 必须同时
配置，缺少任意一项都会失败。fork 或 Dependabot PR 永不接收或签发 App 令牌，只能使用公开回退；
同级仓库为私有时应由维护者在可信上下文运行。

For private operation, create or reuse a GitHub App under the current owner, grant repository
Contents read-only access (Metadata read access is implicit), install it only on the fixed client and
server repositories, and add the Client ID variable and private-key secret to both repositories.
Validate both contract-monitor workflows and a native E2E run before changing visibility. The
Release App credentials must not be reused, and checkout credentials remain non-persistent.

私有模式下，在当前 owner 创建或复用 GitHub App，仅授予仓库 Contents 只读权限（Metadata 只读为
固有权限），并只安装到固定的客户端与服务端仓库；随后在两个仓库分别配置 Client ID 变量和私钥
secret。切换可见性前，应先验证双端协议监控和一次原生 E2E。不得复用 Release App 凭据，checkout
凭据也不会持久化。

For a public-to-private change, provision and validate the App credentials first. For a
private-to-public change, either retain the App mode or remove both values from each repository to
exercise public fallback; never leave a partial pair. After an owner migration, create/install an App
for the destination owner and replace both repositories' values before validation. To rotate a key,
add the replacement key, update the secret in both repositories, validate trusted runs, and only then
revoke the old key. Recreating the App also requires replacing the Client ID variable.

从公开切换为私有前，先配置并验证 App 凭据；从私有切换为公开后，可以继续使用 App，也可以在每个
仓库同时删除两个值以验证公开回退，不能留下不完整的凭据对。迁移 owner 后，应在目标 owner 创建并
安装 App，更新双仓值后再验证。轮换密钥时先增加新密钥、更新双仓 secret、验证可信运行，最后撤销
旧密钥；若重建 App，还必须同步更新 Client ID 变量。

## Disposable local providers / 一次性本地提供器

For a maintained Windows workstation, `scripts/provision-e2e-compose.sh` provides a machine-neutral
backend to the desktop harness:

```bash
scripts/provision-e2e-compose.sh up --source <server-checkout>
scripts/provision-e2e-compose.sh logs <environment-id>
scripts/provision-e2e-compose.sh pause <environment-id>
scripts/provision-e2e-compose.sh resume <environment-id>
scripts/provision-e2e-compose.sh account-state <environment-id> <account-id> <active|suspended|denylisted>
scripts/provision-e2e-compose.sh down <environment-id>
```

`up` builds the current source, chooses an available host port unless one is explicitly supplied,
generates independent keys/keyrings, migrates a fresh PostgreSQL volume, creates independent
Free/Pro/Team accounts plus billing and multi-device activation fixtures, and emits exactly one schema-3 JSON
descriptor to stdout. The descriptor contains one-use activation codes: capture it directly in the
caller, mask it in CI, and never persist it in source control or general logs. `pause`, `resume`, and
`account-state` are controlled full-suite operations for environments owned by the harness. `down`
removes the Compose project, volume, test image, and secret directory. Under Docker Desktop, callers
place `CAMELLIA_NEXUS_E2E_STATE_ROOT` on a Windows-mounted drive; the provider translates each generated
secret to the engine-visible host path and rejects a missing source instead of creating a directory.

`up` 会构建当前源码、自动选择端口、生成独立密钥、迁移全新 PostgreSQL 卷、建立 Free/Pro/Team
测试账户、账单及多设备激活夹具，并仅向 stdout 输出一个 schema-3 JSON descriptor。Descriptor 含一次性
激活码，调用方必须直接捕获、在 CI 中屏蔽且不得写入源码或普通日志；`pause`、`resume` 与
`account-state` 只供 Harness 自有环境中的 full 套件进行受控操作；`down` 会删除 Compose 项目、卷、
测试镜像及密钥目录。在 Docker Desktop 下，调用方将 `CAMELLIA_NEXUS_E2E_STATE_ROOT` 放在 Windows
挂载盘中；提供器会将生成密钥转换为引擎可见宿主机路径，并在源文件缺失时直接失败而不是创建目录。

The provider accepts only loopback or all-interface binding. Remote execution must bind loopback and
use an authenticated SSH tunnel. All-interface binding is for the Windows-to-WSL2 boundary only; it
must not be used to expose the development issuer to an untrusted network. These disposable services
run in development mode with trace logging and synthetic commercial data and are never production
deployment templates.

提供器只允许回环或全接口监听。远程执行必须绑定回环并使用经过认证的 SSH 隧道；全接口模式仅用于
Windows 到 WSL2 的边界，不得将开发 issuer 暴露到不可信网络。这类服务使用 development 模式、
trace 日志和虚构商业数据，只用于测试，不能作为生产部署模板。

## Hosted versus maintained Windows / 托管与维护 Windows

GitHub-hosted CI is authoritative whenever it can reproduce the behavior. A maintained Windows 11
workstation is reserved for real-browser focus/callback handoff, installer repair/removal, tray and
startup behavior, Explorer and native file dialogs, Authenticode shell presentation, DPI/multi-monitor
placement, sleep/wake transitions, and an optional real public Webhook receiver. Those checks must not
replace final-image, live Admin UI, or native business scenarios that hosted runners can execute.

凡 GitHub 托管 CI 可稳定复现的行为均以远程门禁为准。维护中的 Windows 11 工作站只保留真实浏览器
焦点/回调交接、安装修复/卸载、托盘与启动、Explorer 与原生文件对话框、Authenticode 外壳显示、
DPI/多显示器、睡眠唤醒以及可选真实公网 Webhook 接收器。它们不得替代托管 Runner 可以执行的最终
镜像、真实 Admin UI 或原生业务场景。
