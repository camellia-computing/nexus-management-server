use std::fmt::Write;

pub const BINARY_NAME: &str = "camellia-nexus-management-server";

struct AdminGroup {
    name: &'static str,
    summary_en: &'static str,
    summary_zh: &'static str,
}

struct AdminCommand {
    group: &'static str,
    name: &'static str,
    usage: &'static str,
    summary_en: &'static str,
    summary_zh: &'static str,
    options: &'static [&'static str],
    example: &'static str,
}

struct HelpOption {
    name: &'static str,
    value: &'static str,
    summary_en: &'static str,
    summary_zh: &'static str,
}

const ADMIN_GROUPS: &[AdminGroup] = &[
    AdminGroup {
        name: "account",
        summary_en: "Manage durable customer accounts.",
        summary_zh: "管理可审计、持久化的客户账号。",
    },
    AdminGroup {
        name: "license",
        summary_en: "Provision licenses and change commercial state.",
        summary_zh: "配置授权并调整商业状态。",
    },
    AdminGroup {
        name: "code",
        summary_en: "Issue and administer activation codes.",
        summary_zh: "签发和管理激活授权码。",
    },
    AdminGroup {
        name: "device",
        summary_en: "Inspect devices and apply security state changes.",
        summary_zh: "查看设备并执行安全状态变更。",
    },
    AdminGroup {
        name: "audit",
        summary_en: "Review immutable licensing audit events.",
        summary_zh: "查询不可变的授权审计事件。",
    },
    AdminGroup {
        name: "billing",
        summary_en: "Manage offers, invoices and manually verified payments.",
        summary_zh: "管理报价、账单和人工验证的付款。",
    },
    AdminGroup {
        name: "operator",
        summary_en: "Bootstrap and recover control-plane administrators.",
        summary_zh: "引导和恢复管理控制面的管理员。",
    },
];

const ADMIN_COMMANDS: &[AdminCommand] = &[
    AdminCommand {
        group: "operator",
        name: "bootstrap",
        usage: "operator bootstrap <username> --display-name <name> --actor <id> --reason <text>",
        summary_en: "Create the first Platform Owner and print a ten-minute enrollment token.",
        summary_zh: "创建首位平台所有者并输出十分钟有效的登记令牌。",
        options: &["display-name", "actor", "reason"],
        example: "operator bootstrap owner --display-name 'Primary owner' --actor deployment --reason 'initial control-plane bootstrap'",
    },
    AdminCommand {
        group: "operator",
        name: "recover-owner",
        usage: "operator recover-owner <username> --actor <id> --reason <text> --confirm <normalized-username>",
        summary_en: "Invalidate a Platform Owner's factors and print a replaceable ten-minute reset token.",
        summary_zh: "使平台所有者认证因子全部失效，并输出可重新签发的十分钟重置令牌。",
        options: &["actor", "reason", "confirm"],
        example: "operator recover-owner owner --actor emergency-console --reason 'restore control-plane access' --confirm owner",
    },
    AdminCommand {
        group: "billing",
        name: "offer list",
        usage: "billing offer list",
        summary_en: "List active commercial offer definitions.",
        summary_zh: "列出启用中的商业报价定义。",
        options: &[],
        example: "billing offer list",
    },
    AdminCommand {
        group: "billing",
        name: "offer create",
        usage: "billing offer create <offer-id> --plan <pro|team> --duration-days <1..3660> --currency <code> --amount <amount> --name-en <text> --name-zh <text> --actor <id> --reason <text> [--seat-amount <amount>]",
        summary_en: "Create an immutable versioned offer; Team requires a non-negative per-seat amount and Pro forbids one.",
        summary_zh: "创建不可变、带策略版本的报价；Team 必须指定非负每席价格，Pro 不得指定每席价格。",
        options: &[
            "plan",
            "duration-days",
            "currency",
            "amount",
            "seat-amount",
            "name-en",
            "name-zh",
            "actor",
            "reason",
        ],
        example: "billing offer create pro-yearly --plan pro --duration-days 365 --currency USD --amount 99 --name-en 'Pro yearly' --name-zh '专业版年付' --actor finance --reason '2026 catalog'",
    },
    AdminCommand {
        group: "billing",
        name: "method list",
        usage: "billing method list",
        summary_en: "List active customer-visible manual payment methods.",
        summary_zh: "列出启用且客户可见的人工付款方式。",
        options: &[],
        example: "billing method list",
    },
    AdminCommand {
        group: "billing",
        name: "method create",
        usage: "billing method create <method-id> --name-en <text> --name-zh <text> --instructions-en <text> --instructions-zh <text> --asset <code> --destination-hint <text> --actor <id> --reason <text>",
        summary_en: "Create customer-visible manual settlement instructions without storing a secret.",
        summary_zh: "创建不包含秘密信息的客户可见人工结算说明。",
        options: &[
            "name-en",
            "name-zh",
            "instructions-en",
            "instructions-zh",
            "asset",
            "destination-hint",
            "actor",
            "reason",
        ],
        example: "billing method create bank-transfer --name-en 'Bank transfer' --name-zh '银行转账' --instructions-en 'Contact billing for settlement details.' --instructions-zh '请联系财务获取结算信息。' --asset USD --destination-hint 'Reference the invoice ID' --actor finance --reason 'enable bank transfer'",
    },
    AdminCommand {
        group: "billing",
        name: "invoice list",
        usage: "billing invoice list [--account <account-id>] [--query <text>] [--cursor <opaque>] [--page-size <1..100>]",
        summary_en: "List one bounded invoice page, optionally scoped to an account or search query.",
        summary_zh: "列出一页有界账单，可按账号或搜索内容筛选。",
        options: &["account", "query", "cursor", "page-size"],
        example: "billing invoice list --account acct_customer_001",
    },
    AdminCommand {
        group: "billing",
        name: "invoice create",
        usage: "billing invoice create <invoice-id> --account <account-id> --license <license-id> --offer <offer-id> --due-at <time> --actor <id> --reason <text> [--seats <3..10000>]",
        summary_en: "Create an invoice from existing resources; Team offers require 3..10000 seats and Pro requires zero.",
        summary_zh: "基于既有账号、授权和报价快照创建账单；Team 报价必须指定 3 至 10,000 席，Pro 席位必须为零。",
        options: &[
            "account", "license", "offer", "seats", "due-at", "actor", "reason",
        ],
        example: "billing invoice create inv_001 --account acct_customer_001 --license lic_customer_001 --offer pro-yearly --due-at 14d --actor finance --reason 'annual renewal'",
    },
    AdminCommand {
        group: "billing",
        name: "payment list",
        usage: "billing payment list [--status <state>] [--query <text>] [--cursor <opaque>] [--page-size <1..100>]",
        summary_en: "List one bounded manual-payment page, optionally filtered by review state or search query.",
        summary_zh: "列出一页有界人工付款声明，可按审核状态或搜索内容筛选。",
        options: &["status", "query", "cursor", "page-size"],
        example: "billing payment list --status submitted",
    },
    AdminCommand {
        group: "billing",
        name: "payment submit",
        usage: "billing payment submit <claim-id> --invoice <invoice-id> --method <method-id> --transaction <external-id> --amount <amount> --asset <code> --paid-at <absolute-time> --submitted-by <id> [--payer <name>] [--note <text>]",
        summary_en: "Submit an auditable manual payment claim for later independent review.",
        summary_zh: "提交可审计的人工付款声明，供后续独立复核。",
        options: &[
            "invoice",
            "method",
            "transaction",
            "amount",
            "asset",
            "paid-at",
            "submitted-by",
            "payer",
            "note",
        ],
        example: "billing payment submit claim_001 --invoice inv_001 --method bank-transfer --transaction bank-ref-001 --amount 99 --asset USD --paid-at 2026-07-19T08:00:00Z --submitted-by billing-intake",
    },
    AdminCommand {
        group: "billing",
        name: "payment approve",
        usage: "billing payment approve <claim-id> --row-version <n> --actor <id> --reason <text> --operation-id <id> [--allow-amount-override <true|false>]",
        summary_en: "Approve the exact loaded claim version idempotently; amount override is an explicit exceptional decision.",
        summary_zh: "以幂等方式批准所读取的精确付款声明版本；金额覆盖属于必须显式声明的例外决策。",
        options: &[
            "row-version",
            "actor",
            "reason",
            "operation-id",
            "allow-amount-override",
        ],
        example: "billing payment approve claim_001 --row-version 1 --actor reviewer_001 --reason 'bank receipt verified' --operation-id op_001",
    },
    AdminCommand {
        group: "billing",
        name: "payment reject",
        usage: "billing payment reject <claim-id> --row-version <n> --actor <id> --reason <text> --operation-id <id>",
        summary_en: "Reject the exact loaded claim version idempotently with an auditable reason.",
        summary_zh: "使用可审计原因，以幂等方式拒绝所读取的精确付款声明版本。",
        options: &["row-version", "actor", "reason", "operation-id"],
        example: "billing payment reject claim_001 --row-version 1 --actor reviewer_001 --reason 'transaction could not be verified' --operation-id op_002",
    },
    AdminCommand {
        group: "billing",
        name: "payment request-information",
        usage: "billing payment request-information <claim-id> --row-version <n> --actor <id> --reason <text> --operation-id <id>",
        summary_en: "Request more evidence for the exact loaded claim version idempotently with an auditable reason.",
        summary_zh: "使用可审计原因，以幂等方式要求为所读取的精确付款声明版本补充凭证。",
        options: &["row-version", "actor", "reason", "operation-id"],
        example: "billing payment request-information claim_001 --row-version 1 --actor reviewer_001 --reason 'provide a complete receipt' --operation-id op_003",
    },
    AdminCommand {
        group: "account",
        name: "list",
        usage: "account list",
        summary_en: "List every account.",
        summary_zh: "列出全部账号。",
        options: &[],
        example: "account list",
    },
    AdminCommand {
        group: "account",
        name: "show",
        usage: "account show <account-id>",
        summary_en: "Show one account by identifier.",
        summary_zh: "按标识符查看单个账号。",
        options: &[],
        example: "account show acct_customer_001",
    },
    AdminCommand {
        group: "account",
        name: "create",
        usage: "account create <account-id> --actor <id> --reason <text> [--note <text>]",
        summary_en: "Create an active account and its audit event.",
        summary_zh: "创建启用状态的账号及对应审计事件。",
        options: &["actor", "reason", "note"],
        example: "account create acct_customer_001 --actor operator_001 --reason \"customer created\"",
    },
    AdminCommand {
        group: "account",
        name: "set-state",
        usage: "account set-state <account-id> <active|suspended|denylisted> --actor <id> --reason <text>",
        summary_en: "Change account access state and revoke sessions when required.",
        summary_zh: "修改账号访问状态，并在需要时撤销相关会话。",
        options: &["actor", "reason"],
        example: "account set-state acct_customer_001 suspended --actor operator_001 --reason \"billing review\"",
    },
    AdminCommand {
        group: "license",
        name: "list",
        usage: "license list [--account <account-id>]",
        summary_en: "List licenses, optionally scoped to an account.",
        summary_zh: "列出授权，可选择限定到指定账号。",
        options: &["account"],
        example: "license list --account acct_customer_001",
    },
    AdminCommand {
        group: "license",
        name: "show",
        usage: "license show <license-id>",
        summary_en: "Show one license by identifier.",
        summary_zh: "按标识符查看单个授权。",
        options: &[],
        example: "license show lic_customer_001",
    },
    AdminCommand {
        group: "license",
        name: "create",
        usage: "license create <license-id> --account <account-id> --plan <free|pro|team> --actor <id> --reason <text> [--status <active|past_due|canceled>] [--seats <n>] [--expires-at <time|none>]",
        summary_en: "Create a license; Team requires 3..10000 seats and Free/Pro require no seats.",
        summary_zh: "创建授权；Team 必须指定 3..10000 席，Free/Pro 不得指定席位。",
        options: &[
            "account",
            "actor",
            "reason",
            "plan",
            "status",
            "seats",
            "expires-at",
        ],
        example: "license create lic_customer_001 --account acct_customer_001 --plan pro --actor operator_001 --reason \"purchase provisioned\"",
    },
    AdminCommand {
        group: "license",
        name: "set-plan",
        usage: "license set-plan <license-id> <free|pro|team> --actor <id> --reason <text> [--seats <n>]",
        summary_en: "Apply a complete plan policy; entering Team requires seats and leaving it clears seats.",
        summary_zh: "应用完整套餐策略；进入 Team 时必须指定席位，离开 Team 时自动清零。",
        options: &["actor", "reason", "seats"],
        example: "license set-plan lic_customer_001 team --seats 3 --actor operator_001 --reason \"team upgrade\"",
    },
    AdminCommand {
        group: "license",
        name: "set-status",
        usage: "license set-status <license-id> <active|past_due|canceled> --actor <id> --reason <text>",
        summary_en: "Set commercial status and advance the license epoch.",
        summary_zh: "设置商业状态并推进授权 epoch。",
        options: &["actor", "reason"],
        example: "license set-status lic_customer_001 past_due --actor operator_001 --reason \"invoice overdue\"",
    },
    AdminCommand {
        group: "license",
        name: "set-seats",
        usage: "license set-seats <license-id> <n> --actor <id> --reason <text>",
        summary_en: "Set Team seats; the device limit is derived as three devices per seat.",
        summary_zh: "设置 Team 席位；设备上限按每席三台自动派生。",
        options: &["actor", "reason"],
        example: "license set-seats lic_customer_001 5 --actor operator_001 --reason \"seat expansion\"",
    },
    AdminCommand {
        group: "license",
        name: "set-expires-at",
        usage: "license set-expires-at <license-id> <time|none> --actor <id> --reason <text>",
        summary_en: "Set or clear the authoritative license expiry.",
        summary_zh: "设置或清除权威授权到期时间。",
        options: &["actor", "reason"],
        example: "license set-expires-at lic_customer_001 2027-01-01T00:00:00Z --actor operator_001 --reason \"renewal term\"",
    },
    AdminCommand {
        group: "code",
        name: "issue",
        usage: "code issue --account <account-id> --license <license-id> --issued-by <actor> --reason <text> --operation-id <id> [--count <1..1000>] [--max-redemptions <n>] [--channel <name>] [--ttl-days <1..3650> | --expires-at <time>] [--note <text>]",
        summary_en: "Atomically issue a traceable activation-code batch; plaintext is shown once.",
        summary_zh: "以原子事务签发可追踪的授权码批次；明文只显示一次。",
        options: &[
            "account",
            "license",
            "issued-by",
            "reason",
            "operation-id",
            "count",
            "max-redemptions",
            "channel",
            "ttl-days",
            "expires-at",
            "note",
        ],
        example: "code issue --account acct_customer_001 --license lic_customer_001 --issued-by operator_001 --reason \"customer purchase\" --operation-id order_001-issue-01 --count 3 --ttl-days 365",
    },
    AdminCommand {
        group: "code",
        name: "list",
        usage: "code list [--account <account-id>] [--status <active|consumed|revoked>]",
        summary_en: "List activation-code metadata without plaintext secrets.",
        summary_zh: "列出授权码元数据，不返回明文秘密。",
        options: &["account", "status"],
        example: "code list --account acct_customer_001 --status active",
    },
    AdminCommand {
        group: "code",
        name: "show",
        usage: "code show <code|hash|prefix>",
        summary_en: "Resolve and show one activation-code record.",
        summary_zh: "通过明文、哈希或唯一前缀解析并查看授权码记录。",
        options: &[],
        example: "code show CNX1-ABCDE-FGHIJ-KLMNO-PQRST-UVWXY",
    },
    AdminCommand {
        group: "code",
        name: "revoke",
        usage: "code revoke <code|hash|prefix> --actor <id> --reason <text>",
        summary_en: "Revoke an activation code with an audited reason.",
        summary_zh: "使用可审计原因撤销授权码。",
        options: &["actor", "reason"],
        example: "code revoke CNX1-ABCDE --actor operator_001 --reason \"order refunded\"",
    },
    AdminCommand {
        group: "code",
        name: "restore",
        usage: "code restore <code|hash|prefix> --actor <id> --reason <text> [--max-redemptions <n>]",
        summary_en: "Reset redemption state after an audited review; expiry is unchanged.",
        summary_zh: "经审计复核后重置兑换状态；不会修改到期时间。",
        options: &["actor", "reason", "max-redemptions"],
        example: "code restore CNX1-ABCDE --actor operator_001 --reason \"refund reversed\" --max-redemptions 1",
    },
    AdminCommand {
        group: "code",
        name: "expire",
        usage: "code expire <code|hash|prefix> --actor <id> --reason <text> --expires-at <time>",
        summary_en: "Set an activation-code expiry explicitly.",
        summary_zh: "显式设置授权码到期时间。",
        options: &["actor", "reason", "expires-at"],
        example: "code expire CNX1-ABCDE --actor operator_001 --reason \"contract ended\" --expires-at 2027-01-01",
    },
    AdminCommand {
        group: "device",
        name: "list",
        usage: "device list [--account <account-id>]",
        summary_en: "List registered devices, optionally by account.",
        summary_zh: "列出已注册设备，可选择限定到指定账号。",
        options: &["account"],
        example: "device list --account acct_customer_001",
    },
    AdminCommand {
        group: "device",
        name: "show",
        usage: "device show <device-id>",
        summary_en: "Show one registered device.",
        summary_zh: "查看单个已注册设备。",
        options: &[],
        example: "device show f5a924e5-57e1-49d6-8990-4f230c5f563d",
    },
    AdminCommand {
        group: "device",
        name: "set-state",
        usage: "device set-state <device-id> <removed|revoked|suspicious> --actor <id> --reason <text>",
        summary_en: "Apply a non-active security state and revoke sessions.",
        summary_zh: "设置非活跃安全状态并撤销设备会话。",
        options: &["actor", "reason"],
        example: "device set-state f5a924e5-57e1-49d6-8990-4f230c5f563d suspicious --actor operator_001 --reason \"risk signal\"",
    },
    AdminCommand {
        group: "device",
        name: "revoke",
        usage: "device revoke <device-id> --actor <id> --reason <text>",
        summary_en: "Revoke a device and all of its sessions.",
        summary_zh: "撤销设备及其全部会话。",
        options: &["actor", "reason"],
        example: "device revoke f5a924e5-57e1-49d6-8990-4f230c5f563d --actor operator_001 --reason \"key compromise\"",
    },
    AdminCommand {
        group: "audit",
        name: "list",
        usage: "audit list [--account <account-id>] [--limit <1..500>]",
        summary_en: "List recent audit events, newest first.",
        summary_zh: "按时间倒序列出近期审计事件。",
        options: &["account", "limit"],
        example: "audit list --account acct_customer_001 --limit 100",
    },
];

const HELP_OPTIONS: &[HelpOption] = &[
    HelpOption {
        name: "display-name",
        value: "<name>",
        summary_en: "Human-readable administrator display name.",
        summary_zh: "管理员的人类可读显示名称。",
    },
    HelpOption {
        name: "confirm",
        value: "<username>",
        summary_en: "Destructive confirmation; must exactly match the normalized target username.",
        summary_zh: "破坏性操作确认值，必须与规范化后的目标用户名完全一致。",
    },
    HelpOption {
        name: "account",
        value: "<account-id>",
        summary_en: "Limit or bind the operation to an account.",
        summary_zh: "将操作限定或绑定到指定账号。",
    },
    HelpOption {
        name: "query",
        value: "<text>",
        summary_en: "Case-insensitive search text; maximum 128 characters.",
        summary_zh: "不区分大小写的搜索文本，最多 128 个字符。",
    },
    HelpOption {
        name: "cursor",
        value: "<opaque>",
        summary_en: "Opaque continuation cursor returned by the preceding page.",
        summary_zh: "上一页返回的不透明续页游标。",
    },
    HelpOption {
        name: "page-size",
        value: "<1..100>",
        summary_en: "Bounded page size; defaults to 50.",
        summary_zh: "有界页大小，默认 50。",
    },
    HelpOption {
        name: "license",
        value: "<license-id>",
        summary_en: "Bind issuance to an existing license.",
        summary_zh: "将签发操作绑定到既有授权。",
    },
    HelpOption {
        name: "actor",
        value: "<id>",
        summary_en: "Auditable operator identity; maximum 128 characters.",
        summary_zh: "可审计的操作者身份，最多 128 个字符。",
    },
    HelpOption {
        name: "issued-by",
        value: "<id>",
        summary_en: "Auditable issuer identity; maximum 128 characters.",
        summary_zh: "可审计的签发者身份，最多 128 个字符。",
    },
    HelpOption {
        name: "reason",
        value: "<text>",
        summary_en: "Required audit reason; maximum 512 characters.",
        summary_zh: "必填审计原因，最多 512 个字符。",
    },
    HelpOption {
        name: "note",
        value: "<text>",
        summary_en: "Optional operator note; maximum 1024 characters.",
        summary_zh: "可选操作备注，最多 1024 个字符。",
    },
    HelpOption {
        name: "plan",
        value: "<free|pro|team>",
        summary_en: "Commercial plan assigned to a license.",
        summary_zh: "分配给授权的商业方案。",
    },
    HelpOption {
        name: "status",
        value: "<state>",
        summary_en: "Filter or set the state accepted by this command.",
        summary_zh: "筛选或设置该命令支持的状态。",
    },
    HelpOption {
        name: "seats",
        value: "<3..10000>",
        summary_en: "Team-only seats; active/suspended members and pending invitations consume one each.",
        summary_zh: "仅适用于 Team；Active/Suspended 成员与待接受邀请各占一席。",
    },
    HelpOption {
        name: "expires-at",
        value: "<time[|none]>",
        summary_en: "Absolute/relative expiry; none is accepted only by license operations.",
        summary_zh: "绝对或相对到期时间；只有授权类操作接受 none。",
    },
    HelpOption {
        name: "operation-id",
        value: "<1..128-chars>",
        summary_en: "Globally unique idempotency key for one logical mutation.",
        summary_zh: "单次逻辑变更全局唯一的幂等键。",
    },
    HelpOption {
        name: "row-version",
        value: "<positive-integer>",
        summary_en: "Optimistic-concurrency version returned by the most recent read.",
        summary_zh: "最近一次读取所返回的乐观并发版本。",
    },
    HelpOption {
        name: "count",
        value: "<1..1000>",
        summary_en: "Number of activation codes to issue; default 1.",
        summary_zh: "签发授权码数量，默认为 1。",
    },
    HelpOption {
        name: "max-redemptions",
        value: "<n>",
        summary_en: "Maximum successful device redemptions; default 1.",
        summary_zh: "最大成功设备兑换次数，默认为 1。",
    },
    HelpOption {
        name: "channel",
        value: "<name>",
        summary_en: "Optional distribution-channel metadata.",
        summary_zh: "可选的分发渠道元数据。",
    },
    HelpOption {
        name: "ttl-days",
        value: "<1..3650>",
        summary_en: "Expiry relative to issuance; conflicts with --expires-at.",
        summary_zh: "相对签发时间的有效天数；不能与 --expires-at 同时使用。",
    },
    HelpOption {
        name: "limit",
        value: "<1..500>",
        summary_en: "Maximum audit records to return; default 100.",
        summary_zh: "最多返回的审计记录数，默认为 100。",
    },
    HelpOption {
        name: "duration-days",
        value: "<1..3660>",
        summary_en: "Commercial term in whole days.",
        summary_zh: "以完整天数表示的商业期限。",
    },
    HelpOption {
        name: "currency",
        value: "<code>",
        summary_en: "Settlement currency code; normalized to uppercase.",
        summary_zh: "结算货币代码，保存时规范化为大写。",
    },
    HelpOption {
        name: "amount",
        value: "<amount>",
        summary_en: "Non-negative decimal amount with at most eight decimal places.",
        summary_zh: "非负十进制金额，最多八位小数。",
    },
    HelpOption {
        name: "seat-amount",
        value: "<amount>",
        summary_en: "Optional per-seat price for a Team offer.",
        summary_zh: "Team 报价可选的每席价格。",
    },
    HelpOption {
        name: "name-en",
        value: "<text>",
        summary_en: "Required customer-visible English name.",
        summary_zh: "必填的客户可见英文名称。",
    },
    HelpOption {
        name: "name-zh",
        value: "<text>",
        summary_en: "Required customer-visible Chinese name.",
        summary_zh: "必填的客户可见中文名称。",
    },
    HelpOption {
        name: "instructions-en",
        value: "<text>",
        summary_en: "Required customer-visible English settlement instructions.",
        summary_zh: "必填的客户可见英文结算说明。",
    },
    HelpOption {
        name: "instructions-zh",
        value: "<text>",
        summary_en: "Required customer-visible Chinese settlement instructions.",
        summary_zh: "必填的客户可见中文结算说明。",
    },
    HelpOption {
        name: "asset",
        value: "<code>",
        summary_en: "Settlement asset code accepted by the payment method or claim.",
        summary_zh: "付款方式或付款声明使用的结算资产代码。",
    },
    HelpOption {
        name: "destination-hint",
        value: "<text>",
        summary_en: "Non-secret settlement destination guidance shown to customers.",
        summary_zh: "向客户显示且不包含秘密信息的结算目的地提示。",
    },
    HelpOption {
        name: "offer",
        value: "<offer-id>",
        summary_en: "Existing offer whose versioned commercial terms are snapshotted.",
        summary_zh: "要对其版本化商业条款建立快照的既有报价。",
    },
    HelpOption {
        name: "due-at",
        value: "<time>",
        summary_en: "Absolute or relative invoice due time.",
        summary_zh: "账单的绝对或相对到期时间。",
    },
    HelpOption {
        name: "invoice",
        value: "<invoice-id>",
        summary_en: "Existing invoice associated with the payment claim.",
        summary_zh: "付款声明所关联的既有账单。",
    },
    HelpOption {
        name: "method",
        value: "<method-id>",
        summary_en: "Existing manual payment method used for settlement.",
        summary_zh: "结算时使用的既有人工付款方式。",
    },
    HelpOption {
        name: "transaction",
        value: "<external-id>",
        summary_en: "External settlement transaction identifier; maximum 256 characters.",
        summary_zh: "外部结算交易标识，最多 256 个字符。",
    },
    HelpOption {
        name: "paid-at",
        value: "<absolute-time>",
        summary_en: "Absolute payment time; future timestamps beyond clock tolerance are rejected.",
        summary_zh: "绝对付款时间；超出时钟容差的未来时间会被拒绝。",
    },
    HelpOption {
        name: "submitted-by",
        value: "<id>",
        summary_en: "Auditable identity that submitted the payment evidence.",
        summary_zh: "提交付款凭证的可审计身份。",
    },
    HelpOption {
        name: "payer",
        value: "<name>",
        summary_en: "Optional payer name; maximum 256 characters.",
        summary_zh: "可选付款人名称，最多 256 个字符。",
    },
    HelpOption {
        name: "allow-amount-override",
        value: "<true|false>",
        summary_en: "Explicitly permit approval when the claimed amount differs from the invoice.",
        summary_zh: "当申报金额与账单不一致时，显式允许批准该声明。",
    },
];

pub fn root_help() -> &'static str {
    r#"Camellia Nexus Management Server
Server-authoritative licensing service / 服务端权威授权服务

USAGE / 用法:
  camellia-nexus-management-server [serve]
  camellia-nexus-management-server migrate
  camellia-nexus-management-server healthcheck <local-url>
  camellia-nexus-management-server admin-web
  camellia-nexus-management-server admin-worker
  camellia-nexus-management-server admin <command> [options]
  camellia-nexus-management-server help [serve|migrate|validate-deployment-secrets|db-bootstrap|healthcheck|admin-web|admin-worker|admin [group [operation ...]]]

COMMANDS / 命令:
  serve    Run the HTTP licensing service (default).
           运行 HTTP 授权服务（默认命令）。
  migrate  Apply pending database migrations and verify readiness, then exit.
           应用待执行的数据库迁移、验证就绪状态后退出。
  validate-deployment-secrets
           Validate every staged production secret without network access.
           在无网络访问的情况下验证全部已暂存生产 secret。
  db-bootstrap
           Reconcile or check database login roles before migration.
           在迁移前校正或检查数据库登录角色。
  healthcheck Probe a local /healthz or /readyz endpoint, then exit.
              探测本机 /healthz 或 /readyz 端点后退出。
  admin-web Run the isolated administration control plane.
            运行隔离的管理控制面。
  admin-worker Run durable administration and maintenance jobs.
               运行持久化管理与维护任务。
  admin    Run audited database administration commands.
           执行带审计的数据库管理命令。
  help     Show root or nested command help.
           显示根命令或分层子命令帮助。

OPTIONS / 选项:
  -h, --help       Show this bilingual help and exit.
                   显示本中英双语帮助并退出。
  -V, --version    Show the binary version and exit.
                   显示二进制版本并退出。

HELP EXAMPLES / 帮助示例:
  camellia-nexus-management-server serve --help
  camellia-nexus-management-server migrate --help
  camellia-nexus-management-server validate-deployment-secrets --help
  camellia-nexus-management-server db-bootstrap --help
  camellia-nexus-management-server healthcheck --help
  camellia-nexus-management-server admin-web --help
  camellia-nexus-management-server admin-worker --help
  camellia-nexus-management-server admin --help
  camellia-nexus-management-server admin code issue --help

Help is available without server configuration or a database connection.
帮助信息无需服务配置或数据库连接即可查看。"#
}

pub fn serve_help() -> &'static str {
    r#"Camellia Nexus Management Server — serve
Run the production HTTP service / 运行生产 HTTP 服务

USAGE / 用法:
  camellia-nexus-management-server [serve]

The service is configured through environment variables and validates all
production requirements and the PostgreSQL schema before binding its socket.
服务通过环境变量配置，并在监听端口前验证全部生产要求及 PostgreSQL 结构。

CORE ENVIRONMENT / 核心环境变量:
  CAMELLIA_NEXUS_LICENSE_ENV                 development | production
  CAMELLIA_NEXUS_LICENSE_BIND                Listener address / 监听地址
  CAMELLIA_NEXUS_LICENSE_STORAGE             memory | postgres
  DATABASE_URL                         Required for PostgreSQL / PostgreSQL 必填
  DATABASE_PASSWORD_FILE               Optional password secret file / 可选数据库密码文件
  CAMELLIA_NEXUS_LICENSE_ISSUER              HTTPS issuer in production / 生产 HTTPS 签发者
  CAMELLIA_NEXUS_LICENSE_AUDIENCE            Entitlement audience / entitlement 受众
  CAMELLIA_NEXUS_LICENSE_KEY_ID              Active signing key id / 当前签名密钥标识
  CAMELLIA_NEXUS_LICENSE_PRIVATE_KEY_PEM_PATH  ES256 private-key path / ES256 私钥路径
  CAMELLIA_NEXUS_OAUTH_CLIENT_ID             Desktop OAuth client id / 桌面 OAuth 客户端标识
  CAMELLIA_NEXUS_OAUTH_REDIRECT_URIS         Allowed redirect URI list / 回调 URI 白名单
  CAMELLIA_NEXUS_DATABASE_MIGRATE            Auto-migrate switch / 自动迁移开关
  CAMELLIA_NEXUS_METRICS_BIND                Separate operations listener / 独立运维监听地址
  CAMELLIA_NEXUS_METRICS_ALLOW_NON_LOOPBACK  Explicit non-loopback opt-in / 显式允许非回环监听

PRODUCTION MIGRATIONS / 生产迁移:
  Keep CAMELLIA_NEXUS_DATABASE_MIGRATE=false for the long-running service. Apply
  migrations once with the same release artifact before rolling the service.
  常驻服务保持 CAMELLIA_NEXUS_DATABASE_MIGRATE=false；滚动发布前使用同版本工件执行一次迁移。

ENDPOINTS / 端点:
  GET /healthz    Process liveness / 进程存活
  GET /readyz     Database and time-authority readiness / 数据库与时间权威就绪状态

METRICS LISTENER / 指标监听器:
  GET /healthz    Metrics process liveness / 指标进程存活
  GET /metrics    Low-cardinality Prometheus text / 低基数 Prometheus 文本

See README.md and deploy/public-api.env.example for the complete schema.
完整配置请参阅 README.md 与 deploy/public-api.env.example。"#
}

pub fn runtime_help(command: &str) -> Result<&'static str, String> {
    match command {
        "migrate" => Ok(r#"Camellia Nexus Management Server — migrate
Apply and verify the database schema / 应用并验证数据库结构

USAGE / 用法:
  camellia-nexus-management-server migrate

BEHAVIOR / 行为:
  Applies every pending append-only migration, replaces ambient database privileges
  with explicit per-runtime grants, verifies schema readiness, and exits.
  应用全部待执行的追加式迁移，以显式的逐角色授权替换数据库环境权限，
  验证数据库结构已就绪后退出。

  Run this one-shot role with the same immutable artifact before starting or rolling
  any long-running service role. Never rewrite an applied migration or its SQLx record.
  启动或滚动更新任何常驻角色前，应使用同一不可变工件执行本一次性角色；
  不得改写已应用的迁移或其 SQLx 记录。

REQUIRED ENVIRONMENT / 必需环境:
  DATABASE_URL                PostgreSQL connection URL / PostgreSQL 连接地址
  DATABASE_PASSWORD_FILE      Optional password secret file / 可选数据库密码文件
  CAMELLIA_NEXUS_DATABASE_PUBLIC_ROLE
  CAMELLIA_NEXUS_DATABASE_ADMIN_WEB_ROLE
  CAMELLIA_NEXUS_DATABASE_ADMIN_WORKER_ROLE
                              Three distinct unprivileged login roles in production
                              生产环境中的三个独立无特权登录角色

RELATED ENVIRONMENT / 相关环境:
  CAMELLIA_NEXUS_LICENSE_ENV        development | production
  CAMELLIA_NEXUS_LOG_LEVEL          Runtime log level / 运行日志级别
  CAMELLIA_NEXUS_LOG_FORMAT         compact | json

See docs/systemd-deployment.md for role provisioning, deployment order, and recovery.
角色创建、部署顺序及恢复规则见 docs/systemd-deployment.md。"#),
        "validate-deployment-secrets" => Ok(
            r#"Camellia Nexus Management Server — validate-deployment-secrets
Validate staged production secrets / 验证已暂存的生产 secret

USAGE / 用法:
  camellia-nexus-management-server validate-deployment-secrets

The command performs no network access and prints only logical secret names and
validation status. It rejects missing, malformed, oversized, or unreadable files.
本命令不访问网络，只输出 secret 逻辑名称及验证状态；缺失、畸形、超限或不可读文件均会被拒绝。"#,
        ),
        "db-bootstrap" => Ok(r#"Camellia Nexus Management Server — db-bootstrap
Reconcile the production database identity contract / 校正生产数据库身份契约

USAGE / 用法:
  camellia-nexus-management-server db-bootstrap reconcile
  camellia-nexus-management-server db-bootstrap check

reconcile creates or corrects the migration and runtime logins, passwords,
memberships, and ownership. check is read-only. Bootstrap credentials are
installation credentials and are not rotated by this command.
reconcile 创建或校正迁移及运行登录、密码、成员关系与所有权；check 只读检查；
bootstrap 凭据属于安装级凭据，本命令不会轮换。

Passwords are accepted only through *_PASSWORD_FILE variables and never through
command arguments or password-bearing URLs.
密码只允许通过 *_PASSWORD_FILE 提供，不得出现在命令参数或 URL 中。"#),
        "healthcheck" => Ok(r#"Camellia Nexus Management Server — healthcheck
Probe one local process endpoint / 探测一个本机进程端点

USAGE / 用法:
  camellia-nexus-management-server healthcheck <local-url>

URL CONTRACT / URL 约束:
  The URL must use plain HTTP, an explicit port, a numeric loopback host
  (127.0.0.0/8 or [::1]), and exactly /healthz or /readyz. Credentials, query
  parameters, fragments, redirects, and non-loopback targets are rejected.
  URL 必须使用 HTTP、显式端口、数字形式的回环地址（127.0.0.0/8 或 [::1]），
  且路径只能是 /healthz 或 /readyz；凭据、查询、片段、重定向及非回环目标均被拒绝。

ENDPOINTS / 端点:
  /healthz   Process liveness only / 仅检查进程存活
  /readyz    Dependency, schema, key and trusted-time readiness
             检查依赖、结构、密钥及可信时间就绪状态

The probe has a 2.5-second timeout and exits non-zero on transport or HTTP failure.
探测超时为 2.5 秒；传输失败或非成功 HTTP 状态均以非零状态退出。

EXAMPLES / 示例:
  camellia-nexus-management-server healthcheck http://127.0.0.1:8088/healthz
  camellia-nexus-management-server healthcheck http://127.0.0.1:8090/readyz"#),
        "admin-web" => Ok(r#"Camellia Nexus Management Server — admin-web
Run the isolated administration control plane / 运行隔离的管理控制面

USAGE / 用法:
  camellia-nexus-management-server admin-web

BEHAVIOR / 行为:
  Serves the static Admin UI and its private /api/v1 control-plane API. Startup
  fails closed unless assets, PostgreSQL schema, trusted time, key material,
  object storage, and the evidence scanner required by the environment are ready.
  提供静态 Admin UI 与私有 /api/v1 控制面 API；若静态资源、PostgreSQL 结构、
  可信时间、密钥、对象存储或当前环境要求的凭证扫描器未就绪，启动将失败关闭。

CORE ENVIRONMENT / 核心环境变量:
  DATABASE_URL                              PostgreSQL connection URL / PostgreSQL 连接地址
  DATABASE_PASSWORD_FILE                    Optional password secret file / 可选数据库密码文件
  CAMELLIA_NEXUS_LICENSE_ENV                      development | production
  CAMELLIA_NEXUS_ADMIN_BIND                       Private listener / 私有监听地址
  CAMELLIA_NEXUS_ADMIN_PUBLIC_ORIGIN              Exact browser origin; HTTPS in production
                                             精确浏览器来源；生产环境必须为 HTTPS
  CAMELLIA_NEXUS_ADMIN_ASSET_DIR                  Static Admin UI build directory / 静态 UI 构建目录
  CAMELLIA_NEXUS_ADMIN_KEYRING_PATH               Required in production / 生产环境必需
  CAMELLIA_NEXUS_ADMIN_FORWARDED_FOR_SECRET_PATH  Optional trusted-proxy proof secret file
                                             可选可信代理证明秘密文件
  CAMELLIA_NEXUS_ADMIN_REQUEST_TIMEOUT_SECONDS    Positive Admin API timeout / 正数管理 API 超时
  CAMELLIA_NEXUS_ADMIN_MAX_IN_FLIGHT              Positive Admin API concurrency / 正数管理 API 并发上限
  CAMELLIA_NEXUS_DATABASE_MAX_CONNECTIONS         Positive connection-pool size / 正数连接池大小
  CAMELLIA_NEXUS_DATABASE_ACQUIRE_TIMEOUT_SECONDS Positive pool wait timeout / 正数连接等待超时
  CAMELLIA_NEXUS_METRICS_BIND                     Separate operations listener / 独立运维监听地址

Keep this listener private behind the exact configured HTTPS origin. Do not enable
automatic migrations for a long-running role.
本监听必须置于与配置完全一致的私有 HTTPS 入口之后；常驻角色不得启用自动迁移。

See README.md and deploy/admin-web.env.example for the complete validated schema.
完整校验配置见 README.md 与 deploy/admin-web.env.example。"#),
        "admin-worker" => Ok(r#"Camellia Nexus Management Server — admin-worker
Run durable administration maintenance / 运行持久化管理维护任务

USAGE / 用法:
  camellia-nexus-management-server admin-worker

BEHAVIOR / 行为:
  Leases and executes durable Admin jobs, advances overdue invoices, purges expired
  one-display deliveries and enrollment state, retries payment-evidence scanning,
  and removes stale objects. Work remains retryable across process restarts.
  租用并执行持久化管理任务，推进逾期账单，清理过期的一次性秘密交付及登记状态，
  重试付款凭证扫描并移除陈旧对象；进程重启后未完成工作仍可重试。

CORE ENVIRONMENT / 核心环境变量:
  DATABASE_URL                       PostgreSQL connection URL / PostgreSQL 连接地址
  DATABASE_PASSWORD_FILE             Optional password secret file / 可选数据库密码文件
  CAMELLIA_NEXUS_LICENSE_ENV               development | production
  CAMELLIA_NEXUS_ADMIN_KEYRING_PATH        Required in production / 生产环境必需
  CAMELLIA_NEXUS_DATABASE_MAX_CONNECTIONS  Positive connection-pool size / 正数连接池大小
  CAMELLIA_NEXUS_DATABASE_ACQUIRE_TIMEOUT_SECONDS Positive pool wait timeout / 正数连接等待超时
  CAMELLIA_NEXUS_METRICS_BIND              Separate operations listener / 独立运维监听地址

Object-storage, evidence-scanner, trusted-time, and logging settings are shared with
admin-web. Startup verifies the same schema and keyring before claiming work.
对象存储、凭证扫描、可信时间及日志设置与 admin-web 共用；认领任务前会验证相同的
数据库结构及密钥环。

See README.md and deploy/admin-worker.env.example for the complete validated schema.
完整校验配置见 README.md 与 deploy/admin-worker.env.example。"#),
        _ => Err(format!(
            "unknown runtime help topic: {command} / 未知运行角色帮助主题：{command}"
        )),
    }
}

pub fn version() -> String {
    format!("{BINARY_NAME} {}", env!("CARGO_PKG_VERSION"))
}

pub fn is_admin_group(value: &str) -> bool {
    ADMIN_GROUPS.iter().any(|group| group.name == value)
}

pub fn canonical_admin_help_topic(args: &[String]) -> Vec<String> {
    let Some(group) = args.first() else {
        return Vec::new();
    };
    if !is_admin_group(group) {
        return vec![group.clone()];
    }
    let matching = ADMIN_COMMANDS
        .iter()
        .filter(|command| command.group == group)
        .filter_map(|command| {
            let path = command.name.split_ascii_whitespace().collect::<Vec<_>>();
            args.get(1..1 + path.len())
                .filter(|provided| provided.iter().map(String::as_str).eq(path.iter().copied()))
                .map(|_| path)
        })
        .max_by_key(Vec::len);
    if let Some(path) = matching {
        return std::iter::once(group.clone())
            .chain(path.into_iter().map(str::to_owned))
            .collect();
    }
    if let Some(prefix) = args.get(1)
        && ADMIN_COMMANDS.iter().any(|command| {
            command.group == group
                && command
                    .name
                    .split_ascii_whitespace()
                    .next()
                    .is_some_and(|candidate| candidate == prefix)
        })
    {
        return vec![group.clone(), prefix.clone()];
    }
    args.iter()
        .take_while(|value| !value.starts_with('-'))
        .cloned()
        .collect()
}

pub fn admin_help(topic: &[String]) -> Result<String, String> {
    match topic {
        [] => Ok(render_admin_root()),
        [group] => render_admin_group(group),
        [group, command @ ..] => render_admin_command(group, &command.join(" ")),
    }
}

fn render_admin_root() -> String {
    let mut output = String::from(
        "Camellia Nexus License Administration\nAudited production administration / 可审计的生产管理工具\n\nUSAGE / 用法:\n  camellia-nexus-management-server admin [--human|--raw|--output <human|raw>] <group> <operation> [options]\n  camellia-nexus-management-server admin help [group [operation ...]]\n\nCOMMAND GROUPS / 命令组:\n",
    );
    for group in ADMIN_GROUPS {
        let _ = writeln!(
            output,
            "  {:<9} {} / {}",
            group.name, group.summary_en, group.summary_zh
        );
    }
    output.push_str(
        "\nGLOBAL OPTIONS / 全局选项:\n  --human                Human JSON plus derived UTC ISO fields (default).\n                         人类友好 JSON，并补充 UTC ISO 字段（默认）。\n  --raw                  Exact machine JSON without derived fields.\n                         不含派生字段的精确机器 JSON。\n  --output <human|raw>   Select output mode explicitly. / 显式选择输出模式。\n  -h, --help             Show help without connecting to PostgreSQL.\n                         无需连接 PostgreSQL 即可显示帮助。\n\nENVIRONMENT / 环境:\n  DATABASE_URL is required only when executing an Admin operation.\n  只有实际执行 Admin 操作时才需要 DATABASE_URL。\n  DATABASE_PASSWORD_FILE supplies a database password without embedding it in the URL.\n  DATABASE_PASSWORD_FILE 用于通过文件提供数据库密码，避免将其嵌入 URL。\n  Production rejects a password embedded in DATABASE_URL.\n  生产环境拒绝 DATABASE_URL 中的内嵌密码。\n  CAMELLIA_NEXUS_DATABASE_MIGRATE defaults to true in development and false in production.\n  CAMELLIA_NEXUS_DATABASE_MIGRATE 在开发环境默认 true，在生产环境默认 false。\n\nTIME INPUT / 时间输入:\n  RFC3339, UTC date/date-time, relative expiry (30d, 12h, 2w), or Unix seconds.\n  支持 RFC3339、UTC 日期/日期时间、相对有效期（30d、12h、2w）或 Unix 秒。\n\nRun `camellia-nexus-management-server admin <group> --help` for group commands.\n执行 `camellia-nexus-management-server admin <group> --help` 查看命令组详情。\n",
    );
    output
}

fn render_admin_group(group_name: &str) -> Result<String, String> {
    let group = ADMIN_GROUPS
        .iter()
        .find(|group| group.name == group_name)
        .ok_or_else(|| unknown_admin_topic(group_name))?;
    let mut output = format!(
        "Camellia Nexus License Administration — {}\n{}\n{}\n\nUSAGE / 用法:\n  {BINARY_NAME} admin {} <operation> [options]\n\nOPERATIONS / 操作:\n",
        group.name, group.summary_en, group.summary_zh, group.name,
    );
    for command in ADMIN_COMMANDS
        .iter()
        .filter(|command| command.group == group.name)
    {
        let _ = writeln!(
            output,
            "  {:<29} {} / {}",
            command.name, command.summary_en, command.summary_zh
        );
    }
    let _ = write!(
        output,
        "\nRun `{BINARY_NAME} admin {} <operation> --help` for operation details.\n执行 `{BINARY_NAME} admin {} <operation> --help` 查看操作详情。\n",
        group.name, group.name,
    );
    Ok(output)
}

fn render_admin_command(group: &str, name: &str) -> Result<String, String> {
    let Some(command) = ADMIN_COMMANDS
        .iter()
        .find(|command| command.group == group && command.name == name)
    else {
        return render_admin_subgroup(group, name);
    };
    let mut output = format!(
        "Camellia Nexus License Administration — {} {}\n{}\n{}\n\nUSAGE / 用法:\n  {BINARY_NAME} admin [--human|--raw] {}\n",
        command.group, command.name, command.summary_en, command.summary_zh, command.usage,
    );
    if !command.options.is_empty() {
        output.push_str("\nOPTIONS / 选项:\n");
        for option_name in command.options {
            let option = HELP_OPTIONS
                .iter()
                .find(|option| option.name == *option_name)
                .expect("admin command help references a known option");
            let _ = writeln!(
                output,
                "  --{:<17} {:<24} {}\n  {:<19} {:<24} {}",
                option.name, option.value, option.summary_en, "", "", option.summary_zh,
            );
        }
    }
    let _ = write!(
        output,
        "\nCOMMON OPTIONS / 通用选项:\n  --human | --raw | --output <human|raw>\n  -h, --help\n\nEXAMPLE / 示例:\n  {BINARY_NAME} admin {}\n",
        command.example,
    );
    Ok(output)
}

fn render_admin_subgroup(group: &str, prefix: &str) -> Result<String, String> {
    let prefix_with_separator = format!("{prefix} ");
    let operations = ADMIN_COMMANDS
        .iter()
        .filter(|command| {
            command.group == group && command.name.starts_with(&prefix_with_separator)
        })
        .collect::<Vec<_>>();
    if operations.is_empty() {
        return Err(unknown_admin_topic(&format!("{group} {prefix}")));
    }
    let mut output = format!(
        "Camellia Nexus License Administration — {group} {prefix}\n\nUSAGE / 用法:\n  {BINARY_NAME} admin {group} {prefix} <operation> [options]\n\nOPERATIONS / 操作:\n"
    );
    for command in operations {
        let leaf = command
            .name
            .strip_prefix(&prefix_with_separator)
            .expect("subgroup command starts with its prefix");
        let _ = writeln!(
            output,
            "  {:<24} {} / {}",
            leaf, command.summary_en, command.summary_zh
        );
    }
    let _ = write!(
        output,
        "\nRun `{BINARY_NAME} admin {group} {prefix} <operation> --help` for operation details.\n执行 `{BINARY_NAME} admin {group} {prefix} <operation> --help` 查看操作详情。\n"
    );
    Ok(output)
}

fn unknown_admin_topic(topic: &str) -> String {
    format!("unknown admin help topic: {topic} / 未知的 Admin 帮助主题：{topic}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_every_top_level_runtime_help_without_configuration() {
        assert!(root_help().contains("admin-worker --help"));
        assert!(serve_help().contains("CAMELLIA_NEXUS_LICENSE_BIND"));
        for command in ["migrate", "healthcheck", "admin-web", "admin-worker"] {
            let help = runtime_help(command).expect("declared runtime help must render");
            assert!(help.contains(&format!("— {command}")));
            assert!(help.contains("USAGE / 用法:"));
        }
        assert!(runtime_help("unknown").is_err());
    }

    #[test]
    fn renders_bilingual_root_group_and_operation_help() {
        let root = admin_help(&[]).unwrap();
        assert!(root.contains("COMMAND GROUPS / 命令组"));
        assert!(root.contains("without connecting to PostgreSQL"));

        let group = admin_help(&["code".into()]).unwrap();
        assert!(group.contains("issue"));
        assert!(group.contains("签发和管理激活授权码"));

        let operation = admin_help(&["code".into(), "issue".into()]).unwrap();
        assert!(operation.contains("--operation-id"));
        assert!(operation.contains("明文只显示一次"));

        let nested = admin_help(&["billing".into(), "payment".into(), "approve".into()]).unwrap();
        assert!(nested.contains("--allow-amount-override"));
        assert!(nested.contains("--row-version"));

        let recovery = admin_help(&["operator".into(), "recover-owner".into()]).unwrap();
        assert!(recovery.contains("--confirm"));
    }

    #[test]
    fn rejects_unknown_or_over_nested_help_topics() {
        assert!(admin_help(&["unknown".into()]).is_err());
        assert!(admin_help(&["code".into(), "issue".into(), "extra".into()]).is_err());
    }

    #[test]
    fn every_declared_operation_has_complete_renderable_help() {
        for command in ADMIN_COMMANDS {
            let mut topic = vec![command.group.to_owned()];
            topic.extend(command.name.split_ascii_whitespace().map(str::to_owned));
            let help = admin_help(&topic).expect("declared operation help must render");
            assert!(help.contains(command.usage));
            for option in command.options {
                assert!(
                    HELP_OPTIONS
                        .iter()
                        .any(|candidate| candidate.name == *option),
                    "missing help definition for --{option}"
                );
                assert!(help.contains(&format!("--{option}")));
            }
        }
    }

    #[test]
    fn canonicalizes_nested_help_before_positional_arguments() {
        assert_eq!(
            canonical_admin_help_topic(&[
                "billing".into(),
                "payment".into(),
                "approve".into(),
                "claim_001".into(),
            ]),
            ["billing", "payment", "approve"]
        );
        assert_eq!(
            canonical_admin_help_topic(&["billing".into(), "payment".into()]),
            ["billing", "payment"]
        );
        assert_eq!(
            canonical_admin_help_topic(&["license".into(), "show".into(), "lic_001".into()]),
            ["license", "show"]
        );
    }
}
