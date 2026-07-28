# Security policy

## Supported versions

Camellia Nexus is pre-production. Security fixes are made on the default branch and released only
through the managed release workflow. The latest published stable server release is the only
supported production version; operators must deploy its immutable, signed image digest rather than
a mutable tag. Older releases and arbitrary development snapshots do not receive security fixes.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting flow for this repository:
`Security` → `Advisories` → `Report a vulnerability`. Do not disclose a suspected vulnerability,
secret, customer identifier, exploit, or production log in a public issue or pull request. If the
private form is unavailable, open a public issue containing only a request for a private contact
channel.

Include the affected release or commit, component, prerequisites, impact, a minimal reproduction,
and whether exploitation has been observed. Remove credentials, activation codes, session tokens,
private keys, personal data, and payment evidence. The maintainers will coordinate validation,
remediation, release, and disclosure through the private advisory. No response or disclosure SLA is
promised until the project publishes a formal support offering.

## Security boundaries

- PostgreSQL is authoritative for licensing and commercial state. The browser and desktop UI are
  never authorization authorities.
- Production secrets are read from restricted files or the deployment secret store; they must not
  be committed, logged, passed on command lines, or stored in ordinary JSON outside the defined
  encrypted keyring formats.
- Public licensing and private administration listeners require separate ingress policy. The Admin
  listener must remain private and behind authenticated HTTPS ingress.
- Releases are accepted only when tag, commit, version, image labels, immutable digest, provenance,
  SBOM, signature, and public Release records agree.

For active incidents, follow [Incident response](docs/runbooks/incident-response.md). For planned or
emergency secret replacement, follow [Key rotation](docs/runbooks/key-rotation.md).

## 中文摘要

当前仅支持最新稳定版本及其不可变、已签名镜像摘要。请通过仓库的 GitHub 私有漏洞报告入口提交
安全问题；不得在公开 Issue/PR 中包含漏洞细节、密钥、令牌、客户数据、付款证据或生产日志。正在
发生的事件按[事件响应手册](docs/runbooks/incident-response.md)处理，密钥与凭据更换按
[密钥轮换手册](docs/runbooks/key-rotation.md)处理。
