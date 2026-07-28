#!/usr/bin/env node

import { readFileSync, statSync, writeSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const currentIsClient = isFile(resolve(scriptRoot, 'crates/camellia-nexus-licensing/src/license_api.rs'));
const currentIsServer = isFile(resolve(scriptRoot, 'src/contracts.rs'));
if (currentIsClient === currentIsServer) fail('run this script from exactly one Camellia Nexus repository');

const siblingArgument = process.argv[2];
if (process.argv.length > 3 || siblingArgument === '--help' || siblingArgument === '-h') {
  console.log('Usage: node scripts/check-cross-repo-contract.mjs [sibling-repository]');
  process.exit(siblingArgument === '--help' || siblingArgument === '-h' ? 0 : 2);
}

const sibling = resolve(
  scriptRoot,
  siblingArgument ?? (currentIsClient ? '../nexus-management-server' : '../nexus')
);
const clientRoot = currentIsClient ? scriptRoot : sibling;
const serverRoot = currentIsServer ? scriptRoot : sibling;
const siblingScript = resolve(sibling, 'scripts/check-cross-repo-contract.mjs');
if (!isFile(siblingScript)) fail(`sibling contract checker is missing: ${siblingScript}`);
if (readFileSync(fileURLToPath(import.meta.url), 'utf8') !== readFileSync(siblingScript, 'utf8')) {
  fail('the client and server contract checkers differ; update them in one coordinated change');
}
const clientSemanticsPath = resolve(clientRoot, 'scripts/public-api-semantics.json');
const serverSemanticsPath = resolve(serverRoot, 'scripts/public-api-semantics.json');
if (!isFile(clientSemanticsPath) || !isFile(serverSemanticsPath)) {
  fail('both repositories must contain scripts/public-api-semantics.json');
}
const clientSemantics = readFileSync(clientSemanticsPath, 'utf8');
const serverSemantics = readFileSync(serverSemanticsPath, 'utf8');
if (clientSemantics !== serverSemantics) {
  fail('the client and server public API semantic manifests differ');
}
let semanticManifest;
try {
  semanticManifest = JSON.parse(clientSemantics);
} catch (error) {
  fail(`the public API semantic manifest is invalid JSON: ${error.message}`);
}
const clientApiPath = resolve(clientRoot, 'crates/camellia-nexus-licensing/src/license_api.rs');
const serverContractPaths = [
  'src/contracts.rs',
  'src/billing.rs',
  'src/team.rs',
  'src/workspace.rs',
  'src/webhooks.rs'
].map((path) => resolve(serverRoot, path));
for (const path of [clientApiPath, ...serverContractPaths, resolve(serverRoot, 'src/http.rs')]) {
  if (!isFile(path)) fail(`required contract source is missing: ${path}`);
}

const clientApi = readFileSync(clientApiPath, 'utf8');
const serverSources = serverContractPaths.map((path) => readFileSync(path, 'utf8')).join('\n');
const aliases = new Map([
  ['WorkspaceWebhookEndpoint', 'WebhookEndpoint'],
  ['CreateWorkspaceWebhookEndpoint', 'CreateWebhookEndpoint'],
  ['UpdateWorkspaceWebhookEndpoint', 'UpdateWebhookEndpoint'],
  ['RotateWorkspaceWebhookSecret', 'RotateWebhookSecret'],
  ['DeleteWorkspaceWebhookEndpoint', 'DeleteWebhookEndpoint'],
  ['WorkspaceWebhookSecretResult', 'WebhookSecretResult'],
  ['WorkspaceWebhookDeletion', 'WebhookDeletion'],
  ['WorkspaceWebhookDeliveryStatus', 'WebhookDeliveryStatus'],
  ['WorkspaceWebhookDelivery', 'WebhookDeliverySummary']
]);
const reverseAliases = new Map([...aliases].map(([client, server]) => [server, client]));
const clientTypes = extractWireTypes(clientApi);
const serverTypes = extractWireTypes(serverSources);
const differences = [];

for (const [clientName, clientSignature] of clientTypes) {
  if (clientName === 'HttpLicenseApi') continue;
  const serverName = aliases.get(clientName) ?? clientName;
  const serverSignature = serverTypes.get(serverName);
  if (!serverSignature) {
    differences.push(`${clientName}: provider type ${serverName} is missing`);
    continue;
  }
  const normalizedClient = normalizeSignature(clientSignature);
  const normalizedServer = normalizeSignature(serverSignature);
  if (normalizedClient !== normalizedServer) {
    differences.push(
      `${clientName}:\n  client ${normalizedClient}\n  server ${normalizedServer}`
    );
  }
}

const serverRoutes = extractServerRoutes(readFileSync(resolve(serverRoot, 'src/http.rs'), 'utf8'));
const clientRoutes = extractClientRoutes(clientApi);
compareSets('public route', clientRoutes, serverRoutes, differences);
validateSemanticManifest(semanticManifest, clientRoot, serverRoot, clientRoutes, serverRoutes, differences);

const serverErrors = extractServerErrors(readFileSync(resolve(serverRoot, 'src/error.rs'), 'utf8'));
const clientErrors = extractClientErrors(clientApi);
for (const code of clientErrors) {
  if (!serverErrors.has(code) && code !== 'request_too_large') {
    differences.push(`client maps an error code the provider does not define: ${code}`);
  }
}
const genericServerErrors = new Set([
  'database',
  'database_schema_not_ready',
  'internal',
  'signing_key_unavailable',
  'time_authority_unavailable'
]);
for (const code of serverErrors) {
  if (!clientErrors.has(code) && !genericServerErrors.has(code)) {
    differences.push(`client does not map the provider business error code: ${code}`);
  }
}

if (differences.length) fail(`public contract drift detected:\n${differences.join('\n')}`);
console.log(
  `Cross-repository public contract is aligned: ${clientTypes.size - 1} wire types, ${clientRoutes.size} method/path pairs, ${semanticManifest.proofScopes.length} proof scopes, ${clientErrors.size} business errors.`
);

function validateSemanticManifest(manifest, clientRoot, serverRoot, clientRoutes, serverRoutes, differences) {
  if (!manifest || manifest.schemaVersion !== 1) {
    differences.push('semantic manifest schemaVersion must be 1');
    return;
  }
  if (!Array.isArray(manifest.routes) || !Array.isArray(manifest.proofScopes)) {
    differences.push('semantic manifest routes and proofScopes must be arrays');
    return;
  }
  const semanticRoutes = new Set(manifest.routes);
  if (semanticRoutes.size !== manifest.routes.length) {
    differences.push('semantic manifest routes contain duplicates');
  }
  if (JSON.stringify(manifest.routes) !== JSON.stringify([...manifest.routes].sort())) {
    differences.push('semantic manifest routes must be sorted');
  }
  compareSets('semantic route/client implementation', semanticRoutes, clientRoutes, differences);
  compareSets('semantic route/server implementation', semanticRoutes, serverRoutes, differences);

  const clientProtocol = [
    'crates/camellia-nexus-licensing/src/auth_client.rs',
    'crates/camellia-nexus-licensing/src/device_identity.rs',
    'crates/camellia-nexus-licensing/src/license_api.rs',
    'crates/camellia-nexus-licensing/src/service.rs'
  ].map((path) => readFileSync(resolve(clientRoot, path), 'utf8')).join('\n');
  const serverProtocol = [
    'src/http.rs',
    'src/service.rs',
    'src/team.rs',
    'src/webhooks.rs',
    'src/workspace.rs'
  ].map((path) => readFileSync(resolve(serverRoot, path), 'utf8')).join('\n');

  requireSemanticValue(clientProtocol, manifest.oauthScope, 'client OAuth scope', differences);
  requireSemanticValue(serverProtocol, manifest.oauthScope, 'server OAuth scope', differences);
  requireSemanticValue(clientProtocol, manifest.deviceProofHeader, 'client device-proof header', differences);
  requireSemanticValue(serverProtocol, manifest.deviceProofHeader, 'server device-proof header', differences);
  requireSemanticValue(serverProtocol, 'DEVICE_PROOF_HEADER_MAX_BYTES: usize = 4 * 1024', 'server device-proof header limit', differences);
  requireSemanticValue(serverProtocol, 'DefaultBodyLimit::max(64 * 1024)', 'server default JSON body limit', differences);
  requireSemanticValue(serverProtocol, 'CONFIGURATION_HTTP_BODY_LIMIT: usize = 8 * 1024 * 1024 + 64 * 1024', 'workspace configuration body limit', differences);
  requireSemanticValue(serverProtocol, 'MAX_DEVICE_PAGE_SIZE: u32 = 100', 'device page limit', differences);
  requireSemanticValue(clientProtocol, 'MAX_TEAM_MEMBER_PAGE_SIZE: u32 = 200', 'client Team member page limit', differences);
  requireSemanticValue(serverProtocol, 'MAX_MEMBER_PAGE_SIZE: u32 = 200', 'server Team member page limit', differences);
  requireSemanticValue(serverProtocol, 'MAX_PAGE_SIZE: u32 = 200', 'server workspace page limit', differences);

  const fixedValues = [
    [manifest.deviceProofHeaderMaxBytes, 4096, 'deviceProofHeaderMaxBytes'],
    [manifest.defaultJsonBodyMaxBytes, 65536, 'defaultJsonBodyMaxBytes'],
    [manifest.workspaceConfigurationBodyMaxBytes, 8454144, 'workspaceConfigurationBodyMaxBytes'],
    [manifest.pageLimits?.devices, 100, 'pageLimits.devices'],
    [manifest.pageLimits?.teamMembers, 200, 'pageLimits.teamMembers'],
    [manifest.pageLimits?.workspace, 200, 'pageLimits.workspace']
  ];
  for (const [actual, expected, label] of fixedValues) {
    if (actual !== expected) differences.push(`semantic manifest ${label} must be ${expected}`);
  }
  if (manifest.mutationIdentity?.field !== 'operationId'
      || manifest.mutationIdentity?.format !== 'canonical-rfc4122-uuid-v4'
      || manifest.mutationIdentity?.conflictError !== 'idempotency_conflict') {
    differences.push('semantic manifest mutation identity contract is incomplete');
  } else {
    requireSemanticValue(clientProtocol, manifest.mutationIdentity.conflictError, 'client idempotency-conflict mapping', differences);
    requireSemanticValue(serverProtocol, manifest.mutationIdentity.conflictError, 'server idempotency-conflict mapping', differences);
  }
  if (manifest.optimisticConcurrency?.field !== 'rowVersion'
      || manifest.optimisticConcurrency?.conflictError !== 'workspace_version_conflict') {
    differences.push('semantic manifest optimistic-concurrency contract is incomplete');
  } else {
    requireSemanticValue(clientProtocol, manifest.optimisticConcurrency.conflictError, 'client version-conflict mapping', differences);
    requireSemanticValue(serverProtocol, manifest.optimisticConcurrency.conflictError, 'server version-conflict mapping', differences);
  }
  if (manifest.teamLeaveRecovery?.path !== 'GET /v1/team/operations/{operation_id}'
      || manifest.teamLeaveRecovery?.command !== 'leave_workspace'
      || JSON.stringify(manifest.teamLeaveRecovery?.bindings) !== JSON.stringify(['operationId', 'memberId', 'rowVersion'])
      || manifest.teamLeaveRecovery?.session !== 'exact-original') {
    differences.push('semantic manifest Team leave recovery contract is incomplete');
  } else {
    if (!semanticRoutes.has(manifest.teamLeaveRecovery.path)) {
      differences.push('semantic manifest Team leave recovery route is missing');
    }
    requireSemanticValue(clientProtocol, '.append_pair("memberId"', 'client Team leave member binding', differences);
    requireSemanticValue(clientProtocol, '.append_pair("rowVersion"', 'client Team leave row-version binding', differences);
    requireSemanticValue(serverProtocol, manifest.teamLeaveRecovery.command, 'server Team leave command binding', differences);
    requireSemanticValue(serverProtocol, '.ct_eq(request_hash.as_bytes())', 'server Team leave request-hash binding', differences);
    requireSemanticValue(serverProtocol, '.ct_eq(requester_session_hash.as_bytes())', 'server Team leave session binding', differences);
  }

  const scopeValues = new Set();
  for (const scope of manifest.proofScopes) {
    if (!scope || typeof scope.value !== 'string' || typeof scope.clientConstructs !== 'boolean') {
      differences.push('semantic manifest proof scope entries require value and clientConstructs');
      continue;
    }
    if (scopeValues.has(scope.value)) differences.push(`semantic manifest proof scope is duplicated: ${scope.value}`);
    scopeValues.add(scope.value);
    requireSemanticValue(serverProtocol, scope.value, `server proof scope ${scope.value}`, differences);
    if (scope.clientConstructs) {
      requireSemanticValue(clientProtocol, scope.value, `client proof scope ${scope.value}`, differences);
    }
  }
}

function requireSemanticValue(source, value, label, differences) {
  if (typeof value !== 'string' || !value || !source.includes(value)) {
    differences.push(`${label} does not match the semantic manifest`);
  }
}

function extractWireTypes(source) {
  const declarations = new Map();
  const pattern = /^pub (struct|enum) ([A-Za-z][A-Za-z0-9_]*)\s*\{/gm;
  for (const match of source.matchAll(pattern)) {
    const open = match.index + match[0].lastIndexOf('{');
    const close = matchingDelimiter(source, open, '{', '}');
    const prefix = source.slice(Math.max(0, source.lastIndexOf('\n\n', match.index)), match.index);
    const rename = prefix.match(/#\[serde\([^\]]*rename_all\s*=\s*"([^"]+)"[^\]]*\)\]/)?.[1];
    const body = source.slice(open + 1, close);
    declarations.set(
      match[2],
      match[1] === 'struct'
        ? structSignature(body, rename)
        : enumSignature(body, rename)
    );
  }
  return declarations;
}

function structSignature(body, renameAll) {
  const fields = [];
  for (const raw of splitTopLevel(stripComments(body), ',')) {
    const field = raw.trim();
    if (!field) continue;
    const match = field.match(/^(?<attrs>(?:#\[[^\]]+\]\s*)*)pub\s+(?<name>[A-Za-z0-9_]+)\s*:\s*(?<type>[\s\S]+)$/);
    if (!match) continue;
    const attrs = match.groups.attrs;
    if (/#\[serde\([^\]]*\bskip\b[^\]]*\)\]/.test(attrs)) continue;
    const explicit = attrs.match(/#\[serde\([^\]]*\brename\s*=\s*"([^"]+)"[^\]]*\)\]/)?.[1];
    const name = explicit ?? renamed(match.groups.name, renameAll, false);
    const type = normalizeType(match.groups.type);
    fields.push(/#\[serde\([^\]]*\bflatten\b[^\]]*\)\]/.test(attrs) ? `...${type}` : `${name}:${type}`);
  }
  return `struct{${fields.join(',')}}`;
}

function enumSignature(body, renameAll) {
  const variants = [];
  for (const raw of splitTopLevel(stripComments(body), ',')) {
    const variant = raw.replace(/#\[[^\]]+\]/g, '').trim();
    if (!variant) continue;
    const match = variant.match(/^([A-Za-z][A-Za-z0-9_]*)([\s\S]*)$/);
    if (!match) continue;
    variants.push(`${renamed(match[1], renameAll, true)}${normalizeType(match[2])}`);
  }
  return `enum{${variants.join(',')}}`;
}

function normalizeSignature(signature) {
  let normalized = signature;
  for (const [server, client] of reverseAliases) {
    normalized = normalized.replace(new RegExp(`\\b${server}\\b`, 'g'), client);
  }
  return normalized.replaceAll('OneTimeWebhookSecret', 'SecretValue');
}

function normalizeType(type) {
  return type
    .replaceAll('crate::', '')
    .replaceAll('rust_decimal::', '')
    .replace(/\bDecimal\b/g, 'String')
    .replace(/\s+/g, '');
}

function renamed(value, style, variant) {
  if (!style) return value;
  const words = variant
    ? value.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase().split('_')
    : value.split('_');
  if (style === 'snake_case') return words.join('_');
  if (style === 'camelCase') return words[0] + words.slice(1).map(capitalize).join('');
  throw new Error(`unsupported serde rename_all style: ${style}`);
}

function capitalize(value) {
  return value ? value[0].toUpperCase() + value.slice(1) : value;
}

function extractServerRoutes(source) {
  const routerStart = source.indexOf('pub fn router(');
  const routerEnd = source.indexOf('\nasync fn healthz', routerStart);
  if (routerStart < 0 || routerEnd < 0) fail('could not locate the public Axum router');
  const router = source.slice(routerStart, routerEnd);
  const routes = new Set();
  let cursor = 0;
  while ((cursor = router.indexOf('.route(', cursor)) >= 0) {
    const open = cursor + '.route'.length;
    const close = matchingDelimiter(router, open, '(', ')');
    const args = splitTopLevel(router.slice(open + 1, close), ',');
    const path = args[0]?.trim().match(/^"([^"]+)"$/)?.[1];
    if (path?.startsWith('/v1/')) {
      for (const method of args.slice(1).join(',').matchAll(/\b(get|post|patch|delete)\s*\(/g)) {
        routes.add(`${method[1].toUpperCase()} ${path}`);
      }
    }
    cursor = close + 1;
  }
  return routes;
}

function extractClientRoutes(source) {
  const implementation = source.indexOf('impl LicenseApi for HttpLicenseApi');
  if (implementation < 0) fail('could not locate the HTTP license client implementation');
  const routes = new Set();
  const functionPattern = /async fn [A-Za-z0-9_]+\s*\([^)]*\)[^{]*\{/g;
  functionPattern.lastIndex = implementation;
  for (let match; (match = functionPattern.exec(source)); ) {
    const open = match.index + match[0].lastIndexOf('{');
    const close = matchingDelimiter(source, open, '{', '}');
    const body = source.slice(open + 1, close);
    const path =
      body.match(/endpoint\s*\(\s*"(v1\/[^"]+)"/)?.[1] ??
      body.match(/format!\s*\(\s*"(v1\/[^"]+)"/)?.[1];
    if (!path) {
      functionPattern.lastIndex = close + 1;
      continue;
    }
    const method =
      body.match(/reqwest::Method::(GET|POST|PATCH|DELETE)/)?.[1] ??
      body.match(/\.client\s*\.\s*(get|post|patch|delete)\s*\(/)?.[1]?.toUpperCase();
    if (!method) fail(`could not determine HTTP method for ${path}`);
    routes.add(`${method} /${path}`);
    functionPattern.lastIndex = close + 1;
  }
  return routes;
}

function extractServerErrors(source) {
  const start = source.indexOf('pub fn code(&self)');
  const end = source.indexOf('\n    fn status(&self)', start);
  if (start < 0 || end < 0) fail('could not locate provider error codes');
  return new Set([...source.slice(start, end).matchAll(/=>\s*"([a-z0-9_]+)"/g)].map((match) => match[1]));
}

function extractClientErrors(source) {
  const start = source.indexOf('\nfn service_error(');
  const end = source.indexOf('\nfn is_loopback_http', start);
  if (start < 0 || end < 0) fail('could not locate client error mappings');
  return new Set([...source.slice(start, end).matchAll(/"([a-z0-9_]+)"\)\s*=>/g)].map((match) => match[1]));
}

function compareSets(label, left, right, differences) {
  for (const value of left) if (!right.has(value)) differences.push(`${label} exists only in client: ${value}`);
  for (const value of right) if (!left.has(value)) differences.push(`${label} exists only in server: ${value}`);
}

function splitTopLevel(value, delimiter) {
  const parts = [];
  let start = 0;
  let string = false;
  let escaped = false;
  const depths = { '(': 0, '[': 0, '{': 0, '<': 0 };
  const closing = { ')': '(', ']': '[', '}': '{', '>': '<' };
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (string) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') string = false;
      continue;
    }
    if (character === '"') {
      string = true;
      continue;
    }
    if (character in depths) depths[character] += 1;
    else if (character in closing) depths[closing[character]] -= 1;
    else if (character === delimiter && Object.values(depths).every((depth) => depth === 0)) {
      parts.push(value.slice(start, index));
      start = index + 1;
    }
  }
  parts.push(value.slice(start));
  return parts;
}

function matchingDelimiter(source, open, opening, closing) {
  let depth = 0;
  let string = false;
  let escaped = false;
  for (let index = open; index < source.length; index += 1) {
    const character = source[index];
    if (string) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') string = false;
      continue;
    }
    if (character === '"') string = true;
    else if (character === opening) depth += 1;
    else if (character === closing && --depth === 0) return index;
  }
  fail(`unterminated ${opening} at source offset ${open}`);
}

function stripComments(source) {
  return source.replace(/\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
}

function isFile(path) {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

function fail(message) {
  writeSync(2, `${message}\n`);
  process.exit(1);
}
