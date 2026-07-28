#!/usr/bin/env node

import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const rootIsClient = existsSync(join(root, 'crates/camellia-nexus-licensing/src/license_api.rs'));
if (process.argv.length > 3) throw new Error('Usage: node scripts/test-cross-repo-contract.mjs [sibling-repository]');
const sibling = process.argv[2]
  ? resolve(root, process.argv[2])
  : resolve(root, rootIsClient ? '../nexus-management-server' : '../nexus');
const clientSource = rootIsClient ? root : sibling;
const serverSource = rootIsClient ? sibling : root;
const temporary = mkdtempSync(join(tmpdir(), 'camellia-public-contract-'));
const client = join(temporary, 'nexus');
const server = join(temporary, 'nexus-management-server');

try {
  copyFixture(clientSource, client, [
    'crates/camellia-nexus-licensing/src/auth_client.rs',
    'crates/camellia-nexus-licensing/src/device_identity.rs',
    'crates/camellia-nexus-licensing/src/license_api.rs',
    'crates/camellia-nexus-licensing/src/service.rs'
  ]);
  copyFixture(serverSource, server, [
    'src/billing.rs',
    'src/contracts.rs',
    'src/error.rs',
    'src/http.rs',
    'src/service.rs',
    'src/team.rs',
    'src/webhooks.rs',
    'src/workspace.rs'
  ]);
  for (const target of [client, server]) {
    mkdirSync(join(target, 'scripts'), { recursive: true });
    cpSync(join(root, 'scripts/check-cross-repo-contract.mjs'), join(target, 'scripts/check-cross-repo-contract.mjs'));
    cpSync(join(root, 'scripts/public-api-semantics.json'), join(target, 'scripts/public-api-semantics.json'));
  }

  runChecker(client);

  const serverManifestPath = join(server, 'scripts/public-api-semantics.json');
  const originalManifest = readFileSync(serverManifestPath, 'utf8');
  const drifted = JSON.parse(originalManifest);
  drifted.oauthScope = 'drifted.scope';
  writeFileSync(serverManifestPath, `${JSON.stringify(drifted, null, 2)}\n`);
  expectFailure(client, 'public API semantic manifests differ');
  writeFileSync(serverManifestPath, originalManifest);

  for (const target of [client, server]) {
    const manifestPath = join(target, 'scripts/public-api-semantics.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    manifest.routes = manifest.routes.slice(1);
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  }
  expectFailure(client, 'semantic route/client implementation');

  for (const target of [client, server]) {
    const manifestPath = join(target, 'scripts/public-api-semantics.json');
    writeFileSync(manifestPath, originalManifest);
    const manifest = JSON.parse(originalManifest);
    manifest.proofScopes[0].value = 'activation:drifted';
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  }
  expectFailure(client, 'server proof scope activation:drifted');

  for (const target of [client, server]) {
    const manifestPath = join(target, 'scripts/public-api-semantics.json');
    const manifest = JSON.parse(originalManifest);
    manifest.optimisticConcurrency.conflictError = 'version_conflict';
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  }
  expectFailure(client, 'optimistic-concurrency contract is incomplete');

  for (const target of [client, server]) {
    const manifestPath = join(target, 'scripts/public-api-semantics.json');
    const manifest = JSON.parse(originalManifest);
    manifest.teamLeaveRecovery.bindings = ['operationId'];
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  }
  expectFailure(client, 'Team leave recovery contract is incomplete');

  console.log('Cross-repository semantic manifest drift detection verified');
} finally {
  rmSync(temporary, { recursive: true, force: true });
}

function copyFixture(sourceRoot, targetRoot, files) {
  for (const relative of files) {
    const target = join(targetRoot, relative);
    mkdirSync(dirname(target), { recursive: true });
    cpSync(join(sourceRoot, relative), target);
  }
}

function runChecker(clientRoot) {
  return execFileSync(process.execPath, ['scripts/check-cross-repo-contract.mjs'], {
    cwd: clientRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe']
  });
}

function expectFailure(clientRoot, expected) {
  try {
    runChecker(clientRoot);
  } catch (error) {
    const output = `${error.stdout ?? ''}${error.stderr ?? ''}${error.message ?? ''}`;
    if (output.includes(expected)) return;
    throw new Error(`contract checker failed without expected evidence ${JSON.stringify(expected)}:\n${output}`);
  }
  throw new Error(`contract checker unexpectedly accepted mutation ${JSON.stringify(expected)}`);
}
