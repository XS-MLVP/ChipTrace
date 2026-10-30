'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const integrationRoot = __dirname;
const installerPath = path.join(integrationRoot, 'install-patched-codex.sh');
const launcherPatchPath = path.join(integrationRoot, 'patches', 'patched-upstream.patch');
const readmePath = path.join(integrationRoot, 'patches', 'README.md');
const installer = fs.readFileSync(installerPath, 'utf8');
const launcherPatch = fs.readFileSync(launcherPatchPath, 'utf8');
const readme = fs.readFileSync(readmePath, 'utf8');

// Every runtime companion Codex resolves from the package layout. Missing any
// of these keeps the CLI answering prompts while tools silently fail.
const REQUIRED_PACKAGE_PARTS = [
  'codex-package.json',
  'bin/codex',
  'bin/codex-code-mode-host',
  'codex-path/rg',
  'codex-resources/bwrap',
];

test('installer lays down a complete Codex package', () => {
  for (const part of REQUIRED_PACKAGE_PARTS) {
    assert.match(
      installer,
      new RegExp(part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')),
      `installer never installs ${part}, so the patched CLI would be a lone binary`,
    );
  }
  assert.match(installer, /"entrypoint": "bin\/codex"/);
  assert.match(installer, /"pathDir": "codex-path"/);
  assert.match(installer, /"resourcesDir": "codex-resources"/);
});

test('installer refuses to finish when a package part is missing', () => {
  assert.match(installer, /missing_parts\(\)/, 'installer has no completeness check');
  const missingCheckUses = installer.match(/missing="\$\(missing_parts /g) ?? [];
  assert.ok(
    missingCheckUses.length >= 2,
    'completeness must be checked before and after the swap, so a half package is never left live',
  );
  assert.match(installer, /previous install restored|previous one restored|rollback/);
});

test('installer proves the tool runtime actually spawns', () => {
  assert.match(
    installer,
    /succeeded in/,
    'smoke test must assert a command really ran, not just that files exist',
  );
  assert.match(installer, /echo codex-tools-ok/);
  assert.match(
    installer,
    /mkdir -p [^\n]*\$\{?work\}?\/home\/sessions/,
    'smoke test must pre-create sessions/ so the probe cannot leak into the shared session list',
  );
});

test('launcher refuses an incomplete patched package instead of launching it', () => {
  for (const part of REQUIRED_PACKAGE_PARTS.slice(1)) {
    assert.ok(
      launcherPatch.includes(part),
      `launcher patch does not validate ${part}, so a partial install would still be launched`,
    );
  }
  assert.match(launcherPatch, /official package is used/);
  assert.match(launcherPatch, /install-patched-codex\.sh/);
});

test('patch README points at the installer rather than hand-copying a binary', () => {
  assert.match(readme, /install-patched-codex\.sh/);
  assert.match(readme, /failed to spawn code-mode host/);
});
