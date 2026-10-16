'use strict';

// Recover legacy Gateway Capture files without rewriting the original failed
// evidence.  The current Relay validates body byte counts and hashes against
// the bytes it receives; older Gateway versions kept the pre-redaction proof
// in those fields.  This command creates a new, auditable pending copy with
// metadata reconciled to the retained (possibly redacted) body and with
// protocol-observed Session/Turn context restored when it is unambiguous.

const fs = require('node:fs');
const fsp = fs.promises;
const path = require('node:path');
const crypto = require('node:crypto');
const {
  codexTraceContextFromHeaders,
  reconcileCaptureBodyMetadata,
} = require('../../integrations/openai-gateway/durable-outbox');

const CAPTURE_ID_RE = /^cap-[A-Za-z0-9._:-]+$/;
const RECOVERY_SCHEMA_VERSION = 'chiptrace.failed-outbox-recovery.v1';
const DEFAULT_MAX_BYTES = 1024 * 1024 * 1024;
const RECOVERY_CAPTURE_PREFIX = 'cap-replay-';

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function captureFileName(captureId) {
  if (Buffer.byteLength(`${captureId}.json`, 'utf8') <= 240) return `${captureId}.json`;
  return `${captureId.slice(0, 80)}-${sha256(Buffer.from(captureId, 'utf8'))}.json`;
}

// A normalized replay can differ from the bytes that an older Gateway sent
// under the original Capture ID. Reusing that ID would make the Relay return
// a permanent 409 conflict, so derive a deterministic new ID from both the
// original identity and the immutable failed-file hash. The original ID is
// retained in outboxRecovery for audit and Session joins still use traceContext.
function recoveryCaptureId(originalCaptureId, originalFailedFileSha256) {
  const digest = sha256(Buffer.from(
    `${originalCaptureId}\u0000${originalFailedFileSha256}`,
    'utf8',
  ));
  return `${RECOVERY_CAPTURE_PREFIX}${digest}`;
}

function parsePositiveInteger(value, name) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return parsed;
}

function parseArgs(argv) {
  const options = {
    root: process.env.FULL_TRACE_CAPTURE_OUTBOX_DIR || '/capture-outbox',
    apply: false,
    limit: Number.POSITIVE_INFINITY,
    maxBytes: DEFAULT_MAX_BYTES,
    captureIds: null,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    const next = () => {
      if (index + 1 >= argv.length) throw new Error(`${argument} requires a value`);
      index += 1;
      return argv[index];
    };
    if (argument === '--root') options.root = path.resolve(next());
    else if (argument === '--apply') options.apply = true;
    else if (argument === '--dry-run') options.apply = false;
    else if (argument === '--limit') options.limit = parsePositiveInteger(next(), '--limit');
    else if (argument === '--max-bytes') options.maxBytes = parsePositiveInteger(next(), '--max-bytes');
    else if (argument === '--capture-id') {
      const captureId = next();
      (options.captureIds ||= new Set()).add(captureId);
    } else if (argument === '--help' || argument === '-h') {
      options.help = true;
    } else {
      throw new Error(`unknown argument: ${argument}`);
    }
  }
  return options;
}

function usage() {
  return [
    'Usage: node scripts/ops/replay-failed-outbox.js [options]',
    '',
    'Defaults to a dry-run. --apply atomically copies normalized records to pending/.',
    'The failed/ source files and their .error.json markers are never moved or deleted.',
    '',
    'Options:',
    '  --root <dir>          Gateway outbox root (default: FULL_TRACE_CAPTURE_OUTBOX_DIR)',
    '  --apply               Create pending copies after validation',
    '  --dry-run             Inspect only (the default)',
    '  --limit <n>           Process at most n failed records',
    '  --max-bytes <n>       Refuse records larger than n bytes',
    '  --capture-id <id>     Restrict processing; may be repeated',
  ].join('\n');
}

async function listFailedRecords(directory, captureIds, limit) {
  const entries = await fsp.readdir(directory, { withFileTypes: true });
  const records = entries
    .filter(entry => entry.isFile() && entry.name.endsWith('.json') && !entry.name.endsWith('.error.json'))
    .map(entry => path.join(directory, entry.name))
    .sort();
  const selected = [];
  for (const file of records) {
    if (selected.length >= limit) break;
    const name = path.basename(file, '.json');
    if (captureIds && !captureIds.has(name)) continue;
    selected.push(file);
  }
  return selected;
}

async function readOptionalJson(file) {
  try {
    return JSON.parse(await fsp.readFile(file, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

function appendUniqueEvidence(existing, additions) {
  const output = Array.isArray(existing) ? [...existing] : [];
  const seen = new Set(output.map(item => JSON.stringify(item)));
  for (const item of additions) {
    const key = JSON.stringify(item);
    if (!seen.has(key)) {
      seen.add(key);
      output.push(item);
    }
  }
  return output;
}

function deriveRecoveryRecord(record, originalBytes, failureReason, now, originalFailedFileName) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    return { blocked: 'record is not a JSON object' };
  }
  const captureId = typeof record.captureId === 'string' ? record.captureId : '';
  if (!CAPTURE_ID_RE.test(captureId) || Buffer.byteLength(captureId, 'utf8') > 256) {
    return { blocked: 'captureId is invalid' };
  }
  const originalFailedFileSha256 = sha256(originalBytes);
  const replayCaptureId = recoveryCaptureId(captureId, originalFailedFileSha256);
  const context = codexTraceContextFromHeaders(record.requestHeaders, record.responseHeaders);
  if (context.errors.length > 0) {
    return { blocked: `protocol context parse error: ${context.errors.join('; ')}` };
  }
  const existingTrace = record.traceContext && typeof record.traceContext === 'object'
    && !Array.isArray(record.traceContext) ? record.traceContext : {};
  const mergedTrace = { ...existingTrace };
  const addedFields = [];
  for (const [field, value] of Object.entries(context.trace)) {
    if (mergedTrace[field] !== undefined && JSON.stringify(mergedTrace[field]) !== JSON.stringify(value)) {
      return { blocked: `protocol identity conflict for traceContext.${field}` };
    }
    if (mergedTrace[field] === undefined) {
      mergedTrace[field] = value;
      addedFields.push(field);
    }
  }
  const existingConflicts = Array.isArray(record.fieldEvidenceConflicts)
    ? record.fieldEvidenceConflicts.filter(item => String(item?.field || '').startsWith('traceContext.'))
    : [];
  if (existingConflicts.length > 0) {
    return { blocked: 'record already contains a trace identity conflict' };
  }

  const reconciled = reconcileCaptureBodyMetadata(record);
  const normalized = {
    ...reconciled.record,
    captureId: replayCaptureId,
    traceContext: mergedTrace,
    fieldEvidence: appendUniqueEvidence(record.fieldEvidence, context.evidence),
    outboxRecovery: {
      schema_version: RECOVERY_SCHEMA_VERSION,
      original_capture_id: captureId,
      replay_capture_id: replayCaptureId,
      original_failed_file_name: originalFailedFileName || captureFileName(captureId),
      original_failed_file_sha256: originalFailedFileSha256,
      original_failure_reason: failureReason || null,
      normalized_at: now,
      body_metadata_reconciled: reconciled.changed,
      trace_context_fields_added: addedFields,
    },
  };
  const bytes = Buffer.from(`${JSON.stringify(normalized)}\n`, 'utf8');
  return {
    captureId: replayCaptureId,
    originalCaptureId: captureId,
    replayCaptureId,
    record: normalized,
    bytes,
    bodyMetadataReconciled: reconciled.changed,
    traceContextFieldsAdded: addedFields,
  };
}

async function fsyncDirectory(directory) {
  let handle;
  try {
    handle = await fsp.open(directory, 'r');
    await handle.sync();
  } catch (error) {
    if (!['EINVAL', 'EISDIR', 'ENOTSUP', 'EPERM'].includes(error.code)) throw error;
  } finally {
    await handle?.close();
  }
}

async function atomicCreate(file, bytes) {
  const temporary = `${file}.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}.tmp`;
  let handle;
  try {
    handle = await fsp.open(temporary, 'wx', 0o600);
    await handle.writeFile(bytes);
    await handle.sync();
  } finally {
    await handle?.close();
  }
  try {
    await fsp.link(temporary, file);
  } catch (error) {
    try { await fsp.unlink(temporary); } catch (cleanupError) {
      if (cleanupError.code !== 'ENOENT') throw cleanupError;
    }
    throw error;
  }
  await fsp.unlink(temporary);
  await fsyncDirectory(path.dirname(file));
}

async function inspectTarget(target, bytes, originalFailedSha256 = null, captureId = null) {
  try {
    const existing = await fsp.readFile(target);
    if (sha256(existing) === sha256(bytes)) return { state: 'already_present' };
    // A repeat invocation intentionally gets a new wall-clock timestamp in
    // outboxRecovery.normalized_at.  The immutable source hash is the stable
    // idempotency key; require the schema and Capture identity as well.
    try {
      const parsed = JSON.parse(existing.toString('utf8'));
      if (parsed.captureId === captureId
        && parsed.outboxRecovery?.schema_version === RECOVERY_SCHEMA_VERSION
        && parsed.outboxRecovery?.original_failed_file_sha256 === originalFailedSha256) {
        return { state: 'already_present' };
      }
    } catch {
      // A malformed or unrelated pending file remains a hard conflict.
    }
    return { state: 'target_conflict' };
  } catch (error) {
    if (error.code === 'ENOENT') return { state: 'absent' };
    throw error;
  }
}

async function replayFailedOutbox({
  root,
  apply = false,
  limit = Number.POSITIVE_INFINITY,
  maxBytes = DEFAULT_MAX_BYTES,
  captureIds = null,
  now = new Date().toISOString(),
}) {
  const absoluteRoot = path.resolve(root);
  const failed = path.join(absoluteRoot, 'failed');
  const pending = path.join(absoluteRoot, 'pending');
  await fsp.mkdir(pending, { recursive: true, mode: 0o700 });
  const files = await listFailedRecords(failed, captureIds, limit);
  const report = {
    schema_version: 'chiptrace.failed-outbox-replay-report.v1',
    mode: apply ? 'apply' : 'dry_run',
    selected: files.length,
    planned: 0,
    copied: 0,
    already_present: 0,
    blocked: 0,
    records: [],
  };
  for (const file of files) {
    const baseName = path.basename(file, '.json');
    let originalBytes;
    let item;
    try {
      const stat = await fsp.stat(file);
      if (stat.size > maxBytes) throw new Error(`record exceeds --max-bytes (${maxBytes})`);
      originalBytes = await fsp.readFile(file);
      const record = JSON.parse(originalBytes.toString('utf8'));
      const marker = await readOptionalJson(`${file}.error.json`);
      item = deriveRecoveryRecord(record, originalBytes, marker?.reason, now, path.basename(file));
    } catch (error) {
      item = { blocked: error.message || String(error) };
    }
    if (item.blocked) {
      report.blocked += 1;
      report.records.push({ capture_id: baseName, state: 'blocked', reason: item.blocked });
      continue;
    }
    const target = path.join(pending, captureFileName(item.captureId));
    const targetState = await inspectTarget(
      target,
      item.bytes,
      sha256(originalBytes),
      item.captureId,
    );
    if (targetState.state === 'target_conflict') {
      report.blocked += 1;
      report.records.push({ capture_id: item.captureId, state: 'blocked', reason: 'pending target differs' });
      continue;
    }
    if (targetState.state === 'already_present') {
      report.already_present += 1;
      report.records.push({ capture_id: item.captureId, state: 'already_present' });
      continue;
    }
    report.planned += 1;
    if (apply) {
      try {
        await atomicCreate(target, item.bytes);
        report.copied += 1;
        report.records.push({
          capture_id: item.captureId,
          original_capture_id: item.originalCaptureId,
          replay_capture_id: item.replayCaptureId,
          state: 'copied',
          bytes: item.bytes.length,
          body_metadata_reconciled: item.bodyMetadataReconciled,
          trace_context_fields_added: item.traceContextFieldsAdded,
        });
      } catch (error) {
        if (error.code === 'EEXIST') {
          const raced = await inspectTarget(
            target,
            item.bytes,
            sha256(originalBytes),
            item.captureId,
          );
          if (raced.state === 'already_present') {
            report.already_present += 1;
            report.records.push({ capture_id: item.captureId, state: 'already_present' });
            continue;
          }
        }
        report.blocked += 1;
        report.records.push({ capture_id: item.captureId, state: 'blocked', reason: error.message || String(error) });
      }
    } else {
      report.records.push({
        capture_id: item.captureId,
        original_capture_id: item.originalCaptureId,
        replay_capture_id: item.replayCaptureId,
        state: 'planned',
        bytes: item.bytes.length,
        body_metadata_reconciled: item.bodyMetadataReconciled,
        trace_context_fields_added: item.traceContextFieldsAdded,
      });
    }
  }
  return report;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    console.log(usage());
    return;
  }
  const report = await replayFailedOutbox(options);
  console.log(JSON.stringify(report, null, 2));
  if (report.blocked > 0) process.exitCode = 1;
}

if (require.main === module) {
  main().catch(error => {
    console.error(error.message || String(error));
    process.exitCode = 1;
  });
}

module.exports = {
  RECOVERY_SCHEMA_VERSION,
  recoveryCaptureId,
  deriveRecoveryRecord,
  replayFailedOutbox,
};
