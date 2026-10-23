'use strict';

const http = require('http');
const { URL } = require('url');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { PassThrough } = require('stream');
const FULL_TRACE_OUTBOX_MODULE = process.env.FULL_TRACE_OUTBOX_MODULE || './full_trace_outbox';
const {
  DurableCaptureOutbox,
  ResponsesSseBoundaryTracker,
  codexTraceContextFromHeaders,
  validateProviderCredential,
} = require(FULL_TRACE_OUTBOX_MODULE);

const PORT = Number(process.env.PORT || 3000);
const SUB2API_BASE = (process.env.SUB2API_BASE || 'http://sub2api:8080').replace(/\/$/, '');
const PUBLIC_SUB2API_BASE = (process.env.PUBLIC_SUB2API_BASE || 'http://172.28.11.121:18080').replace(/\/$/, '');
const PUBLIC_SELF_BASE = (process.env.PUBLIC_SELF_BASE || 'http://172.28.11.121:18084').replace(/\/$/, '');
const PUBLIC_DIR = process.env.PUBLIC_DIR || path.join(__dirname, 'public');
const DEFAULT_GROUP_ID = Number(process.env.DEFAULT_GROUP_ID || 3);
const LEGACY_API_ID_MAP = process.env.LEGACY_API_ID_MAP || '/data/legacy-api-id-map.json';
const SUB2API_ADMIN_EMAIL = process.env.SUB2API_ADMIN_EMAIL || '';
const SUB2API_ADMIN_PASSWORD = process.env.SUB2API_ADMIN_PASSWORD || '';
const LANGFUSE_BASE_URL = (process.env.LANGFUSE_BASE_URL || '').replace(/\/$/, '');
const LANGFUSE_PUBLIC_KEY = process.env.LANGFUSE_PUBLIC_KEY || '';
const LANGFUSE_SECRET_KEY = process.env.LANGFUSE_SECRET_KEY || '';
const TRACE_EXPORT_ENABLED = ['1', 'true', 'yes', 'on'].includes(String(process.env.TRACE_EXPORT_ENABLED || 'false').toLowerCase());
const TRACE_EXPORT_ENVIRONMENT = process.env.TRACE_EXPORT_ENVIRONMENT || 'router-v2-test';
const TRACE_EXPORT_DATASET = process.env.TRACE_EXPORT_DATASET || 'router_v2_online_traces';
const TRACE_EXPORT_STATE = process.env.TRACE_EXPORT_STATE || '/trace-state/langfuse-usage-export-state.json';
const TRACE_EXPORT_FACTS_LEDGER = process.env.TRACE_EXPORT_FACTS_LEDGER || '';
const TRACE_EXPORT_POLL_MS = Math.max(Number(process.env.TRACE_EXPORT_POLL_MS || 30000), 5000);
const TRACE_EXPORT_INITIAL_DELAY_MS = Math.max(Number(process.env.TRACE_EXPORT_INITIAL_DELAY_MS || 5000), 0);
const TRACE_EXPORT_LOOKBACK_DAYS = Math.min(Math.max(Number(process.env.TRACE_EXPORT_LOOKBACK_DAYS || 7), 1), 30);
const TRACE_EXPORT_BATCH_SIZE = Math.min(Math.max(Number(process.env.TRACE_EXPORT_BATCH_SIZE || 100), 1), 500);
const TRACE_EXPORT_PAGE_SIZE = Math.min(Math.max(Number(process.env.TRACE_EXPORT_PAGE_SIZE || 200), 1), 1000);
const TRACE_EXPORT_MAX_SCAN_PAGES = Math.min(Math.max(Number(process.env.TRACE_EXPORT_MAX_SCAN_PAGES || 20), 1), 200);
const TRACE_EXPORT_CURSOR_OVERLAP_MS = Math.max(Number(process.env.TRACE_EXPORT_CURSOR_OVERLAP_MS || 10 * 60 * 1000), 0);
const TRACE_EXPORT_FILTER_MECHANICAL_MONITOR = !['0', 'false', 'no', 'off'].includes(
  String(process.env.TRACE_EXPORT_FILTER_MECHANICAL_MONITOR || 'true').toLowerCase(),
);
const TRACE_EXPORT_MECHANICAL_USER_NAME = (process.env.TRACE_EXPORT_MECHANICAL_USER_NAME || 'router-monitor').toLowerCase();
const TRACE_EXPORT_MECHANICAL_KEY_NAME = (process.env.TRACE_EXPORT_MECHANICAL_KEY_NAME || 'GPT watchdog').toLowerCase();
const WATCHDOG_ENABLED = ['1', 'true', 'yes', 'on'].includes(String(process.env.WATCHDOG_ENABLED || 'true').toLowerCase());
const WATCHDOG_STATE_DIR = process.env.WATCHDOG_STATE_DIR || '/monitor-state';
const WATCHDOG_STATE_FILE = process.env.WATCHDOG_STATE_FILE || path.join(WATCHDOG_STATE_DIR, 'gpt-watchdog-state.json');
const WATCHDOG_KEY_FILE = process.env.WATCHDOG_KEY_FILE || path.join(WATCHDOG_STATE_DIR, 'gpt-watchdog-key.json');
const WATCHDOG_INTERVAL_MS = Math.max(Number(process.env.WATCHDOG_INTERVAL_MS || 60000), 10000);
const WATCHDOG_INITIAL_DELAY_MS = Math.max(Number(process.env.WATCHDOG_INITIAL_DELAY_MS || 3000), 0);
const WATCHDOG_RETENTION_DAYS = Math.min(Math.max(Number(process.env.WATCHDOG_RETENTION_DAYS || 7), 1), 30);
const WATCHDOG_MODEL = process.env.WATCHDOG_MODEL || 'gpt-5.5';
const WATCHDOG_PROMPT = process.env.WATCHDOG_PROMPT || 'ping';
const WATCHDOG_TIMEOUT_MS = Math.max(Number(process.env.WATCHDOG_TIMEOUT_MS || 30000), 5000);
const WATCHDOG_SLOW_MS = Math.max(Number(process.env.WATCHDOG_SLOW_MS || 10000), 1000);
const WATCHDOG_USER_EMAIL = process.env.WATCHDOG_USER_EMAIL || `router-monitor-${stableHash(PUBLIC_SELF_BASE, 8)}@bosc.cn`;
const WATCHDOG_USER_NAME = process.env.WATCHDOG_USER_NAME || 'router-monitor';
const API_STATS_SUB2API_KEY_MAP = process.env.API_STATS_SUB2API_KEY_MAP || path.join(WATCHDOG_STATE_DIR, 'api-stats-sub2api-key-map.json');
const API_STATS_USAGE_CACHE_TTL_MS = Math.min(Math.max(Number(process.env.API_STATS_USAGE_CACHE_TTL_MS || 2000), 0), 10000);
const API_STATS_USAGE_CACHE_MAX = Math.min(Math.max(Number(process.env.API_STATS_USAGE_CACHE_MAX || 1000), 10), 5000);
const API_STATS_BATCH_MAX_IDS = boundedNumber(process.env.API_STATS_BATCH_MAX_IDS, 500, 1, 2000);
const API_STATS_BATCH_CONCURRENCY = boundedNumber(process.env.API_STATS_BATCH_CONCURRENCY, 8, 1, 50);
const API_STATS_METADATA_CACHE_TTL_MS = boundedNumber(process.env.API_STATS_METADATA_CACHE_TTL_MS, 5 * 60 * 1000, 10 * 1000, 60 * 60 * 1000);
const API_STATS_METADATA_USER_PAGE_SIZE = boundedNumber(process.env.API_STATS_METADATA_USER_PAGE_SIZE, 200, 1, 1000);
const API_STATS_METADATA_KEY_PAGE_SIZE = boundedNumber(process.env.API_STATS_METADATA_KEY_PAGE_SIZE, 200, 1, 1000);
const API_STATS_METADATA_MAX_PAGES = boundedNumber(process.env.API_STATS_METADATA_MAX_PAGES, 20, 1, 200);
const API_STATS_METADATA_CONCURRENCY = boundedNumber(process.env.API_STATS_METADATA_CONCURRENCY, 4, 1, 20);
const FULL_TRACE_CAPTURE_ENABLED = envFlag(process.env.FULL_TRACE_CAPTURE_ENABLED, false);
const FULL_TRACE_CAPTURE_BODY_ENABLED = envFlag(process.env.FULL_TRACE_CAPTURE_BODY_ENABLED, false);
const FULL_TRACE_CAPTURE_RELAY_URL = (process.env.FULL_TRACE_CAPTURE_RELAY_URL || '').replace(/\/$/, '');
const FULL_TRACE_CAPTURE_RELAY_TIMEOUT_MS = boundedNumber(process.env.FULL_TRACE_CAPTURE_RELAY_TIMEOUT_MS, 30000, 1, 300000);
const FULL_TRACE_CAPTURE_SHUTDOWN_GRACE_MS = boundedNumber(
  process.env.FULL_TRACE_CAPTURE_SHUTDOWN_GRACE_MS,
  20000,
  1000,
  120000,
);
const FULL_TRACE_CAPTURE_SUBMIT_ATTEMPTS = boundedNumber(process.env.FULL_TRACE_CAPTURE_SUBMIT_ATTEMPTS, 25, 1, 64);
const FULL_TRACE_CAPTURE_RETRY_BASE_MS = boundedNumber(process.env.FULL_TRACE_CAPTURE_RETRY_BASE_MS, 250, 10, 60000);
const FULL_TRACE_CAPTURE_RETRY_MAX_MS = boundedNumber(
  process.env.FULL_TRACE_CAPTURE_RETRY_MAX_MS,
  5000,
  FULL_TRACE_CAPTURE_RETRY_BASE_MS,
  300000,
);
const FULL_TRACE_CAPTURE_RETRY_JITTER_PERCENT = boundedNumber(
  process.env.FULL_TRACE_CAPTURE_RETRY_JITTER_PERCENT,
  20,
  0,
  50,
);
const FULL_TRACE_CAPTURE_SUBMIT_CONCURRENCY = boundedNumber(process.env.FULL_TRACE_CAPTURE_SUBMIT_CONCURRENCY, 8, 1, 64);
const FULL_TRACE_CAPTURE_SUBMIT_MAX_INFLIGHT_BYTES = boundedNumber(
  process.env.FULL_TRACE_CAPTURE_SUBMIT_MAX_INFLIGHT_BYTES,
  1024 * 1024 * 1024,
  1024 * 1024,
  Number.MAX_SAFE_INTEGER,
);
const FULL_TRACE_CAPTURE_OUTBOX_DIR = process.env.FULL_TRACE_CAPTURE_OUTBOX_DIR || '/var/lib/chiptrace/relay-shell-outbox';
const FULL_TRACE_CAPTURE_OUTBOX_MAX_BYTES = boundedNumber(
  process.env.FULL_TRACE_CAPTURE_OUTBOX_MAX_BYTES,
  10 * 1024 * 1024 * 1024,
  1024 * 1024,
  Number.MAX_SAFE_INTEGER,
);
const FULL_TRACE_CAPTURE_OUTBOX_MAX_FILES = boundedNumber(
  process.env.FULL_TRACE_CAPTURE_OUTBOX_MAX_FILES,
  100000,
  1,
  1000000,
);
const FULL_TRACE_CAPTURE_OUTBOX_MIN_FREE_BYTES = boundedNumber(
  process.env.FULL_TRACE_CAPTURE_OUTBOX_MIN_FREE_BYTES,
  5 * 1024 * 1024 * 1024,
  0,
  Number.MAX_SAFE_INTEGER,
);
const FULL_TRACE_CAPTURE_OUTBOX_MIN_FREE_FILES = boundedNumber(
  process.env.FULL_TRACE_CAPTURE_OUTBOX_MIN_FREE_FILES,
  10000,
  0,
  Number.MAX_SAFE_INTEGER,
);
const FULL_TRACE_CAPTURE_SOURCE_NAMESPACE = process.env.FULL_TRACE_CAPTURE_SOURCE_NAMESPACE || 'relay-18084';
const FULL_TRACE_CAPTURE_MAX_REQUEST_BYTES = boundedNumber(process.env.FULL_TRACE_CAPTURE_MAX_REQUEST_BYTES, 1024 * 1024, 1024, 256 * 1024 * 1024);
const FULL_TRACE_CAPTURE_MAX_RESPONSE_BYTES = boundedNumber(process.env.FULL_TRACE_CAPTURE_MAX_RESPONSE_BYTES, 4 * 1024 * 1024, 1024, 384 * 1024 * 1024);
// One cloud credential covers OTLP and Codex Hook ingestion. The gateway is
// only a protocol proxy; no local ChipTrace producer is part of production.
const CHIPTRACE_INGEST_TOKEN = String(process.env.CHIPTRACE_INGEST_TOKEN || '').trim();
const FULL_TRACE_CAPTURE_HEALTH_MAX_PENDING_FILES = boundedNumber(
  process.env.FULL_TRACE_CAPTURE_HEALTH_MAX_PENDING_FILES,
  128,
  0,
  1000000,
);
const FULL_TRACE_CAPTURE_HEALTH_MAX_QUEUE_BYTES = boundedNumber(
  process.env.FULL_TRACE_CAPTURE_HEALTH_MAX_QUEUE_BYTES,
  512 * 1024 * 1024,
  0,
  Number.MAX_SAFE_INTEGER,
);
const FULL_TRACE_CAPTURE_HEALTH_MAX_OLDEST_PENDING_MS = boundedNumber(
  process.env.FULL_TRACE_CAPTURE_HEALTH_MAX_OLDEST_PENDING_MS,
  60000,
  0,
  24 * 60 * 60 * 1000,
);
const FULL_TRACE_CAPTURE_HEALTH_MAX_OPEN_MS = boundedNumber(
  process.env.FULL_TRACE_CAPTURE_HEALTH_MAX_OPEN_MS,
  30 * 60 * 1000,
  1000,
  7 * 24 * 60 * 60 * 1000,
);
const FULL_TRACE_CAPTURE_ALL_AUTHENTICATED_KEYS = envFlag(
  process.env.FULL_TRACE_CAPTURE_ALL_AUTHENTICATED_KEYS,
  envFlag(process.env.FULL_TRACE_CAPTURE_ALLOW_ALL_CANARY, false),
);
const FULL_TRACE_CAPTURE_API_KEY_FINGERPRINTS = new Set(String(process.env.FULL_TRACE_CAPTURE_API_KEY_FINGERPRINTS || '').split(',').map((item) => item.trim()).filter(Boolean));
const FULL_TRACE_CAPTURE_EXCLUDE_API_KEY_FINGERPRINTS = new Set(String(process.env.FULL_TRACE_CAPTURE_EXCLUDE_API_KEY_FINGERPRINTS || '').split(',').map((item) => item.trim()).filter(Boolean));
const fullTraceMonitorKeyFingerprints = new Set(FULL_TRACE_CAPTURE_EXCLUDE_API_KEY_FINGERPRINTS);
const FULL_TRACE_CAPTURE_PHASE = FULL_TRACE_CAPTURE_ENABLED ? 'local_outbox_to_rust_relay' : 'disabled';
let legacyApiMapCache = null;
let adminTokenCache = { token: '', expiresAt: 0 };
const apiStatsUsageCache = new Map();
const apiStatsUsageCacheStats = {
  hits: 0,
  inFlightHits: 0,
  misses: 0,
  evictionsExpired: 0,
  evictionsCapacity: 0,
  errors: 0,
};
let apiStatsMetadataCache = { expiresAt: 0, byKeyHash: new Map() };
const fullTraceCaptureStatus = {
  acceptedCount: 0,
  submittedCount: 0,
  filteredCount: 0,
  droppedCount: 0,
  actorResolvedCount: 0,
  actorMissCount: 0,
  // Actor metadata is optional enrichment.  A lookup failure must remain
  // visible to operators without turning a durable Wire capture into a
  // transport-health failure.
  actorMetadataLastError: null,
  truncatedRequestCount: 0,
  truncatedResponseCount: 0,
  lastAcceptedAt: null,
  lastSubmittedAt: null,
  lastFilteredAt: null,
  lastFilterReason: null,
  lastDroppedAt: null,
  lastDropReason: null,
  lastError: null,
};
let fullTraceSubmitterStartupError = null;
if (FULL_TRACE_CAPTURE_ENABLED) {
  try {
    const relayUrl = new URL(FULL_TRACE_CAPTURE_RELAY_URL);
    if (!['http:', 'https:'].includes(relayUrl.protocol)) throw new Error('Rust Relay URL must use HTTP or HTTPS');
  } catch (error) {
    fullTraceSubmitterStartupError = (error.message || String(error)).slice(0, 500);
    fullTraceCaptureStatus.lastError = fullTraceSubmitterStartupError;
  }
}
const fullTraceSubmitterStatus = {
  offered: 0,
  attempts: 0,
  retries: 0,
  durable: 0,
  localDurable: 0,
  duplicates: 0,
  rejected: 0,
  inFlight: 0,
  inFlightBytes: 0,
  lastDurableAt: null,
  lastError: fullTraceSubmitterStartupError,
};
const fullTracePendingLocalWrites = new Set();
const fullTraceOutbox = new DurableCaptureOutbox({
  root: FULL_TRACE_CAPTURE_OUTBOX_DIR,
  relayUrl: FULL_TRACE_CAPTURE_RELAY_URL,
  bearerToken: CHIPTRACE_INGEST_TOKEN,
  maxBytes: FULL_TRACE_CAPTURE_OUTBOX_MAX_BYTES,
  maxFiles: FULL_TRACE_CAPTURE_OUTBOX_MAX_FILES,
  minFreeBytes: FULL_TRACE_CAPTURE_OUTBOX_MIN_FREE_BYTES,
  minFreeFiles: FULL_TRACE_CAPTURE_OUTBOX_MIN_FREE_FILES,
  maxInflightBytes: FULL_TRACE_CAPTURE_SUBMIT_MAX_INFLIGHT_BYTES,
  concurrency: FULL_TRACE_CAPTURE_SUBMIT_CONCURRENCY,
  maxAttempts: FULL_TRACE_CAPTURE_SUBMIT_ATTEMPTS,
  timeoutMs: FULL_TRACE_CAPTURE_RELAY_TIMEOUT_MS,
  maxOpenAgeMs: FULL_TRACE_CAPTURE_HEALTH_MAX_OPEN_MS,
  retryBaseMs: FULL_TRACE_CAPTURE_RETRY_BASE_MS,
  retryMaxMs: FULL_TRACE_CAPTURE_RETRY_MAX_MS,
  retryJitterPercent: FULL_TRACE_CAPTURE_RETRY_JITTER_PERCENT,
  sanitize: envFlag(process.env.FULL_TRACE_CAPTURE_OUTBOX_SANITIZE, false),
  onAttempt: () => {
    fullTraceSubmitterStatus.attempts += 1;
  },
  onDurable: ({ duplicate }) => {
    fullTraceSubmitterStatus.durable += 1;
    if (duplicate) fullTraceSubmitterStatus.duplicates += 1;
    const now = new Date().toISOString();
    fullTraceSubmitterStatus.lastDurableAt = now;
    fullTraceSubmitterStatus.lastError = null;
    fullTraceCaptureStatus.submittedCount += 1;
    fullTraceCaptureStatus.lastSubmittedAt = now;
    fullTraceCaptureStatus.lastError = null;
  },
  onRetry: () => {
    fullTraceSubmitterStatus.retries += 1;
  },
  onFailure: ({ reason, error }) => {
    fullTraceSubmitterStatus.lastError = (error?.message || reason || 'capture delivery failed').slice(0, 500);
  },
});
const fullTraceActorCache = new Map();
let traceExportRunning = false;
let traceExportDatasetReady = false;
let traceExportTimer = null;
let watchdogTimer = null;
let watchdogRunning = false;
let watchdogKeyCache = null;
const traceExportStatus = {
  enabled: TRACE_EXPORT_ENABLED,
  configured: false,
  running: false,
  dataset: TRACE_EXPORT_DATASET,
  lastRunAt: null,
  lastError: null,
  lastFactsLedgerWriteAt: null,
  lastFactsLedgerError: null,
  lastExportedUsageLogId: null,
  lastExportedTraceId: null,
  lastScannedUsageLogId: null,
  exportedCount: 0,
  skippedCount: 0,
  lastScanStrategy: null,
  lastScanPages: 0,
  lastScanFetchedRows: 0,
  lastScanCandidateRows: 0,
  lastScanReturnedRows: 0,
  lastScanReachedCursor: null,
  lastScanWindowStartDate: null,
  lastScanWindowEndDate: null,
  filters: {
    mechanicalMonitor: {
      enabled: TRACE_EXPORT_FILTER_MECHANICAL_MONITOR,
      userName: TRACE_EXPORT_MECHANICAL_USER_NAME,
      apiKeyName: TRACE_EXPORT_MECHANICAL_KEY_NAME,
      activatedAfterUsageLogId: null,
      skippedCount: 0,
    },
  },
};
const watchdogState = {
  enabled: WATCHDOG_ENABLED,
  configured: false,
  running: false,
  intervalMs: WATCHDOG_INTERVAL_MS,
  retentionDays: WATCHDOG_RETENTION_DAYS,
  model: WATCHDOG_MODEL,
  lastRunAt: null,
  lastAvailableAt: null,
  lastError: null,
  lastProbeId: null,
  checks: [],
};

function send(res, status, body, headers = {}) {
  const data = typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(status, {
    'content-type': typeof body === 'string' ? 'text/html; charset=utf-8' : 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    ...headers,
  });
  res.end(data);
}

function redirect(res, location) {
  res.writeHead(302, { location });
  res.end();
}

function errorCauseCode(error) {
  return error?.cause?.code || error?.code || error?.name || null;
}

function upstreamFailureStatus(error) {
  const code = String(errorCauseCode(error) || '').toUpperCase();
  if (code.includes('TIMEOUT') || code === 'ABORT_ERR' || code === 'ABORTERROR') return 504;
  if (['ECONNREFUSED', 'ECONNRESET', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH', 'UND_ERR_SOCKET'].includes(code)) return 502;
  return 502;
}

function sendProxyFailure(res, error, context = {}) {
  const causeCode = errorCauseCode(error);
  console.error('relay proxy failed:', context.proxiedPath || context.url || '', causeCode || '', error?.message || String(error));
  if (res.destroyed) return;
  if (res.headersSent) {
    if (!res.writableEnded) res.destroy(error);
    return;
  }
  send(res, upstreamFailureStatus(error), {
    success: false,
    error: {
      message: 'Upstream request failed',
      type: 'upstream_error',
      code: causeCode || 'fetch_failed',
    },
    upstream: SUB2API_BASE,
    proxiedPath: context.proxiedPath || null,
  });
}

function sendUnhandledFailure(req, res, error) {
  console.error('relay request failed:', req?.url || '', error?.message || String(error));
  if (res.destroyed) return;
  if (res.headersSent) {
    if (!res.writableEnded) res.destroy(error);
    return;
  }
  send(res, 500, {
    success: false,
    error: {
      message: 'Relay request failed',
      type: 'relay_internal_error',
      code: errorCauseCode(error) || 'internal_error',
    },
  });
}

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  if (!chunks.length) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function unwrap(payload) {
  if (payload && typeof payload === 'object' && Object.prototype.hasOwnProperty.call(payload, 'code')) {
    if (payload.code !== 0) {
      const error = new Error(payload.message || 'sub2api error');
      error.payload = payload;
      throw error;
    }
    return payload.data;
  }
  return payload;
}

async function sub2api(path, options = {}) {
  const response = await fetch(`${SUB2API_BASE}${path}`, {
    ...options,
    headers: {
      'content-type': 'application/json',
      ...(options.headers || {}),
    },
  });
  const text = await response.text();
  let payload = {};
  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    payload = { raw: text };
  }
  if (!response.ok) {
    const error = new Error(payload.message || payload.error || response.statusText);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return unwrap(payload);
}

async function sub2apiRaw(path, options = {}) {
  const response = await fetch(`${SUB2API_BASE}${path}`, {
    ...options,
    headers: {
      'content-type': 'application/json',
      ...(options.headers || {}),
    },
  });
  const text = await response.text();
  let payload = {};
  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    payload = { raw: text };
  }
  if (!response.ok) {
    const error = new Error(payload.message || payload.error || response.statusText);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

async function getAdminToken() {
  if (!SUB2API_ADMIN_EMAIL || !SUB2API_ADMIN_PASSWORD) {
    throw new Error('Sub2API admin credentials are not configured');
  }
  if (adminTokenCache.token && Date.now() < adminTokenCache.expiresAt) {
    return adminTokenCache.token;
  }
  const payload = await sub2apiRaw('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({
      email: SUB2API_ADMIN_EMAIL,
      password: SUB2API_ADMIN_PASSWORD,
    }),
  });
  const data = unwrap(payload) || {};
  const token = data.access_token || data.token || payload.access_token || payload.token;
  if (!token) throw new Error('Sub2API admin login did not return a token');
  adminTokenCache = {
    token,
    expiresAt: Date.now() + 10 * 60 * 1000,
  };
  return token;
}

async function sub2apiAdmin(path, options = {}) {
  const token = await getAdminToken();
  try {
    return await sub2api(path, {
      ...options,
      headers: {
        authorization: `Bearer ${token}`,
        ...(options.headers || {}),
      },
    });
  } catch (error) {
    if (error.status === 401) {
      adminTokenCache = { token: '', expiresAt: 0 };
      const freshToken = await getAdminToken();
      return sub2api(path, {
        ...options,
        headers: {
          authorization: `Bearer ${freshToken}`,
          ...(options.headers || {}),
        },
      });
    }
    throw error;
  }
}

function bearer(req) {
  const token = req.headers['x-user-token'] || req.headers.authorization?.replace(/^Bearer\s+/i, '');
  return token || '';
}

function mapUser(user) {
  return {
    id: user.id,
    username: user.email,
    displayName: user.username || user.email,
    email: user.email,
    role: user.role || 'user',
    status: user.status || 'active',
    balance: user.balance,
  };
}

function oemSettings() {
  return {
    siteName: 'Router',
    siteIcon: '',
    siteIconData: '',
    showAdminButton: true,
    ldapEnabled: false,
    apiStatsNotice: {
      enabled: false,
      title: '',
      content: '',
    },
    updatedAt: new Date().toISOString(),
  };
}

function legacyApiMap() {
  if (!legacyApiMapCache) {
    legacyApiMapCache = JSON.parse(fs.readFileSync(LEGACY_API_ID_MAP, 'utf8'));
  }
  return legacyApiMapCache;
}

function legacyRecordByIdOrKey({ apiId, apiKey }) {
  const map = legacyApiMap();
  if (apiId && map.byId?.[apiId]) return map.byId[apiId];
  if (apiKey && map.byKey?.[apiKey]) return map.byKey[apiKey];
  return null;
}

function sub2apiKeyMap() {
  const map = readJsonFile(API_STATS_SUB2API_KEY_MAP, {});
  return {
    byId: map.byId && typeof map.byId === 'object' ? map.byId : {},
    byKeyHash: map.byKeyHash && typeof map.byKeyHash === 'object' ? map.byKeyHash : {},
  };
}

function saveSub2apiKeyMap(map) {
  writeJsonFileAtomic(API_STATS_SUB2API_KEY_MAP, {
    version: 1,
    updatedAt: new Date().toISOString(),
    byId: map.byId || {},
    byKeyHash: map.byKeyHash || {},
  });
}

function apiStatsKeyHash(apiKey) {
  return stableHash(apiKey, 32);
}

function apiStatsIdForSub2apiKey(apiKey) {
  const hash = apiStatsKeyHash(apiKey);
  return [
    hash.slice(0, 8),
    hash.slice(8, 12),
    `4${hash.slice(13, 16)}`,
    `8${hash.slice(17, 20)}`,
    hash.slice(20, 32),
  ].join('-');
}

function normalizeSub2apiRecord(item = {}, apiKey = '') {
  const key = String(apiKey || item.key || '').trim();
  if (!key) return null;
  const userName = item.user?.username || item.user_name || item.username || '';
  const userEmail = item.user?.email || item.user_email || item.email || '';
  const groupName = item.group?.name || item.group_name || '';
  return {
    id: apiStatsIdForSub2apiKey(key),
    source: 'sub2api',
    sub2apiApiKeyId: Number(item.id || 0) || null,
    sub2apiUserId: Number(item.user_id || 0) || null,
    name: item.name || userName || userEmail || 'Sub2API Key',
    apiKey: key,
    description: groupName || '',
    tags: JSON.stringify([groupName || 'Sub2API'].filter(Boolean)),
    isActive: item.status ? item.status === 'active' : true,
    createdAt: item.created_at || item.createdAt || new Date().toISOString(),
    openaiAccountId: null,
    legacyRequests: 0,
  };
}

function sub2apiRecordNeedsMetadata(record) {
  return Boolean(record?.apiKey && (!record.sub2apiApiKeyId || !record.sub2apiUserId || record.name === 'Sub2API Key'));
}

function maskRecordForStorage(record) {
  const copy = { ...record };
  delete copy.apiKey;
  return copy;
}

function recordFromStoredSub2api(apiId = '') {
  if (!apiId) return null;
  const map = sub2apiKeyMap();
  const stored = map.byId[String(apiId)];
  if (!stored?.apiKey) return null;
  return normalizeSub2apiRecord(stored, stored.apiKey);
}

function storeSub2apiRecord(record) {
  if (!record?.id || !record.apiKey) return record;
  const map = sub2apiKeyMap();
  const stored = {
    ...maskRecordForStorage(record),
    apiKey: record.apiKey,
    keyHash: apiStatsKeyHash(record.apiKey),
    updatedAt: new Date().toISOString(),
  };
  map.byId[record.id] = stored;
  map.byKeyHash[stored.keyHash] = record.id;
  saveSub2apiKeyMap(map);
  return record;
}

function mergeSub2apiKeyUser(item = {}, user = {}) {
  return {
    ...item,
    user_id: item.user_id || user.id,
    user: {
      ...(item.user || {}),
      id: user.id,
      username: user.username,
      email: user.email,
    },
  };
}

async function listSub2apiAdminUsersPage(page) {
  const query = new URLSearchParams({
    page: String(page),
    page_size: String(API_STATS_METADATA_USER_PAGE_SIZE),
    include_subscriptions: 'false',
  });
  return sub2apiAdmin(`/api/v1/admin/users?${query.toString()}`);
}

async function listSub2apiAdminUserKeys(userId, page = 1) {
  const query = new URLSearchParams({
    page: String(page),
    page_size: String(API_STATS_METADATA_KEY_PAGE_SIZE),
  });
  return sub2apiAdmin(`/api/v1/admin/users/${encodeURIComponent(userId)}/api-keys?${query.toString()}`);
}

async function refreshSub2apiMetadataCache() {
  const first = await listSub2apiAdminUsersPage(1);
  const users = adminListItems(first).filter((item) => item?.id && !item.deleted_at);
  const totalPages = Math.min(
    Number(first?.pages || first?.data?.pages || 1) || 1,
    API_STATS_METADATA_MAX_PAGES,
  );
  if (totalPages > 1) {
    const rest = await mapLimit(Array.from({ length: totalPages - 1 }, (_, index) => index + 2), API_STATS_METADATA_CONCURRENCY, listSub2apiAdminUsersPage);
    for (const payload of rest) users.push(...adminListItems(payload).filter((item) => item?.id && !item.deleted_at));
  }

  const byKeyHash = new Map();
  await mapLimit(users, API_STATS_METADATA_CONCURRENCY, async (user) => {
    try {
      const firstKeys = await listSub2apiAdminUserKeys(user.id, 1);
      const keyItems = adminListItems(firstKeys);
      const keyPages = Math.min(
        Number(firstKeys?.pages || firstKeys?.data?.pages || 1) || 1,
        API_STATS_METADATA_MAX_PAGES,
      );
      if (keyPages > 1) {
        const restKeys = await mapLimit(Array.from({ length: keyPages - 1 }, (_, index) => index + 2), API_STATS_METADATA_CONCURRENCY, (page) => listSub2apiAdminUserKeys(user.id, page));
        for (const payload of restKeys) keyItems.push(...adminListItems(payload));
      }
      for (const item of keyItems) {
        if (!item?.key || item.deleted_at) continue;
        byKeyHash.set(apiStatsKeyHash(item.key), mergeSub2apiKeyUser(item, user));
      }
    } catch {
      // Metadata is best-effort; key validation and usage stats still work without it.
    }
  });

  apiStatsMetadataCache = {
    expiresAt: Date.now() + API_STATS_METADATA_CACHE_TTL_MS,
    byKeyHash,
  };
  return byKeyHash;
}

async function findSub2apiKeyMetadata(apiKey) {
  const hash = apiStatsKeyHash(apiKey);
  if (!hash) return null;
  if (Date.now() < apiStatsMetadataCache.expiresAt && apiStatsMetadataCache.byKeyHash?.has(hash)) {
    return apiStatsMetadataCache.byKeyHash.get(hash);
  }
  try {
    const refreshed = await refreshSub2apiMetadataCache();
    return refreshed.get(hash) || null;
  } catch {
    return null;
  }
}

async function hydrateSub2apiRecordMetadata(record) {
  if (!sub2apiRecordNeedsMetadata(record)) return record;
  const item = await findSub2apiKeyMetadata(record.apiKey);
  if (!item) return record;
  return storeSub2apiRecord(normalizeSub2apiRecord(item, record.apiKey) || record);
}

function fullTraceActorDisplayName(item = {}) {
  const user = item.user || {};
  return String(user.username || item.user_name || item.username || user.email || item.user_email || item.email || item.name || '').trim();
}

function fullTraceActorFromMetadata(item = {}, apiKeyFingerprint = '') {
  const user = item.user || {};
  const displayName = fullTraceActorDisplayName(item);
  if (!displayName) return null;
  return {
    userId: item.user_id || user.id || null,
    userEmail: user.email || item.user_email || item.email || null,
    userName: user.username || item.user_name || item.username || null,
    displayName,
    apiKeyId: item.id || null,
    apiKeyName: item.name || null,
    apiKeyFingerprint: apiKeyFingerprint || null,
    source: 'sub2api_admin_metadata',
  };
}

async function resolveFullTraceActor(apiKey, apiKeyFingerprint) {
  if (!apiKey || !apiKeyFingerprint) return null;
  const cached = fullTraceActorCache.get(apiKeyFingerprint);
  if (cached && Date.now() < cached.expiresAt) return cached.value;
  const item = await findSub2apiKeyMetadata(apiKey);
  const actor = item ? fullTraceActorFromMetadata(item, apiKeyFingerprint) : null;
  fullTraceActorCache.set(apiKeyFingerprint, {
    expiresAt: Date.now() + API_STATS_METADATA_CACHE_TTL_MS,
    value: actor,
  });
  if (actor) fullTraceCaptureStatus.actorResolvedCount += 1;
  else fullTraceCaptureStatus.actorMissCount += 1;
  return actor;
}

async function validateSub2apiApiKey(apiKey) {
  const key = String(apiKey || '').trim();
  if (!key) return null;
  try {
    await sub2apiRaw('/v1/models', {
      headers: { authorization: `Bearer ${key}` },
    });
  } catch {
    return null;
  }
  const item = await findSub2apiKeyMetadata(key);
  const record = normalizeSub2apiRecord(item || {}, key);
  return storeSub2apiRecord(record);
}

async function apiStatsRecordByIdOrKey({ apiId, apiKey }) {
  const legacy = legacyRecordByIdOrKey({ apiId, apiKey });
  if (legacy) return legacy;
  if (apiId) {
    const stored = recordFromStoredSub2api(apiId);
    if (stored) return hydrateSub2apiRecordMetadata(stored);
  }
  if (apiKey) return validateSub2apiApiKey(apiKey);
  return null;
}

function formatCost(cost) {
  const value = Number(cost || 0);
  if (value === 0) return '$0.000000';
  if (value >= 1) return `$${value.toFixed(2)}`;
  if (value >= 0.01) return `$${value.toFixed(4)}`;
  return `$${value.toFixed(6)}`;
}

function readJsonFile(file, fallback = {}) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function refreshFullTraceMonitorKeyFingerprints() {
  for (const fingerprint of FULL_TRACE_CAPTURE_EXCLUDE_API_KEY_FINGERPRINTS) {
    fullTraceMonitorKeyFingerprints.add(fingerprint);
  }
  // The watchdog key is rotated through Sub2API and persisted locally. Load
  // only its fingerprint; the secret itself never enters a Capture envelope.
  const watchdog = readJsonFile(WATCHDOG_KEY_FILE, {});
  if (watchdog.apiKey) fullTraceMonitorKeyFingerprints.add(stableHash(watchdog.apiKey, 16));
  return fullTraceMonitorKeyFingerprints;
}

refreshFullTraceMonitorKeyFingerprints();

function writeJsonFileAtomic(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(tmp, file);
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function boundedNumber(value, fallback, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(Math.max(Math.floor(number), min), max);
}

function envFlag(value, fallback = false) {
  if (value === undefined || value === null || value === '') return Boolean(fallback);
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function headerValue(headers, name) {
  const value = headers?.[name.toLowerCase()];
  if (Array.isArray(value)) return value[0] || '';
  return value || '';
}

// Correlation headers are safe protocol metadata. Keep this allow-list narrow:
// authorization, cookies, and arbitrary client headers must never enter the
// trace envelope. Values are retained verbatim so downstream provenance can
// distinguish client assertions from proxy observations.
const FULL_TRACE_CORRELATION_HEADERS = [
  'x-client-request-id',
  'x-request-id',
  'session-id',
  'thread-id',
  'session_id',
  'conversation_id',
  'traceparent',
  'tracestate',
  'originator',
  'openai-beta',
  'x-codex-turn-metadata',
  'x-codex-installation-id',
  'x-codex-window-id',
];

function captureCorrelationHeaders(headers) {
  const captured = {};
  for (const name of FULL_TRACE_CORRELATION_HEADERS) {
    const value = headerValue(headers, name);
    if (value) captured[name] = String(value).slice(0, 4096);
  }
  return captured;
}

function traceContextFromCorrelationHeaders(requestHeaders, responseHeaders = {}) {
  return codexTraceContextFromHeaders(requestHeaders, responseHeaders);
}

// Claude Code does not send session-id headers. Its Messages request carries
// metadata.user_id as a JSON string containing the native session UUID.
function claudeTurnFromHookState(sessionId) {
  const stateDir = process.env.CHIPTRACE_CLAUDE_TURN_STATE_DIR || '/monitor-state/claude-turns';
  try {
    const value = JSON.parse(fs.readFileSync(path.join(stateDir, `${sessionId}.json`), 'utf8'));
    return typeof value?.turn_id === 'string' && value.turn_id.trim() !== ''
      ? value.turn_id
      : null;
  } catch {
    return null;
  }
}

const SESSION_UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function sessionFromUserId(userId) {
  if (typeof userId !== 'string') return null;
  try {
    const session = JSON.parse(userId)?.session_id;
    return typeof session === 'string' && SESSION_UUID_RE.test(session) ? session : null;
  } catch {
    return null;
  }
}

function anthropicSessionFromBody(requestBodyText) {
  if (typeof requestBodyText !== 'string' || requestBodyText.trim() === '') return null;
  try {
    const body = JSON.parse(requestBodyText);
    const session = sessionFromUserId(body?.metadata?.user_id);
    if (session) return session;
  } catch {
    // Large interactive requests are only sampled at the head and tail, so a
    // full JSON parse can fail; fall through to the encoded-string search.
  }
  // The tail sample contains the trailing metadata object. Match the encoded
  // JSON string and parse it twice (string -> JSON text -> object).
  const match = requestBodyText.match(/"user_id"\s*:\s*("(?:\\.|[^"\\])*")/);
  if (!match) return null;
  try {
    return sessionFromUserId(JSON.parse(match[1]));
  } catch {
    return null;
  }
}

function fullTraceClientRequestId(req) {
  const inbound = String(headerValue(req.headers, 'x-client-request-id') || '').trim();
  if (inbound) return inbound;
  return `chiptrace-${crypto.randomUUID()}`;
}

function bearerToken(req) {
  const auth = headerValue(req.headers, 'authorization');
  const match = String(auth || '').match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : '';
}

function shouldConsiderFullTrace(req, proxiedPath) {
  if (!FULL_TRACE_CAPTURE_ENABLED || !FULL_TRACE_CAPTURE_BODY_ENABLED) return false;
  if (!['POST', 'PUT', 'PATCH'].includes(req.method)) return false;
  const pathname = new URL(proxiedPath, 'http://sub2api.local').pathname;
  if (!['/v1/responses', '/v1/chat/completions', '/v1/messages'].includes(pathname)) return false;
  const contentType = headerValue(req.headers, 'content-type').toLowerCase();
  if (contentType && !contentType.includes('application/json') && !contentType.includes('text/')) return false;
  const keyFingerprint = stableHash(bearerToken(req), 16);
  if (keyFingerprint && fullTraceMonitorKeyFingerprints.has(keyFingerprint)) {
    fullTraceCaptureStatus.filteredCount += 1;
    fullTraceCaptureStatus.lastFilteredAt = new Date().toISOString();
    fullTraceCaptureStatus.lastFilterReason = 'stable_monitor_key_fingerprint';
    return false;
  }
  // Body capture requires a stable caller identity even in canary mode. An
  // absent key is retained only by the normal metadata/API path, never as a
  // full user conversation payload.
  if (FULL_TRACE_CAPTURE_ALL_AUTHENTICATED_KEYS) return Boolean(keyFingerprint);
  return Boolean(keyFingerprint && FULL_TRACE_CAPTURE_API_KEY_FINGERPRINTS.has(keyFingerprint));
}

// Keep only the last maxBytes of a stream. Used for the trailing metadata of
// requests that exceed the identity head sample.
function appendRollingTail(state, chunk, maxBytes) {
  if (!chunk) return;
  const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
  state.chunks.push(buffer);
  state.bytes += buffer.length;
  while (state.bytes > maxBytes && state.chunks.length > 1) {
    const excess = state.bytes - maxBytes;
    const first = state.chunks[0];
    if (first.length <= excess) {
      state.chunks.shift();
      state.bytes -= first.length;
    } else {
      state.chunks[0] = first.subarray(excess);
      state.bytes -= excess;
    }
  }
}

function appendBoundedBuffer(state, chunk, maxBytes) {
  if (!chunk || state.truncated) return;
  const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
  const remaining = maxBytes - state.bytes;
  if (remaining <= 0) {
    state.truncated = true;
    return;
  }
  if (buffer.length > remaining) {
    state.chunks.push(buffer.subarray(0, remaining));
    state.bytes += remaining;
    state.truncated = true;
    return;
  }
  state.chunks.push(buffer);
  state.bytes += buffer.length;
}

function captureDrop(reason, error = null) {
  fullTraceCaptureStatus.droppedCount += 1;
  fullTraceCaptureStatus.lastDroppedAt = new Date().toISOString();
  fullTraceCaptureStatus.lastDropReason = reason;
  fullTraceCaptureStatus.lastError = error ? (error.message || String(error)).slice(0, 500) : fullTraceCaptureStatus.lastError;
}

async function probeFullTraceRelay() {
  if (!FULL_TRACE_CAPTURE_ENABLED) return { configured: false, healthy: null };
  if (fullTraceSubmitterStartupError) {
    return { configured: false, healthy: false, error: fullTraceSubmitterStartupError };
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.min(FULL_TRACE_CAPTURE_RELAY_TIMEOUT_MS, 2000));
  try {
    const response = await fetch(`${FULL_TRACE_CAPTURE_RELAY_URL}/health`, { signal: controller.signal });
    const payload = await response.json().catch(() => ({}));
    return {
      configured: true,
      healthy: response.ok && payload.ok === true && payload.conservation_ok === true,
      httpStatus: response.status,
      deliveryRecords: Number(payload.delivery_records || 0),
      pending: Number(payload.pending || 0),
      inflight: Number(payload.inflight || 0),
      delivered: Number(payload.delivered || 0),
      conflicts: Number(payload.conflicts || 0),
      failed: Number(payload.failed || 0),
      conservationOk: payload.conservation_ok === true,
    };
  } catch (error) {
    return {
      configured: true,
      healthy: false,
      error: (error.message || String(error)).slice(0, 500),
    };
  } finally {
    clearTimeout(timer);
  }
}

async function submitFullTraceCapture(record) {
  fullTraceSubmitterStatus.offered += 1;
  try {
    const ack = await fullTraceOutbox.enqueue(record);
    fullTraceSubmitterStatus.localDurable += 1;
    if (ack.duplicate) fullTraceSubmitterStatus.duplicates += 1;
    fullTraceSubmitterStatus.lastError = null;
    return ack;
  } catch (error) {
    fullTraceSubmitterStatus.rejected += 1;
    fullTraceSubmitterStatus.lastError = (error.message || String(error)).slice(0, 500);
    const reason = error.code === 'CAPTURE_ID_CONFLICT'
      ? 'capture_outbox_conflict'
      : error.code === 'OUTBOX_FULL'
        ? 'capture_outbox_full'
        : error.code === 'OUTBOX_DISK_PRESSURE'
          ? 'capture_outbox_disk_pressure'
          : error.code === 'OUTBOX_INODE_PRESSURE'
            ? 'capture_outbox_inode_pressure'
            : 'capture_outbox_write_failed';
    captureDrop(reason, error);
    return null;
  }
}

async function finalizeFullTraceCapture(transaction, record) {
  fullTraceSubmitterStatus.offered += 1;
  try {
    const ack = await transaction.finalize(record);
    fullTraceSubmitterStatus.localDurable += 1;
    if (ack.duplicate) fullTraceSubmitterStatus.duplicates += 1;
    fullTraceSubmitterStatus.lastError = null;
    return ack;
  } catch (error) {
    fullTraceSubmitterStatus.rejected += 1;
    fullTraceSubmitterStatus.lastError = (error.message || String(error)).slice(0, 500);
    const reason = error.code === 'CAPTURE_ID_CONFLICT'
      ? 'capture_outbox_conflict'
      : error.code === 'OUTBOX_FULL'
        ? 'capture_outbox_full'
        : error.code === 'OUTBOX_DISK_PRESSURE'
          ? 'capture_outbox_disk_pressure'
          : error.code === 'OUTBOX_INODE_PRESSURE'
            ? 'capture_outbox_inode_pressure'
            : 'capture_finalize_failed';
    captureDrop(reason, error);
    throw error;
  }
}

async function scheduleFullTraceSubmit({
  captureId,
  clientRequestId,
  startedAt,
  req,
  proxiedPath,
  apiKeyFingerprint,
  requestCapture,
  requestIdentityCapture,
  requestIdentityTail,
  responseCapture,
  response,
  responseError,
  clientRequestAborted,
  clientResponseClosedBeforeFinish,
  clientResponseFinished,
  responseBytesForwarded,
  responseBytesForwardedAtClientClose,
  responseProtocolTerminalObservedAtClientClose,
  responseFramingDoneObservedAtClientClose,
  upstreamResponseCompleted,
  responseStreamState,
  actor,
  actorMetadataStatus,
  captureTransaction,
  captureWritePromises = [],
}) {
  await Promise.all(captureWritePromises);
  const requestBodyBytes = Buffer.concat(requestCapture.chunks, requestCapture.bytes);
  const responseBodyBytes = Buffer.concat(responseCapture.chunks, responseCapture.bytes);
  const requestBodyText = requestBodyBytes.toString('utf8');
  const requestIdentityText = [
    Buffer.concat(
      requestIdentityCapture?.chunks || [],
      requestIdentityCapture?.bytes || 0,
    ).toString('utf8'),
    Buffer.concat(
      requestIdentityTail?.chunks || [],
      requestIdentityTail?.bytes || 0,
    ).toString('utf8'),
  ].join('\n');
  const responseBodyText = responseBodyBytes.toString('utf8');
  const requestHeaders = {
    'content-type': headerValue(req.headers, 'content-type') || null,
    'user-agent': headerValue(req.headers, 'user-agent') || null,
    ...captureCorrelationHeaders(req.headers),
    'x-client-request-id': clientRequestId,
  };
  const responseHeaders = {
    'content-type': response ? response.headers.get('content-type') : null,
    ...(response ? captureCorrelationHeaders(Object.fromEntries(response.headers.entries())) : {}),
    'x-request-id': response ? response.headers.get('x-request-id') : null,
    'x-client-request-id': response ? response.headers.get('x-client-request-id') : null,
    'traceparent': response ? response.headers.get('traceparent') : null,
    'tracestate': response ? response.headers.get('tracestate') : null,
  };
  const traceContext = traceContextFromCorrelationHeaders(req.headers, responseHeaders);
  const anthropicSession = anthropicSessionFromBody(requestIdentityText || requestBodyText);
  if (anthropicSession) {
    const trace = traceContext.trace || (traceContext.trace = {});
    trace.session_id ||= anthropicSession;
    trace.thread_id ||= anthropicSession;
    trace.conversation_id ||= anthropicSession;
    trace.session_identity_source ||= 'anthropic_metadata_user_id';
    const turn = claudeTurnFromHookState(anthropicSession);
    if (turn) {
      trace.turn_id ||= turn;
      trace.root_turn_id ||= turn;
      trace.turn_identity_source ||= 'claude_hook_prompt_boundary';
    }
  }
  const record = {
    recordType: 'api_snapshot',
    captureId,
    captureStage: 'combined',
    sourceNamespace: FULL_TRACE_CAPTURE_SOURCE_NAMESPACE,
    requestId: responseHeaders['x-client-request-id'] || requestHeaders['x-client-request-id'] || null,
    upstreamRequestId: responseHeaders['x-request-id'] || null,
    startedAt: startedAt.toISOString(),
    finishedAt: new Date().toISOString(),
    method: req.method,
    inboundPath: req.url,
    proxiedPath,
    apiKeyFingerprint,
    actor: actor || null,
    actorMetadataStatus,
    requestHeaders,
    requestBodyText,
    requestTruncated: requestCapture.truncated,
    requestBytesCaptured: requestCapture.bytes,
    requestBodySha256: crypto.createHash('sha256').update(requestBodyBytes).digest('hex'),
    responseStatus: response ? response.status : null,
    responseHeaders,
    responseBodyText,
    responseTruncated: responseCapture.truncated,
    responseBytesCaptured: responseCapture.bytes,
    responseBodySha256: crypto.createHash('sha256').update(responseBodyBytes).digest('hex'),
    responseBytesForwarded,
    responseBytesForwardedAtClientClose,
    clientRequestAborted,
    clientResponseClosedBeforeFinish,
    clientResponseFinished,
    upstreamResponseCompleted,
    responseProtocolTerminalObserved: responseStreamState?.protocolTerminalObserved ?? null,
    responseProtocolTerminalEvent: responseStreamState?.protocolTerminalEvent ?? null,
    responseProtocolTerminalByteOffset: responseStreamState?.protocolTerminalByteOffset ?? null,
    responseFramingDoneObserved: responseStreamState?.framingDoneObserved ?? null,
    responseFramingDoneByteOffset: responseStreamState?.framingDoneByteOffset ?? null,
    responseProtocolTerminalObservedAtClientClose,
    responseFramingDoneObservedAtClientClose,
    traceContext: traceContext.trace,
    fieldEvidence: traceContext.evidence,
    fieldEvidenceConflicts: traceContext.conflicts,
    traceContextErrors: traceContext.errors,
    stream: String(response?.headers.get('content-type') || '').toLowerCase().includes('text/event-stream'),
    captureError: responseError ? (responseError.message || String(responseError)).slice(0, 500) : null,
    captureErrorCode: responseError ? (errorCauseCode(responseError) || null) : null,
  };
  if (captureTransaction) {
    // The transaction owns the exact request/response byte spools. Keep the
    // in-memory buffers above only as a fallback/debug view; finalization reads
    // and hashes the durable spools itself.
    const {
      requestBodyText: _requestBodyText,
      requestTruncated: _requestTruncated,
      requestBytesCaptured: _requestBytesCaptured,
      requestBodySha256: _requestBodySha256,
      responseBodyText: _responseBodyText,
      responseTruncated: _responseTruncated,
      responseBytesCaptured: _responseBytesCaptured,
      responseBodySha256: _responseBodySha256,
      ...metadata
    } = record;
    await finalizeFullTraceCapture(captureTransaction, metadata);
  } else {
    await submitFullTraceCapture(record);
  }
}

function trackFullTraceLocalWrite(promise) {
  fullTracePendingLocalWrites.add(promise);
  promise.then(
    () => fullTracePendingLocalWrites.delete(promise),
    () => fullTracePendingLocalWrites.delete(promise),
  );
  return promise;
}

async function startFullTraceCaptureOutbox() {
  if (!FULL_TRACE_CAPTURE_ENABLED) return;
  try {
    await fullTraceOutbox.start();
    fullTraceSubmitterStatus.lastError = null;
  } catch (error) {
    // The proxy remains fail-open. A later request will retry initialization
    // through enqueue(), while health makes the unavailable outbox visible.
    fullTraceSubmitterStatus.lastError = (error.message || String(error)).slice(0, 500);
    fullTraceCaptureStatus.lastError = fullTraceSubmitterStatus.lastError;
  }
}

async function mapLimit(items, concurrency, mapper) {
  const list = Array.isArray(items) ? items : [];
  if (!list.length) return [];
  const width = Math.min(Math.max(Number(concurrency || 1), 1), list.length);
  const results = new Array(list.length);
  let nextIndex = 0;
  await Promise.all(Array.from({ length: width }, async () => {
    while (nextIndex < list.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await mapper(list[index], index);
    }
  }));
  return results;
}

function relayUsageShape(stats = {}, overrideRequests = null) {
  const requests = Number(overrideRequests ?? stats.requests ?? 0);
  const inputTokens = Number(stats.input_tokens || stats.inputTokens || 0);
  const outputTokens = Number(stats.output_tokens || stats.outputTokens || 0);
  const cacheCreateTokens = Number(stats.cache_creation_tokens || stats.cacheCreateTokens || 0);
  const cacheReadTokens = Number(stats.cache_read_tokens || stats.cacheReadTokens || 0);
  const allTokens = Number(stats.total_tokens || stats.allTokens || inputTokens + outputTokens + cacheCreateTokens + cacheReadTokens);
  const cost = Number(stats.actual_cost ?? stats.cost ?? 0);
  return {
    tokens: allTokens,
    inputTokens,
    outputTokens,
    cacheCreateTokens,
    cacheReadTokens,
    allTokens,
    requests,
    cost,
    formattedCost: formatCost(cost),
    costMetadata: {
      estimated: false,
      source: 'stored',
    },
  };
}

function emptyUsageShape() {
  return relayUsageShape({});
}

function addUsageShape(target, item = {}) {
  target.tokens += Number(item.tokens || item.allTokens || 0);
  target.inputTokens += Number(item.inputTokens || 0);
  target.outputTokens += Number(item.outputTokens || 0);
  target.cacheCreateTokens += Number(item.cacheCreateTokens || 0);
  target.cacheReadTokens += Number(item.cacheReadTokens || 0);
  target.allTokens += Number(item.allTokens || item.tokens || 0);
  target.requests += Number(item.requests || 0);
  target.cost += Number(item.cost || 0);
  target.formattedCost = formatCost(target.cost);
  return target;
}

function formatDay(date) {
  const shanghai = new Date(date.getTime() + 8 * 60 * 60 * 1000);
  return shanghai.toISOString().slice(0, 10);
}

function recentSevenDays() {
  const days = [];
  const now = new Date();
  for (let i = 6; i >= 0; i -= 1) {
    const day = new Date(now);
    day.setUTCDate(day.getUTCDate() - i);
    days.push(formatDay(day));
  }
  return days;
}

function periodDateRange(period = 'alltime') {
  const end = new Date();
  if (period === 'daily') {
    const day = formatDay(end);
    return { startDate: day, endDate: day };
  }
  if (period === 'monthly') {
    const endDay = formatDay(end);
    return { startDate: `${endDay.slice(0, 7)}-01`, endDate: endDay };
  }
  return null;
}

function dayFromApiDate(value) {
  if (!value) return '';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return String(value).slice(0, 10);
  return formatDay(parsed);
}

function normalizeStatus(status) {
  const value = String(status || '').toLowerCase();
  if (value === 'operational') return 'operational';
  if (value === 'degraded') return 'degraded';
  if (value === 'failed') return 'failed';
  if (value === 'error') return 'error';
  return 'unknown';
}

function statusLabel(status) {
  return {
    operational: '正常',
    degraded: '降级',
    failed: '失败',
    error: '错误',
    unknown: '未知',
  }[normalizeStatus(status)] || '未知';
}

function average(values) {
  const numbers = values.map(Number).filter((value) => Number.isFinite(value));
  if (!numbers.length) return null;
  return numbers.reduce((sum, value) => sum + value, 0) / numbers.length;
}

function firstArray(...values) {
  for (const value of values) {
    if (Array.isArray(value)) return value;
  }
  return [];
}

function adminListItems(payload) {
  return firstArray(payload?.items, payload?.data?.items, payload);
}

function parseApiDate(value) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString();
}

function gptModelName(item = {}) {
  return item.upstream_model || item.requested_model || item.model || item.primary_model || 'gpt';
}

function gptModelMatches(item = {}) {
  const model = String(item.model || '').toLowerCase();
  const requestedModel = String(item.requested_model || '').toLowerCase();
  const upstreamModel = String(item.upstream_model || '').toLowerCase();
  if (
    model.startsWith('legacy') ||
    requestedModel.startsWith('legacy') ||
    upstreamModel.startsWith('legacy')
  ) {
    return false;
  }
  const fields = [
    model,
    requestedModel,
    upstreamModel,
    item.primary_model,
    item.inbound_endpoint,
    item.upstream_endpoint,
  ].filter(Boolean).join(' ').toLowerCase();
  return fields.includes('gpt') || fields.includes('openai') || fields.includes('codex');
}

function usageLogTokens(item = {}) {
  return Number(item.total_tokens || 0) ||
    Number(item.input_tokens || 0) +
    Number(item.output_tokens || 0) +
    Number(item.cache_creation_tokens || 0) +
    Number(item.cache_read_tokens || 0) +
    Number(item.image_output_tokens || 0);
}

function usageLogCost(item = {}) {
  return Number(item.actual_cost ?? item.cost ?? 0);
}

function modelOption(model) {
  if (typeof model === 'string') {
    return { id: model, value: model, label: model };
  }
  const value = model.value || model.id || model.name || model.model;
  if (!value) return null;
  return {
    ...model,
    value,
    label: model.label || model.display_name || model.name || value,
  };
}

function modelOptions(models = []) {
  return models.map(modelOption).filter(Boolean);
}

function stableHash(value, length = 16) {
  const text = String(value || '');
  if (!text) return '';
  return crypto.createHash('sha256').update(text).digest('hex').slice(0, length);
}

function traceExportConfigured() {
  return Boolean(TRACE_EXPORT_ENABLED && LANGFUSE_BASE_URL && LANGFUSE_PUBLIC_KEY && LANGFUSE_SECRET_KEY);
}

function readTraceExportState() {
  try {
    return JSON.parse(fs.readFileSync(TRACE_EXPORT_STATE, 'utf8'));
  } catch {
    return {
      lastUsageLogId: 0,
      exportedCount: 0,
      seenUsageLogIds: [],
    };
  }
}

function writeTraceExportState(state) {
  const dir = path.dirname(TRACE_EXPORT_STATE);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = `${TRACE_EXPORT_STATE}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(state, null, 2)}\n`);
  fs.renameSync(tmp, TRACE_EXPORT_STATE);
}

function compactSeenUsageLogIds(values = []) {
  const ids = [...new Set(values.map((value) => Number(value)).filter((value) => Number.isFinite(value) && value > 0))];
  return ids.sort((a, b) => a - b).slice(-1000).map(String);
}

function cloneJson(value) {
  if (value === null || value === undefined) return value;
  return JSON.parse(JSON.stringify(value));
}

function usageCacheKey(record, period) {
  return `${record.id || ''}:${stableHash(record.apiKey, 16)}:${period || 'alltime'}`;
}

function trimUsageCache(now = Date.now()) {
  for (const [key, entry] of apiStatsUsageCache.entries()) {
    if (entry.expiresAt <= now && !entry.promise) {
      apiStatsUsageCache.delete(key);
      apiStatsUsageCacheStats.evictionsExpired += 1;
    }
  }
  while (apiStatsUsageCache.size > API_STATS_USAGE_CACHE_MAX) {
    const oldestKey = apiStatsUsageCache.keys().next().value;
    if (!oldestKey) break;
    apiStatsUsageCache.delete(oldestKey);
    apiStatsUsageCacheStats.evictionsCapacity += 1;
  }
}

async function cachedApiStatsUsage(record, period, fetcher) {
  if (!API_STATS_USAGE_CACHE_TTL_MS) return fetcher();
  const key = usageCacheKey(record, period);
  const now = Date.now();
  const cached = apiStatsUsageCache.get(key);
  if (cached && cached.value !== undefined && cached.expiresAt > now) {
    apiStatsUsageCacheStats.hits += 1;
    return cloneJson(cached.value);
  }
  if (cached?.promise) {
    apiStatsUsageCacheStats.inFlightHits += 1;
    return cloneJson(await cached.promise);
  }
  apiStatsUsageCacheStats.misses += 1;

  const promise = Promise.resolve()
    .then(fetcher)
    .then((value) => {
      apiStatsUsageCache.set(key, {
        value: cloneJson(value),
        expiresAt: Date.now() + API_STATS_USAGE_CACHE_TTL_MS,
        promise: null,
      });
      trimUsageCache();
      return value;
    })
    .catch((error) => {
      apiStatsUsageCache.delete(key);
      apiStatsUsageCacheStats.errors += 1;
      throw error;
    });
  apiStatsUsageCache.set(key, {
    value: undefined,
    expiresAt: now + API_STATS_USAGE_CACHE_TTL_MS,
    promise,
  });
  trimUsageCache(now);
  return cloneJson(await promise);
}

function langfuseAuthHeader() {
  return `Basic ${Buffer.from(`${LANGFUSE_PUBLIC_KEY}:${LANGFUSE_SECRET_KEY}`).toString('base64')}`;
}

async function langfuseFetch(pathname, options = {}) {
  const response = await fetch(`${LANGFUSE_BASE_URL}${pathname}`, {
    ...options,
    headers: {
      authorization: langfuseAuthHeader(),
      'content-type': 'application/json',
      ...(options.headers || {}),
    },
  });
  const text = await response.text();
  let payload = {};
  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    payload = { raw: text };
  }
  if (!response.ok && response.status !== 207 && response.status !== 409) {
    const error = new Error(payload.message || payload.error || response.statusText);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return { response, payload };
}

async function ensureTraceExportDataset() {
  if (traceExportDatasetReady) return;
  try {
    await langfuseFetch('/api/public/v2/datasets', {
      method: 'POST',
      body: JSON.stringify({
        name: TRACE_EXPORT_DATASET,
        description: 'Router V2 online forwarding usage exported from Sub2API usage logs.',
        metadata: {
          source: 'router_v2_relay_shell',
          environment: TRACE_EXPORT_ENVIRONMENT,
          kind: 'online_forwarding_trace',
        },
      }),
    });
  } catch (error) {
    if (error.status !== 409 && error.status !== 400) throw error;
    await langfuseFetch(`/api/public/v2/datasets/${encodeURIComponent(TRACE_EXPORT_DATASET)}`);
  }
  traceExportDatasetReady = true;
}

function usageTraceId(item = {}) {
  return `router-v2-usage-${item.id}`;
}

function usageObservationId(item = {}) {
  return `router-v2-usage-${item.id}-generation`;
}

function dateMinusMs(value, ms) {
  const end = new Date(value || Date.now());
  if (Number.isNaN(end.getTime())) return new Date().toISOString();
  return new Date(end.getTime() - Math.max(Number(ms || 0), 0)).toISOString();
}

function sanitizeUsageLog(item = {}) {
  const apiKey = item.api_key || {};
  const user = item.user || {};
  const account = item.account || {};
  const group = item.group || {};
  const model = gptModelName(item);
  const createdAt = parseApiDate(item.created_at) || new Date().toISOString();
  const durationMs = Number(item.duration_ms || 0);
  const traceId = usageTraceId(item);
  const observationId = usageObservationId(item);
  const inputTokens = Number(item.input_tokens || 0);
  const outputTokens = Number(item.output_tokens || 0);
  const cacheCreationTokens = Number(item.cache_creation_tokens || 0);
  const cacheReadTokens = Number(item.cache_read_tokens || 0);
  const totalTokens = usageLogTokens(item);
  const cost = usageLogCost(item);
  const metadata = {
    source: 'sub2api_usage_log',
    usageLogId: Number(item.id),
    requestType: item.request_type || null,
    stream: item.stream ?? null,
    inboundEndpoint: item.inbound_endpoint || null,
    upstreamEndpoint: item.upstream_endpoint || null,
    requestedModel: item.requested_model || null,
    upstreamModel: item.upstream_model || null,
    model,
    durationMs,
    userId: item.user_id || null,
    userEmail: user.email || null,
    userName: user.username || null,
    apiKeyId: item.api_key_id || null,
    apiKeyName: apiKey.name || null,
    apiKeyFingerprint: stableHash(apiKey.key),
    accountId: item.account_id || null,
    accountName: account.name || null,
    groupId: item.group_id || null,
    groupName: group.name || null,
    groupPlatform: group.platform || null,
    billingType: item.billing_type ?? null,
    pricingSource: item.pricing_source || null,
  };
  return {
    id: Number(item.id),
    traceId,
    observationId,
    createdAt,
    startTime: dateMinusMs(createdAt, durationMs),
    endTime: createdAt,
    userId: user.email || (item.user_id ? `sub2api-user-${item.user_id}` : null),
    sessionId: item.api_key_id ? `api-key-${item.api_key_id}` : null,
    model,
    durationMs,
    inputTokens,
    outputTokens,
    cacheCreationTokens,
    cacheReadTokens,
    totalTokens,
    cost,
    metadata,
  };
}

function shouldExportTraceUsageLog(item = {}) {
  return !traceExportSkipReason(item);
}

function traceExportSkipReason(item = {}) {
  const modelFields = [
    item.model,
    item.requested_model,
    item.upstream_model,
  ].filter(Boolean).join(' ').toLowerCase();
  const requestId = String(item.request_id || '').toLowerCase();
  const userAgent = String(item.user_agent || '').toLowerCase();
  const apiKey = item.api_key || {};
  const user = item.user || {};
  const apiKeyName = String(apiKey.name || '').toLowerCase();
  const userName = String(user.username || '').toLowerCase();
  const userEmail = String(user.email || '').toLowerCase();
  const endpoints = [
    item.inbound_endpoint,
    item.upstream_endpoint,
  ].filter(Boolean).join(' ').toLowerCase();
  if (modelFields.split(/\s+/).some((field) => field.startsWith('legacy'))) return 'legacy_model';
  if (requestId.startsWith('legacy-')) return 'legacy_request_id';
  if (userAgent.startsWith('legacy-relay')) return 'legacy_user_agent';
  if (endpoints.includes('legacy-import')) return 'legacy_import_endpoint';
  if (
    TRACE_EXPORT_FILTER_MECHANICAL_MONITOR
    && (
      apiKeyName === TRACE_EXPORT_MECHANICAL_KEY_NAME
      || userName === TRACE_EXPORT_MECHANICAL_USER_NAME
      || userEmail.startsWith(`${TRACE_EXPORT_MECHANICAL_USER_NAME}-`)
    )
  ) {
    return 'mechanical_monitor';
  }
  return null;
}

function traceExportEvents(item) {
  const traceName = `router-v2 ${item.metadata.groupPlatform || 'api'} ${item.model}`;
  return [
    {
      id: `${item.traceId}-trace-create`,
      type: 'trace-create',
      timestamp: item.createdAt,
      body: {
        id: item.traceId,
        timestamp: item.createdAt,
        name: traceName,
        userId: item.userId,
        sessionId: item.sessionId,
        environment: TRACE_EXPORT_ENVIRONMENT,
        release: 'router-v2-relay-shell',
        version: 'usage-log-export-v1',
        tags: ['router-v2', 'sub2api', 'online-forwarding'],
        input: {
          endpoint: item.metadata.inboundEndpoint,
          model: item.metadata.requestedModel || item.model,
        },
        output: {
          status: 'logged',
          totalTokens: item.totalTokens,
          cost: item.cost,
        },
        metadata: item.metadata,
      },
    },
    {
      id: `${item.observationId}-generation-create`,
      type: 'generation-create',
      timestamp: item.createdAt,
      body: {
        id: item.observationId,
        traceId: item.traceId,
        name: item.model,
        startTime: item.startTime,
        endTime: item.endTime,
        completionStartTime: item.endTime,
        model: item.model,
        environment: TRACE_EXPORT_ENVIRONMENT,
        usage: {
          promptTokens: item.inputTokens,
          completionTokens: item.outputTokens,
          totalTokens: item.totalTokens,
        },
        usageDetails: {
          input: item.inputTokens,
          output: item.outputTokens,
          total: item.totalTokens,
          cache_creation: item.cacheCreationTokens,
          cache_read: item.cacheReadTokens,
        },
        costDetails: {
          total: item.cost,
        },
        metadata: {
          usageLogId: item.id,
          accountId: item.metadata.accountId,
          accountName: item.metadata.accountName,
          groupId: item.metadata.groupId,
          groupName: item.metadata.groupName,
          inboundEndpoint: item.metadata.inboundEndpoint,
          upstreamEndpoint: item.metadata.upstreamEndpoint,
          durationMs: item.durationMs,
        },
      },
    },
  ];
}

async function createTraceDatasetItem(item) {
  await langfuseFetch('/api/public/dataset-items', {
    method: 'POST',
    body: JSON.stringify({
      id: `${item.traceId}-dataset-item`,
      datasetName: TRACE_EXPORT_DATASET,
      sourceTraceId: item.traceId,
      sourceObservationId: item.observationId,
      input: {
        usageLogId: item.id,
        endpoint: item.metadata.inboundEndpoint,
        model: item.metadata.requestedModel || item.model,
        accountName: item.metadata.accountName,
        groupName: item.metadata.groupName,
      },
      expectedOutput: {
        status: 'forwarded',
        totalTokens: item.totalTokens,
        cost: item.cost,
        durationMs: item.durationMs,
      },
      metadata: {
        source: 'router_v2_usage_log_exporter',
        environment: TRACE_EXPORT_ENVIRONMENT,
        traceId: item.traceId,
        observationId: item.observationId,
        usageLogId: item.id,
        userId: item.metadata.userId,
        userEmail: item.metadata.userEmail,
        apiKeyId: item.metadata.apiKeyId,
        accountId: item.metadata.accountId,
        groupId: item.metadata.groupId,
      },
    }),
  });
}

function appendTraceExportFactsLedger(items = []) {
  if (!TRACE_EXPORT_FACTS_LEDGER || !items.length) return;
  const records = items.map((item) => JSON.stringify({
    exportedAt: new Date().toISOString(),
    usageLogId: item.id,
    traceId: item.traceId,
    observationId: item.observationId,
    datasetItemId: `${item.traceId}-dataset-item`,
    source: 'router_v2_usage_log_exporter',
    version: 'usage-log-export-v1',
  })).join('\n');
  fs.mkdirSync(path.dirname(TRACE_EXPORT_FACTS_LEDGER), { recursive: true, mode: 0o700 });
  fs.appendFileSync(TRACE_EXPORT_FACTS_LEDGER, `${records}\n`, { mode: 0o600 });
  traceExportStatus.lastFactsLedgerWriteAt = new Date().toISOString();
  traceExportStatus.lastFactsLedgerError = null;
}

async function fetchTraceExportUsageLogs(state) {
  const end = new Date();
  const defaultStart = new Date(end.getTime() - TRACE_EXPORT_LOOKBACK_DAYS * 24 * 60 * 60 * 1000);
  const cursorStart = state.lastScannedUsageLogCreatedAt || state.lastUsageLogCreatedAt;
  const parsedCursorStart = cursorStart ? new Date(cursorStart) : null;
  const start = parsedCursorStart && !Number.isNaN(parsedCursorStart.getTime())
    ? new Date(parsedCursorStart.getTime() - TRACE_EXPORT_CURSOR_OVERLAP_MS)
    : defaultStart;
  const query = [
    `start_date=${encodeURIComponent(formatDay(start))}`,
    `end_date=${encodeURIComponent(formatDay(end))}`,
    `timezone=${encodeURIComponent('Asia/Shanghai')}`,
    'sort_by=created_at',
    'sort_order=desc',
  ].join('&');
  const basePath = `/api/v1/admin/usage?${query}`;
  const lastId = Number(state.lastUsageLogId || 0);
  const candidatesById = new Map();
  const scan = {
    lastScanStrategy: 'admin-usage-desc-id-cursor-v2',
    lastScanStartedAt: new Date().toISOString(),
    lastScanPages: 0,
    lastScanFetchedRows: 0,
    lastScanCandidateRows: 0,
    lastScanReturnedRows: 0,
    lastScanReachedCursor: false,
    lastScanWindowStartDate: formatDay(start),
    lastScanWindowEndDate: formatDay(end),
    lastScanPageSize: TRACE_EXPORT_PAGE_SIZE,
    lastScanMaxPages: TRACE_EXPORT_MAX_SCAN_PAGES,
  };

  for (let page = 1; page <= TRACE_EXPORT_MAX_SCAN_PAGES; page += 1) {
    const payload = await listAdminUsagePage(basePath, page, TRACE_EXPORT_PAGE_SIZE);
    const items = adminListItems(payload);
    scan.lastScanPages = page;
    scan.lastScanFetchedRows += items.length;
    if (!items.length) {
      scan.lastScanReachedCursor = true;
      break;
    }

    for (const item of items) {
      const id = Number(item.id || 0);
      if (!Number.isFinite(id) || id <= 0) continue;
      if (id <= lastId) {
        scan.lastScanReachedCursor = true;
        continue;
      }
      candidatesById.set(id, item);
    }

    if (scan.lastScanReachedCursor || items.length < TRACE_EXPORT_PAGE_SIZE) {
      scan.lastScanReachedCursor = true;
      break;
    }
  }

  const candidates = [...candidatesById.entries()]
    .sort(([left], [right]) => left - right)
    .map(([, item]) => item);
  scan.lastScanCandidateRows = candidates.length;
  const logs = candidates.slice(0, TRACE_EXPORT_BATCH_SIZE);
  scan.lastScanReturnedRows = logs.length;
  const returnedIds = logs.map((item) => Number(item.id || 0)).filter((id) => Number.isFinite(id) && id > 0);
  scan.lastScanOldestReturnedUsageLogId = returnedIds.length ? Math.min(...returnedIds) : null;
  scan.lastScanNewestReturnedUsageLogId = returnedIds.length ? Math.max(...returnedIds) : null;
  scan.lastScanFinishedAt = new Date().toISOString();

  if (!scan.lastScanReachedCursor && candidates.length > TRACE_EXPORT_BATCH_SIZE) {
    const error = new Error(`trace export backlog exceeded scan cap before reaching usage_log_id=${lastId}`);
    error.scan = scan;
    throw error;
  }

  return { logs, scan };
}

async function exportUsageLogBatch(logs) {
  if (!logs.length) return [];
  const sanitized = logs.map(sanitizeUsageLog);
  const batch = sanitized.flatMap(traceExportEvents);
  const { response, payload } = await langfuseFetch('/api/public/ingestion', {
    method: 'POST',
    body: JSON.stringify({
      batch,
      metadata: {
        source: 'router_v2_usage_log_exporter',
        environment: TRACE_EXPORT_ENVIRONMENT,
      },
    }),
  });
  const errors = Array.isArray(payload.errors) ? payload.errors : [];
  if (response.status === 207 && errors.length) {
    const error = new Error(`Langfuse ingestion returned ${errors.length} errors`);
    error.payload = payload;
    throw error;
  }

  for (const item of sanitized) {
    await createTraceDatasetItem(item);
  }
  try {
    appendTraceExportFactsLedger(sanitized);
  } catch (error) {
    traceExportStatus.lastFactsLedgerError = error.message || 'trace export facts ledger write failed';
    console.error('trace exporter facts ledger failed:', traceExportStatus.lastFactsLedgerError);
  }
  return sanitized;
}

async function runTraceExportOnce() {
  traceExportStatus.configured = traceExportConfigured();
  traceExportStatus.running = true;
  traceExportStatus.lastRunAt = new Date().toISOString();
  try {
    if (!traceExportConfigured()) return;
    await ensureTraceExportDataset();
    const state = readTraceExportState();
    const { logs, scan } = await fetchTraceExportUsageLogs(state);
    Object.assign(traceExportStatus, scan);
    traceExportStatus.lastScannedUsageLogId = Number(state.lastUsageLogId || 0) || null;
    traceExportStatus.lastExportedUsageLogId = Number(state.lastExportedUsageLogId || state.lastUsageLogId || 0) || null;
    traceExportStatus.lastExportedTraceId = state.lastTraceId || null;
    traceExportStatus.exportedCount = Number(state.exportedCount || 0);
    traceExportStatus.skippedCount = Number(state.skippedCount || 0);
    traceExportStatus.filters = state.filters || traceExportStatus.filters;

    const activatedAfterUsageLogId = TRACE_EXPORT_FILTER_MECHANICAL_MONITOR
      ? Number(state.filters?.mechanicalMonitor?.activatedAfterUsageLogId || state.lastUsageLogId || 0)
      : null;
    const mechanicalSkipped = logs.filter((item) => traceExportSkipReason(item) === 'mechanical_monitor').length;
    const exportableLogs = logs.filter(shouldExportTraceUsageLog);
    const exported = await exportUsageLogBatch(exportableLogs);
    let nextState = {
      ...state,
      ...scan,
      lastScannedUsageLogId: Number(state.lastUsageLogId || 0) || null,
      lastExportedUsageLogId: Number(state.lastExportedUsageLogId || state.lastUsageLogId || 0) || null,
      exportedCount: Number(state.exportedCount || 0),
      skippedCount: Number(state.skippedCount || 0),
      filters: {
        ...(state.filters || {}),
        mechanicalMonitor: {
          ...(state.filters?.mechanicalMonitor || {}),
          enabled: TRACE_EXPORT_FILTER_MECHANICAL_MONITOR,
          userName: TRACE_EXPORT_MECHANICAL_USER_NAME,
          apiKeyName: TRACE_EXPORT_MECHANICAL_KEY_NAME,
          activatedAfterUsageLogId,
          skippedCount: Number(state.filters?.mechanicalMonitor?.skippedCount || 0),
        },
      },
      updatedAt: new Date().toISOString(),
    };
    if (logs.length) {
      const seen = new Set((state.seenUsageLogIds || []).map(String));
      for (const item of logs) seen.add(String(item.id));
      const lastScannedId = Math.max(Number(state.lastUsageLogId || 0), ...logs.map((item) => Number(item.id || 0)));
      const lastScannedLog = logs.reduce((latest, item) => (
        Number(item.id || 0) > Number(latest?.id || 0) ? item : latest
      ), null);
      nextState = {
        ...state,
        ...scan,
        lastUsageLogId: lastScannedId,
        lastScannedUsageLogId: lastScannedId,
        lastScannedUsageLogCreatedAt: parseApiDate(lastScannedLog?.created_at) || state.lastScannedUsageLogCreatedAt || null,
        exportedCount: Number(state.exportedCount || 0) + exported.length,
        skippedCount: Number(state.skippedCount || 0) + (logs.length - exported.length),
        seenUsageLogIds: compactSeenUsageLogIds([...seen]),
        updatedAt: new Date().toISOString(),
      };
      if (exported.length) {
        const last = exported[exported.length - 1];
        nextState.lastUsageLogCreatedAt = last.createdAt;
        nextState.lastTraceId = last.traceId;
        nextState.lastExportedUsageLogId = Math.max(
          Number(state.lastExportedUsageLogId || 0),
          ...exported.map((item) => item.id),
        );
      } else {
        nextState.lastExportedUsageLogId = Number(state.lastExportedUsageLogId || state.lastUsageLogId || 0) || null;
      }
    }
    nextState.filters = {
      ...(nextState.filters || {}),
      mechanicalMonitor: {
        ...(nextState.filters?.mechanicalMonitor || {}),
        enabled: TRACE_EXPORT_FILTER_MECHANICAL_MONITOR,
        userName: TRACE_EXPORT_MECHANICAL_USER_NAME,
        apiKeyName: TRACE_EXPORT_MECHANICAL_KEY_NAME,
        activatedAfterUsageLogId,
        skippedCount: Number(state.filters?.mechanicalMonitor?.skippedCount || 0) + mechanicalSkipped,
      },
    };
    writeTraceExportState(nextState);
    traceExportStatus.lastScannedUsageLogId = nextState.lastScannedUsageLogId;
    traceExportStatus.lastExportedUsageLogId = nextState.lastExportedUsageLogId;
    traceExportStatus.lastExportedTraceId = nextState.lastTraceId;
    traceExportStatus.exportedCount = nextState.exportedCount;
    traceExportStatus.skippedCount = nextState.skippedCount;
    traceExportStatus.filters = nextState.filters;
    if (logs.length || scan.lastScanFetchedRows > 0) {
      console.log(`trace exporter pages=${scan.lastScanPages} rows=${scan.lastScanFetchedRows} new=${logs.length} exported=${exported.length} reached_cursor=${scan.lastScanReachedCursor} last_scanned_usage_log_id=${nextState.lastUsageLogId || state.lastUsageLogId || 0}`);
    }
    traceExportStatus.lastError = null;
  } catch (error) {
    if (error.scan) Object.assign(traceExportStatus, error.scan);
    traceExportStatus.lastError = error.message || 'trace export failed';
    console.error('trace exporter failed:', traceExportStatus.lastError);
  } finally {
    traceExportStatus.running = false;
  }
}

function startTraceExporter() {
  traceExportStatus.configured = traceExportConfigured();
  if (!TRACE_EXPORT_ENABLED) {
    console.log('trace exporter disabled');
    return;
  }
  if (!traceExportConfigured()) {
    console.log('trace exporter enabled but Langfuse credentials/base URL are incomplete');
    return;
  }
  if (traceExportTimer) return;
  console.log(`trace exporter enabled, dataset=${TRACE_EXPORT_DATASET}, poll_ms=${TRACE_EXPORT_POLL_MS}`);
  const tick = () => {
    if (traceExportRunning) return;
    traceExportRunning = true;
    runTraceExportOnce().finally(() => {
      traceExportRunning = false;
    });
  };
  setTimeout(tick, TRACE_EXPORT_INITIAL_DELAY_MS);
  traceExportTimer = setInterval(tick, TRACE_EXPORT_POLL_MS);
  traceExportTimer.unref?.();
}

function watchdogRetentionMs() {
  return WATCHDOG_RETENTION_DAYS * 24 * 60 * 60 * 1000;
}

function watchdogStaleMs() {
  return Math.max(WATCHDOG_INTERVAL_MS * 3, 3 * 60 * 1000);
}

function normalizeWatchdogCheck(item = {}) {
  const finishedAt = parseApiDate(item.finishedAt || item.checkedAt || item.createdAt);
  if (!finishedAt) return null;
  const latencyMs = Number(item.latencyMs || 0);
  const ok = Boolean(item.ok);
  const slow = Boolean(item.slow || latencyMs >= WATCHDOG_SLOW_MS);
  const status = ok ? (slow ? 'degraded' : 'operational') : 'failed';
  return {
    id: String(item.id || stableHash(`${finishedAt}:${latencyMs}:${item.error || ''}`, 16)),
    ok,
    slow,
    status,
    statusLabel: item.statusLabel || statusLabel(status),
    startedAt: parseApiDate(item.startedAt) || finishedAt,
    finishedAt,
    checkedAt: finishedAt,
    latencyMs: Number.isFinite(latencyMs) && latencyMs > 0 ? latencyMs : null,
    model: item.model || WATCHDOG_MODEL,
    endpoint: item.endpoint || '/v1/responses',
    relayBase: item.relayBase || item.base || null,
    error: item.error ? String(item.error).slice(0, 500) : null,
  };
}

function loadWatchdogState() {
  const raw = readJsonFile(WATCHDOG_STATE_FILE, {});
  const cutoff = Date.now() - watchdogRetentionMs();
  const checks = asArray(raw.checks)
    .map(normalizeWatchdogCheck)
    .filter(Boolean)
    .filter((item) => new Date(item.finishedAt).getTime() >= cutoff)
    .sort((a, b) => new Date(a.finishedAt).getTime() - new Date(b.finishedAt).getTime());

  watchdogState.enabled = WATCHDOG_ENABLED;
  watchdogState.configured = Boolean(raw.configured || watchdogKeyCache || fs.existsSync(WATCHDOG_KEY_FILE));
  watchdogState.intervalMs = WATCHDOG_INTERVAL_MS;
  watchdogState.retentionDays = WATCHDOG_RETENTION_DAYS;
  watchdogState.model = WATCHDOG_MODEL;
  watchdogState.lastRunAt = parseApiDate(raw.lastRunAt) || null;
  watchdogState.lastAvailableAt = parseApiDate(raw.lastAvailableAt) || null;
  watchdogState.lastError = raw.lastError ? String(raw.lastError).slice(0, 500) : null;
  watchdogState.lastProbeId = raw.lastProbeId || null;
  watchdogState.checks = checks;
  return watchdogState;
}

function saveWatchdogState() {
  const payload = {
    enabled: watchdogState.enabled,
    configured: watchdogState.configured,
    intervalMs: watchdogState.intervalMs,
    retentionDays: watchdogState.retentionDays,
    model: watchdogState.model,
    lastRunAt: watchdogState.lastRunAt,
    lastAvailableAt: watchdogState.lastAvailableAt,
    lastError: watchdogState.lastError,
    lastProbeId: watchdogState.lastProbeId,
    updatedAt: new Date().toISOString(),
    checks: watchdogState.checks,
  };
  writeJsonFileAtomic(WATCHDOG_STATE_FILE, payload);
}

function appendWatchdogCheck(check) {
  const cutoff = Date.now() - watchdogRetentionMs();
  const normalized = normalizeWatchdogCheck(check);
  if (!normalized) return null;
  const nextChecks = [...watchdogState.checks, normalized]
    .filter((item) => new Date(item.finishedAt).getTime() >= cutoff)
    .sort((a, b) => new Date(a.finishedAt).getTime() - new Date(b.finishedAt).getTime());
  watchdogState.checks = nextChecks.slice(-12000);
  watchdogState.lastRunAt = normalized.finishedAt;
  watchdogState.lastProbeId = normalized.id;
  if (normalized.ok) watchdogState.lastAvailableAt = normalized.finishedAt;
  watchdogState.lastError = normalized.ok ? null : normalized.error;
  return normalized;
}

function randomSecret(prefix, bytes = 24) {
  return `${prefix}${crypto.randomBytes(bytes).toString('base64url')}`;
}

async function loginSub2apiUser(email, password) {
  const payload = await sub2apiRaw('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  });
  const data = unwrap(payload) || {};
  const token = data.access_token || data.token || payload.access_token || payload.token;
  if (!token) throw new Error(`Sub2API login did not return a token for ${email}`);
  return { token, user: data.user || payload.user || null };
}

async function findWatchdogUser() {
  const payload = await sub2apiAdmin(`/api/v1/admin/users?search=${encodeURIComponent(WATCHDOG_USER_EMAIL)}&page=1&page_size=10&include_subscriptions=false`);
  return adminListItems(payload).find((item) => String(item.email || '').toLowerCase() === WATCHDOG_USER_EMAIL.toLowerCase()) || null;
}

async function ensureWatchdogUser(password) {
  const notes = 'router-v2 global watchdog user; managed by relay-shell';
  try {
    const created = await sub2apiAdmin('/api/v1/admin/users', {
      method: 'POST',
      body: JSON.stringify({
        email: WATCHDOG_USER_EMAIL,
        password,
        username: WATCHDOG_USER_NAME,
        notes,
        balance: 1000000,
        concurrency: 1,
        rpm_limit: 5,
        allowed_groups: [DEFAULT_GROUP_ID],
      }),
    });
    return created;
  } catch (error) {
    if (![400, 409].includes(Number(error.status || 0))) throw error;
  }

  const existing = await findWatchdogUser();
  if (!existing?.id) throw new Error('watchdog user exists but could not be found by email');
  const status = 'active';
  const updated = await sub2apiAdmin(`/api/v1/admin/users/${existing.id}`, {
    method: 'PUT',
    body: JSON.stringify({
      email: WATCHDOG_USER_EMAIL,
      password,
      username: WATCHDOG_USER_NAME,
      notes,
      status,
      balance: Number(existing.balance ?? 1000000),
      concurrency: Number(existing.concurrency || 1),
      rpm_limit: Number(existing.rpm_limit || 5),
      allowed_groups: [DEFAULT_GROUP_ID],
    }),
  });
  return updated || existing;
}

async function watchdogKeyUsable(apiKey) {
  if (!apiKey) return false;
  try {
    await sub2apiRaw('/v1/models', {
      headers: { authorization: `Bearer ${apiKey}` },
    });
    return true;
  } catch {
    return false;
  }
}

async function createWatchdogApiKey(userToken, customKey) {
  const created = await sub2api('/api/v1/keys', {
    method: 'POST',
    headers: { authorization: `Bearer ${userToken}` },
    body: JSON.stringify({
      name: 'GPT watchdog',
      group_id: DEFAULT_GROUP_ID,
      custom_key: customKey,
      quota: 0,
      rate_limit_5h: 0,
      rate_limit_1d: 0,
      rate_limit_7d: 0,
    }),
  });
  return created;
}

async function ensureWatchdogApiKey() {
  if (watchdogKeyCache?.apiKey && await watchdogKeyUsable(watchdogKeyCache.apiKey)) {
    return watchdogKeyCache;
  }

  const persisted = readJsonFile(WATCHDOG_KEY_FILE, {});
  if (persisted.apiKey && await watchdogKeyUsable(persisted.apiKey)) {
    watchdogKeyCache = persisted;
    refreshFullTraceMonitorKeyFingerprints();
    watchdogState.configured = true;
    return watchdogKeyCache;
  }

  const password = persisted.password || randomSecret('wdp_', 24);
  const apiKey = persisted.apiKey || randomSecret('cr_watchdog_', 24);
  const user = await ensureWatchdogUser(password);
  const auth = await loginSub2apiUser(WATCHDOG_USER_EMAIL, password);

  let keyPayload;
  let finalApiKey = apiKey;
  try {
    keyPayload = await createWatchdogApiKey(auth.token, finalApiKey);
  } catch (error) {
    if (Number(error.status || 0) !== 409 && !String(error.message || '').toLowerCase().includes('exist')) throw error;
    finalApiKey = randomSecret('cr_watchdog_', 24);
    keyPayload = await createWatchdogApiKey(auth.token, finalApiKey);
  }

  watchdogKeyCache = {
    email: WATCHDOG_USER_EMAIL,
    password,
    apiKey: finalApiKey,
    userId: Number(user?.id || auth.user?.id || 0) || null,
    apiKeyId: Number(keyPayload?.id || 0) || null,
    groupId: DEFAULT_GROUP_ID,
    createdAt: persisted.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  writeJsonFileAtomic(WATCHDOG_KEY_FILE, watchdogKeyCache);
  refreshFullTraceMonitorKeyFingerprints();
  watchdogState.configured = true;
  return watchdogKeyCache;
}

function watchdogCheckSummary(checks) {
  const latencyValues = checks.map((item) => item.latencyMs).filter((value) => Number.isFinite(Number(value)));
  const successChecks = checks.filter((item) => item.ok).length;
  const failedChecks = checks.filter((item) => !item.ok).length;
  const latest = checks[checks.length - 1] || null;
  const latestAgeMs = latest ? Date.now() - new Date(latest.finishedAt).getTime() : Infinity;
  let status = latest?.status || 'unknown';
  let label = latest?.statusLabel || '等待监控';
  if (!latest) {
    status = 'unknown';
    label = '等待监控';
  } else if (latestAgeMs > watchdogStaleMs()) {
    status = latest.ok ? 'degraded' : 'failed';
    label = latest.ok ? '监控延迟' : '不可用';
  }

  return {
    status,
    statusLabel: label,
    totalChecks: checks.length,
    successChecks,
    failedChecks,
    uptimePercent: checks.length ? (successChecks / checks.length) * 100 : null,
    avgLatencyMs: average(latencyValues),
    p95LatencyMs: percentile(latencyValues, 95),
    lastCheckedAt: latest?.finishedAt || null,
    lastSuccessAt: watchdogState.lastAvailableAt || null,
    lastError: latest && !latest.ok ? latest.error : null,
  };
}

function statusFromAvailability(okCount, totalCount) {
  if (!totalCount) return 'unknown';
  const uptime = okCount / totalCount;
  if (uptime >= 0.97) return 'operational';
  if (uptime >= 0.9) return 'degraded';
  return 'failed';
}

function buildWatchdogBars(checks, bucketCount = 80) {
  const now = Date.now();
  const start = now - watchdogRetentionMs();
  const span = watchdogRetentionMs();
  const bucketMs = span / bucketCount;
  const buckets = Array.from({ length: bucketCount }, (_, index) => ({
    index,
    startAt: new Date(start + index * bucketMs).toISOString(),
    endAt: new Date(start + (index + 1) * bucketMs).toISOString(),
    checks: [],
  }));

  for (const check of checks) {
    const time = new Date(check.finishedAt).getTime();
    if (time < start || time > now) continue;
    const index = Math.min(bucketCount - 1, Math.max(0, Math.floor((time - start) / bucketMs)));
    buckets[index].checks.push(check);
  }

  return buckets.map((bucket) => {
    const count = bucket.checks.length;
    const okCount = bucket.checks.filter((item) => item.ok).length;
    const latencyValues = bucket.checks.map((item) => item.latencyMs).filter((value) => Number.isFinite(Number(value)));
    const status = statusFromAvailability(okCount, count);
    return {
      index: bucket.index,
      startAt: bucket.startAt,
      endAt: bucket.endAt,
      status,
      statusLabel: count ? `${okCount}/${count} 可用` : '暂无探测',
      checks: count,
      okChecks: okCount,
      uptimePercent: count ? (okCount / count) * 100 : null,
      avgLatencyMs: average(latencyValues),
    };
  });
}

function buildWatchdogDailyHistory(checks) {
  const days = recentSevenDays();
  const map = new Map(days.map((day) => [day, {
    date: day,
    checks: 0,
    okChecks: 0,
    failedChecks: 0,
    latencyValues: [],
    lastCheckedAt: null,
  }]));

  for (const check of checks) {
    const day = dayFromApiDate(check.finishedAt);
    const target = map.get(day);
    if (!target) continue;
    target.checks += 1;
    if (check.ok) target.okChecks += 1;
    else target.failedChecks += 1;
    if (Number.isFinite(Number(check.latencyMs))) target.latencyValues.push(Number(check.latencyMs));
    if (!target.lastCheckedAt || check.finishedAt > target.lastCheckedAt) target.lastCheckedAt = check.finishedAt;
  }

  return [...map.values()].map((item) => {
    const status = statusFromAvailability(item.okChecks, item.checks);
    return {
      ...item,
      status,
      statusLabel: item.checks ? `${item.okChecks}/${item.checks} 可用` : '暂无探测',
      uptimePercent: item.checks ? (item.okChecks / item.checks) * 100 : null,
      avgLatencyMs: average(item.latencyValues),
    };
  }).reverse();
}

async function runWatchdogProbe() {
  if (watchdogRunning) return null;
  watchdogRunning = true;
  watchdogState.running = true;
  const probeId = `gpt-watchdog-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
  const startedAt = new Date().toISOString();
  watchdogState.lastRunAt = startedAt;

  try {
    loadWatchdogState();
    const keyInfo = await ensureWatchdogApiKey();
    const result = await postRelayOpenAIResponse({
      apiKey: keyInfo.apiKey,
      model: WATCHDOG_MODEL,
      prompt: WATCHDOG_PROMPT,
      timeoutMs: WATCHDOG_TIMEOUT_MS,
    });
    const finishedAt = new Date().toISOString();
    const slow = Number(result.latencyMs || 0) >= WATCHDOG_SLOW_MS;
    const check = appendWatchdogCheck({
      id: probeId,
      ok: true,
      slow,
      status: slow ? 'degraded' : 'operational',
      statusLabel: slow ? '响应偏慢' : '正常',
      startedAt,
      finishedAt,
      latencyMs: result.latencyMs,
      model: WATCHDOG_MODEL,
      endpoint: '/v1/responses',
      relayBase: result.base,
    });
    saveWatchdogState();
    return check;
  } catch (error) {
    const finishedAt = new Date().toISOString();
    const check = appendWatchdogCheck({
      id: probeId,
      ok: false,
      slow: false,
      status: 'failed',
      statusLabel: '不可用',
      startedAt,
      finishedAt,
      latencyMs: null,
      model: WATCHDOG_MODEL,
      endpoint: '/v1/responses',
      error: error.message || 'watchdog probe failed',
    });
    watchdogState.configured = Boolean(watchdogKeyCache || fs.existsSync(WATCHDOG_KEY_FILE));
    saveWatchdogState();
    console.error('watchdog probe failed:', watchdogState.lastError);
    return check;
  } finally {
    watchdogState.running = false;
    watchdogRunning = false;
  }
}

function startWatchdog() {
  loadWatchdogState();
  if (!WATCHDOG_ENABLED) {
    console.log('GPT watchdog disabled');
    return;
  }
  if (watchdogTimer) return;
  console.log(`GPT watchdog enabled, model=${WATCHDOG_MODEL}, interval_ms=${WATCHDOG_INTERVAL_MS}, retention_days=${WATCHDOG_RETENTION_DAYS}`);
  const tick = () => {
    runWatchdogProbe().catch((error) => {
      watchdogState.lastError = error.message || 'watchdog tick failed';
      console.error('watchdog tick failed:', watchdogState.lastError);
    });
  };
  const initialTimer = setTimeout(tick, WATCHDOG_INITIAL_DELAY_MS);
  initialTimer.unref?.();
  watchdogTimer = setInterval(tick, WATCHDOG_INTERVAL_MS);
  watchdogTimer.unref?.();
}

async function watchdogGptChannelHealth() {
  loadWatchdogState();
  const checks = watchdogState.checks;
  const summaryBase = watchdogCheckSummary(checks);
  const bars = buildWatchdogBars(checks, 80);
  const history = buildWatchdogDailyHistory(checks);
  const latest = checks[checks.length - 1] || null;
  const status = summaryBase.status;
  const component = {
    id: 'gpt-relay-watchdog',
    name: 'GPT API 服务',
    description: '用户 relay 入口到 Sub2API GPT 分组的真实请求探测',
    endpoint: '/v1/responses',
    model: WATCHDOG_MODEL,
    status,
    statusLabel: summaryBase.statusLabel,
    requests7d: summaryBase.totalChecks,
    checks7d: summaryBase.totalChecks,
    successChecks7d: summaryBase.successChecks,
    failedChecks7d: summaryBase.failedChecks,
    uptimePercent: summaryBase.uptimePercent,
    latencyMs: summaryBase.avgLatencyMs,
    p95LatencyMs: summaryBase.p95LatencyMs,
    lastCheckedAt: summaryBase.lastCheckedAt,
    lastSuccessAt: summaryBase.lastSuccessAt,
    lastAvailableAt: watchdogState.lastAvailableAt,
    latestError: summaryBase.lastError,
    timeline: bars,
  };

  const headline = {
    operational: '全部系统正常',
    degraded: '系统响应偏慢',
    failed: 'GPT 转发不可用',
    error: '监控异常',
    unknown: '等待监控数据',
  }[status] || '等待监控数据';

  const incidentMessage = status === 'operational'
    ? '最近一次真实 GPT 探测通过，用户 API 通路可用。'
    : (latest?.error || '监控正在等待下一次探测结果。');

  const summary = {
    total: 1,
    available: status === 'operational' ? 1 : 0,
    degraded: status === 'degraded' ? 1 : 0,
    failed: status === 'failed' ? 1 : 0,
    unknown: status === 'unknown' ? 1 : 0,
    status,
    statusLabel: summaryBase.statusLabel,
    totalRequests: summaryBase.totalChecks,
    totalChecks: summaryBase.totalChecks,
    successChecks: summaryBase.successChecks,
    failedChecks: summaryBase.failedChecks,
    uptimePercent: summaryBase.uptimePercent,
    totalTokens: 0,
    totalCost: 0,
    avgLatencyMs: summaryBase.avgLatencyMs,
    p95LatencyMs: summaryBase.p95LatencyMs,
    lastCheckedAt: summaryBase.lastCheckedAt,
    lastSuccessAt: summaryBase.lastSuccessAt,
    lastAvailableAt: watchdogState.lastAvailableAt,
    lastError: summaryBase.lastError,
  };

  return {
    configured: watchdogState.configured,
    source: 'relay_watchdog',
    sourceLabel: '全局稳定性',
    sourceDescription: '服务端每分钟通过真实 relay API 探测一次，保存最近 7 天结果。',
    window: '7d',
    monitorIntervalMs: WATCHDOG_INTERVAL_MS,
    retentionDays: WATCHDOG_RETENTION_DAYS,
    summary,
    monitors: [component],
    models: [{
      model: WATCHDOG_MODEL,
      requests: summaryBase.totalChecks,
      checks: summaryBase.totalChecks,
      successChecks: summaryBase.successChecks,
      failedChecks: summaryBase.failedChecks,
      uptimePercent: summaryBase.uptimePercent,
      avgLatencyMs: summaryBase.avgLatencyMs,
    }],
    trend: bars,
    statusPage: {
      title: 'sub2api Relay Status',
      brand: 'OpenAI',
      product: 'sub2api monitor',
      headline,
      incidentTitle: 'GPT 转发通路',
      incidentMessage,
      incidentMeta: summaryBase.lastCheckedAt ? `最近检查 ${summaryBase.lastCheckedAt}` : '等待首次检查',
      rangeLabel: '过去 7 天',
      components: [component],
      bars,
      history,
    },
  };
}

function percentile(values, p) {
  const numbers = values.map(Number).filter((value) => Number.isFinite(value)).sort((a, b) => a - b);
  if (!numbers.length) return null;
  const index = Math.min(numbers.length - 1, Math.max(0, Math.ceil((p / 100) * numbers.length) - 1));
  return numbers[index];
}

async function listAllAdminUsage(path) {
  const first = await sub2apiAdmin(`${path}&page=1&page_size=1000&exact_total=true`);
  const items = adminListItems(first);
  const pages = Number(first?.pages || first?.data?.pages || 1);
  if (pages <= 1) return items;

  const rest = await Promise.all(Array.from({ length: pages - 1 }, (_, index) => (
    sub2apiAdmin(`${path}&page=${index + 2}&page_size=1000&exact_total=true`)
  )));
  for (const payload of rest) items.push(...adminListItems(payload));
  return items;
}

async function listAdminUsagePage(path, page, pageSize) {
  return sub2apiAdmin(`${path}&page=${page}&page_size=${pageSize}`);
}

function apiDateInFuture(value) {
  if (!value) return false;
  const date = new Date(value);
  return !Number.isNaN(date.getTime()) && date.getTime() > Date.now();
}

function apiDateIsRecent(value, windowMs) {
  if (!value) return false;
  const date = new Date(value);
  return !Number.isNaN(date.getTime()) && Date.now() - date.getTime() <= windowMs;
}

function currentAccountStatus(account = {}) {
  if (account.status !== 'active') return 'failed';
  if (account.schedulable === false) return 'degraded';
  if (apiDateInFuture(account.temp_unschedulable_until) || apiDateInFuture(account.overload_until)) return 'degraded';
  if (apiDateIsRecent(account.rate_limited_at, 10 * 60 * 1000)) return 'degraded';
  return 'operational';
}

function currentAccountStatusLabel(account = {}) {
  if (account.status !== 'active') return '停用';
  if (account.schedulable === false) return '不可调度';
  if (apiDateIsRecent(account.rate_limited_at, 10 * 60 * 1000)) return '限流中';
  if (apiDateInFuture(account.temp_unschedulable_until) || apiDateInFuture(account.overload_until)) return '临时不可用';
  return '正常';
}

function emptyDailyMap(days) {
  return new Map(days.map((day) => [day, {
    date: day,
    requests: 0,
    totalTokens: 0,
    cost: 0,
    latencyValues: [],
  }]));
}

function dailyPointsFromMap(map) {
  return [...map.values()].map((item) => ({
    date: item.date,
    requests: item.requests,
    totalTokens: item.totalTokens,
    cost: item.cost,
    avgLatencyMs: average(item.latencyValues),
    status: item.requests > 0 ? 'operational' : 'unknown',
    statusLabel: item.requests > 0 ? `${item.requests} 次` : '无请求',
    checkedAt: `${item.date}T00:00:00.000Z`,
  }));
}

async function currentGptChannelHealth() {
  const days = recentSevenDays();
  const startDate = days[0];
  const endDate = days[days.length - 1];
  const query = `start_date=${encodeURIComponent(startDate)}&end_date=${encodeURIComponent(endDate)}&timezone=${encodeURIComponent('Asia/Shanghai')}&sort_by=created_at&sort_order=desc`;
  const checkedAt = new Date().toISOString();
  const [usageLogs, accountPayload] = await Promise.all([
    listAllAdminUsage(`/api/v1/admin/usage?${query}`),
    sub2apiAdmin('/api/v1/admin/accounts?platform=openai&page=1&page_size=1000'),
  ]);

  const accounts = adminListItems(accountPayload).filter((account) => !account.deleted_at);
  const logs = usageLogs.filter(gptModelMatches);
  const modelsByName = new Map();
  const timelineMap = emptyDailyMap(days);
  const latencyValues = [];
  let lastSuccessAt = null;
  let totalTokens = 0;
  let totalCost = 0;

  for (const item of logs) {
    const model = gptModelName(item);
    const tokens = usageLogTokens(item);
    const cost = usageLogCost(item);
    const latency = Number(item.duration_ms || 0);
    const day = dayFromApiDate(item.created_at);

    totalTokens += tokens;
    totalCost += cost;
    if (latency) latencyValues.push(latency);
    const requestAt = parseApiDate(item.created_at);
    if (requestAt && (!lastSuccessAt || requestAt > lastSuccessAt)) lastSuccessAt = requestAt;

    if (timelineMap.has(day)) {
      const target = timelineMap.get(day);
      target.requests += 1;
      target.totalTokens += tokens;
      target.cost += cost;
      if (latency) target.latencyValues.push(latency);
    }

    if (!modelsByName.has(model)) {
      modelsByName.set(model, { model, requests: 0, totalTokens: 0, cost: 0 });
    }
    const target = modelsByName.get(model);
    target.requests += 1;
    target.totalTokens += tokens;
    target.cost += cost;
  }

  const accountStatuses = accounts.map((account) => currentAccountStatus(account));
  const activeAccountCount = accounts.filter((account) => account.status === 'active').length;
  const schedulableAccountCount = accounts.filter((account) => currentAccountStatus(account) === 'operational').length;
  let status = 'unknown';
  if (schedulableAccountCount > 0) {
    status = 'operational';
  } else if (accountStatuses.includes('degraded')) {
    status = 'degraded';
  } else if (accounts.length > 0) {
    status = 'failed';
  }
  const statusText = {
    operational: '实时可用',
    degraded: '调度异常',
    failed: '不可用',
    unknown: '未配置',
  }[status] || '未知';

  const models = [...modelsByName.values()].sort((a, b) => b.requests - a.requests);
  const timeline = dailyPointsFromMap(timelineMap);
  const monitors = accounts.length ? [{
    id: 'gpt-user-route',
    name: 'GPT API 服务',
    model: models[0]?.model || 'gpt',
    status,
    statusLabel: statusText,
    schedulable: schedulableAccountCount > 0,
    accountCount: accounts.length,
    activeAccountCount,
    schedulableAccountCount,
    requests7d: logs.length,
    totalTokens7d: totalTokens,
    cost7d: totalCost,
    latencyMs: average(latencyValues),
    p95LatencyMs: percentile(latencyValues, 95),
    lastCheckedAt: checkedAt,
    lastSuccessAt,
    timeline,
    models,
    extraModels: [],
  }] : [];

  const summary = {
    total: monitors.length,
    available: status === 'operational' ? 1 : 0,
    degraded: status === 'degraded' ? 1 : 0,
    failed: status === 'failed' ? 1 : 0,
    unknown: status === 'unknown' ? 1 : 0,
    status,
    statusLabel: statusText,
    accountCount: accounts.length,
    activeAccountCount,
    schedulableAccountCount,
    totalRequests: logs.length,
    totalTokens,
    totalCost,
    avgLatencyMs: average(latencyValues),
    p95LatencyMs: percentile(latencyValues, 95),
    lastCheckedAt: checkedAt,
    lastSuccessAt,
  };

  return {
    configured: accounts.length > 0,
    source: 'sub2api_live_scheduler',
    sourceLabel: '实时可用性',
    sourceDescription: '来自 Sub2API 实时调度状态和真实 7 天 GPT 用量，不展示内部渠道名称。',
    window: '7d',
    summary,
    monitors,
    models,
    trend: [],
  };
}

async function gptChannelHealth() {
  return watchdogGptChannelHealth();
}

function relayModelShape(model = {}, overrideRequests = null) {
  const name = model.model || 'legacy-total';
  const inputTokens = Number(model.input_tokens || model.inputTokens || 0);
  const outputTokens = Number(model.output_tokens || model.outputTokens || 0);
  const cacheCreateTokens = Number(model.cache_creation_tokens || model.cacheCreateTokens || 0);
  const cacheReadTokens = Number(model.cache_read_tokens || model.cacheReadTokens || 0);
  const allTokens = Number(model.total_tokens || model.allTokens || inputTokens + outputTokens + cacheCreateTokens + cacheReadTokens);
  const total = Number(model.actual_cost ?? model.cost ?? 0);
  return {
    model: name,
    requests: Number(overrideRequests ?? model.requests ?? 0),
    inputTokens,
    outputTokens,
    cacheCreateTokens,
    cacheReadTokens,
    allTokens,
    costs: {
      input: Number(model.input_cost || 0),
      output: Number(model.output_cost || 0),
      cacheWrite: Number(model.cache_creation_cost || 0),
      cacheRead: Number(model.cache_read_cost || 0),
      total,
      real: total,
      rated: total,
    },
    formatted: {
      input: formatCost(Number(model.input_cost || 0)),
      output: formatCost(Number(model.output_cost || 0)),
      cacheWrite: formatCost(Number(model.cache_creation_cost || 0)),
      cacheRead: formatCost(Number(model.cache_read_cost || 0)),
      total: formatCost(total),
    },
    pricing: null,
    isLegacy: isLegacyModel({ model: name }),
  };
}

function isLegacyModel(model = {}) {
  return String(model.model || '').toLowerCase().startsWith('legacy');
}

function usageTotalModelStats(usage = {}) {
  const total = usage.usage?.total;
  if (!total) return null;
  const inputTokens = Number(total.input_tokens || 0);
  const outputTokens = Number(total.output_tokens || 0);
  const cacheCreateTokens = Number(total.cache_creation_tokens || 0);
  const cacheReadTokens = Number(total.cache_read_tokens || 0);
  const allTokens = Number(total.total_tokens || inputTokens + outputTokens + cacheCreateTokens + cacheReadTokens);
  const cost = Number(total.actual_cost ?? total.cost ?? 0);
  if (!allTokens && !cost && !Number(total.requests || 0)) return null;
  return {
    model: 'legacy-total',
    requests: Number(total.requests || 0),
    input_tokens: inputTokens,
    output_tokens: outputTokens,
    cache_creation_tokens: cacheCreateTokens,
    cache_read_tokens: cacheReadTokens,
    total_tokens: allTokens,
    cost,
    actual_cost: cost,
  };
}

function usageModelStatsForPeriod(usage = {}, period = 'alltime') {
  const rows = Array.isArray(usage.model_stats) ? [...usage.model_stats] : [];
  if (period === 'alltime' && !rows.some(isLegacyModel)) {
    const total = usageTotalModelStats(usage);
    if (total) rows.unshift(total);
  }
  return rows;
}

function relayModelStatsForPeriod(record, usage = {}, period = 'alltime') {
  return usageModelStatsForPeriod(usage, period)
    .filter((model) => period === 'alltime' || !isLegacyModel(model))
    .map((model) => relayModelShape(model, legacyRequestOverrideForModel(record, model, period)))
    .sort((a, b) => b.allTokens - a.allTokens);
}

function usageShapeFromModelStats(modelStats = []) {
  return modelStats.reduce((shape, item) => addUsageShape(shape, {
    tokens: item.allTokens,
    inputTokens: item.inputTokens,
    outputTokens: item.outputTokens,
    cacheCreateTokens: item.cacheCreateTokens,
    cacheReadTokens: item.cacheReadTokens,
    allTokens: item.allTokens,
    requests: item.requests,
    cost: item.costs?.total || 0,
  }), emptyUsageShape());
}

function legacyRequestOverrideForModel(record, model = {}, period = 'alltime') {
  return period === 'alltime' && isLegacyModel(model) ? (record.legacyRequests || null) : null;
}

async function usageForApiStats(record, period = 'alltime') {
  const range = periodDateRange(period);
  const query = range
    ? `?start_date=${encodeURIComponent(range.startDate)}&end_date=${encodeURIComponent(range.endDate)}&timezone=${encodeURIComponent('Asia/Shanghai')}`
    : '';
  return cachedApiStatsUsage(record, period, () => (
    sub2apiRaw(`/v1/usage${query}`, {
      headers: { authorization: `Bearer ${record.apiKey}` },
    })
  ));
}

async function usageShapes(record, usage = null) {
  const [alltimeUsage, dailyUsage, monthlyUsage] = usage ? [usage, null, null] : await Promise.all([
    usageForApiStats(record, 'alltime'),
    usageForApiStats(record, 'daily'),
    usageForApiStats(record, 'monthly'),
  ]);
  const total = usageShapeFromModelStats(relayModelStatsForPeriod(record, alltimeUsage, 'alltime'));
  const today = usageShapeFromModelStats(relayModelStatsForPeriod(record, dailyUsage || alltimeUsage, 'daily'));
  const month = usageShapeFromModelStats(relayModelStatsForPeriod(record, monthlyUsage || alltimeUsage, 'monthly'));
  return { total, today, month, alltime: total };
}

async function relayStatsPayload(record, usage = null) {
  const { total, today, month, alltime } = await usageShapes(record, usage);
  return {
    apiId: record.id,
    id: record.id,
    name: record.name,
    description: record.description || '',
    isActive: record.isActive !== false,
    createdAt: record.createdAt || '',
    expiresAt: '',
    expirationMode: 'fixed',
    isActivated: true,
    activationDays: 0,
    activatedAt: record.createdAt || null,
    permissions: JSON.stringify(['openai']),
    usage: { total },
    dailyUsage: today,
    monthlyUsage: month,
    alltimeUsage: alltime,
    limits: {
      tokenLimit: 0,
      concurrencyLimit: 0,
      rateLimitWindow: 0,
      rateLimitRequests: 0,
      rateLimitCost: 0,
      dailyCostLimit: 0,
      totalCostLimit: 0,
      weeklyOpusCostLimit: 0,
      weeklyResetDay: 1,
      weeklyResetHour: 0,
      currentWindowRequests: 0,
      currentWindowTokens: 0,
      currentWindowCost: 0,
      currentDailyCost: today.cost,
      currentTotalCost: total.cost,
      weeklyOpusCost: 0,
      windowStartTime: null,
      windowEndTime: null,
      windowRemainingSeconds: null,
    },
    accounts: {
      claudeAccountId: null,
      geminiAccountId: null,
      openaiAccountId: record.openaiAccountId || null,
      details: null,
    },
    restrictions: {
      enableModelRestriction: false,
      restrictedModels: [],
      enableClientRestriction: false,
      allowedClients: [],
    },
    serviceRates: {},
  };
}

async function batchStatsPayload(record, usage = null) {
  const { total, today, month, alltime } = await usageShapes(record, usage);
  return {
    apiId: record.id,
    id: record.id,
    name: record.name,
    description: record.description || '',
    isActive: record.isActive !== false,
    usage: total,
    dailyUsage: today,
    monthlyUsage: month,
    alltimeUsage: alltime,
    serviceRates: {},
  };
}

function aggregateBatchStats(items) {
  const aggregated = {
    totalKeys: items.length,
    activeKeys: items.filter((item) => item.isActive !== false).length,
    usage: emptyUsageShape(),
    dailyUsage: emptyUsageShape(),
    monthlyUsage: emptyUsageShape(),
    alltimeUsage: emptyUsageShape(),
    limits: {
      tokenLimit: 0,
      concurrencyLimit: 0,
      rateLimitWindow: 0,
      rateLimitRequests: 0,
      rateLimitCost: 0,
      dailyCostLimit: 0,
      totalCostLimit: 0,
      currentDailyCost: 0,
      currentTotalCost: 0,
    },
  };
  for (const item of items) {
    addUsageShape(aggregated.usage, item.usage);
    addUsageShape(aggregated.dailyUsage, item.dailyUsage);
    addUsageShape(aggregated.monthlyUsage, item.monthlyUsage);
    addUsageShape(aggregated.alltimeUsage, item.alltimeUsage);
  }
  aggregated.limits.currentDailyCost = aggregated.dailyUsage.cost;
  aggregated.limits.currentTotalCost = aggregated.usage.cost;
  return aggregated;
}

function requestedApiIdCount(apiIds = []) {
  return Array.isArray(apiIds) ? apiIds.length : String(apiIds || '').split(',').filter((value) => value.trim()).length;
}

async function recordsFromApiIds(apiIds = []) {
  const ids = Array.isArray(apiIds) ? apiIds : String(apiIds || '').split(',');
  const seen = new Set();
  const records = [];
  for (const apiId of ids) {
    const id = String(apiId || '').trim();
    if (!id || seen.has(id)) continue;
    seen.add(id);
    const record = await apiStatsRecordByIdOrKey({ apiId: id });
    if (record) records.push(record);
  }
  return records;
}

function validateApiStatsBatch(body = {}) {
  const requested = requestedApiIdCount(body.apiIds);
  if (requested > API_STATS_BATCH_MAX_IDS) {
    const error = new Error(`Too many apiIds: ${requested} > ${API_STATS_BATCH_MAX_IDS}`);
    error.status = 413;
    error.payload = {
      requestedApiIds: requested,
      maxApiIds: API_STATS_BATCH_MAX_IDS,
    };
    throw error;
  }
  return requested;
}

function aggregateModelStats(modelStats) {
  const byModel = new Map();
  for (const item of modelStats) {
    const name = item.model || 'legacy-total';
    if (!byModel.has(name)) {
      byModel.set(name, {
        model: name,
        requests: 0,
        inputTokens: 0,
        outputTokens: 0,
        cacheCreateTokens: 0,
        cacheReadTokens: 0,
        allTokens: 0,
        costs: {
          input: 0,
          output: 0,
          cacheWrite: 0,
          cacheRead: 0,
          total: 0,
          real: 0,
          rated: 0,
        },
        pricing: {
          input: 0,
          output: 0,
          cacheWrite: 0,
          cacheRead: 0,
        },
        isLegacy: isLegacyModel({ model: name }),
      });
    }
    const target = byModel.get(name);
    target.requests += Number(item.requests || 0);
    target.inputTokens += Number(item.inputTokens || 0);
    target.outputTokens += Number(item.outputTokens || 0);
    target.cacheCreateTokens += Number(item.cacheCreateTokens || 0);
    target.cacheReadTokens += Number(item.cacheReadTokens || 0);
    target.allTokens += Number(item.allTokens || 0);
    target.costs.input += Number(item.costs?.input || 0);
    target.costs.output += Number(item.costs?.output || 0);
    target.costs.cacheWrite += Number(item.costs?.cacheWrite || 0);
    target.costs.cacheRead += Number(item.costs?.cacheRead || 0);
    target.costs.total += Number(item.costs?.total || 0);
    target.costs.real += Number(item.costs?.real || item.costs?.total || 0);
    target.costs.rated += Number(item.costs?.rated || item.costs?.total || 0);
  }
  return [...byModel.values()].map((item) => ({
    ...item,
    formatted: {
      input: formatCost(item.costs.input),
      output: formatCost(item.costs.output),
      cacheWrite: formatCost(item.costs.cacheWrite),
      cacheRead: formatCost(item.costs.cacheRead),
      total: formatCost(item.costs.total),
    },
  })).sort((a, b) => b.allTokens - a.allTokens);
}

function sse(res, event) {
  res.write(`data: ${JSON.stringify(event)}\n\n`);
}

function responseText(payload) {
  if (typeof payload.output_text === 'string') return payload.output_text;
  if (typeof payload.text === 'string') return payload.text;
  const output = Array.isArray(payload.output) ? payload.output : [];
  const parts = [];
  for (const item of output) {
    const content = Array.isArray(item.content) ? item.content : [];
    for (const contentItem of content) {
      if (typeof contentItem.text === 'string') parts.push(contentItem.text);
      if (typeof contentItem.content === 'string') parts.push(contentItem.content);
    }
  }
  const choices = Array.isArray(payload.choices) ? payload.choices : [];
  for (const choice of choices) {
    if (typeof choice.message?.content === 'string') parts.push(choice.message.content);
    if (typeof choice.text === 'string') parts.push(choice.text);
  }
  return parts.join('');
}

function sub2apiForwardingBases() {
  const bases = [PUBLIC_SUB2API_BASE]
    .map((value) => String(value || '').replace(/\/$/, ''))
    .filter(Boolean);
  return [...new Set(bases)];
}

async function postRelayOpenAIResponse({ apiKey, model, prompt, timeoutMs }) {
  const payload = {
    model: model || 'gpt-5',
    input: [{ role: 'user', content: String(prompt || 'hi') }],
  };
  const errors = [];

  for (const base of sub2apiForwardingBases()) {
    const startedAt = Date.now();
    const controller = timeoutMs ? new AbortController() : null;
    const timer = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
    timer?.unref?.();
    try {
      const response = await fetch(`${base}/v1/responses`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${apiKey}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify(payload),
        signal: controller?.signal,
      });
      const text = await response.text();
      let parsed = {};
      try {
        parsed = text ? JSON.parse(text) : {};
      } catch {
        parsed = { raw: text };
      }
      const latencyMs = Date.now() - startedAt;
      if (!response.ok) {
        const message = parsed.error?.message || parsed.message || parsed.error || response.statusText;
        errors.push(`${base}: ${message}`);
        continue;
      }
      return {
        ok: true,
        base,
        latencyMs,
        payload: parsed,
        text: responseText(parsed) || 'OK',
      };
    } catch (error) {
      const message = error.name === 'AbortError' ? `timeout after ${timeoutMs}ms` : (error.message || 'request failed');
      errors.push(`${base}: ${message}`);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  const error = new Error(errors.join('; ') || 'relay API request failed');
  error.details = errors;
  throw error;
}

async function handleOpenAITest(req, res) {
  res.writeHead(200, {
    'content-type': 'text/event-stream; charset=utf-8',
    'cache-control': 'no-store',
    connection: 'keep-alive',
  });

  try {
    const body = await readJson(req);
    const record = await apiStatsRecordByIdOrKey({ apiId: body.apiId, apiKey: body.apiKey });
    const apiKey = String(body.apiKey || record?.apiKey || '').trim();
    if (!apiKey) {
      sse(res, { type: 'error', error: 'API Key or apiId is required' });
      return res.end();
    }

    sse(res, { type: 'test_start' });
    const result = await postRelayOpenAIResponse({
      apiKey,
      model: body.model || 'gpt-5',
      prompt: body.prompt || 'hi',
    });
    sse(res, { type: 'content', text: result.text });
    sse(res, {
      type: 'test_complete',
      success: true,
      endpoint: '/v1/responses',
      relayBase: result.base,
      latencyMs: result.latencyMs,
      apiId: record?.id || body.apiId || null,
    });
    res.end();
  } catch (error) {
    sse(res, { type: 'error', error: error.message || 'request failed' });
    res.end();
  }
}

async function handleApiStats(req, res, url) {
  try {
    if (req.method === 'GET' && url.pathname === '/apiStats/trace-export/status') {
      send(res, 200, {
        success: true,
        data: {
          ...traceExportStatus,
          statePath: TRACE_EXPORT_STATE,
          factsLedgerPath: TRACE_EXPORT_FACTS_LEDGER || null,
          baseUrlConfigured: Boolean(LANGFUSE_BASE_URL),
          credentialsConfigured: Boolean(LANGFUSE_PUBLIC_KEY && LANGFUSE_SECRET_KEY),
        },
      });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/apiStats/channel-monitor/gpt-7d') {
      const data = await gptChannelHealth();
      send(res, 200, {
        success: true,
        data: {
          ...data,
          generatedAt: new Date().toISOString(),
        },
      });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/apiStats/models') {
      const models = await sub2apiRaw('/v1/models', { headers: { authorization: `Bearer ${legacyApiMap().byId[Object.keys(legacyApiMap().byId)[0]]?.apiKey || ''}` } }).catch(() => ({ data: [] }));
      const openaiModels = modelOptions(models.data || []);
      send(res, 200, {
        success: true,
        data: {
          claude: [],
          gemini: [],
          openai: openaiModels,
          other: [],
          all: openaiModels,
          platforms: {},
        },
      });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/apiStats/service-rates') {
      send(res, 200, {
        success: true,
        data: null,
        message: 'Service rates are not configured in the Sub2API-backed relay shell',
      });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/apiStats/api/get-key-id') {
      const body = await readJson(req);
      const record = await apiStatsRecordByIdOrKey({ apiKey: body.apiKey });
      if (!record) return send(res, 401, { success: false, error: 'Invalid API key', message: 'Invalid API key' });
      send(res, 200, { success: true, data: { id: record.id } });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/apiStats/api/user-stats') {
      const body = await readJson(req);
      const record = await apiStatsRecordByIdOrKey({ apiId: body.apiId, apiKey: body.apiKey });
      if (!record) return send(res, 404, { success: false, error: 'API key not found', message: 'The specified API key does not exist' });
      send(res, 200, { success: true, data: await relayStatsPayload(record) });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/apiStats/api/user-model-stats') {
      const body = await readJson(req);
      const record = await apiStatsRecordByIdOrKey({ apiId: body.apiId, apiKey: body.apiKey });
      if (!record) return send(res, 404, { success: false, error: 'API key not found', message: 'The specified API key does not exist' });
      const period = body.period || 'monthly';
      const usage = await usageForApiStats(record, period);
      const data = relayModelStatsForPeriod(record, usage, period);
      send(res, 200, { success: true, data, period });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/apiStats/api/batch-stats') {
      const body = await readJson(req);
      const requested = validateApiStatsBatch(body);
      const records = await recordsFromApiIds(body.apiIds);
      if (!records.length) return send(res, 404, { success: false, message: 'No valid API keys found' });
      const individual = await mapLimit(records, API_STATS_BATCH_CONCURRENCY, (record) => batchStatsPayload(record));
      send(res, 200, {
        success: true,
        data: {
          aggregated: aggregateBatchStats(individual),
          individual,
          meta: {
            requestedApiIds: requested,
            resolvedApiIds: records.length,
            maxApiIds: API_STATS_BATCH_MAX_IDS,
            concurrency: API_STATS_BATCH_CONCURRENCY,
          },
        },
      });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/apiStats/api/batch-model-stats') {
      const body = await readJson(req);
      const requested = validateApiStatsBatch(body);
      const records = await recordsFromApiIds(body.apiIds);
      const allModelStats = [];
      const period = body.period || 'daily';
      const modelStatsByRecord = await mapLimit(records, API_STATS_BATCH_CONCURRENCY, async (record) => {
        const usage = await usageForApiStats(record, period);
        return relayModelStatsForPeriod(record, usage, period);
      });
      for (const stats of modelStatsByRecord) allModelStats.push(...stats);
      return send(res, 200, {
        success: true,
        data: aggregateModelStats(allModelStats),
        period,
        meta: {
          requestedApiIds: requested,
          resolvedApiIds: records.length,
          maxApiIds: API_STATS_BATCH_MAX_IDS,
          concurrency: API_STATS_BATCH_CONCURRENCY,
        },
      });
    }

    if (req.method === 'POST' && url.pathname === '/apiStats/api-key/test-openai') {
      return handleOpenAITest(req, res);
    }

    if (req.method === 'POST' && url.pathname === '/apiStats/api/redeem-card') {
      return send(res, 400, { success: false, message: 'Quota card redemption is managed by Sub2API' });
    }

    if (req.method === 'GET' && url.pathname === '/apiStats/api/redemption-history') {
      return send(res, 404, { success: false, message: 'Quota card history is not available in the Sub2API-backed relay shell' });
    }

    send(res, 404, { success: false, message: 'not found' });
  } catch (error) {
    send(res, error.status || 500, {
      success: false,
      message: error.message || 'request failed',
      data: error.payload || undefined,
    });
  }
}

function mapUsageStats(stats) {
  const totalCost = stats.total_actual_cost ?? stats.total_cost ?? 0;
  return {
    requests: stats.total_requests || 0,
    totalRequests: stats.total_requests || 0,
    inputTokens: stats.total_input_tokens || 0,
    totalInputTokens: stats.total_input_tokens || 0,
    outputTokens: stats.total_output_tokens || 0,
    totalOutputTokens: stats.total_output_tokens || 0,
    cacheCreateTokens: stats.total_cache_creation_tokens || 0,
    cacheCreationTokens: stats.total_cache_creation_tokens || 0,
    cacheReadTokens: stats.total_cache_read_tokens || 0,
    totalTokens: stats.total_tokens || 0,
    totalCost,
    todayRequests: stats.today_requests || 0,
    todayCost: stats.today_actual_cost ?? stats.today_cost ?? 0,
    modelStats: (stats.by_platform || []).map((item) => ({
      name: item.platform || 'unknown',
      requests: item.total_requests || 0,
      totalTokens: item.total_tokens || 0,
      cost: item.total_actual_cost ?? item.total_cost ?? 0,
    })),
  };
}

function previewKey(key) {
  const text = String(key || '');
  if (text.length <= 12) return text ? '****' : '';
  return `${text.slice(0, 8)}...${text.slice(-4)}`;
}

function mapApiKeyUsage(usage = {}) {
  return {
    requests: usage.total_requests || 0,
    inputTokens: usage.total_input_tokens || 0,
    outputTokens: usage.total_output_tokens || 0,
    cacheCreationTokens: usage.total_cache_creation_tokens || 0,
    cacheReadTokens: usage.total_cache_read_tokens || 0,
    totalTokens: usage.total_tokens || 0,
    totalCost: usage.total_actual_cost ?? usage.total_cost ?? 0,
    todayCost: usage.today_actual_cost ?? usage.today_cost ?? 0,
  };
}

function mapApiKey(item, usageById = {}) {
  const usage = mapApiKeyUsage(usageById[String(item.id)] || {});
  const deleted = Boolean(item.deleted_at);
  return {
    id: item.id,
    name: item.name,
    key: item.key,
    keyPreview: previewKey(item.key),
    isActive: item.status === 'active',
    status: item.status,
    description: item.group?.name || item.group_name || '',
    createdAt: item.created_at,
    updatedAt: item.updated_at,
    lastUsedAt: item.last_used_at,
    expiresAt: item.expires_at,
    deletedAt: item.deleted_at || null,
    isDeleted: deleted,
    quota: item.quota || 0,
    quotaUsed: item.quota_used || 0,
    usage,
  };
}

async function apiKeyUsageStats(token, items) {
  const stats = {};
  await Promise.all(items.slice(0, 20).map(async (item) => {
    try {
      stats[String(item.id)] = await sub2api(`/api/v1/usage/stats?api_key_id=${encodeURIComponent(item.id)}`, {
        headers: { authorization: `Bearer ${token}` },
      });
    } catch {
      stats[String(item.id)] = {};
    }
  }));
  return stats;
}

async function listApiKeys(token) {
  const list = await sub2api('/api/v1/keys?page=1&page_size=200', { headers: { authorization: `Bearer ${token}` } });
  const items = list.items || [];
  if (!items.length) return [];

  const usageById = await apiKeyUsageStats(token, items);
  return items.map((item) => mapApiKey(item, usageById));
}

async function handleCompat(req, res, url) {
  try {
    if (req.method === 'POST' && url.pathname === '/users/login') {
      const body = await readJson(req);
      const email = body.email || body.username;
      const auth = await sub2api('/api/v1/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password: body.password }),
      });
      send(res, 200, {
        success: true,
        sessionToken: auth.access_token,
        user: mapUser(auth.user),
      });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/users/logout') {
      send(res, 200, { success: true });
      return;
    }

    if (url.pathname === '/users/profile') {
      const token = bearer(req);
      const profile = await sub2api('/api/v1/user/profile', { headers: { authorization: `Bearer ${token}` } });
      const stats = await sub2api('/api/v1/usage/dashboard/stats', { headers: { authorization: `Bearer ${token}` } });
      send(res, 200, {
        success: true,
        user: {
          ...mapUser(profile),
          createdAt: profile.created_at,
          updatedAt: profile.updated_at,
          lastLoginAt: profile.last_login_at,
          totalUsage: mapUsageStats(stats),
        },
        config: {
          maxApiKeysPerUser: 50,
          allowUserDeleteApiKeys: false,
        },
      });
      return;
    }

    if (req.method === 'GET' && url.pathname === '/users/api-keys') {
      send(res, 200, {
        success: true,
        apiKeys: await listApiKeys(bearer(req)),
      });
      return;
    }

    if (req.method === 'POST' && url.pathname === '/users/api-keys') {
      const body = await readJson(req);
      const created = await sub2api('/api/v1/keys', {
        method: 'POST',
        headers: { authorization: `Bearer ${bearer(req)}` },
        body: JSON.stringify({ name: body.name, group_id: body.group_id || DEFAULT_GROUP_ID, custom_key: body.custom_key }),
      });
      send(res, 200, { success: true, apiKey: mapApiKey(created) });
      return;
    }

    const deleteMatch = url.pathname.match(/^\/users\/api-keys\/(\d+)$/);
    if (req.method === 'DELETE' && deleteMatch) {
      await sub2api(`/api/v1/keys/${deleteMatch[1]}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${bearer(req)}` },
      });
      send(res, 200, { success: true });
      return;
    }

    if (url.pathname === '/users/usage-stats') {
      const stats = await sub2api('/api/v1/usage/dashboard/stats', { headers: { authorization: `Bearer ${bearer(req)}` } });
      send(res, 200, { success: true, stats: mapUsageStats(stats) });
      return;
    }

    send(res, 404, { success: false, message: 'not found' });
  } catch (error) {
    send(res, error.status || 500, {
      success: false,
      message: error.message || 'request failed',
    });
  }
}

function contentType(file) {
  if (file.endsWith('.html')) return 'text/html; charset=utf-8';
  if (file.endsWith('.js')) return 'application/javascript; charset=utf-8';
  if (file.endsWith('.css')) return 'text/css; charset=utf-8';
  if (file.endsWith('.json')) return 'application/json; charset=utf-8';
  if (file.endsWith('.svg')) return 'image/svg+xml';
  if (file.endsWith('.png')) return 'image/png';
  if (file.endsWith('.jpg') || file.endsWith('.jpeg')) return 'image/jpeg';
  if (file.endsWith('.woff2')) return 'font/woff2';
  if (file.endsWith('.ttf')) return 'font/ttf';
  return 'application/octet-stream';
}

function staticFile(res, pathname) {
  const normalized = decodeURIComponent(pathname.replace(/^\/admin-next\/?/, ''));
  const rel = normalized && normalized !== '/' ? normalized : 'index.html';
  const target = path.resolve(PUBLIC_DIR, rel);
  const root = path.resolve(PUBLIC_DIR);
  const index = path.join(root, 'index.html');
  const file = target.startsWith(root) && fs.existsSync(target) && fs.statSync(target).isFile() ? target : index;
  const body = fs.readFileSync(file);
  res.writeHead(200, {
    'content-type': contentType(file),
    'cache-control': file.endsWith('index.html') ? 'no-store' : 'public, max-age=31536000, immutable',
  });
  res.end(body);
}

const OPENAI_ROOT_PROXY_PATHS = [
  '/models',
  '/usage',
  '/messages',
  '/responses',
  '/chat/completions',
  '/embeddings',
];

function isOpenAiRootProxyPath(pathname) {
  return OPENAI_ROOT_PROXY_PATHS.includes(pathname) ||
    pathname.startsWith('/messages/') ||
    pathname.startsWith('/responses/') ||
    pathname.startsWith('/images/');
}

function shouldProxyToGateway(pathname) {
  return pathname === '/openai' ||
    pathname.startsWith('/openai/') ||
    pathname === '/v1' ||
    pathname.startsWith('/v1/') ||
    pathname.startsWith('/backend-api/codex/') ||
    isOpenAiRootProxyPath(pathname);
}

function gatewayProxyPath(originalUrl) {
  const parsed = new URL(originalUrl, 'http://relay-shell.local');
  let pathname = parsed.pathname;

  if (pathname === '/openai') {
    pathname = '/v1';
  } else if (pathname === '/openai/v1') {
    pathname = '/v1';
  } else if (pathname.startsWith('/openai/v1/')) {
    pathname = `/v1/${pathname.slice('/openai/v1/'.length)}`;
  } else if (pathname.startsWith('/openai/')) {
    const rest = pathname.slice('/openai'.length);
    if (
      rest === '/models' ||
      rest === '/usage' ||
      rest === '/messages' ||
      rest.startsWith('/messages/') ||
      rest === '/responses' ||
      rest.startsWith('/responses/') ||
      rest === '/chat/completions' ||
      rest === '/embeddings' ||
      rest.startsWith('/images/')
    ) {
      pathname = `/v1${rest}`;
    } else {
      pathname = rest;
    }
  } else if (isOpenAiRootProxyPath(pathname)) {
    pathname = `/v1${pathname}`;
  }

  return `${pathname}${parsed.search}`;
}

async function proxy(req, res) {
  const proxiedPath = gatewayProxyPath(req.url);
  if (shouldConsiderFullTrace(req, proxiedPath)) return proxyWithFullTrace(req, res, proxiedPath);
  const target = `${SUB2API_BASE}${proxiedPath}`;
  const headers = { ...req.headers, host: new URL(SUB2API_BASE).host };
  try {
    const response = await fetch(target, {
      method: req.method,
      headers,
      body: ['GET', 'HEAD'].includes(req.method) ? undefined : req,
      duplex: ['GET', 'HEAD'].includes(req.method) ? undefined : 'half',
    });
    res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
    res.flushHeaders?.();
    if (response.body) {
      for await (const chunk of response.body) res.write(chunk);
    }
    res.end();
  } catch (error) {
    sendProxyFailure(res, error, { proxiedPath });
  }
}

function cloudIngestTokenMatches(req) {
  const observed = bearerToken(req);
  if (!observed || !CHIPTRACE_INGEST_TOKEN) return false;
  const expectedHash = crypto.createHash('sha256').update(CHIPTRACE_INGEST_TOKEN).digest();
  const observedHash = crypto.createHash('sha256').update(observed).digest();
  return crypto.timingSafeEqual(expectedHash, observedHash);
}

async function proxyCloudIngest(req, res, url) {
  if (!CHIPTRACE_INGEST_TOKEN || Buffer.byteLength(CHIPTRACE_INGEST_TOKEN, 'utf8') < 32) {
    return send(res, 503, { ok: false, reason: 'cloud_ingest_not_configured' });
  }
  if (!cloudIngestTokenMatches(req)) {
    res.setHeader('www-authenticate', 'Bearer');
    return send(res, 401, { ok: false, reason: 'cloud_ingest_auth_required' });
  }
  const headers = {
    authorization: `Bearer ${CHIPTRACE_INGEST_TOKEN}`,
    'content-type': headerValue(req.headers, 'content-type') || 'application/json',
  };
  for (const name of ['content-encoding', 'content-length', 'traceparent', 'tracestate', 'x-request-id']) {
    const value = headerValue(req.headers, name);
    if (value) headers[name] = value;
  }
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FULL_TRACE_CAPTURE_RELAY_TIMEOUT_MS);
  const abort = () => controller.abort();
  req.once('aborted', abort);
  try {
    const response = await fetch(`${FULL_TRACE_CAPTURE_RELAY_URL}${url.pathname}`, {
      method: 'POST',
      headers,
      body: req,
      duplex: 'half',
      signal: controller.signal,
    });
    const responseHeaders = {};
    for (const name of ['content-type', 'retry-after']) {
      const value = response.headers.get(name);
      if (value) responseHeaders[name] = value;
    }
    res.writeHead(response.status, responseHeaders);
    if (response.body) {
      for await (const chunk of response.body) res.write(chunk);
    }
    res.end();
  } catch (error) {
    if (!res.headersSent) {
      send(res, error?.name === 'AbortError' ? 504 : 503, {
        ok: false,
        reason: error?.name === 'AbortError'
          ? 'cloud_ingest_relay_timeout'
          : 'cloud_ingest_relay_unavailable',
      });
    } else {
      res.destroy(error);
    }
  } finally {
    clearTimeout(timer);
    req.off('aborted', abort);
  }
}

async function proxyManagedModels(req, res, url) {
  const businessAuthorization = headerValue(req.headers, 'authorization');
  const validation = await validateProviderCredential({
    authorization: businessAuthorization,
    modelsUrl: `${SUB2API_BASE}/v1/models`,
    timeoutMs: FULL_TRACE_CAPTURE_RELAY_TIMEOUT_MS,
  });
  if (!validation.ok) {
    if (validation.status === 401) {
      res.setHeader('www-authenticate', 'Bearer');
    }
    return send(res, validation.status, { ok: false, reason: validation.reason });
  }
  if (!CHIPTRACE_INGEST_TOKEN || Buffer.byteLength(CHIPTRACE_INGEST_TOKEN, 'utf8') < 32) {
    return send(res, 503, { ok: false, reason: 'managed_models_not_configured' });
  }
  try {
    const response = await fetch(`${FULL_TRACE_CAPTURE_RELAY_URL}${url.pathname}`, {
      method: 'GET',
      headers: { authorization: `Bearer ${CHIPTRACE_INGEST_TOKEN}` },
    });
    const headers = {};
    for (const name of ['content-type', 'cache-control', 'etag', 'x-chiptrace-catalog-source']) {
      const value = response.headers.get(name);
      if (value) headers[name] = value;
    }
    res.writeHead(response.status, headers);
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch (error) {
    send(res, 503, {
      ok: false,
      reason: 'managed_models_unavailable',
      detail: (error?.message || String(error)).slice(0, 300),
    });
  }
}

async function proxyWithFullTrace(req, res, proxiedPath) {
  const target = `${SUB2API_BASE}${proxiedPath}`;
  const headers = { ...req.headers, host: new URL(SUB2API_BASE).host };
  const clientRequestId = fullTraceClientRequestId(req);
  headers['x-client-request-id'] = clientRequestId;
  const startedAt = new Date();
  const captureId = `cap-${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
  const requestCapture = { chunks: [], bytes: 0, truncated: false };
  // Bounded copy used only to derive producer identity (for example Claude
  // Code's metadata.user_id) before the transaction spool is finalized.
  const requestIdentityCapture = { chunks: [], bytes: 0, truncated: false };
  // Interactive Claude Code requests can exceed the head sample; keep the
  // trailing metadata object too.
  const requestIdentityTail = { chunks: [], bytes: 0, truncated: false };
  const responseCapture = { chunks: [], bytes: 0, truncated: false };
  const requestTee = new PassThrough();
  const apiKey = bearerToken(req);
  const apiKeyFingerprint = stableHash(apiKey, 16);
  let actorSnapshot = null;
  let actorMetadataStatus = 'pending';
  resolveFullTraceActor(apiKey, apiKeyFingerprint)
    .then((actor) => {
      actorSnapshot = actor;
      actorMetadataStatus = actor ? 'resolved' : 'missing';
    })
    .catch((error) => {
      actorMetadataStatus = 'error';
      fullTraceCaptureStatus.actorMetadataLastError = (error.message || String(error)).slice(0, 500);
    });

  fullTraceCaptureStatus.acceptedCount += 1;
  fullTraceCaptureStatus.lastAcceptedAt = startedAt.toISOString();

  // Persist the interaction identity before any request byte is forwarded.
  // Request and response chunks are then appended to durable spools; a process
  // crash leaves an explicit recoverable incomplete Capture.
  let captureTransaction = null;
  try {
    const requestHeaders = {
      'content-type': headerValue(req.headers, 'content-type') || null,
      'user-agent': headerValue(req.headers, 'user-agent') || null,
      ...captureCorrelationHeaders(req.headers),
      'x-client-request-id': clientRequestId,
    };
    captureTransaction = await fullTraceOutbox.beginCapture({
      recordType: 'api_snapshot',
      captureId,
      sourceNamespace: FULL_TRACE_CAPTURE_SOURCE_NAMESPACE,
      captureStage: 'ingress',
      requestId: clientRequestId,
      startedAt: startedAt.toISOString(),
      method: req.method,
      inboundPath: req.url,
      proxiedPath,
      apiKeyFingerprint,
      requestHeaders,
      traceContext: traceContextFromCorrelationHeaders(req.headers).trace,
    }, {
      maxRequestBytes: FULL_TRACE_CAPTURE_MAX_REQUEST_BYTES,
      maxResponseBytes: FULL_TRACE_CAPTURE_MAX_RESPONSE_BYTES,
    });
  } catch (error) {
    captureDrop('capture_start_failed', error);
  }

  let clientRequestAborted = false;
  let clientResponseClosedBeforeFinish = false;
  let clientResponseFinished = false;
  let responseBytesForwarded = 0;
  let responseBytesForwardedAtClientClose = null;
  let responseProtocolTerminalObservedAtClientClose = null;
  let responseFramingDoneObservedAtClientClose = null;
  let upstreamResponseCompleted = false;
  req.once('aborted', () => {
    clientRequestAborted = true;
  });
  res.once('finish', () => {
    clientResponseFinished = true;
  });
  res.once('close', () => {
    if (!clientResponseFinished) {
      clientResponseClosedBeforeFinish = true;
      responseBytesForwardedAtClientClose = responseBytesForwarded;
      const snapshot = responseStreamTracker?.snapshot();
      responseProtocolTerminalObservedAtClientClose = snapshot?.protocolTerminalObserved ?? null;
      responseFramingDoneObservedAtClientClose = snapshot?.framingDoneObserved ?? null;
    }
  });

  const captureWritePromises = [];
  const appendCaptureChunk = (side, chunk, state, maxBytes) => {
    if (side === 'request') {
      appendBoundedBuffer(
        requestIdentityCapture,
        chunk,
        Math.min(maxBytes, 1024 * 1024),
      );
      appendRollingTail(
        requestIdentityTail,
        chunk,
        Math.min(maxBytes, 256 * 1024),
      );
    }
    if (!captureTransaction) {
      appendBoundedBuffer(state, chunk, maxBytes);
      return;
    }
    const write = side === 'request'
      ? captureTransaction.appendRequest(chunk)
      : captureTransaction.appendResponse(chunk);
    captureWritePromises.push(write);
  };
  req.on('data', (chunk) => appendCaptureChunk(
    'request',
    chunk,
    requestCapture,
    FULL_TRACE_CAPTURE_MAX_REQUEST_BYTES,
  ));
  req.on('error', (error) => {
    requestTee.destroy(error);
    captureDrop('request_stream_error', error);
  });
  req.pipe(requestTee);

  let response = null;
  let responseError = null;
  let responseStreamTracker = null;
  let responseStreamState = null;
  try {
    response = await fetch(target, {
      method: req.method,
      headers,
      body: requestTee,
      duplex: 'half',
    });
    res.writeHead(response.status, Object.fromEntries(response.headers.entries()));
    res.flushHeaders?.();
    const responseContentType = String(response.headers.get('content-type') || '').toLowerCase();
    if (responseContentType.includes('text/event-stream') && /\/responses(?:\?|$)/.test(proxiedPath)) {
      responseStreamTracker = new ResponsesSseBoundaryTracker();
    }
    if (response.body) {
      for await (const chunk of response.body) {
        appendCaptureChunk(
          'response',
          chunk,
          responseCapture,
          FULL_TRACE_CAPTURE_MAX_RESPONSE_BYTES,
        );
        responseStreamState = responseStreamTracker?.observe(chunk) || null;
        if (!res.writableEnded && !res.destroyed) {
          res.write(chunk);
          responseBytesForwarded += chunk.length;
        }
      }
    }
    upstreamResponseCompleted = true;
  } catch (error) {
    responseError = error;
    sendProxyFailure(res, error, { proxiedPath });
  } finally {
    if (requestCapture.truncated || captureTransaction?.requestTruncated) {
      fullTraceCaptureStatus.truncatedRequestCount += 1;
    }
    if (responseCapture.truncated || captureTransaction?.responseTruncated) {
      fullTraceCaptureStatus.truncatedResponseCount += 1;
    }
    const submitAfterFinish = () => {
      trackFullTraceLocalWrite(scheduleFullTraceSubmit({
        captureId,
        clientRequestId,
        startedAt,
        req,
        proxiedPath,
        apiKeyFingerprint,
        requestCapture,
        requestIdentityCapture,
        requestIdentityTail,
        responseCapture,
        response,
        responseError,
        clientRequestAborted,
        clientResponseClosedBeforeFinish,
        clientResponseFinished,
        responseBytesForwarded,
        responseBytesForwardedAtClientClose,
        responseProtocolTerminalObservedAtClientClose,
        responseFramingDoneObservedAtClientClose,
        upstreamResponseCompleted,
        responseStreamState,
        actor: actorSnapshot,
        actorMetadataStatus,
        captureTransaction,
        captureWritePromises,
      }))
        .catch((error) => captureDrop('post_response_capture_failed', error));
    };
    if (res.writableFinished || res.destroyed) {
      setImmediate(submitAfterFinish);
    } else {
      res.once('finish', () => setImmediate(submitAfterFinish));
    }
    if (!res.writableEnded && !res.destroyed) res.end();
  }
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (['/models', '/v1/models'].includes(url.pathname)) {
      if (req.method !== 'GET') {
        res.setHeader('allow', 'GET');
        return send(res, 405, { ok: false, reason: 'method_not_allowed' });
      }
      return proxyManagedModels(req, res, url);
    }
    if (['/otel/v1/logs', '/otel/v1/traces', '/hooks/codex'].includes(url.pathname)) {
      if (req.method !== 'POST') {
        res.setHeader('allow', 'POST');
        return send(res, 405, { ok: false, reason: 'method_not_allowed' });
      }
      return proxyCloudIngest(req, res, url);
    }
    if (url.pathname === '/health') {
      const captureRelay = await probeFullTraceRelay();
      const outboxHealth = fullTraceOutbox.snapshot();
      const activeQueueFiles = outboxHealth.pending + outboxHealth.processing;
      const cloudIngestConfigured = CHIPTRACE_INGEST_TOKEN.length >= 32;
      const backlogHealthy = activeQueueFiles <= FULL_TRACE_CAPTURE_HEALTH_MAX_PENDING_FILES
        && outboxHealth.activeQueueBytes <= FULL_TRACE_CAPTURE_HEALTH_MAX_QUEUE_BYTES
        && outboxHealth.oldestPendingAgeMs <= FULL_TRACE_CAPTURE_HEALTH_MAX_OLDEST_PENDING_MS;
      const captureHealthy = !FULL_TRACE_CAPTURE_ENABLED || (
        captureRelay.healthy === true
        && cloudIngestConfigured
        && Boolean(outboxHealth.startedAt)
        && backlogHealthy
        && outboxHealth.rejected === 0
        && outboxHealth.conflicts === 0
        // Failed files are immutable audit evidence and may predate this
        // process. Only failures observed since startup affect live health.
        && outboxHealth.currentFailureCount === 0
        && outboxHealth.stalledFiles === 0
        && outboxHealth.openCaptureHealthy === true
        && fullTraceCaptureStatus.droppedCount === 0
        && fullTraceCaptureStatus.truncatedRequestCount === 0
        && fullTraceCaptureStatus.truncatedResponseCount === 0
        && !fullTraceSubmitterStatus.lastError
        && !outboxHealth.lastError
      );
      return send(res, 200, {
      status: captureHealthy ? 'healthy' : 'degraded',
      upstream: SUB2API_BASE,
      traceExporter: {
        enabled: traceExportStatus.enabled,
        configured: traceExportStatus.configured,
        running: traceExportStatus.running,
        dataset: traceExportStatus.dataset,
        lastRunAt: traceExportStatus.lastRunAt,
        lastScannedUsageLogId: traceExportStatus.lastScannedUsageLogId,
        lastExportedUsageLogId: traceExportStatus.lastExportedUsageLogId,
        exportedCount: traceExportStatus.exportedCount,
        skippedCount: traceExportStatus.skippedCount,
        lastScanStrategy: traceExportStatus.lastScanStrategy,
        lastScanPages: traceExportStatus.lastScanPages,
        lastScanFetchedRows: traceExportStatus.lastScanFetchedRows,
        lastScanCandidateRows: traceExportStatus.lastScanCandidateRows,
        lastScanReturnedRows: traceExportStatus.lastScanReturnedRows,
        lastScanReachedCursor: traceExportStatus.lastScanReachedCursor,
        lastScanWindowStartDate: traceExportStatus.lastScanWindowStartDate,
        lastScanWindowEndDate: traceExportStatus.lastScanWindowEndDate,
        factsLedgerPath: TRACE_EXPORT_FACTS_LEDGER || null,
        lastFactsLedgerWriteAt: traceExportStatus.lastFactsLedgerWriteAt,
        lastFactsLedgerError: traceExportStatus.lastFactsLedgerError,
        lastError: traceExportStatus.lastError,
        filters: traceExportStatus.filters,
      },
      fullTraceCapture: {
        phase: FULL_TRACE_CAPTURE_PHASE,
        enabled: FULL_TRACE_CAPTURE_ENABLED,
        bodyEnabled: FULL_TRACE_CAPTURE_BODY_ENABLED,
        forwardingPath: FULL_TRACE_CAPTURE_ENABLED ? 'bounded_text_tee_to_local_outbox' : 'hard_bypass',
        relayUrlConfigured: Boolean(FULL_TRACE_CAPTURE_RELAY_URL),
        sourceNamespace: FULL_TRACE_CAPTURE_SOURCE_NAMESPACE,
        relayTimeoutMs: FULL_TRACE_CAPTURE_RELAY_TIMEOUT_MS,
        maxRequestBytes: FULL_TRACE_CAPTURE_MAX_REQUEST_BYTES,
        maxResponseBytes: FULL_TRACE_CAPTURE_MAX_RESPONSE_BYTES,
        allAuthenticatedKeys: FULL_TRACE_CAPTURE_ALL_AUTHENTICATED_KEYS,
        allowedKeyFingerprints: FULL_TRACE_CAPTURE_API_KEY_FINGERPRINTS.size,
        excludedKeyFingerprints: fullTraceMonitorKeyFingerprints.size,
        monitorIdentityGate: 'stable_api_key_fingerprint',
        cloudIngestEndpointConfigured: cloudIngestConfigured,
        ingestTokenConfigured: cloudIngestConfigured,
        healthLimits: {
          maxPendingFiles: FULL_TRACE_CAPTURE_HEALTH_MAX_PENDING_FILES,
          maxQueueBytes: FULL_TRACE_CAPTURE_HEALTH_MAX_QUEUE_BYTES,
          maxOldestPendingMs: FULL_TRACE_CAPTURE_HEALTH_MAX_OLDEST_PENDING_MS,
          maxOpenMs: FULL_TRACE_CAPTURE_HEALTH_MAX_OPEN_MS,
        },
        backlogHealthy,
        currentDeliveryHealthy: captureHealthy,
        outboxEnabled: FULL_TRACE_CAPTURE_ENABLED,
        outbox: outboxHealth,
        historicalFailures: {
          records: outboxHealth.historicalFailedFiles,
          markers: outboxHealth.historicalAuxiliaryFiles,
          bytes: outboxHealth.historicalFailedBytes,
        },
        recentFailures: {
          records: outboxHealth.recentFailedFiles,
          markers: outboxHealth.recentAuxiliaryFiles,
          bytes: outboxHealth.recentFailureBytes,
        },
        pendingLocalWrites: fullTracePendingLocalWrites.size,
        skippedResponseStatuses: [],
        stats: { ...fullTraceCaptureStatus },
        submitter: {
          ...fullTraceSubmitterStatus,
          inFlight: outboxHealth.processing,
          inFlightBytes: outboxHealth.inflightBytes,
          maxConcurrency: FULL_TRACE_CAPTURE_SUBMIT_CONCURRENCY,
          maxInFlightBytes: FULL_TRACE_CAPTURE_SUBMIT_MAX_INFLIGHT_BYTES,
          maxAttempts: FULL_TRACE_CAPTURE_SUBMIT_ATTEMPTS,
          maxRetries: Math.max(FULL_TRACE_CAPTURE_SUBMIT_ATTEMPTS - 1, 0),
          retryBaseMs: FULL_TRACE_CAPTURE_RETRY_BASE_MS,
          retryMaxMs: FULL_TRACE_CAPTURE_RETRY_MAX_MS,
          retryJitterPercent: FULL_TRACE_CAPTURE_RETRY_JITTER_PERCENT,
        },
        rustRelay: captureRelay,
        adapterDiskWritePhase: FULL_TRACE_CAPTURE_ENABLED ? 'after_business_response' : 'disabled',
        adapterDoesDiskWrites: FULL_TRACE_CAPTURE_ENABLED,
        adapterDoesPayloadSanitization: outboxHealth.sanitize,
        adapterDoesLangfuseWrites: false,
      },
      apiStatsUsageCache: {
        enabled: Boolean(API_STATS_USAGE_CACHE_TTL_MS),
        ttlMs: API_STATS_USAGE_CACHE_TTL_MS,
        maxEntries: API_STATS_USAGE_CACHE_MAX,
        size: apiStatsUsageCache.size,
        batchMaxApiIds: API_STATS_BATCH_MAX_IDS,
        batchConcurrency: API_STATS_BATCH_CONCURRENCY,
        stats: { ...apiStatsUsageCacheStats },
      },
      watchdog: {
        enabled: watchdogState.enabled,
        configured: watchdogState.configured,
        running: watchdogState.running,
        intervalMs: watchdogState.intervalMs,
        retentionDays: watchdogState.retentionDays,
        model: watchdogState.model,
        lastRunAt: watchdogState.lastRunAt,
        lastAvailableAt: watchdogState.lastAvailableAt,
        checks: watchdogState.checks.length,
        lastError: watchdogState.lastError,
      },
      });
    }
    if (url.pathname === '/' || url.pathname === '/admin-next' || url.pathname === '/admin-next/') {
      return redirect(res, '/admin-next/api-stats');
    }
    if (url.pathname.startsWith('/admin-next/admin') || url.pathname === '/admin-next/dashboard' || url.pathname === '/admin-next/login' || url.pathname === '/login') {
      return redirect(res, `${PUBLIC_SUB2API_BASE}/admin/dashboard`);
    }
    if (req.method === 'GET' && url.pathname === '/admin/oem-settings') {
      return send(res, 200, { success: true, data: oemSettings() });
    }
    if (req.method === 'PUT' && url.pathname === '/admin/oem-settings') {
      return send(res, 403, { success: false, message: 'admin settings are managed by sub2api' });
    }
    if (url.pathname.startsWith('/apiStats/')) return handleApiStats(req, res, url);
    if (url.pathname.startsWith('/users/')) return handleCompat(req, res, url);
    if (shouldProxyToGateway(url.pathname)) return proxy(req, res);
    if (url.pathname.startsWith('/admin-next/')) return staticFile(res, url.pathname);
    return send(res, 404, { success: false, message: 'not found' });
  } catch (error) {
    sendUnhandledFailure(req, res, error);
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`relay shell listening on ${PORT}, upstream ${SUB2API_BASE}`);
  startFullTraceCaptureOutbox().catch((error) => {
    fullTraceSubmitterStatus.lastError = (error.message || String(error)).slice(0, 500);
  });
  startTraceExporter();
  startWatchdog();
});

let gracefulShutdownStarted = false;
async function gracefulShutdown(signal) {
  if (gracefulShutdownStarted) return;
  gracefulShutdownStarted = true;
  console.log(`relay shell received ${signal}; draining local Capture writes`);
  let serverClosed = false;
  server.close(() => {
    serverClosed = true;
  });
  const drain = (async () => {
    while (!serverClosed || fullTracePendingLocalWrites.size > 0) {
      if (fullTracePendingLocalWrites.size > 0) {
        await Promise.allSettled([...fullTracePendingLocalWrites]);
      } else {
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
    }
  })();
  const completed = await Promise.race([
    drain.then(() => true),
    new Promise((resolve) => setTimeout(() => resolve(false), FULL_TRACE_CAPTURE_SHUTDOWN_GRACE_MS)),
  ]);
  await fullTraceOutbox.close();
  if (!completed) console.error('relay shell shutdown grace expired; outbox recovery will replay retained files');
  process.exit(0);
}

process.once('SIGTERM', () => {
  gracefulShutdown('SIGTERM').catch((error) => {
    console.error('relay shell graceful shutdown failed:', error.message || String(error));
    process.exit(1);
  });
});
process.once('SIGINT', () => {
  gracefulShutdown('SIGINT').catch((error) => {
    console.error('relay shell graceful shutdown failed:', error.message || String(error));
    process.exit(1);
  });
});
