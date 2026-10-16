'use strict';

// Only process metadata and bounded source locations leave the isolated child.
// stdout/stderr and assertion values can contain complete interaction payloads.
function describePlatformProcessFailure(error, { mode, elapsedMs, timeoutMs }) {
  const bytes = value => typeof value === 'string' || Buffer.isBuffer(value)
    ? Buffer.byteLength(value) : 0;
  const locations = [...String(error.stderr || '').matchAll(
    /\b(protocol-platform|plugin|client|storage|engine)\.js:(\d{1,7}):(\d{1,7})\b/g,
  )].slice(0, 6).map(match => `${match[1]}.js:${match[2]}:${match[3]}`);
  return {
    schema_version: 'chiptrace.native-platform-process-failure.v1',
    mode,
    elapsed_ms: Math.round(elapsedMs),
    timeout_ms: timeoutMs,
    exit_code: Number.isInteger(error.code) ? error.code : null,
    error_code: typeof error.code === 'string' && /^E[A-Z0-9_]{1,63}$/.test(error.code)
      ? error.code : null,
    signal: typeof error.signal === 'string' && /^SIG[A-Z0-9]{1,16}$/.test(error.signal)
      ? error.signal : null,
    killed: typeof error.killed === 'boolean' ? error.killed : null,
    stdout_bytes: bytes(error.stdout),
    stderr_bytes: bytes(error.stderr),
    reported_stderr_locations: locations,
  };
}

module.exports = { describePlatformProcessFailure };
