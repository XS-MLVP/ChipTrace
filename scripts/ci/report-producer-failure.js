'use strict';

const fs = require('node:fs');

const [phase, file, statusText, commandText, logText] = process.argv.slice(2);
const status = Number(statusText);
const commandStatus = Number(commandText);
const logStatus = Number(logText);
if (!/^[a-z][a-z0-9-]{0,63}$/.test(phase || '')
  || !file || !Number.isInteger(status) || status < 1 || status > 255
  || !Number.isInteger(commandStatus) || commandStatus < 0 || commandStatus > 255
  || !Number.isInteger(logStatus) || logStatus < 0 || logStatus > 255) {
  console.error('invalid producer failure report arguments');
  process.exitCode = 2;
} else {
  let tail;
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw new Error('not a regular log');
    const bytes = Buffer.alloc(Math.min(stat.size, 8192));
    const read = fs.readSync(fd, bytes, 0, bytes.length, Math.max(0, stat.size - bytes.length));
    tail = bytes.subarray(0, read).toString('utf8');
    if (stat.size > bytes.length) tail = tail.slice(tail.indexOf('\n') + 1);
    tail = tail.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
      .split(/\r?\n/).slice(-40).join('\n').slice(-3000)
      .replace(/Bearer\s+\S+/gi, 'Bearer [redacted]');
  } catch {
    tail = 'The producer log tail could not be read; inspect the retained artifact.';
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
  const message = 'phase=' + phase + '; actual exit=' + status
    + '; command_exit=' + commandStatus + '; log_exit=' + logStatus + '\n' + tail;
  if (process.env.GITHUB_ACTIONS === 'true') {
    const escaped = message.replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');
    console.log('::error title=Producer ' + phase + '::' + escaped);
  } else console.error(message);
}
