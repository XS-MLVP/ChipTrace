'use strict';

const fs = require('node:fs');
const os = require('node:os');

const [phase, intervalText] = process.argv.slice(2);
const once = intervalText === '--once';
const interval = Number(intervalText);
if (!/^[a-z][a-z0-9-]{0,63}$/.test(phase || '')
  || (!once && (!Number.isInteger(interval) || interval < 1 || interval > 3600))) {
  console.error('usage: producer-resources.js <phase> <interval-seconds|--once>');
  process.exitCode = 2;
} else {
  const started = process.hrtime.bigint();
  const sample = () => {
    let availableMemory = null;
    let availableDisk = null;
    try {
      const match = /^MemAvailable:\s+(\d+)\s+kB$/m.exec(fs.readFileSync('/proc/meminfo', 'utf8'));
      if (match) availableMemory = (BigInt(match[1]) * 1024n).toString();
    } catch {}
    try {
      const stat = fs.statfsSync(process.cwd(), { bigint: true });
      availableDisk = (stat.bavail * stat.bsize).toString();
    } catch {}
    const observation = {
      schema_version: 'chiptrace.producer-resources.v1',
      observed_at: new Date().toISOString(),
      phase,
      monitor_pid: process.pid,
      elapsed_seconds: Number(process.hrtime.bigint() - started) / 1e9,
      cpu_count: os.availableParallelism(),
      load_average_1m: os.loadavg()[0],
      memory_total_bytes: String(os.totalmem()),
      memory_available_bytes: availableMemory,
      disk_available_bytes: availableDisk,
    };
    // Fixed host metrics and a validated phase only: never collect environment
    // contents, producer command lines, paths, model inputs or tool outputs.
    const message = JSON.stringify(observation);
    if (process.env.GITHUB_ACTIONS === 'true') {
      console.log('\n::notice title=Producer resources::' + message);
    } else console.log(message);
  };
  sample();
  if (!once) setInterval(sample, interval * 1000);
}
