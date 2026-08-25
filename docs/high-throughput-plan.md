# High-throughput packing plan

## Scope and target

The deployment intentionally keeps two independent entrypoints:

```text
direct entrypoint  -> upstream path without full-trace capture
capture entrypoint -> relay forwarding plus full-trace capture
```

This plan does not merge, redirect, or police the direct path. It optimizes the
capture and delivery path selected by clients that use the capture entrypoint.

The performance objective is measured as raw, uncompressed bytes consumed by
the sealed-segment packer:

- committed target: 500 MB/s sustained for 30 minutes;
- stretch target: 1 GB/s sustained for 30 minutes;
- output bytes depend on the observed compression ratio;
- capture request latency and release copy throughput are reported separately.

Do not combine these metrics into one headline number. A CPU-only compression
result is not an end-to-end packing result.

## Hardware boundary

The measured development host has 16 physical cores, one SATA SSD, and a 1 Gbit/s
NIC. Its network line-rate ceiling is about 125 MB/s before protocol overhead,
so this host cannot demonstrate the end-to-end target against NFS.

The production profile for the stretch target should provide:

- 25 Gbit/s networking, with at least 10 Gbit/s usable end to end;
- two or more NVMe devices, or storage proven above 1.5 GB/s for both reads and
  writes under the intended concurrency;
- at least 16 physical modern CPU cores and 64 GiB RAM;
- a local persistent filesystem for live ledgers and staging state;
- NFS or object storage only for immutable sealed input and published output.

Sizing formulas, where `R` is raw input MB/s and `C` is compression ratio:

```text
minimum network Gbit/s = R * 8 / 1000 / measured_link_efficiency
minimum output MB/s    = R / C + SQLite/index overhead
compression workers    = ceil(R / measured_worker_MBps * 1.30)
```

At 1 GB/s and 80% link efficiency, the minimum network is 10 Gbit/s. A 25GbE
link is recommended so checksum reads, metadata, and retries do not consume the
entire budget.

At the measured 3.23:1 ratio, sustained operation has a large storage cost:

```text
500 MB/s raw -> 43.2 TB/day raw -> about 13.4 TB/day compressed
1 GB/s raw   -> 86.4 TB/day raw -> about 26.7 TB/day compressed
```

A 10 GiB part would finish roughly every 69 seconds at 500 MB/s raw and every
34 seconds at 1 GB/s raw. Unless this storage volume is intentional, treat the
stretch rate as a backlog-drain capability rather than the normal arrival rate.

## Target architecture

```text
client selecting capture entrypoint
              |
              v
        capture Relay
      streaming bounded tee
              |
              v
 local disk-backed outbox partitions
      hash(capture_id) -> shard
              |
              v
 collector shards + per-shard identity ledger
              |
              v
 local NVMe append logs -> immutable sealed segments
              |
              v
       sealed manifest queue
              |
       +------+------+------+
       |             |      |
   reader 0       reader N  metadata/session scan
       |             |      |
       +------> zstd level-1 worker pool
                         |
                 complete-session planner
                         |
       +-----------------+-----------------+
       |                 |                 |
 SQLite part writer 0  writer 1         writer N
       |                 |                 |
       +---------- final fsync, hash, checks --------+
                         |
              immutable 10 GiB release directory
```

All retries for one `capture_id` must route to the same identity shard. Shard
count and hash version are persisted in the dataset manifest. Re-sharding is a
versioned migration, not an implicit runtime change.

## Packing data path

1. Read only immutable sealed segments with recorded size and SHA-256.
2. Read in 4-8 MiB chunks and verify record and segment hashes while streaming.
3. Compress independent frames with zstd level 1 in a bounded worker pool.
4. First pass builds only session membership, sizes, and quality metadata.
5. Assign every complete session to exactly one target part.
6. Build several SQLite parts concurrently, one process and one connection per
   part. Never allow multiple writers on one SQLite file.
7. Use `journal_mode=OFF` and `synchronous=OFF` only for private, rebuildable
   staging files. Run integrity and foreign-key checks, close, fsync, hash, and
   atomically publish before the file is considered durable.
8. Copy already verified compressed BLOBs directly during release construction;
   do not decompress and recompress unchanged records.

Initial production tuning profile:

```text
raw chunk                 4 MiB
compression batch         256-512 MiB per process
zstd level                1
compression workers       8-16, calibrated on production CPU
concurrent SQLite writers 4-8
target part size           10 GiB, session atomic
memory high watermark      <= 60% of host RAM
```

## Quality invariants

Performance work must preserve these gates:

- every offered capture reaches exactly one durable, duplicate, conflict,
  rejected, queued, or in-flight state;
- 408, 429, 5xx, failed, incomplete, and cancelled terminals are retained;
- capture IDs are unique and retries are byte-idempotent;
- source, record, chunk, part, and manifest byte/hash totals reproduce;
- all observed steps for a selected session stay in one release part;
- truncation, missing identity, open boundaries, and unmatched tools remain
  explicit in the completeness score;
- semantic reward stays null unless an evaluator or ground truth supplies it.

## Acceptance benchmark

Run on production-equivalent storage with isolated roots and synthetic bodies
that match the real size and compression-ratio distribution.

Required evidence:

- CPU-only compression exceeds 1.5 GB/s, leaving headroom for parsing and hash;
- storage-only sequential read and write each exceed 1.5 GB/s;
- end-to-end pack raw throughput is at least 500 MB/s for 30 minutes;
- stretch profile reaches 1 GB/s without record loss or session splits;
- a two-times input burst for five minutes drains without unbounded memory;
- p99 batch latency, queue bytes, RSS, CPU, read/write bandwidth, and fsync time
  remain inside declared limits;
- post-run SQLite integrity, foreign keys, raw hashes, manifest hashes, and
  session conservation all pass.

Use `make benchmark-pack` for the CPU-only codec check. It deliberately excludes
SQLite and storage I/O, and labels its result accordingly.

Use the isolated end-to-end harness for a production-equivalent gate:

```bash
PYTHONPATH=src python3 scripts/benchmark_export.py \
  --input-sqlite /audit/sample.sqlite --work-root /benchmark/nvme \
  --sample-mib 32768 --codec zstd --level 1 \
  --shards 8 --max-writers 8 --workers 2 \
  --target-mib-per-second 954
```

The work root must be isolated. Cache state, sample distribution, storage
topology, and elapsed duration belong in the benchmark report.

## Measured development baseline

Read-only payload samples came from `pack-20260731-001`. No body text was
printed. Rates use MiB/s; 500 MB/s is about 477 MiB/s and 1 GB/s is about
954 MiB/s.

| Path | Sample | Result | Boundary |
| --- | ---: | ---: | --- |
| zstd-1, 1 worker | 2.0 GiB replay | about 655.6 MiB/s raw | codec only |
| zstd-1, 8 workers | 2.0 GiB replay | about 3697.4 MiB/s raw | codec only |
| zlib-1, 8 workers | 2.0 GiB replay | about 661.2 MiB/s raw | codec only |
| zstd-1, one SQLite writer | 512 MiB | about 455.8 MiB/s raw | tmpfs, full checks |
| zstd-1, four SQLite writers | 1.85 GiB | about 1286.4 MiB/s raw | tmpfs, full checks |
| zstd-1, four SQLite writers | 512 MiB | about 631 MiB/s raw | local ext4, warm input cache |

The real sample compressed about 3.23:1 with zstd-1. These short development
runs prove that the sharded software path can cross the stretch rate when I/O
is removed. They do not prove cold-storage or 30-minute production throughput.
The current 1GbE NIC remains a hard end-to-end limit.

The machine-readable evidence is in `benchmarks/development-host-20260825.json`.

## Implementation status

Implemented in this repository:

- bounded parallel zlib/zstd chunk compression;
- byte-balanced multi-process raw SQLite shard writers;
- codec-aware trajectory reads and hash verification;
- fast private SQLite staging followed by final fsync and atomic publication;
- direct compressed-BLOB copying into session-atomic release parts;
- a CPU-only compression benchmark with round-trip validation.

Still required for the full target:

- Relay disk-backed outbox;
- deterministic multi-shard collector deployment;
- parallel session-aware final release writers;
- production 25GbE/NVMe benchmark and 30-minute soak evidence.
