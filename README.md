# chat-archive-rs

Personal Codex + Claude Code chat backup tool in Rust.

## Features

1. Collects local JSONL chat history from:
- `~/.codex/sessions/**/*.jsonl`
- `~/.codex/history.jsonl`
- `~/.claude/projects/**/*.jsonl`
- `~/.claude/history.jsonl`
2. Incremental append-only backup.
3. Local encryption before any remote sync copy.
4. New chunks auto-compress before encryption (zstd), old chunks stay readable.
5. Manifest hash-chain integrity verification.
6. Full restore to:
- `canonical-records.jsonl`
- `codex-raw.jsonl`
- `claude-raw.jsonl`
7. Recovery path via recovery code.
8. Live-safe backup while Codex/Claude keeps writing:
- reads each source using a file-size snapshot watermark
- defers incomplete tail lines to next run instead of archiving partial records

## Build

```bash
cd /Users/lifcc/Desktop/code/work/infra/chat-archive-rs
cargo build
```

## Usage

Binary path:

```bash
/Users/lifcc/Desktop/code/work/infra/chat-archive-rs/target/debug/chat-archive-rs
```

Initialize:

```bash
chat-archive-rs --archive-dir ~/.chat-archive-rs init \
  --passphrase 'your-passphrase' \
  --recovery-code 'YOUR-RECOVERY-CODE'
```

Backup:

```bash
chat-archive-rs --archive-dir ~/.chat-archive-rs backup --passphrase 'your-passphrase'
```

Optional: tune compression level (higher = smaller, slower):

```bash
chat-archive-rs --archive-dir ~/.chat-archive-rs backup \
  --passphrase 'your-passphrase' \
  --compress-level 12
```

Backup output now prints payload size:

```text
Compression level: 6
Chunk payload bytes (plain -> encrypted): 123456789 -> 34567890
```

When sources are actively growing, backup may print:

```text
Deferred incomplete tail lines in N source file(s); will capture next backup.
```

This is expected and prevents partial-line corruption during live writes.

Verify:

```bash
chat-archive-rs --archive-dir ~/.chat-archive-rs verify --passphrase 'your-passphrase'
```

Restore:

```bash
chat-archive-rs --archive-dir ~/.chat-archive-rs restore \
  --passphrase 'your-passphrase' \
  --output-dir ~/chat-restore
```

Recovery code drill:

```bash
chat-archive-rs --archive-dir ~/.chat-archive-rs recovery-test \
  --recovery-code 'YOUR-RECOVERY-CODE'
```

Show discovered sources:

```bash
chat-archive-rs --archive-dir ~/.chat-archive-rs show-sources
```

Monitoring service (built-in, weekly verify by default):

```bash
chat-archive-rs --archive-dir ~/.chat-archive-rs monitor \
  --passphrase 'your-passphrase' \
  --interval-sec 300 \
  --verify-schedule weekly
```

`monitor` startup auto-writes policy to `~/.chat-archive-rs/config.json` (first run creates it):

```json
{
  "version": 1,
  "monitor": {
    "interval_sec": 300,
    "verify_schedule": "weekly",
    "verify_every": 0,
    "compress_level": 6
  }
}
```

`--verify-every` is still available as an extra cycle trigger (for example, run verify every N monitor cycles in addition to scheduled verify).

Run one-shot monitor cycle (for cron/manual diagnostics):

```bash
chat-archive-rs --archive-dir ~/.chat-archive-rs monitor \
  --passphrase 'your-passphrase' \
  --cycles 1
```

Structured runtime logs are appended to:

```text
~/.chat-archive-rs/state/ops-log.jsonl
```

Incremental checkpoint and seen-record state is stored transactionally in:

```text
~/.chat-archive-rs/state/state.db
```

Archives created with older `checkpoints.tsv` and `seen_ids.txt` files are migrated into this
database on first use.

Each log line includes operation timing and sampled resource usage (`elapsed_ms`, `rss_kb`, `cpu_pct`) plus backup/verify counters, including `scheduled_verify` on monitor events.

Inspect latest events:

```bash
tail -n 20 ~/.chat-archive-rs/state/ops-log.jsonl
```
