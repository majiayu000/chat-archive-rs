# chat-archive-rs

A Rust CLI for incremental, encrypted backups of local Codex and Claude Code
JSONL history. Verify archive integrity and restore records without depending
on the original terminal session.

[Build and install](#build) · [First recovery drill](#first-recovery-drill) · [Usage](#usage) ·
[Report an issue](https://github.com/majiayu000/chat-archive-rs/issues)

## Features

1. Collects local JSONL chat history from:
- `~/.codex/sessions/**/*.jsonl`
- `~/.codex/history.jsonl`
- `~/.claude/projects/**/*.jsonl`
- `~/.claude/history.jsonl`
Session roots honor `CODEX_HOME` and `CLAUDE_CONFIG_DIR` when set; otherwise
these paths use the current home directory. Empty overrides are errors. Discovery
uses `agent-sessions`, includes subagent JSONL files and skips symbolic links in
session directories. Codex `archived_sessions` remain outside the archive scope.
Missing session directories or history files are optional.

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
git clone https://github.com/majiayu000/chat-archive-rs.git
cd chat-archive-rs
cargo install --locked --path .
```

## First recovery drill

Before relying on an archive, try a backup and restore with synthetic data in
an isolated directory. Build with `cargo build --locked`, then run this from the
repository root. The passphrase and recovery code below are public demo values;
use them only for this disposable drill.

```bash
DRILL_DIR=$(mktemp -d)
mkdir -p "$DRILL_DIR/codex/sessions" "$DRILL_DIR/claude/projects"
printf '%s\n' '{"type":"user","message":{"content":"synthetic recovery drill"}}' > "$DRILL_DIR/claude/projects/demo.jsonl"
export CODEX_HOME="$DRILL_DIR/codex"
export CLAUDE_CONFIG_DIR="$DRILL_DIR/claude"
./target/debug/chat-archive-rs --archive-dir "$DRILL_DIR/archive" show-sources
./target/debug/chat-archive-rs --archive-dir "$DRILL_DIR/archive" init --passphrase 'demo-only' --recovery-code 'demo-recovery-only'
./target/debug/chat-archive-rs --archive-dir "$DRILL_DIR/archive" backup --passphrase 'demo-only'
./target/debug/chat-archive-rs --archive-dir "$DRILL_DIR/archive" verify --passphrase 'demo-only'
./target/debug/chat-archive-rs --archive-dir "$DRILL_DIR/archive" restore --passphrase 'demo-only' --output-dir "$DRILL_DIR/restored"
cat "$DRILL_DIR/restored/claude-raw.jsonl"
unset CODEX_HOME CLAUDE_CONFIG_DIR
```

The restored raw file should contain the synthetic record. Prefer running the
drill in a fresh shell so the overrides do not replace an existing session's
configuration. Keep real passphrases out of shell history and process listings;
the current CLI examples use argv and do not provide a hidden-input workflow.

### What does restore recover?

Restore writes canonical records and provider raw JSONL exports to the output
directory. It does not reinstall a CLI, restore provider login credentials,
copy your source-code workspace, or automatically re-register sessions for
`codex resume` / `claude --resume`. Validate the exported records before any
manual provider-specific import. Codex `archived_sessions` are excluded from
backup discovery, even though the shared reader can discover them.

For monitoring and supported runtime recovery while local session files remain,
see [Keepline](https://github.com/majiayu000/keepline). It serves a different
purpose from an encrypted archive and a verified restore.

## Usage

`cargo install` puts `chat-archive-rs` in Cargo's binary directory (normally
`~/.cargo/bin`); make sure that directory is on `PATH`. For development, use
`cargo build --locked` and `./target/debug/chat-archive-rs`.

Initialize:

```bash
chat-archive-rs --archive-dir ~/.chat-archive-rs init \
  --passphrase 'your-passphrase' \
  --recovery-code 'YOUR-RECOVERY-CODE'
```

`init` refuses an archive directory that already contains `keys/keys.env` or
`manifests/manifest.tsv`. Use a new archive directory to initialize a separate archive.
Initialization stages and syncs the key, then publishes `keys/keys.env` by atomic
no-replace rename only after database and optional recovery-file work succeeds.
A key destination created during initialization is preserved and publication fails;
filesystems without atomic no-replace rename support report an error. The first backup
with new records creates the manifest; until then, the archive is empty. Concurrent
initialization and remote sync share the destination archive's file lock. A competing
`init` or `backup --remote-dir` fails before changing destination payloads or markers;
an init that loses ownership does not reset state or write its recovery file.
This coordinates current CLI writers; external filesystem writers and older binaries
that bypass the lock are not covered. No atomic two-file publication is claimed.
Termination before publication leaves no final archive marker, so you can retry;
abandoned private temporary keys are excluded from remote synchronization. On Unix,
the staged key is private at creation and set to exactly `0600` before any key bytes
are written, even when the umask masks owner access. Reported failures remove the
temporary key, with any cleanup error reported alongside the original error.

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

The shared raw reader preserves the existing archival contract: record IDs use
the provider, source path, byte offset and original line hash. CR/LF delimiters
are stripped as before; unknown record types and malformed newline-terminated
records are retained. The final unterminated line uses the existing enclosing
object/array heuristic, not schema validation. UTF-8 and storage errors still
abort the backup before its checkpoint transaction commits.

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
