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
4. Manifest hash-chain integrity verification.
5. Full restore to:
- `canonical-records.jsonl`
- `codex-raw.jsonl`
- `claude-raw.jsonl`
6. Recovery path via recovery code.
7. Live-safe backup while Codex/Claude keeps writing:
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
