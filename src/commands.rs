use std::collections::HashSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use chrono::Utc;

use crate::collector::{discover_sources, read_records_from_source};
use crate::crypto::{
    openssl_decrypt_chunk, openssl_encrypt_chunk_with_level, openssl_unwrap_b64, openssl_wrap_b64,
    sha256_bytes,
};
use crate::storage::{
    append_seen_ids, load_checkpoints, load_env_file, load_manifest_entries, load_seen_ids,
    save_checkpoints, sync_to_remote,
};
use crate::types::{AppResult, Cli};
use crate::utils::{
    expand_tilde, hex_decode_to_string, json_escape, random_hex, utc_iso, utc_stamp,
};

#[derive(Debug, Clone)]
struct BackupStats {
    sources_scanned: usize,
    checkpoint_rewinds: usize,
    deferred_tail_sources: usize,
    new_records: usize,
    compress_level: i32,
    plain_bytes: usize,
    cipher_bytes: usize,
    chunk_file: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct VerifyStats {
    manifests: usize,
    records: usize,
}

#[derive(Debug, Clone)]
struct RestoreStats {
    total_records: usize,
    unique_raw_hashes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifySchedule {
    None,
    Daily,
    Weekly,
}

impl VerifySchedule {
    fn as_str(self) -> &'static str {
        match self {
            VerifySchedule::None => "none",
            VerifySchedule::Daily => "daily",
            VerifySchedule::Weekly => "weekly",
        }
    }
}

#[derive(Debug, Clone)]
struct MonitorPolicy {
    interval_sec: u64,
    verify_every: u64,
    verify_schedule: VerifySchedule,
    compress_level: i32,
}

#[derive(Debug, Clone, Default)]
struct VerifyScheduleState {
    last_daily_slot: Option<String>,
    last_weekly_slot: Option<String>,
}

pub fn cmd_init(cli: &Cli) -> AppResult<()> {
    let started_at = utc_iso();
    let timer = Instant::now();

    let result: AppResult<()> = (|| -> AppResult<()> {
        let passphrase = option_or_env(cli, "--passphrase", "ARCHIVE_PASSPHRASE")
            .ok_or_else(|| "init requires --passphrase or ARCHIVE_PASSPHRASE".to_string())?;
        let recovery_code = option_or_env(cli, "--recovery-code", "ARCHIVE_RECOVERY_CODE")
            .ok_or_else(|| "init requires --recovery-code or ARCHIVE_RECOVERY_CODE".to_string())?;

        let archive_key = random_hex(32)?;
        let key_hash = sha256_bytes(archive_key.as_bytes())?;
        let pass_wrap = openssl_wrap_b64(archive_key.as_bytes(), &passphrase)?;
        let rec_wrap = openssl_wrap_b64(archive_key.as_bytes(), &recovery_code)?;

        let keys_path = cli.archive_dir.join("keys").join("keys.env");
        let mut keys_file =
            File::create(&keys_path).map_err(|e| format!("create keys file: {e}"))?;
        writeln!(keys_file, "VERSION=1").map_err(|e| format!("write keys: {e}"))?;
        writeln!(keys_file, "CREATED_AT={}", utc_iso()).map_err(|e| format!("write keys: {e}"))?;
        writeln!(keys_file, "KEY_HASH={key_hash}").map_err(|e| format!("write keys: {e}"))?;
        writeln!(keys_file, "PASS_WRAP_B64={pass_wrap}").map_err(|e| format!("write keys: {e}"))?;
        writeln!(keys_file, "REC_WRAP_B64={rec_wrap}").map_err(|e| format!("write keys: {e}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&keys_path, fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("chmod keys: {e}"))?;
        }

        File::create(cli.archive_dir.join("state").join("checkpoints.tsv"))
            .map_err(|e| format!("create checkpoints: {e}"))?;
        File::create(cli.archive_dir.join("state").join("seen_ids.txt"))
            .map_err(|e| format!("create seen_ids: {e}"))?;
        File::create(cli.archive_dir.join("manifests").join("manifest.tsv"))
            .map_err(|e| format!("create manifest: {e}"))?;

        if let Some(recovery_file) = cli.options.get("--recovery-file") {
            let p = expand_tilde(recovery_file);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("mkdir recovery file parent: {e}"))?;
            }
            fs::write(&p, format!("{recovery_code}\n"))
                .map_err(|e| format!("write recovery file: {e}"))?;
        }

        println!("Archive initialized: {}", cli.archive_dir.display());
        println!("Recovery code stored in memory only unless --recovery-file is provided.");
        Ok(())
    })();

    let elapsed_ms = timer.elapsed().as_millis();
    match result {
        Ok(()) => {
            write_ops_log(
                cli,
                "init",
                "ok",
                &started_at,
                elapsed_ms,
                &["\"initialized\":true".to_string()],
            );
            Ok(())
        }
        Err(err) => {
            write_ops_error_log(cli, "init", &started_at, elapsed_ms, &err);
            Err(err)
        }
    }
}

pub fn cmd_show_sources() -> AppResult<()> {
    let sources = discover_sources()?;
    println!("Discovered source files: {}", sources.len());
    for s in sources {
        println!("{}\t{}", s.provider, s.path.display());
    }
    Ok(())
}

pub fn cmd_backup(cli: &Cli) -> AppResult<()> {
    let started_at = utc_iso();
    let timer = Instant::now();
    let result = run_backup_once(cli);
    let elapsed_ms = timer.elapsed().as_millis();

    match result {
        Ok(stats) => {
            if stats.new_records == 0 {
                println!("No new records discovered.");
            } else {
                println!("Archived new records: {}", stats.new_records);
                println!("Compression level: {}", stats.compress_level);
                println!(
                    "Chunk payload bytes (plain -> encrypted): {} -> {}",
                    stats.plain_bytes, stats.cipher_bytes
                );
                if let Some(chunk_file) = &stats.chunk_file {
                    println!("Chunk written: {}", chunk_file.display());
                }
            }
            if stats.deferred_tail_sources > 0 {
                println!(
                    "Deferred incomplete tail lines in {} source file(s); will capture next backup.",
                    stats.deferred_tail_sources
                );
            }

            let chunk_json = match stats.chunk_file.as_ref() {
                Some(p) => format!("\"{}\"", json_escape(&p.to_string_lossy())),
                None => "null".to_string(),
            };
            let ratio = if stats.plain_bytes > 0 {
                stats.cipher_bytes as f64 / stats.plain_bytes as f64
            } else {
                0.0
            };
            write_ops_log(
                cli,
                "backup",
                "ok",
                &started_at,
                elapsed_ms,
                &[
                    format!("\"sources_scanned\":{}", stats.sources_scanned),
                    format!("\"checkpoint_rewinds\":{}", stats.checkpoint_rewinds),
                    format!("\"deferred_tail_sources\":{}", stats.deferred_tail_sources),
                    format!("\"new_records\":{}", stats.new_records),
                    format!("\"compress_level\":{}", stats.compress_level),
                    format!("\"plain_bytes\":{}", stats.plain_bytes),
                    format!("\"cipher_bytes\":{}", stats.cipher_bytes),
                    format!("\"compression_ratio\":{:.6}", ratio),
                    format!("\"chunk_file\":{}", chunk_json),
                ],
            );
            Ok(())
        }
        Err(err) => {
            write_ops_error_log(cli, "backup", &started_at, elapsed_ms, &err);
            Err(err)
        }
    }
}

pub fn cmd_verify(cli: &Cli) -> AppResult<()> {
    let started_at = utc_iso();
    let timer = Instant::now();
    let result = run_verify_once(cli);
    let elapsed_ms = timer.elapsed().as_millis();

    match result {
        Ok(stats) => {
            println!("Verified manifests: {}", stats.manifests);
            println!("Verified records: {}", stats.records);
            write_ops_log(
                cli,
                "verify",
                "ok",
                &started_at,
                elapsed_ms,
                &[
                    format!("\"manifests\":{}", stats.manifests),
                    format!("\"records\":{}", stats.records),
                ],
            );
            Ok(())
        }
        Err(err) => {
            write_ops_error_log(cli, "verify", &started_at, elapsed_ms, &err);
            Err(err)
        }
    }
}

pub fn cmd_restore(cli: &Cli) -> AppResult<()> {
    let started_at = utc_iso();
    let timer = Instant::now();
    let result = run_restore_once(cli);
    let elapsed_ms = timer.elapsed().as_millis();

    match result {
        Ok(stats) => {
            println!("Restore complete. Records: {}", stats.total_records);
            if let Some(output) = cli.options.get("--output-dir") {
                println!("Output dir: {}", expand_tilde(output).display());
            }
            write_ops_log(
                cli,
                "restore",
                "ok",
                &started_at,
                elapsed_ms,
                &[
                    format!("\"total_records\":{}", stats.total_records),
                    format!("\"unique_raw_hashes\":{}", stats.unique_raw_hashes),
                ],
            );
            Ok(())
        }
        Err(err) => {
            write_ops_error_log(cli, "restore", &started_at, elapsed_ms, &err);
            Err(err)
        }
    }
}

pub fn cmd_recovery_test(cli: &Cli) -> AppResult<()> {
    let started_at = utc_iso();
    let timer = Instant::now();

    let result: AppResult<()> = (|| -> AppResult<()> {
        let recovery =
            option_or_env(cli, "--recovery-code", "ARCHIVE_RECOVERY_CODE").ok_or_else(|| {
                "recovery-test requires --recovery-code or ARCHIVE_RECOVERY_CODE".to_string()
            })?;
        let keys = load_env_file(&cli.archive_dir.join("keys").join("keys.env"))?;
        let rec_wrap = keys
            .get("REC_WRAP_B64")
            .ok_or_else(|| "REC_WRAP_B64 missing in keys.env".to_string())?;
        let recovered = openssl_unwrap_b64(rec_wrap, &recovery)?;
        let key_hash = sha256_bytes(&recovered)?;
        let expected = keys
            .get("KEY_HASH")
            .ok_or_else(|| "KEY_HASH missing in keys.env".to_string())?;
        if &key_hash != expected {
            return Err("recovery code unlock failed (hash mismatch)".to_string());
        }
        println!("Recovery code unlock: OK");
        Ok(())
    })();

    let elapsed_ms = timer.elapsed().as_millis();
    match result {
        Ok(()) => {
            write_ops_log(
                cli,
                "recovery-test",
                "ok",
                &started_at,
                elapsed_ms,
                &["\"recovery_unlock\":true".to_string()],
            );
            Ok(())
        }
        Err(err) => {
            write_ops_error_log(cli, "recovery-test", &started_at, elapsed_ms, &err);
            Err(err)
        }
    }
}

pub fn cmd_monitor(cli: &Cli) -> AppResult<()> {
    let cycles = parse_u64_option(cli.options.get("--cycles"), 0, 0, 10_000_000)?;

    let mut policy = load_or_init_monitor_policy(&cli.archive_dir)?;
    if let Some(raw) = cli.options.get("--interval-sec") {
        policy.interval_sec = parse_u64_option(Some(raw), policy.interval_sec, 1, 86_400)?;
    }
    if let Some(raw) = cli.options.get("--verify-every") {
        policy.verify_every = parse_u64_option(Some(raw), policy.verify_every, 0, 10_000_000)?;
    }
    if let Some(raw) = cli.options.get("--verify-schedule") {
        policy.verify_schedule = parse_verify_schedule(raw)?;
    }
    if let Some(raw) = cli.options.get("--compress-level") {
        policy.compress_level = parse_compress_level(Some(raw))?;
    }
    persist_monitor_policy(&cli.archive_dir, &policy)?;

    println!(
        "Monitor started. interval={}s verify_schedule={} verify_every={} cycles={} (0 means forever)",
        policy.interval_sec,
        policy.verify_schedule.as_str(),
        policy.verify_every,
        cycles
    );
    println!(
        "Monitor policy: {}",
        cli.archive_dir.join("config.json").display()
    );
    println!(
        "Ops log: {}",
        cli.archive_dir.join("state/ops-log.jsonl").display()
    );

    let mut cycle: u64 = 0;
    loop {
        cycle += 1;
        let cycle_ts = utc_iso();
        println!("[monitor] cycle={} at {}", cycle, cycle_ts);

        let scheduled_verify = is_scheduled_verify_due(&cli.archive_dir, policy.verify_schedule)?;
        let cycle_verify = policy.verify_every > 0 && cycle.is_multiple_of(policy.verify_every);
        let should_verify = scheduled_verify || cycle_verify;

        let mut backup_cli = cli.clone();
        backup_cli.options.insert(
            "--compress-level".to_string(),
            policy.compress_level.to_string(),
        );

        let backup_started_at = utc_iso();
        let backup_timer = Instant::now();
        match run_backup_once(&backup_cli) {
            Ok(stats) => {
                println!(
                    "[monitor] backup new_records={} plain={} cipher={}",
                    stats.new_records, stats.plain_bytes, stats.cipher_bytes
                );
                let chunk_json = match stats.chunk_file.as_ref() {
                    Some(p) => format!("\"{}\"", json_escape(&p.to_string_lossy())),
                    None => "null".to_string(),
                };
                let ratio = if stats.plain_bytes > 0 {
                    stats.cipher_bytes as f64 / stats.plain_bytes as f64
                } else {
                    0.0
                };
                write_ops_log(
                    cli,
                    "monitor-backup",
                    "ok",
                    &backup_started_at,
                    backup_timer.elapsed().as_millis(),
                    &[
                        format!("\"cycle\":{}", cycle),
                        format!(
                            "\"verify_schedule\":\"{}\"",
                            policy.verify_schedule.as_str()
                        ),
                        format!("\"scheduled_verify\":{}", scheduled_verify),
                        format!("\"cycle_verify\":{}", cycle_verify),
                        format!("\"should_verify\":{}", should_verify),
                        format!("\"sources_scanned\":{}", stats.sources_scanned),
                        format!("\"checkpoint_rewinds\":{}", stats.checkpoint_rewinds),
                        format!("\"deferred_tail_sources\":{}", stats.deferred_tail_sources),
                        format!("\"new_records\":{}", stats.new_records),
                        format!("\"compress_level\":{}", stats.compress_level),
                        format!("\"plain_bytes\":{}", stats.plain_bytes),
                        format!("\"cipher_bytes\":{}", stats.cipher_bytes),
                        format!("\"compression_ratio\":{:.6}", ratio),
                        format!("\"chunk_file\":{}", chunk_json),
                    ],
                );
            }
            Err(err) => {
                eprintln!("[monitor] backup failed: {err}");
                write_ops_log(
                    cli,
                    "monitor-backup",
                    "error",
                    &backup_started_at,
                    backup_timer.elapsed().as_millis(),
                    &[
                        format!("\"cycle\":{}", cycle),
                        format!(
                            "\"verify_schedule\":\"{}\"",
                            policy.verify_schedule.as_str()
                        ),
                        format!("\"scheduled_verify\":{}", scheduled_verify),
                        format!("\"cycle_verify\":{}", cycle_verify),
                        format!("\"should_verify\":{}", should_verify),
                        format!("\"error\":\"{}\"", json_escape(&err)),
                    ],
                );
            }
        }

        if should_verify {
            let verify_started_at = utc_iso();
            let verify_timer = Instant::now();
            match run_verify_once(cli) {
                Ok(stats) => {
                    println!(
                        "[monitor] verify manifests={} records={}",
                        stats.manifests, stats.records
                    );
                    write_ops_log(
                        cli,
                        "monitor-verify",
                        "ok",
                        &verify_started_at,
                        verify_timer.elapsed().as_millis(),
                        &[
                            format!("\"cycle\":{}", cycle),
                            format!(
                                "\"verify_schedule\":\"{}\"",
                                policy.verify_schedule.as_str()
                            ),
                            format!("\"scheduled_verify\":{}", scheduled_verify),
                            format!("\"cycle_verify\":{}", cycle_verify),
                            format!("\"manifests\":{}", stats.manifests),
                            format!("\"records\":{}", stats.records),
                        ],
                    );
                    if scheduled_verify {
                        mark_scheduled_verify_done(&cli.archive_dir, policy.verify_schedule)?;
                    }
                }
                Err(err) => {
                    eprintln!("[monitor] verify failed: {err}");
                    write_ops_log(
                        cli,
                        "monitor-verify",
                        "error",
                        &verify_started_at,
                        verify_timer.elapsed().as_millis(),
                        &[
                            format!("\"cycle\":{}", cycle),
                            format!(
                                "\"verify_schedule\":\"{}\"",
                                policy.verify_schedule.as_str()
                            ),
                            format!("\"scheduled_verify\":{}", scheduled_verify),
                            format!("\"cycle_verify\":{}", cycle_verify),
                            format!("\"error\":\"{}\"", json_escape(&err)),
                        ],
                    );
                }
            }
        }

        if cycles > 0 && cycle >= cycles {
            println!("Monitor completed after {} cycle(s).", cycle);
            break;
        }

        thread::sleep(Duration::from_secs(policy.interval_sec));
    }

    Ok(())
}

fn run_backup_once(cli: &Cli) -> AppResult<BackupStats> {
    let archive_key = unlock_archive_key(cli)?;
    let compress_level = parse_compress_level(cli.options.get("--compress-level"))?;
    let mut checkpoints = load_checkpoints(&cli.archive_dir)?;
    let mut seen = load_seen_ids(&cli.archive_dir)?;
    let mut records: Vec<String> = Vec::new();
    let mut new_ids: Vec<String> = Vec::new();
    let mut deferred_tail_sources = 0usize;
    let mut sources_scanned = 0usize;
    let mut checkpoint_rewinds = 0usize;

    for source in discover_sources()? {
        sources_scanned += 1;
        let spath = source.path.to_string_lossy().to_string();
        let size = fs::metadata(&source.path)
            .map_err(|e| format!("stat {}: {e}", source.path.display()))?
            .len();
        let old_offset = checkpoints.get(&spath).copied().unwrap_or(0);
        let start = if old_offset <= size {
            old_offset
        } else {
            checkpoint_rewinds += 1;
            0
        };
        let (new_records, end_offset, deferred_tail) = read_records_from_source(&source, start)?;
        for rec in new_records {
            let id = rec
                .split('\t')
                .next()
                .ok_or_else(|| "invalid record format".to_string())?
                .to_string();
            if seen.insert(id.clone()) {
                new_ids.push(id);
                records.push(rec);
            }
        }
        checkpoints.insert(spath, end_offset);
        if deferred_tail {
            deferred_tail_sources += 1;
        }
    }

    save_checkpoints(&cli.archive_dir, &checkpoints)?;

    if records.is_empty() {
        return Ok(BackupStats {
            sources_scanned,
            checkpoint_rewinds,
            deferred_tail_sources,
            new_records: 0,
            compress_level,
            plain_bytes: 0,
            cipher_bytes: 0,
            chunk_file: None,
        });
    }

    let plain_bytes = records.join("\n").into_bytes();
    let plain_hash = sha256_bytes(&plain_bytes)?;
    let cipher_bytes =
        openssl_encrypt_chunk_with_level(&plain_bytes, &archive_key, compress_level)?;
    let cipher_hash = sha256_bytes(&cipher_bytes)?;

    let chunk_id = format!("{}-{}", utc_stamp(), random_hex(4)?);
    let chunk_file = cli
        .archive_dir
        .join("chunks")
        .join(format!("{chunk_id}.enc"));
    fs::write(&chunk_file, &cipher_bytes).map_err(|e| format!("write chunk: {e}"))?;

    let manifests = load_manifest_entries(&cli.archive_dir)?;
    let prev_hash = manifests
        .last()
        .map(|m| m.manifest_hash.clone())
        .unwrap_or_else(|| "-".to_string());
    let chunk_rel = format!("chunks/{chunk_id}.enc");
    let core = format!(
        "{prev_hash}\t{}\t{chunk_id}\t{chunk_rel}\t{}\t{plain_hash}\t{cipher_hash}",
        utc_iso(),
        records.len()
    );
    let manifest_hash = sha256_bytes(core.as_bytes())?;
    let line = format!("{manifest_hash}\t{core}\n");
    let mut mf = OpenOptions::new()
        .append(true)
        .open(cli.archive_dir.join("manifests").join("manifest.tsv"))
        .map_err(|e| format!("open manifest append: {e}"))?;
    mf.write_all(line.as_bytes())
        .map_err(|e| format!("append manifest: {e}"))?;

    append_seen_ids(&cli.archive_dir, &new_ids)?;

    if let Some(remote_dir) = cli.options.get("--remote-dir") {
        sync_to_remote(
            &cli.archive_dir,
            &expand_tilde(remote_dir),
            Some(&chunk_file),
        )?;
    }

    Ok(BackupStats {
        sources_scanned,
        checkpoint_rewinds,
        deferred_tail_sources,
        new_records: records.len(),
        compress_level,
        plain_bytes: plain_bytes.len(),
        cipher_bytes: cipher_bytes.len(),
        chunk_file: Some(chunk_file),
    })
}

fn run_verify_once(cli: &Cli) -> AppResult<VerifyStats> {
    let archive_key = unlock_archive_key(cli)?;
    let manifests = load_manifest_entries(&cli.archive_dir)?;
    let mut prev = "-".to_string();
    let mut total = 0usize;
    for (idx, m) in manifests.iter().enumerate() {
        if m.prev_hash != prev {
            return Err(format!("Manifest chain mismatch at entry {}", idx + 1));
        }
        let core = format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            m.prev_hash,
            m.created_at,
            m.chunk_id,
            m.chunk_rel,
            m.record_count,
            m.plain_sha,
            m.cipher_sha
        );
        let chk = sha256_bytes(core.as_bytes())?;
        if chk != m.manifest_hash {
            return Err(format!("Manifest hash mismatch at entry {}", idx + 1));
        }
        let chunk_path = cli.archive_dir.join(&m.chunk_rel);
        if !chunk_path.exists() {
            return Err(format!("Missing chunk: {}", chunk_path.display()));
        }
        let cipher = fs::read(&chunk_path).map_err(|e| format!("read chunk: {e}"))?;
        let cipher_hash = sha256_bytes(&cipher)?;
        if cipher_hash != m.cipher_sha {
            return Err(format!("Cipher hash mismatch: {}", chunk_path.display()));
        }
        let plain = openssl_decrypt_chunk(&cipher, &archive_key)?;
        let plain_hash = sha256_bytes(&plain)?;
        if plain_hash != m.plain_sha {
            return Err(format!("Plain hash mismatch: {}", chunk_path.display()));
        }
        let count = plain
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .count();
        if count != m.record_count {
            return Err(format!(
                "Record count mismatch: {} expected {} got {}",
                chunk_path.display(),
                m.record_count,
                count
            ));
        }
        total += count;
        prev = m.manifest_hash.clone();
    }

    Ok(VerifyStats {
        manifests: manifests.len(),
        records: total,
    })
}

fn run_restore_once(cli: &Cli) -> AppResult<RestoreStats> {
    let archive_key = unlock_archive_key(cli)?;
    let output_dir = cli
        .options
        .get("--output-dir")
        .map(|s| expand_tilde(s))
        .ok_or_else(|| "restore requires --output-dir".to_string())?;
    fs::create_dir_all(&output_dir).map_err(|e| format!("create output dir: {e}"))?;
    let canonical = output_dir.join("canonical-records.jsonl");
    let codex_raw = output_dir.join("codex-raw.jsonl");
    let claude_raw = output_dir.join("claude-raw.jsonl");
    let canonical_file = File::create(&canonical).map_err(|e| format!("reset canonical: {e}"))?;
    let codex_file = File::create(&codex_raw).map_err(|e| format!("reset codex: {e}"))?;
    let claude_file = File::create(&claude_raw).map_err(|e| format!("reset claude: {e}"))?;
    let mut canonical_writer = BufWriter::with_capacity(8 * 1024 * 1024, canonical_file);
    let mut codex_writer = BufWriter::with_capacity(4 * 1024 * 1024, codex_file);
    let mut claude_writer = BufWriter::with_capacity(4 * 1024 * 1024, claude_file);

    let manifests = load_manifest_entries(&cli.archive_dir)?;
    let mut total = 0usize;
    let mut unique_raw = HashSet::new();
    for m in manifests {
        let chunk_path = cli.archive_dir.join(m.chunk_rel);
        let cipher = fs::read(&chunk_path).map_err(|e| format!("read chunk: {e}"))?;
        let plain = openssl_decrypt_chunk(&cipher, &archive_key)?;
        for line in plain.split(|b| *b == b'\n') {
            if line.is_empty() {
                continue;
            }
            let text = String::from_utf8(line.to_vec())
                .map_err(|e| format!("invalid utf-8 record line: {e}"))?;
            let parts: Vec<&str> = text.splitn(6, '\t').collect();
            if parts.len() != 6 {
                return Err("invalid record field count".to_string());
            }
            let record_id = parts[0];
            let provider = parts[1];
            let source_path = hex_decode_to_string(parts[2])?;
            let offset = parts[3];
            let raw_hash = parts[4];
            let raw_line = hex_decode_to_string(parts[5])?;
            unique_raw.insert(raw_hash.to_string());
            total += 1;

            let canonical_line = format!(
                "{{\"record_id\":\"{}\",\"provider\":\"{}\",\"source_path\":\"{}\",\"source_offset\":{},\"raw_hash\":\"{}\",\"raw_line\":\"{}\"}}\n",
                json_escape(record_id),
                json_escape(provider),
                json_escape(&source_path),
                offset,
                json_escape(raw_hash),
                json_escape(&raw_line)
            );
            canonical_writer
                .write_all(canonical_line.as_bytes())
                .map_err(|e| format!("write canonical: {e}"))?;
            if provider == "codex" {
                codex_writer
                    .write_all(raw_line.as_bytes())
                    .and_then(|_| codex_writer.write_all(b"\n"))
                    .map_err(|e| format!("write codex raw: {e}"))?;
            } else {
                claude_writer
                    .write_all(raw_line.as_bytes())
                    .and_then(|_| claude_writer.write_all(b"\n"))
                    .map_err(|e| format!("write claude raw: {e}"))?;
            }
        }
    }
    canonical_writer
        .flush()
        .map_err(|e| format!("flush canonical: {e}"))?;
    codex_writer
        .flush()
        .map_err(|e| format!("flush codex raw: {e}"))?;
    claude_writer
        .flush()
        .map_err(|e| format!("flush claude raw: {e}"))?;

    let report = format!(
        "{{\"restored_at\":\"{}\",\"total_records\":{},\"unique_raw_hashes\":{},\"canonical\":\"{}\",\"codex_raw\":\"{}\",\"claude_raw\":\"{}\"}}\n",
        utc_iso(),
        total,
        unique_raw.len(),
        json_escape(&canonical.to_string_lossy()),
        json_escape(&codex_raw.to_string_lossy()),
        json_escape(&claude_raw.to_string_lossy())
    );
    fs::write(output_dir.join("restore-report.json"), report)
        .map_err(|e| format!("write restore report: {e}"))?;

    Ok(RestoreStats {
        total_records: total,
        unique_raw_hashes: unique_raw.len(),
    })
}

fn default_monitor_policy() -> MonitorPolicy {
    MonitorPolicy {
        interval_sec: 300,
        verify_every: 0,
        verify_schedule: VerifySchedule::Weekly,
        compress_level: 6,
    }
}

fn parse_verify_schedule(raw: &str) -> AppResult<VerifySchedule> {
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "none" => Ok(VerifySchedule::None),
        "daily" => Ok(VerifySchedule::Daily),
        "weekly" => Ok(VerifySchedule::Weekly),
        _ => Err(format!(
            "invalid --verify-schedule: '{raw}' (expected none|daily|weekly)"
        )),
    }
}

fn load_or_init_monitor_policy(archive_dir: &Path) -> AppResult<MonitorPolicy> {
    let path = archive_dir.join("config.json");
    let mut policy = default_monitor_policy();

    if path.exists() {
        let raw = fs::read_to_string(&path)
            .map_err(|e| format!("read monitor policy {}: {e}", path.display()))?;
        let scope = extract_json_object(&raw, "monitor").unwrap_or(raw.as_str());

        if let Some(v) = extract_json_u64_value(scope, "interval_sec")
            && (1..=86_400).contains(&v)
        {
            policy.interval_sec = v;
        }
        if let Some(v) = extract_json_u64_value(scope, "verify_every")
            && v <= 10_000_000
        {
            policy.verify_every = v;
        }
        if let Some(v) = extract_json_string_value(scope, "verify_schedule")
            && let Ok(parsed) = parse_verify_schedule(&v)
        {
            policy.verify_schedule = parsed;
        }
        if let Some(v) = extract_json_i32_value(scope, "compress_level")
            && (1..=19).contains(&v)
        {
            policy.compress_level = v;
        }
    }

    persist_monitor_policy(archive_dir, &policy)?;
    Ok(policy)
}

fn persist_monitor_policy(archive_dir: &Path, policy: &MonitorPolicy) -> AppResult<()> {
    let path = archive_dir.join("config.json");
    let body = format!(
        "{{\n  \"version\": 1,\n  \"monitor\": {{\n    \"interval_sec\": {},\n    \"verify_schedule\": \"{}\",\n    \"verify_every\": {},\n    \"compress_level\": {}\n  }}\n}}\n",
        policy.interval_sec,
        policy.verify_schedule.as_str(),
        policy.verify_every,
        policy.compress_level
    );
    fs::write(&path, body).map_err(|e| format!("write monitor policy {}: {e}", path.display()))
}

fn verify_schedule_state_path(archive_dir: &Path) -> PathBuf {
    archive_dir.join("state").join("verify-schedule-state.env")
}

fn read_verify_schedule_state(archive_dir: &Path) -> AppResult<VerifyScheduleState> {
    let path = verify_schedule_state_path(archive_dir);
    if !path.exists() {
        return Ok(VerifyScheduleState::default());
    }
    let map = load_env_file(&path)?;
    Ok(VerifyScheduleState {
        last_daily_slot: map
            .get("LAST_DAILY_SLOT")
            .cloned()
            .filter(|v| !v.trim().is_empty()),
        last_weekly_slot: map
            .get("LAST_WEEKLY_SLOT")
            .cloned()
            .filter(|v| !v.trim().is_empty()),
    })
}

fn write_verify_schedule_state(archive_dir: &Path, state: &VerifyScheduleState) -> AppResult<()> {
    let path = verify_schedule_state_path(archive_dir);
    let mut body = String::new();
    if let Some(slot) = &state.last_daily_slot {
        body.push_str(&format!("LAST_DAILY_SLOT={slot}\n"));
    }
    if let Some(slot) = &state.last_weekly_slot {
        body.push_str(&format!("LAST_WEEKLY_SLOT={slot}\n"));
    }
    fs::write(&path, body)
        .map_err(|e| format!("write verify schedule state {}: {e}", path.display()))
}

fn current_daily_slot() -> String {
    Utc::now().format("%Y-%m-%d").to_string()
}

fn current_weekly_slot() -> String {
    Utc::now().format("%G-W%V").to_string()
}

fn is_scheduled_verify_due(archive_dir: &Path, schedule: VerifySchedule) -> AppResult<bool> {
    let state = read_verify_schedule_state(archive_dir)?;
    match schedule {
        VerifySchedule::None => Ok(false),
        VerifySchedule::Daily => {
            let slot = current_daily_slot();
            Ok(state.last_daily_slot.as_deref() != Some(slot.as_str()))
        }
        VerifySchedule::Weekly => {
            let slot = current_weekly_slot();
            Ok(state.last_weekly_slot.as_deref() != Some(slot.as_str()))
        }
    }
}

fn mark_scheduled_verify_done(archive_dir: &Path, schedule: VerifySchedule) -> AppResult<()> {
    let mut state = read_verify_schedule_state(archive_dir)?;
    match schedule {
        VerifySchedule::None => return Ok(()),
        VerifySchedule::Daily => {
            state.last_daily_slot = Some(current_daily_slot());
        }
        VerifySchedule::Weekly => {
            state.last_weekly_slot = Some(current_weekly_slot());
        }
    }
    write_verify_schedule_state(archive_dir, &state)
}

fn extract_json_object<'a>(raw: &'a str, key: &str) -> Option<&'a str> {
    let key_marker = format!("\"{key}\"");
    let key_idx = raw.find(&key_marker)?;
    let after_key = &raw[key_idx + key_marker.len()..];
    let colon_idx = after_key.find(':')?;
    let value = after_key[colon_idx + 1..].trim_start();
    if !value.starts_with('{') {
        return None;
    }

    let mut depth = 0usize;
    for (idx, ch) in value.char_indices() {
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(&value[..=idx]);
            }
        }
    }
    None
}

fn extract_json_value_start<'a>(raw: &'a str, key: &str) -> Option<&'a str> {
    let key_marker = format!("\"{key}\"");
    let key_idx = raw.find(&key_marker)?;
    let after_key = &raw[key_idx + key_marker.len()..];
    let colon_idx = after_key.find(':')?;
    Some(after_key[colon_idx + 1..].trim_start())
}

fn extract_json_string_value(raw: &str, key: &str) -> Option<String> {
    let value = extract_json_value_start(raw, key)?;
    let stripped = value.strip_prefix('"')?;
    let end_idx = stripped.find('"')?;
    Some(stripped[..end_idx].to_string())
}

fn extract_json_u64_value(raw: &str, key: &str) -> Option<u64> {
    let value = extract_json_value_start(raw, key)?;
    let bytes = value.as_bytes();
    let mut end = 0usize;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 {
        return None;
    }
    value[..end].parse::<u64>().ok()
}

fn extract_json_i32_value(raw: &str, key: &str) -> Option<i32> {
    let value = extract_json_value_start(raw, key)?;
    let bytes = value.as_bytes();
    let mut end = 0usize;
    if bytes.first() == Some(&b'-') {
        end = 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 || (end == 1 && bytes.first() == Some(&b'-')) {
        return None;
    }
    value[..end].parse::<i32>().ok()
}

fn option_or_env(cli: &Cli, opt: &str, env_key: &str) -> Option<String> {
    cli.options
        .get(opt)
        .cloned()
        .or_else(|| env::var(env_key).ok())
}

fn parse_compress_level(v: Option<&String>) -> AppResult<i32> {
    let Some(raw) = v else {
        return Ok(6);
    };
    let parsed = raw
        .parse::<i32>()
        .map_err(|e| format!("invalid --compress-level: {e}"))?;
    if (1..=19).contains(&parsed) {
        Ok(parsed)
    } else {
        Err("invalid --compress-level: must be between 1 and 19".to_string())
    }
}

fn parse_u64_option(v: Option<&String>, default: u64, min: u64, max: u64) -> AppResult<u64> {
    let Some(raw) = v else {
        return Ok(default);
    };
    let parsed = raw
        .parse::<u64>()
        .map_err(|e| format!("invalid numeric option value '{raw}': {e}"))?;
    if (min..=max).contains(&parsed) {
        Ok(parsed)
    } else {
        Err(format!(
            "numeric option value out of range: {parsed} (expected {min}..={max})"
        ))
    }
}

fn write_ops_error_log(cli: &Cli, operation: &str, started_at: &str, elapsed_ms: u128, err: &str) {
    write_ops_log(
        cli,
        operation,
        "error",
        started_at,
        elapsed_ms,
        &[format!("\"error\":\"{}\"", json_escape(err))],
    );
}

fn write_ops_log(
    cli: &Cli,
    operation: &str,
    status: &str,
    started_at: &str,
    elapsed_ms: u128,
    fields: &[String],
) {
    let mut line = format!(
        "{{\"event_at\":\"{}\",\"operation\":\"{}\",\"status\":\"{}\",\"started_at\":\"{}\",\"elapsed_ms\":{}",
        utc_iso(),
        json_escape(operation),
        json_escape(status),
        json_escape(started_at),
        elapsed_ms
    );
    for field in fields {
        line.push(',');
        line.push_str(field);
    }
    if let Some((rss_kb, cpu_pct)) = sample_self_usage() {
        line.push(',');
        line.push_str(&format!("\"rss_kb\":{}", rss_kb));
        line.push(',');
        line.push_str(&format!("\"cpu_pct\":{:.2}", cpu_pct));
    }
    line.push_str("}\n");

    if let Err(e) = append_ops_log_line(&cli.archive_dir, &line) {
        eprintln!("WARN: ops log write failed: {e}");
    }
}

fn sample_self_usage() -> Option<(u64, f64)> {
    let pid = std::process::id().to_string();
    let out = Command::new("ps")
        .args(["-o", "rss=", "-o", "%cpu=", "-p", &pid])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let mut tokens = text.split_whitespace();
    let rss_kb = tokens.next()?.parse::<u64>().ok()?;
    let cpu_pct = tokens.next()?.parse::<f64>().ok()?;
    Some((rss_kb, cpu_pct))
}

fn append_ops_log_line(archive_dir: &Path, line: &str) -> AppResult<()> {
    let path = archive_dir.join("state").join("ops-log.jsonl");
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("open ops log {}: {e}", path.display()))?;
    f.write_all(line.as_bytes())
        .map_err(|e| format!("append ops log {}: {e}", path.display()))
}

fn unlock_archive_key(cli: &Cli) -> AppResult<String> {
    let keys = load_env_file(&cli.archive_dir.join("keys").join("keys.env"))?;
    let expected = keys
        .get("KEY_HASH")
        .ok_or_else(|| "KEY_HASH missing in keys.env".to_string())?
        .clone();
    if let Some(pass) = option_or_env(cli, "--passphrase", "ARCHIVE_PASSPHRASE") {
        let wrapped = keys
            .get("PASS_WRAP_B64")
            .ok_or_else(|| "PASS_WRAP_B64 missing in keys.env".to_string())?;
        let recovered = openssl_unwrap_b64(wrapped, &pass)?;
        let hash = sha256_bytes(&recovered)?;
        if hash != expected {
            return Err("Passphrase unlock failed".to_string());
        }
        return String::from_utf8(recovered).map_err(|e| format!("invalid key bytes: {e}"));
    }
    if let Some(rec) = option_or_env(cli, "--recovery-code", "ARCHIVE_RECOVERY_CODE") {
        let wrapped = keys
            .get("REC_WRAP_B64")
            .ok_or_else(|| "REC_WRAP_B64 missing in keys.env".to_string())?;
        let recovered = openssl_unwrap_b64(wrapped, &rec)?;
        let hash = sha256_bytes(&recovered)?;
        if hash != expected {
            return Err("Recovery-code unlock failed".to_string());
        }
        return String::from_utf8(recovered).map_err(|e| format!("invalid key bytes: {e}"));
    }
    Err("Provide --passphrase or --recovery-code (or env vars)".to_string())
}
