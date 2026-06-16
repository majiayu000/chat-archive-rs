use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use crate::collector::{discover_sources, read_records_from_source};
use crate::crypto::{openssl_encrypt_chunk_with_level, sha256_bytes};
use crate::storage::{
    append_seen_ids, load_checkpoints, load_manifest_entries, load_seen_ids, save_checkpoints,
    sync_to_remote,
};
use crate::types::{AppResult, Cli};
use crate::utils::{expand_tilde, json_escape, random_hex, utc_iso, utc_stamp};

use super::support::{
    parse_compress_level, unlock_archive_key, write_ops_error_log, write_ops_log,
};

#[derive(Debug, Clone)]
pub(super) struct BackupStats {
    pub(super) sources_scanned: usize,
    pub(super) checkpoint_rewinds: usize,
    pub(super) deferred_tail_sources: usize,
    pub(super) new_records: usize,
    pub(super) compress_level: i32,
    pub(super) plain_bytes: usize,
    pub(super) cipher_bytes: usize,
    pub(super) chunk_file: Option<PathBuf>,
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

pub(super) fn run_backup_once(cli: &Cli) -> AppResult<BackupStats> {
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

    if records.is_empty() {
        save_checkpoints(&cli.archive_dir, &checkpoints)?;
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
    save_checkpoints(&cli.archive_dir, &checkpoints)?;

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
