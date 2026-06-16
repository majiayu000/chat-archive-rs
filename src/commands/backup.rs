use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::time::Instant;

use crate::collector::{discover_sources, stream_records_from_source};
use crate::crypto::{openssl_encrypt_chunk_with_level, sha256_bytes};
use crate::storage::{StateStore, load_manifest_entries, sync_to_remote};
use crate::types::{AppResult, Cli};
use crate::utils::{expand_tilde, json_escape, random_hex, utc_iso, utc_stamp};

use super::support::{
    parse_compress_level, unlock_archive_key, write_ops_error_log, write_ops_log,
};

const DEFAULT_CHUNK_PLAIN_BYTES: usize = 256 * 1024 * 1024;
const CHUNK_PLAIN_BYTES_ENV: &str = "CHAT_ARCHIVE_CHUNK_PLAIN_BYTES";
const FAIL_AFTER_MANIFEST_REPLACE_ENV: &str = "CHAT_ARCHIVE_FAIL_AFTER_MANIFEST_REPLACE";

#[derive(Debug, Clone)]
pub(super) struct BackupStats {
    pub(super) sources_scanned: usize,
    pub(super) checkpoint_rewinds: usize,
    pub(super) deferred_tail_sources: usize,
    pub(super) new_records: usize,
    pub(super) compress_level: i32,
    pub(super) chunk_count: usize,
    pub(super) plain_bytes: usize,
    pub(super) cipher_bytes: usize,
    pub(super) chunk_file: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct PendingChunk {
    temp_file: PathBuf,
    record_count: usize,
    plain_hash: String,
    cipher_hash: String,
    plain_bytes: usize,
    cipher_bytes: usize,
}

struct ChunkStager<'a> {
    archive_dir: &'a Path,
    archive_key: &'a str,
    compress_level: i32,
    chunk_plain_limit: usize,
    current_records: Vec<String>,
    current_plain_bytes: usize,
    pending_chunks: Vec<PendingChunk>,
}

impl<'a> ChunkStager<'a> {
    fn new(
        archive_dir: &'a Path,
        archive_key: &'a str,
        compress_level: i32,
        chunk_plain_limit: usize,
    ) -> Self {
        Self {
            archive_dir,
            archive_key,
            compress_level,
            chunk_plain_limit,
            current_records: Vec::new(),
            current_plain_bytes: 0,
            pending_chunks: Vec::new(),
        }
    }

    fn push(&mut self, record: String) -> AppResult<()> {
        let separator_bytes = usize::from(!self.current_records.is_empty());
        let record_bytes = record.len();
        if !self.current_records.is_empty()
            && self
                .current_plain_bytes
                .saturating_add(separator_bytes + record_bytes)
                > self.chunk_plain_limit
            && let Some(chunk) = stage_records_chunk(
                self.archive_dir,
                self.archive_key,
                self.compress_level,
                &mut self.current_records,
            )?
        {
            self.pending_chunks.push(chunk);
            self.current_plain_bytes = 0;
        }

        if self.current_records.is_empty() {
            self.current_plain_bytes = record_bytes;
        } else {
            self.current_plain_bytes += 1 + record_bytes;
        }
        self.current_records.push(record);
        Ok(())
    }

    fn finish(mut self) -> AppResult<Vec<PendingChunk>> {
        if let Some(chunk) = stage_records_chunk(
            self.archive_dir,
            self.archive_key,
            self.compress_level,
            &mut self.current_records,
        )? {
            self.pending_chunks.push(chunk);
        }
        Ok(self.pending_chunks)
    }
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
                println!("Chunks written: {}", stats.chunk_count);
                println!(
                    "Chunk payload bytes (plain -> encrypted): {} -> {}",
                    stats.plain_bytes, stats.cipher_bytes
                );
                if let Some(chunk_file) = &stats.chunk_file {
                    println!("Last chunk written: {}", chunk_file.display());
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
                    format!("\"chunk_count\":{}", stats.chunk_count),
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
    let chunk_plain_limit = parse_chunk_plain_byte_limit()?;
    let mut state = StateStore::open(&cli.archive_dir)?;
    state.recover_pending_backups(&cli.archive_dir)?;
    let operation_id = format!("{}-{}", utc_stamp(), random_hex(8)?);
    state.begin_pending_backup(&operation_id)?;
    let mut chunk_stager = ChunkStager::new(
        &cli.archive_dir,
        &archive_key,
        compress_level,
        chunk_plain_limit,
    );
    let mut checkpoint_updates: Vec<(String, u64)> = Vec::new();
    let mut deferred_tail_sources = 0usize;
    let mut sources_scanned = 0usize;
    let mut checkpoint_rewinds = 0usize;
    let mut new_record_count = 0usize;

    for source in discover_sources()? {
        sources_scanned += 1;
        let spath = source.path.to_string_lossy().to_string();
        let size = fs::metadata(&source.path)
            .map_err(|e| format!("stat {}: {e}", source.path.display()))?
            .len();
        let old_offset = state.checkpoint(&spath)?.unwrap_or(0);
        let start = if old_offset <= size {
            old_offset
        } else {
            checkpoint_rewinds += 1;
            0
        };
        let read_stats = stream_records_from_source(&source, start, |rec| {
            let id = rec
                .split('\t')
                .next()
                .ok_or_else(|| "invalid record format".to_string())?
                .to_string();
            if state.stage_pending_seen_id(&operation_id, &id)? {
                new_record_count += 1;
                chunk_stager.push(rec)?;
            }
            Ok(())
        })?;
        checkpoint_updates.push((spath, read_stats.commit_offset));
        if read_stats.deferred_partial_line {
            deferred_tail_sources += 1;
        }
    }

    let pending_chunks = chunk_stager.finish()?;

    if pending_chunks.is_empty() {
        state.commit_backup_state(&checkpoint_updates, &[])?;
        state.discard_pending_backup(&cli.archive_dir, &operation_id)?;
        if let Some(remote_dir) = cli.options.get("--remote-dir") {
            sync_to_remote(&cli.archive_dir, &expand_tilde(remote_dir), None)?;
        }
        return Ok(BackupStats {
            sources_scanned,
            checkpoint_rewinds,
            deferred_tail_sources,
            new_records: 0,
            compress_level,
            chunk_count: 0,
            plain_bytes: 0,
            cipher_bytes: 0,
            chunk_file: None,
        });
    }

    state.stage_pending_checkpoint_updates(&operation_id, &checkpoint_updates)?;
    let manifest_entries = load_manifest_entries(&cli.archive_dir)?;
    let mut prev_hash = manifest_entries
        .last()
        .map(|m| m.manifest_hash.clone())
        .unwrap_or_else(|| "-".to_string());
    let mut last_chunk_file = None;
    let mut total_plain_bytes = 0usize;
    let mut total_cipher_bytes = 0usize;
    let mut manifest_lines = Vec::new();
    let mut manifest_pending_entries = Vec::new();
    let mut chunk_promotions = Vec::new();
    for pending in &pending_chunks {
        total_plain_bytes += pending.plain_bytes;
        total_cipher_bytes += pending.cipher_bytes;

        let chunk_id = format!("{}-{}", utc_stamp(), random_hex(4)?);
        let chunk_file = cli
            .archive_dir
            .join("chunks")
            .join(format!("{chunk_id}.enc"));
        let chunk_rel = format!("chunks/{chunk_id}.enc");
        let core = format!(
            "{prev_hash}\t{}\t{chunk_id}\t{chunk_rel}\t{}\t{}\t{}",
            utc_iso(),
            pending.record_count,
            pending.plain_hash,
            pending.cipher_hash
        );
        let manifest_hash = sha256_bytes(core.as_bytes())?;
        let line = format!("{manifest_hash}\t{core}");
        manifest_lines.push(line.clone());
        manifest_pending_entries.push((chunk_rel.clone(), line));
        chunk_promotions.push((pending.temp_file.clone(), chunk_file.clone()));
        prev_hash = manifest_hash;
        last_chunk_file = Some(chunk_file);
    }

    state.stage_pending_manifest_entries(&operation_id, &manifest_pending_entries)?;
    for (temp_file, chunk_file) in &chunk_promotions {
        fs::rename(temp_file, chunk_file).map_err(|e| {
            format!(
                "promote chunk {} -> {}: {e}",
                temp_file.display(),
                chunk_file.display()
            )
        })?;
    }
    replace_manifest_with_appended_lines(&cli.archive_dir, &manifest_lines)?;
    if env::var_os(FAIL_AFTER_MANIFEST_REPLACE_ENV).is_some() {
        return Err(format!(
            "{FAIL_AFTER_MANIFEST_REPLACE_ENV} requested failure after manifest replace"
        ));
    }
    state.commit_pending_backup_state(&operation_id)?;

    if let Some(remote_dir) = cli.options.get("--remote-dir") {
        sync_to_remote(&cli.archive_dir, &expand_tilde(remote_dir), None)?;
    }

    Ok(BackupStats {
        sources_scanned,
        checkpoint_rewinds,
        deferred_tail_sources,
        new_records: new_record_count,
        compress_level,
        chunk_count: pending_chunks.len(),
        plain_bytes: total_plain_bytes,
        cipher_bytes: total_cipher_bytes,
        chunk_file: last_chunk_file,
    })
}

fn parse_chunk_plain_byte_limit() -> AppResult<usize> {
    let Ok(raw) = env::var(CHUNK_PLAIN_BYTES_ENV) else {
        return Ok(DEFAULT_CHUNK_PLAIN_BYTES);
    };
    let parsed = raw
        .parse::<usize>()
        .map_err(|e| format!("invalid {CHUNK_PLAIN_BYTES_ENV}: {e}"))?;
    if parsed == 0 {
        Err(format!(
            "invalid {CHUNK_PLAIN_BYTES_ENV}: must be greater than 0"
        ))
    } else {
        Ok(parsed)
    }
}

fn stage_records_chunk(
    archive_dir: &Path,
    archive_key: &str,
    compress_level: i32,
    records: &mut Vec<String>,
) -> AppResult<Option<PendingChunk>> {
    if records.is_empty() {
        return Ok(None);
    }

    fs::create_dir_all(archive_dir.join("tmp")).map_err(|e| format!("create tmp dir: {e}"))?;
    let record_count = records.len();
    let plain = records.join("\n").into_bytes();
    records.clear();
    let plain_hash = sha256_bytes(&plain)?;
    let cipher = openssl_encrypt_chunk_with_level(&plain, archive_key, compress_level)?;
    let cipher_hash = sha256_bytes(&cipher)?;
    let temp_file =
        archive_dir
            .join("tmp")
            .join(format!("chunk-{}-{}.enc.tmp", utc_stamp(), random_hex(4)?));
    fs::write(&temp_file, &cipher).map_err(|e| format!("write staged chunk: {e}"))?;

    Ok(Some(PendingChunk {
        temp_file,
        record_count,
        plain_hash,
        cipher_hash,
        plain_bytes: plain.len(),
        cipher_bytes: cipher.len(),
    }))
}

fn replace_manifest_with_appended_lines(archive_dir: &Path, lines: &[String]) -> AppResult<()> {
    let manifest_path = archive_dir.join("manifests").join("manifest.tsv");
    let tmp_path = archive_dir.join("tmp").join(format!(
        "manifest-{}-{}.tsv.tmp",
        utc_stamp(),
        random_hex(4)?
    ));
    let mut tmp = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .map_err(|e| format!("create manifest temp {}: {e}", tmp_path.display()))?;

    if manifest_path.exists() {
        let existing = fs::read(&manifest_path)
            .map_err(|e| format!("read manifest {}: {e}", manifest_path.display()))?;
        tmp.write_all(&existing)
            .map_err(|e| format!("write manifest temp: {e}"))?;
        if !existing.is_empty() && !existing.ends_with(b"\n") {
            tmp.write_all(b"\n")
                .map_err(|e| format!("write manifest temp newline: {e}"))?;
        }
    }
    for line in lines {
        tmp.write_all(line.as_bytes())
            .map_err(|e| format!("write manifest temp line: {e}"))?;
        tmp.write_all(b"\n")
            .map_err(|e| format!("write manifest temp newline: {e}"))?;
    }
    tmp.flush()
        .map_err(|e| format!("flush manifest temp: {e}"))?;
    fs::rename(&tmp_path, &manifest_path).map_err(|e| {
        format!(
            "replace manifest {} -> {}: {e}",
            tmp_path.display(),
            manifest_path.display()
        )
    })
}
