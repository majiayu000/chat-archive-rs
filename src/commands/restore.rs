use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::time::Instant;

use crate::crypto::openssl_decrypt_chunk;
use crate::storage::load_manifest_entries;
use crate::types::{AppResult, Cli};
use crate::utils::{expand_tilde, hex_decode_to_string, json_escape, utc_iso};

use super::support::{unlock_archive_key, write_ops_error_log, write_ops_log};

#[derive(Debug, Clone)]
struct RestoreStats {
    total_records: usize,
    unique_raw_hashes: usize,
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
