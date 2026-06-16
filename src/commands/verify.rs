use std::fs;
use std::time::Instant;

use crate::crypto::{openssl_decrypt_chunk, sha256_bytes};
use crate::storage::load_manifest_entries;
use crate::types::{AppResult, Cli};
use crate::utils::utc_iso;

use super::support::{unlock_archive_key, write_ops_error_log, write_ops_log};

#[derive(Debug, Clone)]
pub(super) struct VerifyStats {
    pub(super) manifests: usize,
    pub(super) records: usize,
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

pub(super) fn run_verify_once(cli: &Cli) -> AppResult<VerifyStats> {
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
