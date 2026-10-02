use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::crypto::openssl_decrypt_chunk;
use crate::storage::load_manifest_entries;
use crate::types::{AppResult, Cli, ManifestEntry};
use crate::utils::{expand_tilde, hex_decode_to_string, json_escape, random_hex, utc_iso};

use super::support::{unlock_archive_key, write_ops_error_log, write_ops_log};
use super::verify::verify_manifest_entries;

#[derive(Debug, Clone)]
struct RestoreStats {
    total_records: usize,
    unique_raw_hashes: usize,
}

struct VerifiedChunks {
    file: Option<File>,
    path: PathBuf,
    sizes: Vec<usize>,
}

impl VerifiedChunks {
    fn capture(
        archive_dir: &Path,
        archive_key: &str,
        manifests: &[ManifestEntry],
        output_dir: &Path,
    ) -> AppResult<Self> {
        let snapshot_dir = output_dir
            .ancestors()
            .find(|path| path.is_dir())
            .unwrap_or_else(|| Path::new("."));
        let path = snapshot_dir.join(format!(".chat-archive-rs-restore-{}.enc", random_hex(16)?));
        let mut options = OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .map_err(|e| format!("create restore snapshot: {e}"))?;
        let mut snapshot = Self {
            file: Some(file),
            path,
            sizes: Vec::with_capacity(manifests.len()),
        };
        let file = snapshot.file.as_mut().expect("snapshot file is open");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("chmod restore snapshot: {e}"))?;
        }
        // Snapshot ciphertext, never decrypted chat data, one verified chunk at a time.
        verify_manifest_entries(archive_dir, archive_key, manifests, |cipher| {
            file.write_all(cipher)
                .map_err(|e| format!("write restore snapshot: {e}"))?;
            snapshot.sizes.push(cipher.len());
            Ok(())
        })?;
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("rewind restore snapshot: {e}"))?;
        Ok(snapshot)
    }
}

impl Drop for VerifiedChunks {
    fn drop(&mut self) {
        // Close before unlinking so cleanup works on Windows too.
        drop(self.file.take());
        if let Err(err) = fs::remove_file(&self.path) {
            eprintln!(
                "WARN: remove restore snapshot {}: {err}",
                self.path.display()
            );
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

fn create_private_output(path: &std::path::Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        match path.symlink_metadata() {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(std::io::Error::other(format!(
                    "refusing restore output symlink: {}",
                    path.display()
                )));
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        // Publication replaces the entry without opening it, so a symlink
        // planted after this check still cannot redirect plaintext writes.
        let stage = path.with_file_name(format!(
            ".chat-archive-rs-restore-{}.tmp",
            crate::utils::random_hex(16).map_err(std::io::Error::other)?
        ));
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        options.mode(0o600);
        let file = options.open(&stage)?;
        // A fresh inode keeps previously opened outputs from seeing new plaintext.
        let result = file
            .set_permissions(fs::Permissions::from_mode(0o600))
            .and_then(|()| fs::rename(&stage, path));
        if let Err(err) = result {
            fs::remove_file(&stage).map_err(|cleanup| {
                std::io::Error::other(format!("{err}; remove restore output stage: {cleanup}"))
            })?;
            return Err(err);
        }
        Ok(file)
    }

    #[cfg(not(unix))]
    {
        File::create(path)
    }
}

fn run_restore_once(cli: &Cli) -> AppResult<RestoreStats> {
    let archive_key = unlock_archive_key(cli)?;
    let output_dir = cli
        .options
        .get("--output-dir")
        .map(|s| expand_tilde(s))
        .ok_or_else(|| "restore requires --output-dir".to_string())?;
    let manifests = load_manifest_entries(&cli.archive_dir)?;
    let chunks = VerifiedChunks::capture(&cli.archive_dir, &archive_key, &manifests, &output_dir)?;
    restore_verified_chunks(chunks, &archive_key, &output_dir)
}

fn restore_verified_chunks(
    mut chunks: VerifiedChunks,
    archive_key: &str,
    output_dir: &Path,
) -> AppResult<RestoreStats> {
    fs::create_dir_all(output_dir).map_err(|e| format!("create output dir: {e}"))?;
    let canonical = output_dir.join("canonical-records.jsonl");
    let codex_raw = output_dir.join("codex-raw.jsonl");
    let claude_raw = output_dir.join("claude-raw.jsonl");
    let canonical_file =
        create_private_output(&canonical).map_err(|e| format!("reset canonical: {e}"))?;
    let codex_file = create_private_output(&codex_raw).map_err(|e| format!("reset codex: {e}"))?;
    let claude_file =
        create_private_output(&claude_raw).map_err(|e| format!("reset claude: {e}"))?;
    let mut canonical_writer = BufWriter::with_capacity(8 * 1024 * 1024, canonical_file);
    let mut codex_writer = BufWriter::with_capacity(4 * 1024 * 1024, codex_file);
    let mut claude_writer = BufWriter::with_capacity(4 * 1024 * 1024, claude_file);

    let mut total = 0usize;
    let mut unique_raw = HashSet::new();
    let snapshot_file = chunks.file.as_mut().expect("snapshot file is open");
    for size in &chunks.sizes {
        let mut cipher = vec![0; *size];
        snapshot_file
            .read_exact(&mut cipher)
            .map_err(|e| format!("read restore snapshot: {e}"))?;
        let plain = openssl_decrypt_chunk(&cipher, archive_key)?;
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
    create_private_output(&output_dir.join("restore-report.json"))
        .and_then(|mut file| file.write_all(report.as_bytes()))
        .map_err(|e| format!("write restore report: {e}"))?;

    Ok(RestoreStats {
        total_records: total,
        unique_raw_hashes: unique_raw.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{openssl_encrypt_chunk_with_level, sha256_bytes};
    use crate::utils::hex_encode;

    #[test]
    fn restore_uses_verified_chunks_after_archive_changes() -> AppResult<()> {
        let root =
            std::env::temp_dir().join(format!("chat-archive-rs-snapshot-test-{}", random_hex(16)?));
        let archive = root.join("archive");
        let output = root.join("restore");
        fs::create_dir_all(archive.join("chunks")).map_err(|e| e.to_string())?;
        let key = "test-snapshot-key";
        let raw_lines = [
            "{\"text\":\"verified codex\"}",
            "{\"text\":\"verified claude\"}",
        ];
        let mut manifests = Vec::new();
        let mut expected_cipher = Vec::new();
        let mut prev_hash = "-".to_string();
        for (idx, raw) in raw_lines.iter().enumerate() {
            let provider = if idx == 0 { "codex" } else { "claude" };
            let plain = format!(
                "record-{idx}\t{provider}\t{}\t0\t{}\t{}\n",
                hex_encode(b"source.jsonl"),
                sha256_bytes(raw.as_bytes())?,
                hex_encode(raw.as_bytes())
            );
            let cipher = openssl_encrypt_chunk_with_level(plain.as_bytes(), key, 6)?;
            let chunk_rel = format!("chunks/{idx}.enc");
            fs::write(archive.join(&chunk_rel), &cipher).map_err(|e| e.to_string())?;
            expected_cipher.extend_from_slice(&cipher);
            let mut entry = ManifestEntry {
                manifest_hash: String::new(),
                prev_hash,
                created_at: utc_iso(),
                chunk_id: idx.to_string(),
                chunk_rel,
                record_count: 1,
                plain_sha: sha256_bytes(plain.as_bytes())?,
                cipher_sha: sha256_bytes(&cipher)?,
            };
            entry.manifest_hash = sha256_bytes(
                format!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    entry.prev_hash,
                    entry.created_at,
                    entry.chunk_id,
                    entry.chunk_rel,
                    entry.record_count,
                    entry.plain_sha,
                    entry.cipher_sha
                )
                .as_bytes(),
            )?;
            prev_hash = entry.manifest_hash.clone();
            manifests.push(entry);
        }

        let chunks = VerifiedChunks::capture(&archive, key, &manifests, &output)?;
        let snapshot_path = chunks.path.clone();
        assert_eq!(snapshot_path.parent(), Some(root.as_path()));
        assert_eq!(
            fs::read(&snapshot_path).map_err(|e| e.to_string())?,
            expected_cipher
        );
        fs::write(
            archive.join(&manifests[0].chunk_rel),
            openssl_encrypt_chunk_with_level(b"unverified replacement", key, 6)?,
        )
        .map_err(|e| e.to_string())?;
        fs::remove_file(archive.join(&manifests[1].chunk_rel)).map_err(|e| e.to_string())?;
        assert!(!output.exists());

        let stats = restore_verified_chunks(chunks, key, &output)?;
        assert_eq!(stats.total_records, 2);
        assert_eq!(stats.unique_raw_hashes, 2);
        assert_eq!(
            fs::read_to_string(output.join("codex-raw.jsonl")).map_err(|e| e.to_string())?,
            format!("{}\n", raw_lines[0])
        );
        assert_eq!(
            fs::read_to_string(output.join("claude-raw.jsonl")).map_err(|e| e.to_string())?,
            format!("{}\n", raw_lines[1])
        );
        let report: serde_json::Value = serde_json::from_slice(
            &fs::read(output.join("restore-report.json")).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        assert_eq!(report["total_records"], 2);
        assert!(!snapshot_path.exists());
        fs::remove_dir_all(root).map_err(|e| e.to_string())?;
        Ok(())
    }
}
