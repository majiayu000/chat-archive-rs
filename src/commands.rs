use std::collections::HashSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write;

use crate::collector::{discover_sources, read_records_from_source};
use crate::crypto::{
    openssl_decrypt_chunk, openssl_encrypt_chunk, openssl_unwrap_b64, openssl_wrap_b64,
    sha256_bytes,
};
use crate::storage::{
    append_seen_ids, load_checkpoints, load_env_file, load_manifest_entries, load_seen_ids,
    save_checkpoints, sync_to_remote,
};
use crate::types::{AppResult, Cli, ManifestEntry};
use crate::utils::{
    append_file, expand_tilde, hex_decode_to_string, json_escape, random_hex, utc_iso, utc_stamp,
};

pub fn cmd_init(cli: &Cli) -> AppResult<()> {
    let passphrase = option_or_env(cli, "--passphrase", "ARCHIVE_PASSPHRASE")
        .ok_or_else(|| "init requires --passphrase or ARCHIVE_PASSPHRASE".to_string())?;
    let recovery_code = option_or_env(cli, "--recovery-code", "ARCHIVE_RECOVERY_CODE")
        .ok_or_else(|| "init requires --recovery-code or ARCHIVE_RECOVERY_CODE".to_string())?;

    let archive_key = random_hex(32)?;
    let key_hash = sha256_bytes(archive_key.as_bytes())?;
    let pass_wrap = openssl_wrap_b64(archive_key.as_bytes(), &passphrase)?;
    let rec_wrap = openssl_wrap_b64(archive_key.as_bytes(), &recovery_code)?;

    let keys_path = cli.archive_dir.join("keys").join("keys.env");
    let mut keys_file = File::create(&keys_path).map_err(|e| format!("create keys file: {e}"))?;
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
            fs::create_dir_all(parent).map_err(|e| format!("mkdir recovery file parent: {e}"))?;
        }
        fs::write(&p, format!("{recovery_code}\n"))
            .map_err(|e| format!("write recovery file: {e}"))?;
    }

    println!("Archive initialized: {}", cli.archive_dir.display());
    println!("Recovery code stored in memory only unless --recovery-file is provided.");
    Ok(())
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
    let archive_key = unlock_archive_key(cli)?;
    let mut checkpoints = load_checkpoints(&cli.archive_dir)?;
    let mut seen = load_seen_ids(&cli.archive_dir)?;
    let mut records: Vec<String> = Vec::new();
    let mut new_ids: Vec<String> = Vec::new();
    let mut deferred_tail_sources = 0usize;

    for source in discover_sources()? {
        let spath = source.path.to_string_lossy().to_string();
        let size = fs::metadata(&source.path)
            .map_err(|e| format!("stat {}: {e}", source.path.display()))?
            .len();
        let old_offset = checkpoints.get(&spath).copied().unwrap_or(0);
        let start = if old_offset <= size { old_offset } else { 0 };
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
        println!("No new records discovered.");
        if deferred_tail_sources > 0 {
            println!(
                "Deferred incomplete tail lines in {} source file(s); will capture next backup.",
                deferred_tail_sources
            );
        }
        return Ok(());
    }

    let plain_bytes = records.join("\n").into_bytes();
    let plain_hash = sha256_bytes(&plain_bytes)?;
    let cipher_bytes = openssl_encrypt_chunk(&plain_bytes, &archive_key)?;
    let cipher_hash = sha256_bytes(&cipher_bytes)?;

    let chunk_id = format!("{}-{}", utc_stamp(), random_hex(4)?);
    let chunk_file = cli
        .archive_dir
        .join("chunks")
        .join(format!("{chunk_id}.enc"));
    fs::write(&chunk_file, &cipher_bytes).map_err(|e| format!("write chunk: {e}"))?;

    let mut manifests = load_manifest_entries(&cli.archive_dir)?;
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
    manifests.push(ManifestEntry {
        manifest_hash,
        prev_hash,
        created_at: utc_iso(),
        chunk_id,
        chunk_rel,
        record_count: records.len(),
        plain_sha: plain_hash,
        cipher_sha: cipher_hash,
    });

    if let Some(remote_dir) = cli.options.get("--remote-dir") {
        sync_to_remote(
            &cli.archive_dir,
            &expand_tilde(remote_dir),
            Some(&chunk_file),
        )?;
    }

    println!("Archived new records: {}", records.len());
    if deferred_tail_sources > 0 {
        println!(
            "Deferred incomplete tail lines in {} source file(s); will capture next backup.",
            deferred_tail_sources
        );
    }
    println!("Chunk written: {}", chunk_file.display());
    Ok(())
}

pub fn cmd_verify(cli: &Cli) -> AppResult<()> {
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
    println!("Verified manifests: {}", manifests.len());
    println!("Verified records: {total}");
    Ok(())
}

pub fn cmd_restore(cli: &Cli) -> AppResult<()> {
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
    fs::write(&canonical, "").map_err(|e| format!("reset canonical: {e}"))?;
    fs::write(&codex_raw, "").map_err(|e| format!("reset codex: {e}"))?;
    fs::write(&claude_raw, "").map_err(|e| format!("reset claude: {e}"))?;

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
            append_file(&canonical, canonical_line.as_bytes())?;
            if provider == "codex" {
                append_file(&codex_raw, format!("{raw_line}\n").as_bytes())?;
            } else {
                append_file(&claude_raw, format!("{raw_line}\n").as_bytes())?;
            }
        }
    }

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
    println!("Restore complete. Records: {total}");
    println!("Output dir: {}", output_dir.display());
    Ok(())
}

pub fn cmd_recovery_test(cli: &Cli) -> AppResult<()> {
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
}

fn option_or_env(cli: &Cli, opt: &str, env_key: &str) -> Option<String> {
    cli.options
        .get(opt)
        .cloned()
        .or_else(|| env::var(env_key).ok())
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
