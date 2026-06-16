use std::fs::{self, File};
use std::io::Write;
use std::time::Instant;

use crate::collector::discover_sources;
use crate::crypto::{openssl_unwrap_b64, openssl_wrap_b64, sha256_bytes};
use crate::storage::{StateStore, load_env_file};
use crate::types::{AppResult, Cli};
use crate::utils::{expand_tilde, random_hex, utc_iso, write_private_file};

use super::support::{option_or_env, write_ops_error_log, write_ops_log};

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

        let mut state = StateStore::open(&cli.archive_dir)?;
        state.reset_for_init()?;
        File::create(cli.archive_dir.join("manifests").join("manifest.tsv"))
            .map_err(|e| format!("create manifest: {e}"))?;

        if let Some(recovery_file) = cli.options.get("--recovery-file") {
            let p = expand_tilde(recovery_file);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("mkdir recovery file parent: {e}"))?;
            }
            write_private_file(&p, format!("{recovery_code}\n").as_bytes())?;
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
