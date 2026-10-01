use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::time::Instant;

use crate::collector::discover_sources;
use crate::crypto::{openssl_unwrap_b64, openssl_wrap_b64, sha256_bytes};
use crate::storage::{StateStore, load_env_file, lock_archive_publication};
use crate::types::{AppResult, Cli};
use crate::utils::{expand_tilde, random_hex, utc_iso, write_private_file};

use super::support::{option_or_env, write_ops_error_log, write_ops_log};

pub fn cmd_init(cli: &Cli) -> AppResult<()> {
    let started_at = utc_iso();
    let timer = Instant::now();

    let result: AppResult<()> = (|| -> AppResult<()> {
        let _publication_lock = lock_archive_publication(&cli.archive_dir)?;
        let keys_path = cli.archive_dir.join("keys").join("keys.env");
        let manifest_path = cli.archive_dir.join("manifests").join("manifest.tsv");
        for path in [&keys_path, &manifest_path] {
            match path.symlink_metadata() {
                Ok(_) => {
                    return Err(format!(
                        "refusing to initialize: {} already exists; use a new archive directory",
                        path.display()
                    ));
                }
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => return Err(format!("stat archive file {}: {err}", path.display())),
            }
        }

        let passphrase = option_or_env(cli, "--passphrase", "ARCHIVE_PASSPHRASE")
            .ok_or_else(|| "init requires --passphrase or ARCHIVE_PASSPHRASE".to_string())?;
        let recovery_code = option_or_env(cli, "--recovery-code", "ARCHIVE_RECOVERY_CODE")
            .ok_or_else(|| "init requires --recovery-code or ARCHIVE_RECOVERY_CODE".to_string())?;

        let archive_key = random_hex(32)?;
        let key_hash = sha256_bytes(archive_key.as_bytes())?;
        let pass_wrap = openssl_wrap_b64(archive_key.as_bytes(), &passphrase)?;
        let rec_wrap = openssl_wrap_b64(archive_key.as_bytes(), &recovery_code)?;

        let staged_keys_path =
            keys_path.with_file_name(format!(".keys.env.init-{}.tmp", random_hex(16)?));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        // Stage beside the destination so publication is a same-filesystem rename.
        let mut keys_file = options
            .open(&staged_keys_path)
            .map_err(|e| format!("create staged keys: {e}"))?;
        let init_result: AppResult<()> = (|| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // Creation stays private even with a permissive umask; restore
                // owner access before writing bytes if the umask masked it.
                keys_file
                    .set_permissions(fs::Permissions::from_mode(0o600))
                    .map_err(|e| format!("chmod keys: {e}"))?;
            }
            let body = format!(
                "VERSION=1\nCREATED_AT={}\nKEY_HASH={key_hash}\nPASS_WRAP_B64={pass_wrap}\nREC_WRAP_B64={rec_wrap}\n",
                utc_iso()
            );
            keys_file
                .write_all(body.as_bytes())
                .map_err(|e| format!("write keys: {e}"))?;
            keys_file
                .sync_all()
                .map_err(|e| format!("sync keys: {e}"))?;
            let mut state = StateStore::open(&cli.archive_dir)?;
            state.reset_for_init()?;

            if let Some(recovery_file) = cli.options.get("--recovery-file") {
                let p = expand_tilde(recovery_file);
                if let Some(parent) = p.parent() {
                    fs::create_dir_all(parent)
                        .map_err(|e| format!("mkdir recovery file parent: {e}"))?;
                }
                write_private_file(&p, format!("{recovery_code}\n").as_bytes())?;
            }

            Ok(())
        })();
        drop(keys_file);
        // The key is the only init marker. Missing manifests already represent
        // empty archives and the first backup creates one. No final marker is
        // visible until all other fallible initialization work has succeeded.
        let init_result = init_result.and_then(|()| {
            rename_keys_no_replace(&staged_keys_path, &keys_path)
                .map_err(|e| format!("publish keys: {e}"))
        });
        if let Err(mut err) = init_result {
            if let Err(cleanup_err) = fs::remove_file(&staged_keys_path) {
                err.push_str(&format!(
                    "; remove failed init file {}: {cleanup_err}",
                    staged_keys_path.display()
                ));
            }
            return Err(err);
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

fn rename_keys_no_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox"
    ))]
    {
        use rustix::fs::{CWD, RenameFlags, renameat_with};
        renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE).map_err(Into::into)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::MoveFileExW;
        // Rust canonicalization supplies absolute extended-length Windows
        // paths. Only the destination's parent exists before publication.
        let from = fs::canonicalize(from)?;
        let to =
            fs::canonicalize(to.with_file_name("."))?.join(to.file_name().ok_or_else(|| {
                std::io::Error::new(ErrorKind::InvalidInput, "key destination has no filename")
            })?);
        let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
        let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: both buffers remain alive and are NUL-terminated paths. Zero
        // flags forbids replacement and cross-volume copy/delete publication.
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 0) } == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    #[cfg(not(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox",
        windows
    )))]
    {
        let _ = (from, to);
        Err(std::io::Error::new(
            ErrorKind::Unsupported,
            "atomic no-replace key publication is unsupported on this platform",
        ))
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

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::error::Error;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn key_publication_handles_long_absolute_and_relative_paths_without_replacement()
    -> Result<(), Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let relative_root = Path::new("target").join(format!("init-long-path-{nonce}"));
        let mut directory = relative_root.clone();
        for _ in 0..4 {
            directory = directory.join("deep-directory-".repeat(6));
        }
        fs::create_dir_all(&directory)?;
        for directory in [directory.clone(), std::env::current_dir()?.join(directory)] {
            assert!(directory.as_os_str().len() > 260);
            let staged = directory.join(".keys.env.init-test.tmp");
            let published = directory.join("keys.env");
            fs::write(&staged, b"first key fixture")?;
            rename_keys_no_replace(&staged, &published)?;
            assert!(!staged.exists());
            assert_eq!(fs::read(&published)?, b"first key fixture");
            fs::write(&staged, b"second key fixture")?;
            assert!(rename_keys_no_replace(&staged, &published).is_err());
            assert_eq!(fs::read(&published)?, b"first key fixture");
            assert_eq!(fs::read(&staged)?, b"second key fixture");
            fs::remove_file(staged)?;
            fs::remove_file(published)?;
        }
        fs::remove_dir_all(relative_root)?;
        Ok(())
    }
}
