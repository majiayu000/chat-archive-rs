#![cfg(unix)]

mod common;

use std::error::Error;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::Output;

use common::{create_test_workspace, path_arg, run_cli, run_cli_err};

const SENTINEL: &[u8] = b"outside dummy sentinel\n";

fn assert_error_log(
    archive: &Path,
    output: &Output,
    operation: &str,
    context: &str,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with(&format!("ERROR: {context}")), "{stderr}");
    let logs = fs::read_to_string(archive.join("state/ops-log.jsonl"))?;
    let log: serde_json::Value = serde_json::from_str(logs.lines().last().unwrap())?;
    assert_eq!(log["operation"], operation);
    assert_eq!(log["status"], "error");
    assert!(log["error"].as_str().unwrap().starts_with(context));
    Ok(())
}

fn plant_symlink(path: &Path, outside: &Path, dangling: bool) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(path.parent().unwrap())?;
    if !dangling {
        fs::write(outside, SENTINEL)?;
        fs::set_permissions(outside, fs::Permissions::from_mode(0o640))?;
    }
    symlink(outside, path)?;
    Ok(())
}

fn assert_symlink_untouched(
    path: &Path,
    outside: &Path,
    dangling: bool,
) -> Result<(), Box<dyn Error>> {
    assert!(path.symlink_metadata()?.file_type().is_symlink());
    assert_eq!(fs::read_link(path)?, outside);
    if dangling {
        assert!(!outside.exists());
    } else {
        assert_eq!(fs::read(outside)?, SENTINEL);
        assert_eq!(fs::metadata(outside)?.permissions().mode() & 0o777, 0o640);
    }
    Ok(())
}

#[test]
fn init_rejects_keys_and_recovery_symlinks() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("init-private-symlinks")?;
    let home = root.join("home");
    let bin = Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"));
    for keys in [true, false] {
        for dangling in [false, true] {
            let case = root.join(format!("keys-{keys}-dangling-{dangling}"));
            fs::create_dir_all(&case)?;
            let archive = case.join("archive");
            let recovery = case.join("recovery.txt");
            let path = if keys {
                archive.join("keys/keys.env")
            } else {
                recovery.clone()
            };
            let outside = case.join("outside.txt");
            plant_symlink(&path, &outside, dangling)?;
            let output = run_cli_err(
                bin,
                &home,
                &[
                    "--archive-dir",
                    path_arg(&archive)?,
                    "init",
                    "--passphrase",
                    "test-passphrase",
                    "--recovery-code",
                    "test-recovery-code",
                    "--recovery-file",
                    path_arg(&recovery)?,
                ],
            )?;
            assert_error_log(
                &archive,
                &output,
                "init",
                if keys {
                    "refusing to initialize:"
                } else {
                    "create private file "
                },
            )?;
            assert_symlink_untouched(&path, &outside, dangling)?;
            assert!(!archive.join("manifests/manifest.tsv").exists());
            if !keys {
                assert!(!archive.join("keys/keys.env").exists());
            }
            assert!(fs::read_dir(archive.join("keys"))?.all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".keys.env.init-")
            }));
        }
    }
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn restore_rejects_every_output_symlink() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("restore-private-symlinks")?;
    let home = root.join("home");
    let archive = root.join("archive");
    let bin = Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"));
    fs::create_dir_all(home.join(".codex"))?;
    fs::write(
        home.join(".codex/history.jsonl"),
        "{\"text\":\"dummy transcript\"}\n",
    )?;
    run_cli(
        bin,
        &home,
        &[
            "--archive-dir",
            path_arg(&archive)?,
            "init",
            "--passphrase",
            "test-passphrase",
            "--recovery-code",
            "test-recovery-code",
        ],
    )?;
    run_cli(
        bin,
        &home,
        &[
            "--archive-dir",
            path_arg(&archive)?,
            "backup",
            "--passphrase",
            "test-passphrase",
        ],
    )?;
    for (name, context) in [
        ("canonical-records.jsonl", "reset canonical:"),
        ("codex-raw.jsonl", "reset codex:"),
        ("claude-raw.jsonl", "reset claude:"),
        ("restore-report.json", "write restore report:"),
    ] {
        for dangling in [false, true] {
            let restore = root.join(format!("{name}-{dangling}"));
            let path = restore.join(name);
            let outside = root.join(format!("outside-{name}-{dangling}"));
            plant_symlink(&path, &outside, dangling)?;
            let output = run_cli_err(
                bin,
                &home,
                &[
                    "--archive-dir",
                    path_arg(&archive)?,
                    "restore",
                    "--passphrase",
                    "test-passphrase",
                    "--output-dir",
                    path_arg(&restore)?,
                ],
            )?;
            assert_error_log(&archive, &output, "restore", context)?;
            assert!(String::from_utf8_lossy(&output.stderr).contains("symlink"));
            assert_symlink_untouched(&path, &outside, dangling)?;
            assert!(fs::read_dir(&restore)?.all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".chat-archive-rs-restore-")
            }));
        }
    }
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn recovery_regular_file_overwrite_stays_private() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("recovery-overwrite")?;
    let home = root.join("home");
    let recovery = root.join("recovery.txt");
    fs::write(&recovery, b"old recovery contents that must be truncated\n")?;
    fs::set_permissions(&recovery, fs::Permissions::from_mode(0o666))?;
    let bin = Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"));
    run_cli(
        bin,
        &home,
        &[
            "--archive-dir",
            path_arg(&root.join("archive"))?,
            "init",
            "--passphrase",
            "test-passphrase",
            "--recovery-code",
            "test-recovery-code",
            "--recovery-file",
            path_arg(&recovery)?,
        ],
    )?;
    assert_eq!(fs::read(&recovery)?, b"test-recovery-code\n");
    assert_eq!(fs::metadata(&recovery)?.permissions().mode() & 0o777, 0o600);
    fs::remove_dir_all(root)?;
    Ok(())
}
