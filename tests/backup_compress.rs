use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[test]
fn backup_with_compress_level_creates_verifiable_archive() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("backup-compress")?;
    let home = root.join("home");
    let archive = root.join("archive");
    let restore = root.join("restore");
    let codex_dir = home.join(".codex");
    fs::create_dir_all(&codex_dir)?;
    let raw_line = "{\"type\":\"message\",\"text\":\"hello compressed backup\"}";
    fs::write(codex_dir.join("history.jsonl"), format!("{raw_line}\n"))?;

    let bin = Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"));
    let archive_arg = path_arg(&archive)?;
    let restore_arg = path_arg(&restore)?;

    run_cli(
        bin,
        &home,
        &[
            "--archive-dir",
            archive_arg,
            "init",
            "--passphrase",
            "test-passphrase",
            "--recovery-code",
            "test-recovery-code",
        ],
    )?;
    let backup = run_cli(
        bin,
        &home,
        &[
            "--archive-dir",
            archive_arg,
            "backup",
            "--passphrase",
            "test-passphrase",
            "--compress-level",
            "12",
        ],
    )?;
    let backup_stdout = String::from_utf8(backup.stdout)?;
    assert!(backup_stdout.contains("Compression level: 12"));
    assert_eq!(fs::read_dir(archive.join("chunks"))?.count(), 1);

    run_cli(
        bin,
        &home,
        &[
            "--archive-dir",
            archive_arg,
            "verify",
            "--passphrase",
            "test-passphrase",
        ],
    )?;
    run_cli(
        bin,
        &home,
        &[
            "--archive-dir",
            archive_arg,
            "restore",
            "--passphrase",
            "test-passphrase",
            "--output-dir",
            restore_arg,
        ],
    )?;
    let restored = fs::read_to_string(restore.join("codex-raw.jsonl"))?;
    assert_eq!(restored, format!("{raw_line}\n"));

    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn init_recovery_file_is_owner_only() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("recovery-file-mode")?;
    let home = root.join("home");
    let archive = root.join("archive");
    let recovery_file = root.join("recovery.txt");

    let bin = Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"));
    let archive_arg = path_arg(&archive)?;
    let recovery_arg = path_arg(&recovery_file)?;

    run_cli(
        bin,
        &home,
        &[
            "--archive-dir",
            archive_arg,
            "init",
            "--passphrase",
            "test-passphrase",
            "--recovery-code",
            "test-recovery-code",
            "--recovery-file",
            recovery_arg,
        ],
    )?;

    let mode = fs::metadata(&recovery_file)?.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert_eq!(fs::read_to_string(&recovery_file)?, "test-recovery-code\n");

    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn backup_failure_does_not_advance_checkpoints() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("checkpoint-commit")?;
    let home = root.join("home");
    let archive = root.join("archive");
    let codex_dir = home.join(".codex");
    fs::create_dir_all(&codex_dir)?;
    fs::write(
        codex_dir.join("history.jsonl"),
        "{\"type\":\"message\",\"text\":\"must not skip\"}\n",
    )?;

    let bin = Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"));
    let archive_arg = path_arg(&archive)?;

    run_cli(
        bin,
        &home,
        &[
            "--archive-dir",
            archive_arg,
            "init",
            "--passphrase",
            "test-passphrase",
            "--recovery-code",
            "test-recovery-code",
        ],
    )?;

    let manifest = archive.join("manifests").join("manifest.tsv");
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o400))?;
    let failed = run_cli_err(
        bin,
        &home,
        &[
            "--archive-dir",
            archive_arg,
            "backup",
            "--passphrase",
            "test-passphrase",
        ],
    )?;
    let stderr = String::from_utf8_lossy(&failed.stderr);
    assert!(
        stderr.contains("open manifest append") || stderr.contains("append manifest"),
        "stderr did not contain manifest failure:\n{stderr}"
    );
    assert_eq!(
        fs::read_to_string(archive.join("state").join("checkpoints.tsv"))?,
        ""
    );

    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o600))?;
    fs::remove_dir_all(root)?;
    Ok(())
}

fn create_test_workspace(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = env::temp_dir().join(format!(
        "chat-archive-rs-test-{tag}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn path_arg(path: &Path) -> Result<&str, Box<dyn Error>> {
    path.to_str()
        .ok_or_else(|| format!("path is not valid utf-8: {}", path.display()).into())
}

fn run_cli(bin: &Path, home: &Path, args: &[&str]) -> Result<Output, Box<dyn Error>> {
    let output = Command::new(bin).args(args).env("HOME", home).output()?;
    if output.status.success() {
        return Ok(output);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "command failed: {} {}\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        bin.display(),
        args.join(" "),
        output.status,
        stdout,
        stderr
    )
    .into())
}

fn run_cli_err(bin: &Path, home: &Path, args: &[&str]) -> Result<Output, Box<dyn Error>> {
    let output = Command::new(bin).args(args).env("HOME", home).output()?;
    if !output.status.success() {
        return Ok(output);
    }

    Err(format!(
        "command unexpectedly succeeded: {} {}",
        bin.display(),
        args.join(" ")
    )
    .into())
}
