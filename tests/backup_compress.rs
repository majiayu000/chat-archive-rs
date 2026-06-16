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

#[test]
fn backup_rotates_chunks_at_plaintext_threshold() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("backup-chunk-rotation")?;
    let home = root.join("home");
    let archive = root.join("archive");
    let restore = root.join("restore");
    let codex_dir = home.join(".codex");
    fs::create_dir_all(&codex_dir)?;
    let raw_lines = [
        "{\"type\":\"message\",\"text\":\"chunk one\"}",
        "{\"type\":\"message\",\"text\":\"chunk two\"}",
        "{\"type\":\"message\",\"text\":\"chunk three\"}",
        "{\"type\":\"message\",\"text\":\"chunk four\"}",
        "{\"type\":\"message\",\"text\":\"chunk five\"}",
        "{\"type\":\"message\",\"text\":\"chunk six\"}",
    ];
    fs::write(
        codex_dir.join("history.jsonl"),
        format!("{}\n", raw_lines.join("\n")),
    )?;

    let bin = Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"));
    let archive_arg = path_arg(&archive)?;
    let restore_arg = path_arg(&restore)?;
    let envs = [("CHAT_ARCHIVE_CHUNK_PLAIN_BYTES", "2000")];

    init_archive(bin, &home, archive_arg, &envs)?;
    let backup = run_cli_with_env(
        bin,
        &home,
        &[
            "--archive-dir",
            archive_arg,
            "backup",
            "--passphrase",
            "test-passphrase",
        ],
        &envs,
    )?;
    let backup_stdout = String::from_utf8_lossy(&backup.stdout);
    assert!(backup_stdout.contains("Chunks written: "));
    let chunk_count = fs::read_dir(archive.join("chunks"))?.count();
    assert!(
        chunk_count > 1 && chunk_count < raw_lines.len(),
        "expected multiple aggregated chunks, got {chunk_count}"
    );
    assert_eq!(
        fs::read_to_string(archive.join("manifests").join("manifest.tsv"))?
            .lines()
            .count(),
        chunk_count
    );

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
    assert_eq!(
        fs::read_to_string(restore.join("codex-raw.jsonl"))?,
        format!("{}\n", raw_lines.join("\n"))
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn backup_recovers_state_after_manifest_replace_failure() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("backup-pending-recovery")?;
    let home = root.join("home");
    let archive = root.join("archive");
    let restore = root.join("restore");
    let codex_dir = home.join(".codex");
    fs::create_dir_all(&codex_dir)?;
    let raw_lines = [
        "{\"type\":\"message\",\"text\":\"recover one\"}",
        "{\"type\":\"message\",\"text\":\"recover two\"}",
        "{\"type\":\"message\",\"text\":\"recover three\"}",
    ];
    fs::write(
        codex_dir.join("history.jsonl"),
        format!("{}\n", raw_lines.join("\n")),
    )?;

    let bin = Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"));
    let archive_arg = path_arg(&archive)?;
    let restore_arg = path_arg(&restore)?;
    let envs = [
        ("CHAT_ARCHIVE_CHUNK_PLAIN_BYTES", "1"),
        ("CHAT_ARCHIVE_FAIL_AFTER_MANIFEST_REPLACE", "1"),
    ];

    init_archive(bin, &home, archive_arg, &envs)?;
    let failed = run_cli_err_with_env(
        bin,
        &home,
        &[
            "--archive-dir",
            archive_arg,
            "backup",
            "--passphrase",
            "test-passphrase",
        ],
        &envs,
    )?;
    let stderr = String::from_utf8_lossy(&failed.stderr);
    assert!(
        stderr.contains("CHAT_ARCHIVE_FAIL_AFTER_MANIFEST_REPLACE requested failure"),
        "stderr did not contain injected failure:\n{stderr}"
    );
    assert_eq!(
        fs::read_to_string(archive.join("manifests").join("manifest.tsv"))?
            .lines()
            .count(),
        3
    );

    let retry_envs = [("CHAT_ARCHIVE_CHUNK_PLAIN_BYTES", "1")];
    let retry = run_cli_with_env(
        bin,
        &home,
        &[
            "--archive-dir",
            archive_arg,
            "backup",
            "--passphrase",
            "test-passphrase",
        ],
        &retry_envs,
    )?;
    let retry_stdout = String::from_utf8_lossy(&retry.stdout);
    assert!(retry_stdout.contains("No new records discovered."));
    assert_eq!(fs::read_dir(archive.join("chunks"))?.count(), 3);
    assert_eq!(
        fs::read_to_string(archive.join("manifests").join("manifest.tsv"))?
            .lines()
            .count(),
        3
    );

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
    assert_eq!(
        fs::read_to_string(restore.join("codex-raw.jsonl"))?,
        format!("{}\n", raw_lines.join("\n"))
    );

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn backup_after_restart_skips_seen_records() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("backup-incremental-restart")?;
    let home = root.join("home");
    let archive = root.join("archive");
    let codex_dir = home.join(".codex");
    fs::create_dir_all(&codex_dir)?;
    fs::write(
        codex_dir.join("history.jsonl"),
        "{\"type\":\"message\",\"text\":\"already archived\"}\n",
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
    run_cli(
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
    assert_eq!(fs::read_dir(archive.join("chunks"))?.count(), 1);

    let second = run_cli(
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
    let second_stdout = String::from_utf8_lossy(&second.stdout);
    assert!(second_stdout.contains("No new records discovered."));
    assert_eq!(fs::read_dir(archive.join("chunks"))?.count(), 1);

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn remote_sync_retry_copies_existing_archive_when_no_new_records() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("remote-retry")?;
    let home = root.join("home");
    let archive = root.join("archive");
    let remote = root.join("remote");
    let codex_dir = home.join(".codex");
    fs::create_dir_all(&codex_dir)?;
    fs::write(
        codex_dir.join("history.jsonl"),
        "{\"type\":\"message\",\"text\":\"sync me later\"}\n",
    )?;
    fs::write(&remote, b"not a directory")?;

    let bin = Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"));
    let archive_arg = path_arg(&archive)?;
    let remote_arg = path_arg(&remote)?;

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
    let failed = run_cli_err(
        bin,
        &home,
        &[
            "--archive-dir",
            archive_arg,
            "backup",
            "--passphrase",
            "test-passphrase",
            "--remote-dir",
            remote_arg,
        ],
    )?;
    let stderr = String::from_utf8_lossy(&failed.stderr);
    assert!(
        stderr.contains("mkdir remote"),
        "stderr did not contain remote mkdir failure:\n{stderr}"
    );
    assert_eq!(fs::read_dir(archive.join("chunks"))?.count(), 1);

    fs::remove_file(&remote)?;
    let retry = run_cli(
        bin,
        &home,
        &[
            "--archive-dir",
            archive_arg,
            "backup",
            "--passphrase",
            "test-passphrase",
            "--remote-dir",
            remote_arg,
        ],
    )?;
    let retry_stdout = String::from_utf8_lossy(&retry.stdout);
    assert!(retry_stdout.contains("No new records discovered."));
    assert_eq!(fs::read_dir(remote.join("chunks"))?.count(), 1);
    assert!(remote.join("manifests").join("manifest.tsv").exists());

    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn shared_app_db_path_keeps_archives_isolated() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("shared-db-isolation")?;
    let home = root.join("home");
    let archive1 = root.join("archive1");
    let archive2 = root.join("archive2");
    let shared_db = root.join("shared").join(["state", "db"].join("."));
    let codex_dir = home.join(".codex");
    fs::create_dir_all(&codex_dir)?;
    fs::write(
        codex_dir.join("history.jsonl"),
        "{\"type\":\"message\",\"text\":\"shared db isolation\"}\n",
    )?;

    let bin = Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"));
    let archive1_arg = path_arg(&archive1)?;
    let archive2_arg = path_arg(&archive2)?;
    let shared_db_arg = path_arg(&shared_db)?;
    let envs = [("APP_DB_PATH", shared_db_arg)];

    init_archive(bin, &home, archive1_arg, &envs)?;
    run_cli_with_env(
        bin,
        &home,
        &[
            "--archive-dir",
            archive1_arg,
            "backup",
            "--passphrase",
            "test-passphrase",
        ],
        &envs,
    )?;
    assert_eq!(fs::read_dir(archive1.join("chunks"))?.count(), 1);

    init_archive(bin, &home, archive2_arg, &envs)?;
    run_cli_with_env(
        bin,
        &home,
        &[
            "--archive-dir",
            archive2_arg,
            "backup",
            "--passphrase",
            "test-passphrase",
        ],
        &envs,
    )?;

    let archive1_retry = run_cli_with_env(
        bin,
        &home,
        &[
            "--archive-dir",
            archive1_arg,
            "backup",
            "--passphrase",
            "test-passphrase",
        ],
        &envs,
    )?;
    let archive1_retry_stdout = String::from_utf8_lossy(&archive1_retry.stdout);
    assert!(archive1_retry_stdout.contains("No new records discovered."));
    assert_eq!(fs::read_dir(archive1.join("chunks"))?.count(), 1);

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

    let manifest_dir = archive.join("manifests");
    fs::set_permissions(&manifest_dir, fs::Permissions::from_mode(0o500))?;
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
        stderr.contains("replace manifest"),
        "stderr did not contain manifest failure:\n{stderr}"
    );
    fs::set_permissions(&manifest_dir, fs::Permissions::from_mode(0o700))?;
    let retry = run_cli(
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
    let retry_stdout = String::from_utf8_lossy(&retry.stdout);
    assert!(retry_stdout.contains("Archived new records: 1"));

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
    run_cli_with_env(bin, home, args, &[])
}

fn run_cli_with_env(
    bin: &Path,
    home: &Path,
    args: &[&str],
    envs: &[(&str, &str)],
) -> Result<Output, Box<dyn Error>> {
    let mut command = Command::new(bin);
    command.args(args).env("HOME", home);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command.output()?;
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

fn init_archive(
    bin: &Path,
    home: &Path,
    archive_arg: &str,
    envs: &[(&str, &str)],
) -> Result<Output, Box<dyn Error>> {
    run_cli_with_env(
        bin,
        home,
        &[
            "--archive-dir",
            archive_arg,
            "init",
            "--passphrase",
            "test-passphrase",
            "--recovery-code",
            "test-recovery-code",
        ],
        envs,
    )
}

fn run_cli_err(bin: &Path, home: &Path, args: &[&str]) -> Result<Output, Box<dyn Error>> {
    run_cli_err_with_env(bin, home, args, &[])
}

fn run_cli_err_with_env(
    bin: &Path,
    home: &Path,
    args: &[&str],
    envs: &[(&str, &str)],
) -> Result<Output, Box<dyn Error>> {
    let mut command = Command::new(bin);
    command.args(args).env("HOME", home);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command.output()?;
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
