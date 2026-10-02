mod common;

use std::error::Error;
use std::fs::{self, File, OpenOptions};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use common::{create_test_workspace, path_arg, run_cli, run_cli_err};

#[test]
fn backup_and_monitor_wait_for_lock_before_reading_archive() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("backup-lock-wait")?;
    let home = root.join("home");
    let archive = root.join("archive");
    fs::create_dir_all(archive.join("state"))?;
    let lock = lock_archive(&archive)?;
    let bin = Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"));
    let archive_arg = path_arg(&archive)?;
    let mut backup = spawn_cli(bin, &home, &["--archive-dir", archive_arg, "backup"])?;
    let mut monitor = spawn_cli(
        bin,
        &home,
        &[
            "--archive-dir",
            archive_arg,
            "monitor",
            "--cycles",
            "1",
            "--verify-schedule",
            "none",
        ],
    )?;

    thread::sleep(Duration::from_secs(5));
    let backup_status = backup.try_wait()?;
    let monitor_status = monitor.try_wait()?;
    drop(lock);
    let backup_output = wait_for_exit(backup)?;
    let monitor_output = wait_for_exit(monitor)?;

    assert!(backup_status.is_none(), "backup did not wait for the lock");
    assert!(
        monitor_status.is_none(),
        "monitor did not wait for the lock"
    );
    assert!(!backup_output.status.success());
    assert!(String::from_utf8_lossy(&backup_output.stderr).contains("keys.env"));
    assert!(String::from_utf8_lossy(&monitor_output.stderr).contains("keys.env"));
    let lock = lock_archive(&archive)?;
    drop(lock);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn overlapping_backup_and_monitor_preserve_records_and_remote() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("backup-lock-overlap")?;
    let home = root.join("home");
    let archive = root.join("archive");
    let remote = root.join("remote");
    let restore = root.join("restore");
    let codex_dir = home.join(".codex");
    fs::create_dir_all(&codex_dir)?;
    let history = codex_dir.join("history.jsonl");
    let first = "{\"type\":\"message\",\"text\":\"first record\"}\n";
    let records = format!("{first}{{\"type\":\"message\",\"text\":\"second record\"}}\n");
    fs::write(&history, first)?;
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
    let initial_state = fs::read(archive.join("state/state.db"))?;
    let lock = lock_archive(&archive)?;
    let mut backup = spawn_cli(
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
    let mut monitor = spawn_cli(
        bin,
        &home,
        &[
            "--archive-dir",
            archive_arg,
            "monitor",
            "--passphrase",
            "test-passphrase",
            "--cycles",
            "1",
            "--verify-schedule",
            "none",
            "--remote-dir",
            remote_arg,
        ],
    )?;
    thread::sleep(Duration::from_millis(250));
    let backup_status = backup.try_wait()?;
    let monitor_status = monitor.try_wait()?;
    let state_unchanged = fs::read(archive.join("state/state.db"))? == initial_state;
    fs::write(&history, &records)?;
    drop(lock);
    let backup_output = wait_for_exit(backup)?;
    let monitor_output = wait_for_exit(monitor)?;
    assert!(backup_status.is_none());
    assert!(monitor_status.is_none());
    assert!(
        state_unchanged,
        "backup changed state before acquiring the lock"
    );
    assert!(backup_output.status.success(), "{backup_output:?}");
    assert!(monitor_output.status.success(), "{monitor_output:?}");
    assert!(!String::from_utf8_lossy(&monitor_output.stderr).contains("backup failed"));
    assert_eq!(fs::read_dir(archive.join("chunks"))?.count(), 1);
    let manifest = fs::read_to_string(archive.join("manifests/manifest.tsv"))?;
    assert_eq!(manifest.lines().count(), 1);
    assert_eq!(
        fs::read_to_string(remote.join("manifests/manifest.tsv"))?,
        manifest
    );
    for target in [&archive, &remote] {
        run_cli(
            bin,
            &home,
            &[
                "--archive-dir",
                path_arg(target)?,
                "verify",
                "--passphrase",
                "test-passphrase",
            ],
        )?;
    }
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
            path_arg(&restore)?,
        ],
    )?;
    assert_eq!(
        fs::read_to_string(restore.join("codex-raw.jsonl"))?,
        records
    );
    let lock = lock_archive(&archive)?;
    drop(lock);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn backup_lock_open_error_aborts_before_state_changes() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("backup-lock-error")?;
    let home = root.join("home");
    let archive = root.join("archive");
    fs::create_dir_all(archive.join("state/backup.lock"))?;
    let output = run_cli_err(
        Path::new(env!("CARGO_BIN_EXE_chat-archive-rs")),
        &home,
        &["--archive-dir", path_arg(&archive)?, "backup"],
    )?;
    assert!(String::from_utf8_lossy(&output.stderr).contains("open backup lock"));
    assert!(!archive.join("state/state.db").exists());
    fs::remove_dir_all(root)?;
    Ok(())
}

fn lock_archive(archive: &Path) -> Result<File, Box<dyn Error>> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(archive.join("state/backup.lock"))?;
    lock.lock()?;
    Ok(lock)
}

fn spawn_cli(bin: &Path, home: &Path, args: &[&str]) -> Result<Child, Box<dyn Error>> {
    Ok(Command::new(bin)
        .args(args)
        .env("HOME", home)
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CODEX_HOME")
        .env_remove("APP_DB_PATH")
        .env_remove("ARCHIVE_PASSPHRASE")
        .env_remove("ARCHIVE_RECOVERY_CODE")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?)
}

fn wait_for_exit(mut child: Child) -> Result<Output, Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(60);
    while child.try_wait()?.is_none() {
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err("timed out waiting for backup process".into());
        }
        thread::sleep(Duration::from_millis(20));
    }
    Ok(child.wait_with_output()?)
}
