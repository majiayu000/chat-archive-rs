use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
#[cfg(unix)]
use std::time::{Duration, Instant};

mod common;
use common::{create_test_workspace, path_arg, run_cli, run_cli_err};

fn assert_init_retry(
    bin: &Path,
    home: &Path,
    archive: &Path,
    recovery_file: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    assert!(!archive.join("keys/keys.env").exists());
    assert!(!archive.join("manifests/manifest.tsv").exists());
    assert_eq!(fs::read_dir(archive.join("keys"))?.count(), 0);
    let mut args = vec![
        "--archive-dir",
        path_arg(archive)?,
        "init",
        "--passphrase",
        "test-passphrase",
        "--recovery-code",
        "test-recovery-code",
    ];
    if let Some(path) = recovery_file {
        args.extend(["--recovery-file", path_arg(path)?]);
    }
    run_cli(bin, home, &args)?;
    run_cli(
        bin,
        home,
        &[
            "--archive-dir",
            path_arg(archive)?,
            "recovery-test",
            "--recovery-code",
            "test-recovery-code",
        ],
    )?;
    assert!(!archive.join("manifests/manifest.tsv").exists());
    if let Some(path) = recovery_file {
        assert_eq!(fs::read(path)?, b"test-recovery-code\n");
    }
    Ok(())
}

#[test]
fn init_can_be_retried_after_state_open_failure() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("init-state-open-failure")?;
    let home = root.join("home");
    let archive = root.join("archive");
    let db_path = archive.join("state/state.db");
    fs::create_dir_all(&db_path)?;
    let bin = Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"));
    let failed = run_cli_err(
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
    assert!(String::from_utf8_lossy(&failed.stderr).contains("open state db"));
    fs::remove_dir(&db_path)?;
    assert_init_retry(bin, &home, &archive, None)?;
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn init_can_be_retried_after_state_reset_failure() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("init-state-reset-failure")?;
    let home = root.join("home");
    let archive = root.join("archive");
    fs::create_dir_all(archive.join("state"))?;
    let db = rusqlite::Connection::open(archive.join("state/state.db"))?;
    db.execute_batch(
        "CREATE TABLE state_meta (
             archive_key TEXT, key TEXT, value TEXT, PRIMARY KEY(archive_key, key)
         );
         CREATE TABLE checkpoints (
             archive_key TEXT, path TEXT, offset INTEGER, PRIMARY KEY(archive_key, path)
         );
         CREATE TRIGGER reject_reset BEFORE DELETE ON checkpoints
         BEGIN SELECT RAISE(ABORT, 'test reset failure'); END;",
    )?;
    let archive_key = archive.canonicalize()?.to_string_lossy().into_owned();
    db.execute(
        "INSERT INTO state_meta VALUES(?1, 'legacy_tsv_migrated', '1')",
        [&archive_key],
    )?;
    db.execute(
        "INSERT INTO checkpoints VALUES(?1, 'test-source', 42)",
        [&archive_key],
    )?;
    let bin = Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"));
    let failed = run_cli_err(
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
    assert!(String::from_utf8_lossy(&failed.stderr).contains("reset checkpoints"));
    let offset: i64 = db.query_row("SELECT offset FROM checkpoints", [], |row| row.get(0))?;
    assert_eq!(offset, 42);
    db.execute_batch("DROP TRIGGER reject_reset")?;
    assert_init_retry(bin, &home, &archive, None)?;
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn init_can_be_retried_after_recovery_file_failure() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("init-recovery-file-failure")?;
    let home = root.join("home");
    let archive = root.join("archive");
    let recovery_file = root.join("recovery-code");
    fs::create_dir(&recovery_file)?;
    let bin = Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"));
    let failed = run_cli_err(
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
            path_arg(&recovery_file)?,
        ],
    )?;
    assert!(String::from_utf8_lossy(&failed.stderr).contains("private file"));
    fs::remove_dir(&recovery_file)?;
    assert_init_retry(bin, &home, &archive, Some(&recovery_file))?;
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn init_can_be_retried_after_process_termination() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("init-process-termination")?;
    let home = root.join("home");
    let archive = root.join("archive");
    let recovery_file = root.join("recovery-code");
    // A FIFO with no reader blocks the child during recovery-file creation,
    // after key writing and database initialization have finished.
    assert!(
        Command::new("mkfifo")
            .arg(&recovery_file)
            .status()?
            .success()
    );
    let bin = Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"));
    let mut child = Command::new(bin)
        .args([
            "--archive-dir",
            path_arg(&archive)?,
            "init",
            "--passphrase",
            "test-passphrase",
            "--recovery-code",
            "test-recovery-code",
            "--recovery-file",
            path_arg(&recovery_file)?,
        ])
        .env("HOME", &home)
        .env_remove("APP_DB_PATH")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(180);
    let ready = loop {
        if child.try_wait()?.is_some() || Instant::now() >= deadline {
            break false;
        }
        let db_path = archive.join("state/state.db");
        if db_path.is_file()
            && let Ok(db) = rusqlite::Connection::open_with_flags(
                &db_path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            && db
                .query_row("SELECT value FROM state_meta", [], |row| {
                    row.get::<_, String>(0)
                })
                .is_ok_and(|value| value == "1")
        {
            break true;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let concurrent = if ready {
        Some(run_cli_err(
            bin,
            &home,
            &[
                "--archive-dir",
                path_arg(&archive)?,
                "init",
                "--passphrase",
                "other-test-passphrase",
                "--recovery-code",
                "other-test-recovery-code",
            ],
        ))
    } else {
        None
    };
    child.kill()?;
    assert!(!child.wait()?.success());
    assert!(ready, "init did not reach database initialization");
    assert!(!archive.join("keys/keys.env").exists());
    assert!(!archive.join("manifests/manifest.tsv").exists());
    let concurrent = concurrent.expect("ready child was checked for concurrent init")?;
    assert!(
        String::from_utf8_lossy(&concurrent.stderr)
            .contains("archive initialization already in progress")
    );
    fs::remove_file(&recovery_file)?;
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
            "--recovery-file",
            path_arg(&recovery_file)?,
        ],
    )?;
    run_cli(
        bin,
        &home,
        &[
            "--archive-dir",
            path_arg(&archive)?,
            "recovery-test",
            "--recovery-code",
            "test-recovery-code",
        ],
    )?;
    assert_eq!(fs::read(recovery_file)?, b"test-recovery-code\n");
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn init_rejects_existing_archive_without_losing_backups() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("init-existing")?;
    let home = root.join("home");
    let archive = root.join("archive");
    let restore = root.join("restore");
    fs::create_dir_all(home.join(".codex"))?;
    let raw = "{\"type\":\"message\",\"text\":\"preserve this backup\"}\n";
    fs::write(home.join(".codex/history.jsonl"), raw)?;
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
    let keys = fs::read(archive.join("keys/keys.env"))?;
    let manifest = fs::read(archive.join("manifests/manifest.tsv"))?;
    let state = fs::read(archive.join("state/state.db"))?;
    let chunk_path = fs::read_dir(archive.join("chunks"))?
        .next()
        .unwrap()?
        .path();
    let chunk = fs::read(&chunk_path)?;

    let rejected = run_cli_err(
        bin,
        &home,
        &[
            "--archive-dir",
            archive_arg,
            "init",
            "--passphrase",
            "new-test-passphrase",
            "--recovery-code",
            "new-test-recovery-code",
        ],
    )?;
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("refusing to initialize"));
    assert_eq!(fs::read(archive.join("keys/keys.env"))?, keys);
    assert_eq!(fs::read(archive.join("manifests/manifest.tsv"))?, manifest);
    assert_eq!(fs::read(archive.join("state/state.db"))?, state);
    assert_eq!(fs::read(&chunk_path)?, chunk);
    run_cli(
        bin,
        &home,
        &[
            "--archive-dir",
            archive_arg,
            "recovery-test",
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
        ],
    )?;
    assert!(String::from_utf8_lossy(&backup.stdout).contains("No new records discovered."));
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
    assert_eq!(fs::read_to_string(restore.join("codex-raw.jsonl"))?, raw);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn concurrent_init_publishes_only_one_archive_key() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("init-concurrent")?;
    let home = root.join("home");
    let archive = root.join("archive");
    let bin = Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"));
    let archive_arg = path_arg(&archive)?;
    let recovery_codes = ["first-test-recovery-code", "second-test-recovery-code"];
    let mut children = Vec::new();
    for recovery_code in recovery_codes {
        children.push(
            Command::new(bin)
                .args([
                    "--archive-dir",
                    archive_arg,
                    "init",
                    "--passphrase",
                    "test-passphrase",
                    "--recovery-code",
                    recovery_code,
                ])
                .env("HOME", &home)
                .env_remove("APP_DB_PATH")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?,
        );
    }
    let outputs = children
        .into_iter()
        .map(|child| child.wait_with_output())
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(outputs.iter().filter(|out| out.status.success()).count(), 1);
    let winner = outputs.iter().position(|out| out.status.success()).unwrap();
    run_cli(
        bin,
        &home,
        &[
            "--archive-dir",
            archive_arg,
            "recovery-test",
            "--recovery-code",
            recovery_codes[winner],
        ],
    )?;
    assert!(!archive.join("manifests/manifest.tsv").exists());
    assert_eq!(fs::read_dir(archive.join("keys"))?.count(), 1);
    let verified = run_cli(
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
    assert!(String::from_utf8_lossy(&verified.stdout).contains("Verified manifests: 0"));
    let restore = root.join("restore");
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
    for file in [
        "canonical-records.jsonl",
        "codex-raw.jsonl",
        "claude-raw.jsonl",
    ] {
        assert_eq!(fs::read(restore.join(file))?, b"");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(archive.join("keys/keys.env"))?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    fs::remove_dir_all(root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn init_rejects_dangling_archive_file_symlinks() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let bin = Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"));
    for existing in ["keys/keys.env", "manifests/manifest.tsv"] {
        let root = create_test_workspace("init-symlink")?;
        let archive = root.join("archive");
        let existing_path = archive.join(existing);
        fs::create_dir_all(existing_path.parent().unwrap())?;
        let target = root.join("missing-archive-file");
        symlink(&target, &existing_path)?;
        let rejected = run_cli_err(
            bin,
            &root.join("home"),
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
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("refusing to initialize"));
        assert_eq!(fs::read_link(&existing_path)?, target);
        assert!(!target.exists());
        assert!(!archive.join("state/state.db").exists());
        fs::remove_dir_all(root)?;
    }
    Ok(())
}

#[test]
fn init_rejects_either_existing_file_without_creating_the_other() -> Result<(), Box<dyn Error>> {
    let bin = Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"));
    for (existing, absent) in [
        ("keys/keys.env", "manifests/manifest.tsv"),
        ("manifests/manifest.tsv", "keys/keys.env"),
    ] {
        let root = create_test_workspace("init-partial")?;
        let home = root.join("home");
        let archive = root.join("archive");
        let existing_path = archive.join(existing);
        fs::create_dir_all(existing_path.parent().unwrap())?;
        fs::write(&existing_path, b"existing archive data")?;
        let rejected = run_cli_err(
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
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("refusing to initialize"));
        assert_eq!(fs::read(&existing_path)?, b"existing archive data");
        assert!(!archive.join(absent).exists());
        assert!(!archive.join("state/state.db").exists());
        fs::remove_dir_all(root)?;
    }
    Ok(())
}
