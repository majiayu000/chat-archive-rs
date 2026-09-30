use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

mod common;
use common::{create_test_workspace, path_arg, run_cli, run_cli_err};

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
    assert_eq!(fs::read(archive.join("manifests/manifest.tsv"))?, b"");
    assert_eq!(fs::read_dir(archive.join("keys"))?.count(), 1);
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
