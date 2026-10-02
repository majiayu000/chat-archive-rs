#![cfg(unix)]

mod common;

use std::error::Error;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use common::{create_test_workspace, path_arg, run_cli, run_cli_err};

#[test]
fn backup_remote_symlinks_preserve_outside_files_and_report_errors() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("remote-symlinks")?;
    let home = root.join("home");
    let archive = root.join("archive");
    let remote = root.join("remote");
    let outside = root.join("outside");
    fs::create_dir_all(home.join(".codex"))?;
    let raw_line = "{\"type\":\"message\",\"text\":\"dummy remote backup\"}\n";
    fs::write(home.join(".codex/history.jsonl"), raw_line)?;
    fs::create_dir_all(&outside)?;

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
    let backup_args = [
        "--archive-dir",
        archive_arg,
        "backup",
        "--passphrase",
        "test-passphrase",
    ];
    run_cli(bin, &home, &backup_args)?;
    let chunk_name = fs::read_dir(archive.join("chunks"))?
        .next()
        .unwrap()?
        .file_name();
    let mut files = vec![
        "manifests/manifest.tsv".into(),
        "keys/keys.env".into(),
        "config.json".into(),
    ];
    files.push(std::path::PathBuf::from("chunks").join(&chunk_name));
    fs::write(archive.join("config.json"), b"{\"version\":1}")?;
    for rel in &files {
        let destination = remote.join(rel);
        fs::create_dir_all(destination.parent().unwrap())?;
        let sentinel = outside.join(rel.file_name().unwrap());
        fs::write(&sentinel, b"outside sentinel")?;
        symlink(&sentinel, &destination)?;
    }
    let mut sync_args = backup_args.to_vec();
    sync_args.extend(["--remote-dir", remote_arg]);
    let synced = run_cli(bin, &home, &sync_args)?;
    assert!(String::from_utf8_lossy(&synced.stdout).contains("No new records discovered."));
    for rel in &files {
        assert_eq!(
            fs::read(outside.join(rel.file_name().unwrap()))?,
            b"outside sentinel",
            "{}",
            rel.display()
        );
        assert_eq!(fs::read(remote.join(rel))?, fs::read(archive.join(rel))?);
        assert!(
            !fs::symlink_metadata(remote.join(rel))?
                .file_type()
                .is_symlink()
        );
    }

    fs::remove_dir_all(remote.join("chunks"))?;
    symlink(&outside, remote.join("chunks"))?;
    let failed = run_cli_err(bin, &home, &sync_args)?;
    let stderr = String::from_utf8_lossy(&failed.stderr);
    assert!(stderr.contains("escapes remote root"), "{stderr}");
    for rel in &files {
        assert_eq!(
            fs::read(outside.join(rel.file_name().unwrap()))?,
            b"outside sentinel"
        );
    }
    let mut logged_error = false;
    for line in fs::read_to_string(archive.join("state/ops-log.jsonl"))?.lines() {
        let value: serde_json::Value = serde_json::from_str(line)?;
        if value["operation"] == "backup" && value["status"] == "error" {
            assert!(
                value["error"]
                    .as_str()
                    .unwrap()
                    .contains("escapes remote root")
            );
            logged_error = true;
        }
    }
    assert!(logged_error, "failed remote sync must log the backup error");
    fs::remove_file(remote.join("chunks"))?;
    run_cli(bin, &home, &sync_args)?;
    run_cli(
        bin,
        &home,
        &[
            "--archive-dir",
            remote_arg,
            "verify",
            "--passphrase",
            "test-passphrase",
        ],
    )?;
    let restore = root.join("restore");
    run_cli(
        bin,
        &home,
        &[
            "--archive-dir",
            remote_arg,
            "restore",
            "--passphrase",
            "test-passphrase",
            "--output-dir",
            path_arg(&restore)?,
        ],
    )?;
    assert_eq!(
        fs::read_to_string(restore.join("codex-raw.jsonl"))?,
        raw_line
    );

    fs::remove_dir_all(root)?;
    Ok(())
}
