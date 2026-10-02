#![cfg(unix)]

mod common;

use std::error::Error;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use common::{create_test_workspace, path_arg, run_cli, run_cli_err};

#[test]
fn restore_outputs_are_owner_only_when_created_and_reused() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("restore-permissions")?;
    let home = root.join("home");
    let archive = root.join("archive");
    let restore = root.join("restore");
    let raw_lines = [
        ("codex", "{\"text\":\"private codex transcript\"}"),
        ("claude", "{\"text\":\"private claude transcript\"}"),
    ];
    for (provider, raw) in raw_lines {
        let source = home.join(format!(".{provider}"));
        fs::create_dir_all(&source)?;
        fs::write(source.join("history.jsonl"), format!("{raw}\n"))?;
    }

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

    let files = [
        "canonical-records.jsonl",
        "codex-raw.jsonl",
        "claude-raw.jsonl",
        "restore-report.json",
    ];
    let mut modes = Vec::new();
    let stale_output = b"stale output that must be replaced\n";
    let mut retained_outputs = Vec::new();
    for reused in [false, true] {
        let mut old_descriptors = Vec::new();
        if reused {
            for name in files {
                let path = restore.join(name);
                fs::write(&path, stale_output)?;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o666))?;
                old_descriptors.push((name, fs::File::open(path)?));
            }
        }
        // Set the umask in the child only; the parallel test process is unaffected.
        let output = Command::new("sh")
            .args(["-c", "umask 000; exec \"$@\"", "sh"])
            .arg(bin)
            .args([
                "--archive-dir",
                archive_arg,
                "restore",
                "--passphrase",
                "test-passphrase",
                "--output-dir",
                path_arg(&restore)?,
            ])
            .env("HOME", &home)
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("CODEX_HOME")
            .env_remove("APP_DB_PATH")
            .output()?;
        assert!(
            output.status.success(),
            "restore failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        for name in files {
            modes.push((
                reused,
                name,
                fs::metadata(restore.join(name))?.permissions().mode() & 0o777,
            ));
        }
        for (name, mut file) in old_descriptors {
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            retained_outputs.push((name, bytes));
        }
        for (provider, raw) in raw_lines {
            assert_eq!(
                fs::read_to_string(restore.join(format!("{provider}-raw.jsonl")))?,
                format!("{raw}\n")
            );
        }
        let canonical = fs::read_to_string(restore.join("canonical-records.jsonl"))?;
        let records: Vec<serde_json::Value> = canonical
            .lines()
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        assert_eq!(records.len(), 2);
        for (provider, raw) in raw_lines {
            assert!(
                records
                    .iter()
                    .any(|record| { record["provider"] == provider && record["raw_line"] == raw })
            );
        }
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(restore.join("restore-report.json"))?)?;
        assert_eq!(report["total_records"], 2);
        assert_eq!(report["unique_raw_hashes"], 2);
    }
    fs::remove_dir_all(root)?;
    let expected: Vec<_> = modes
        .iter()
        .map(|(reused, name, _)| (*reused, *name, 0o600))
        .collect();
    assert_eq!(modes, expected);
    let expected: Vec<_> = files
        .iter()
        .map(|name| (*name, stale_output.to_vec()))
        .collect();
    assert_eq!(retained_outputs, expected);
    Ok(())
}

#[test]
fn restore_output_open_failures_keep_the_error_contract() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("restore-output-errors")?;
    let home = root.join("home");
    let archive = root.join("archive");
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

    for (name, context) in [
        ("canonical-records.jsonl", "reset canonical"),
        ("codex-raw.jsonl", "reset codex"),
        ("claude-raw.jsonl", "reset claude"),
        ("restore-report.json", "write restore report"),
    ] {
        let restore = root.join(name);
        fs::create_dir_all(restore.join(name))?;
        let failed = run_cli_err(
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
        assert_eq!(failed.status.code(), Some(1));
        let stderr = String::from_utf8_lossy(&failed.stderr);
        assert!(
            stderr.starts_with(&format!("ERROR: {context}:")),
            "{stderr}"
        );
        let logs = fs::read_to_string(archive.join("state/ops-log.jsonl"))?;
        let log: serde_json::Value = serde_json::from_str(logs.lines().last().unwrap())?;
        assert_eq!(log["operation"], "restore");
        assert_eq!(log["status"], "error");
        assert!(log["error"].as_str().unwrap().starts_with(context));
        assert!(fs::read_dir(&restore)?.all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".chat-archive-rs-restore-")
        }));
    }
    fs::remove_dir_all(root)?;
    Ok(())
}
