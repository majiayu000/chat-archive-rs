use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

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
