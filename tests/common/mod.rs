use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn create_test_workspace(tag: &str) -> Result<PathBuf, Box<dyn Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = env::temp_dir().join(format!(
        "chat-archive-rs-test-{tag}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(&path)?;
    Ok(path)
}

pub fn path_arg(path: &Path) -> Result<&str, Box<dyn Error>> {
    path.to_str()
        .ok_or_else(|| format!("path is not valid utf-8: {}", path.display()).into())
}

pub fn run_cli(bin: &Path, home: &Path, args: &[&str]) -> Result<Output, Box<dyn Error>> {
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
