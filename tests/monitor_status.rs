use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

mod common;
use common::{create_test_workspace, path_arg, run_cli, run_cli_err};

#[test]
fn finite_monitor_reports_backup_failure() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("monitor-backup-error")?;
    let home = root.join("home");
    let archive = root.join("archive");
    let output = run_cli_err(
        binary(),
        &home,
        &[
            "--archive-dir",
            path_arg(&archive)?,
            "monitor",
            "--cycles",
            "1",
            "--verify-schedule",
            "none",
        ],
    )?;
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Monitor completed after 1 cycle(s).")
    );
    let events = read_events(&archive)?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["operation"], "monitor-backup");
    assert_eq!(events[0]["status"], "error");
    assert!(String::from_utf8_lossy(&output.stderr).contains(&format!(
        "ERROR: {}",
        events[0]["error"].as_str().ok_or("missing backup error")?
    )));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn finite_monitor_reports_verify_failure_and_retries_schedule() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("monitor-verify-error")?;
    let home = root.join("home");
    let archive = root.join("archive");
    fs::create_dir_all(home.join(".codex"))?;
    fs::write(
        home.join(".codex/history.jsonl"),
        "{\"text\":\"test record\"}\n",
    )?;
    init_archive(&home, &archive)?;
    run_cli(
        binary(),
        &home,
        &[
            "--archive-dir",
            path_arg(&archive)?,
            "backup",
            "--passphrase",
            "test-passphrase",
        ],
    )?;
    let chunk = fs::read_dir(archive.join("chunks"))?
        .next()
        .ok_or("missing chunk")??
        .path();
    let original = fs::read(&chunk)?;
    fs::write(&chunk, b"corrupt ciphertext")?;
    let args = [
        "--archive-dir",
        path_arg(&archive)?,
        "monitor",
        "--passphrase",
        "test-passphrase",
        "--cycles",
        "1",
        "--verify-schedule",
        "daily",
    ];
    let output = run_cli_err(binary(), &home, &args)?;
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("ERROR: Cipher hash mismatch:"));
    let events = read_events(&archive)?;
    assert_eq!(events[0]["operation"], "monitor-backup");
    assert_eq!(events[0]["status"], "ok");
    assert_eq!(events[1]["operation"], "monitor-verify");
    assert_eq!(events[1]["status"], "error");
    assert_eq!(events[1]["scheduled_verify"], true);

    fs::write(&chunk, original)?;
    run_cli(binary(), &home, &args)?;
    let events = read_events(&archive)?;
    assert_eq!(events[3]["operation"], "monitor-verify");
    assert_eq!(events[3]["status"], "ok");
    assert_eq!(events[3]["scheduled_verify"], true);
    run_cli(binary(), &home, &args)?;
    let events = read_events(&archive)?;
    assert_eq!(events.len(), 5);
    assert_eq!(events[4]["scheduled_verify"], false);
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn finite_monitor_retains_error_after_a_successful_cycle() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("monitor-recovered-cycle")?;
    let home = root.join("home");
    let archive = root.join("archive");
    let remote = root.join("remote");
    init_archive(&home, &archive)?;
    fs::write(&remote, "not a directory")?;
    let mut child = spawn_monitor(
        &home,
        &archive,
        &["--cycles", "2", "--remote-dir", path_arg(&remote)?],
    )?;
    wait_for(&mut child, || Ok(!read_events(&archive)?.is_empty()))?;
    let events = read_events(&archive)?;
    assert_eq!(events[0]["status"], "error");
    fs::remove_file(&remote)?;
    wait_for(&mut child, || Ok(read_events(&archive)?.len() == 2))?;
    let output = child.finish()?;
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Monitor completed after 2 cycle(s).")
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("ERROR: mkdir remote:"));
    let events = read_events(&archive)?;
    assert_eq!(events[1]["cycle"], 2);
    assert_eq!(events[1]["status"], "ok");
    assert!(remote.join("keys/keys.env").is_file());
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn healthy_finite_monitor_exits_successfully() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("monitor-healthy-cycles")?;
    let home = root.join("home");
    let archive = root.join("archive");
    init_archive(&home, &archive)?;
    let output = run_cli(
        binary(),
        &home,
        &[
            "--archive-dir",
            path_arg(&archive)?,
            "monitor",
            "--passphrase",
            "test-passphrase",
            "--cycles",
            "2",
            "--interval-sec",
            "1",
            "--verify-schedule",
            "none",
            "--verify-every",
            "1",
        ],
    )?;
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Monitor completed after 2 cycle(s).")
    );
    let events = read_events(&archive)?;
    assert_eq!(events.len(), 4);
    assert!(events.iter().all(|event| event["status"] == "ok"));
    fs::remove_dir_all(root)?;
    Ok(())
}

#[test]
fn infinite_monitor_continues_after_failed_cycles() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("monitor-infinite-errors")?;
    let home = root.join("home");
    let archive = root.join("archive");
    let mut child = spawn_monitor(&home, &archive, &["--cycles", "0"])?;
    wait_for(&mut child, || Ok(read_events(&archive)?.len() >= 2))?;
    assert!(
        child
            .0
            .as_mut()
            .ok_or("missing child")?
            .try_wait()?
            .is_none()
    );
    child.0.as_mut().ok_or("missing child")?.kill()?;
    child.finish()?;
    let events = read_events(&archive)?;
    assert!(events.iter().all(|event| event["status"] == "error"));
    assert_eq!(events[1]["cycle"], 2);
    fs::remove_dir_all(root)?;
    Ok(())
}

fn binary() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"))
}

fn init_archive(home: &Path, archive: &Path) -> Result<(), Box<dyn Error>> {
    run_cli(
        binary(),
        home,
        &[
            "--archive-dir",
            path_arg(archive)?,
            "init",
            "--passphrase",
            "test-passphrase",
            "--recovery-code",
            "test-recovery-code",
        ],
    )?;
    Ok(())
}

fn read_events(archive: &Path) -> Result<Vec<serde_json::Value>, Box<dyn Error>> {
    let path = archive.join("state/ops-log.jsonl");
    let log = match fs::read_to_string(path) {
        Ok(log) => log,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err.into()),
    };
    // A running monitor can be in the middle of appending its final log line.
    let events: Vec<serde_json::Value> = log
        .split_inclusive('\n')
        .filter(|line| line.ends_with('\n'))
        .map(serde_json::from_str)
        .collect::<Result<_, serde_json::Error>>()?;
    Ok(events
        .into_iter()
        .filter(|event| {
            event["operation"]
                .as_str()
                .is_some_and(|op| op.starts_with("monitor-"))
        })
        .collect())
}

struct RunningMonitor(Option<Child>);

impl RunningMonitor {
    fn finish(&mut self) -> Result<Output, Box<dyn Error>> {
        let deadline = Instant::now() + Duration::from_secs(60);
        while self
            .0
            .as_mut()
            .ok_or("missing child")?
            .try_wait()?
            .is_none()
        {
            if Instant::now() >= deadline {
                return Err("monitor did not exit".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(self.0.take().ok_or("missing child")?.wait_with_output()?)
    }
}

impl Drop for RunningMonitor {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn spawn_monitor(
    home: &Path,
    archive: &Path,
    options: &[&str],
) -> Result<RunningMonitor, Box<dyn Error>> {
    let child = Command::new(binary())
        .args([
            "--archive-dir",
            path_arg(archive)?,
            "monitor",
            "--passphrase",
            "test-passphrase",
            "--interval-sec",
            "1",
            "--verify-schedule",
            "none",
        ])
        .args(options)
        .env("HOME", home)
        .env_remove("CODEX_HOME")
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("APP_DB_PATH")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    Ok(RunningMonitor(Some(child)))
}

fn wait_for(
    child: &mut RunningMonitor,
    ready: impl Fn() -> Result<bool, Box<dyn Error>>,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !ready()? {
        if child
            .0
            .as_mut()
            .ok_or("missing child")?
            .try_wait()?
            .is_some()
            && !ready()?
        {
            return Err("monitor exited before the expected cycle".into());
        }
        if Instant::now() >= deadline {
            return Err("monitor did not reach the expected cycle".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}
