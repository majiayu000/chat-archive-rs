use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;

mod common;
use common::{create_test_workspace, path_arg, run_cli_err};

#[test]
fn monitor_rejects_invalid_verify_schedule_without_rewriting_config() -> Result<(), Box<dyn Error>>
{
    assert_monitor_config_rejected(
        "invalid-schedule",
        "{\n  \"version\": 1,\n  \"monitor\": {\n    \"interval_sec\": 300,\n    \"verify_schedule\": \"sometimes\",\n    \"verify_every\": 0,\n    \"compress_level\": 6\n  }\n}\n",
        "invalid --verify-schedule",
    )
}

#[test]
fn monitor_rejects_out_of_range_numeric_config_without_rewriting_config()
-> Result<(), Box<dyn Error>> {
    assert_monitor_config_rejected(
        "out-of-range",
        "{\n  \"version\": 1,\n  \"monitor\": {\n    \"interval_sec\": 0,\n    \"verify_schedule\": \"weekly\",\n    \"verify_every\": 0,\n    \"compress_level\": 20\n  }\n}\n",
        "monitor.interval_sec out of range",
    )
}

#[test]
fn monitor_rejects_malformed_config_without_rewriting_config() -> Result<(), Box<dyn Error>> {
    assert_monitor_config_rejected("malformed", "{\n  \"monitor\": ", "malformed JSON object")
}

fn assert_monitor_config_rejected(
    tag: &str,
    config: &str,
    expected_error: &str,
) -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace(tag)?;
    let home = root.join("home");
    let archive = root.join("archive");
    fs::create_dir_all(&archive)?;
    let config_path = archive.join("config.json");
    fs::write(&config_path, config)?;

    let bin = Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"));
    let archive_arg = path_arg(&archive)?;
    let output = run_cli_err(
        bin,
        &home,
        &["--archive-dir", archive_arg, "monitor", "--cycles", "1"],
    )?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(expected_error),
        "stderr did not contain {expected_error:?}:\n{stderr}"
    );
    assert_eq!(fs::read_to_string(&config_path)?, config);

    fs::remove_dir_all(root)?;
    Ok(())
}
