mod common;

use std::{error::Error, fs, process::Command};

use common::create_test_workspace;

#[test]
fn custom_roots_replace_home_defaults_and_empty_overrides_fail() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("custom-roots")?;
    let home = root.join("home");
    let claude = root.join("custom-claude");
    let codex = root.join("custom-codex");
    for dir in [&claude, &codex, &home.join(".codex"), &home.join(".claude")] {
        fs::create_dir_all(dir)?;
        fs::write(dir.join("history.jsonl"), "{}\n")?;
    }
    let output = Command::new(env!("CARGO_BIN_EXE_chat-archive-rs"))
        .arg("show-sources")
        .env("HOME", &home)
        .env("CLAUDE_CONFIG_DIR", &claude)
        .env("CODEX_HOME", &codex)
        .output()?;
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)?,
        format!(
            "Discovered source files: 2\nclaude\t{}\ncodex\t{}\n",
            claude.join("history.jsonl").display(),
            codex.join("history.jsonl").display()
        )
    );
    for key in ["CLAUDE_CONFIG_DIR", "CODEX_HOME"] {
        let output = Command::new(env!("CARGO_BIN_EXE_chat-archive-rs"))
            .arg("show-sources")
            .env("HOME", &home)
            .env("CLAUDE_CONFIG_DIR", &claude)
            .env("CODEX_HOME", &codex)
            .env(key, "")
            .output()?;
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr)?.contains(&format!("{key} is empty")));
    }
    fs::remove_dir_all(root)?;
    Ok(())
}
