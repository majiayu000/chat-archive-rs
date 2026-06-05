#![cfg(unix)]

use std::env;
use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

mod common;
use common::{create_test_workspace, path_arg, run_cli};

#[test]
fn init_recovery_file_is_owner_only() -> Result<(), Box<dyn Error>> {
    let root = create_test_workspace("recovery-file-permissions")?;
    let home = root.join("home");
    let archive = root.join("archive");
    let recovery_file = root.join("secrets").join("recovery.txt");
    fs::create_dir_all(recovery_file.parent().expect("recovery parent"))?;
    fs::write(&recovery_file, "old-code\n")?;
    fs::set_permissions(&recovery_file, fs::Permissions::from_mode(0o644))?;

    let bin = Path::new(env!("CARGO_BIN_EXE_chat-archive-rs"));
    let archive_arg = path_arg(&archive)?;
    let recovery_arg = path_arg(&recovery_file)?;

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
            "--recovery-file",
            recovery_arg,
        ],
    )?;

    assert_eq!(fs::read_to_string(&recovery_file)?, "test-recovery-code\n");
    let mode = fs::metadata(&recovery_file)?.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    fs::remove_dir_all(root)?;
    Ok(())
}
