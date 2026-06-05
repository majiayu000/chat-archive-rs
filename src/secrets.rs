use std::fs;
use std::path::Path;

use crate::types::AppResult;
use crate::utils::random_hex;

pub fn write_recovery_file(path: &Path, recovery_code: &str) -> AppResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir recovery file parent: {e}"))?;
    }

    #[cfg(unix)]
    {
        write_recovery_file_unix(path, format!("{recovery_code}\n").as_bytes())
    }

    #[cfg(not(unix))]
    {
        fs::write(path, format!("{recovery_code}\n"))
            .map_err(|e| format!("write recovery file: {e}"))
    }
}

#[cfg(unix)]
fn write_recovery_file_unix(path: &Path, bytes: &[u8]) -> AppResult<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .ok_or_else(|| format!("invalid recovery file path: {}", path.display()))?;
    let temp_path = parent.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        random_hex(8)?
    ));

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp_path)
        .map_err(|e| format!("create recovery temp file: {e}"))?;
    file.write_all(bytes)
        .map_err(|e| format!("write recovery temp file: {e}"))?;
    file.sync_all()
        .map_err(|e| format!("sync recovery temp file: {e}"))?;
    drop(file);

    fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod recovery temp file: {e}"))?;
    fs::rename(&temp_path, path).map_err(|e| format!("install recovery file: {e}"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod recovery file: {e}"))?;

    let mode = fs::metadata(path)
        .map_err(|e| format!("stat recovery file: {e}"))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        return Err(format!(
            "recovery file permissions are {mode:o}, expected 600"
        ));
    }

    Ok(())
}
