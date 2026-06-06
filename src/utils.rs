use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::AppResult;
use chrono::Utc;
use rand::RngCore;
use rand::rngs::OsRng;

pub fn expand_tilde(input: &str) -> PathBuf {
    if let Some(rest) = input.strip_prefix("~/")
        && let Ok(home) = env::var("HOME")
    {
        return Path::new(&home).join(rest);
    }
    PathBuf::from(input)
}

pub fn utc_stamp() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{now}")
}

pub fn utc_iso() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub fn random_hex(n_bytes: usize) -> AppResult<String> {
    let mut buf = vec![0u8; n_bytes];
    OsRng.fill_bytes(&mut buf);
    Ok(hex_encode(&buf))
}

pub fn append_file(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let mut f = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|e| format!("open append {}: {e}", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| format!("append {}: {e}", path.display()))
}

pub fn write_private_file(path: &Path, bytes: &[u8]) -> AppResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("create private file {}: {e}", path.display()))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod private file {}: {e}", path.display()))?;
        file.write_all(bytes)
            .map_err(|e| format!("write private file {}: {e}", path.display()))?;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
            .map_err(|e| format!("write private file {}: {e}", path.display()))
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn hex_decode_to_string(s: &str) -> AppResult<String> {
    let bytes = hex_decode(s)?;
    String::from_utf8(bytes).map_err(|e| format!("hex decode utf8 failed: {e}"))
}

pub fn hex_decode(s: &str) -> AppResult<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err("invalid hex length".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        let h = hex_val(b[i])?;
        let l = hex_val(b[i + 1])?;
        out.push((h << 4) | l);
        i += 2;
    }
    Ok(out)
}

fn hex_val(c: u8) -> AppResult<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err("invalid hex char".to_string()),
    }
}

pub fn fnv1a_hex(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in bytes {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_roundtrip() {
        let s = "hello-世界";
        let h = hex_encode(s.as_bytes());
        let r = hex_decode_to_string(&h).expect("decode");
        assert_eq!(s, r);
    }

    #[test]
    fn test_fnv_stable() {
        let a = fnv1a_hex(b"abc");
        let b = fnv1a_hex(b"abc");
        assert_eq!(a, b);
    }
}
