use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use crate::types::{AppResult, SourceFile};
use crate::utils::{fnv1a_hex, hex_encode};

pub fn discover_sources() -> AppResult<Vec<SourceFile>> {
    let home = env::var("HOME").map_err(|e| format!("HOME not set: {e}"))?;
    let mut out = Vec::new();

    let codex_sessions = Path::new(&home).join(".codex").join("sessions");
    if codex_sessions.exists() {
        walk_jsonl("codex", &codex_sessions, &mut out)?;
    }
    let codex_history = Path::new(&home).join(".codex").join("history.jsonl");
    if codex_history.exists() {
        out.push(SourceFile {
            provider: "codex".to_string(),
            path: codex_history,
        });
    }

    let claude_projects = Path::new(&home).join(".claude").join("projects");
    if claude_projects.exists() {
        walk_jsonl("claude", &claude_projects, &mut out)?;
    }
    let claude_history = Path::new(&home).join(".claude").join("history.jsonl");
    if claude_history.exists() {
        out.push(SourceFile {
            provider: "claude".to_string(),
            path: claude_history,
        });
    }

    out.sort_by(|a, b| {
        let pa = format!("{}:{}", a.provider, a.path.display());
        let pb = format!("{}:{}", b.provider, b.path.display());
        pa.cmp(&pb)
    });
    Ok(out)
}

pub fn read_records_from_source(
    source: &SourceFile,
    start_offset: u64,
) -> AppResult<(Vec<String>, u64, bool)> {
    let mut file =
        File::open(&source.path).map_err(|e| format!("open {}: {e}", source.path.display()))?;
    let snapshot_size = file
        .metadata()
        .map_err(|e| format!("stat {}: {e}", source.path.display()))?
        .len();
    let start = start_offset.min(snapshot_size);
    file.seek(SeekFrom::Start(start))
        .map_err(|e| format!("seek {}: {e}", source.path.display()))?;
    let limited = file.take(snapshot_size.saturating_sub(start));
    let mut reader = BufReader::new(limited);
    let mut read_offset = start;
    let mut commit_offset = start;
    let mut out = Vec::new();
    let mut deferred_partial_line = false;
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| format!("read_line {}: {e}", source.path.display()))?;
        if n == 0 {
            break;
        }
        let line_offset = read_offset;
        read_offset += n as u64;
        let has_newline = line.ends_with('\n');
        let trimmed = line.trim_end_matches(&['\n', '\r'][..]).to_string();
        if !has_newline && !is_likely_complete_json_line(&trimmed) {
            deferred_partial_line = true;
            break;
        }
        if trimmed.is_empty() {
            commit_offset = read_offset;
            continue;
        }
        let raw_hash = fnv1a_hex(trimmed.as_bytes());
        let record_id = fnv1a_hex(
            format!(
                "{}|{}|{}|{}",
                source.provider,
                source.path.display(),
                line_offset,
                raw_hash
            )
            .as_bytes(),
        );
        let path_hex = hex_encode(source.path.to_string_lossy().as_bytes());
        let raw_hex = hex_encode(trimmed.as_bytes());
        out.push(format!(
            "{record_id}\t{}\t{path_hex}\t{line_offset}\t{raw_hash}\t{raw_hex}",
            source.provider
        ));
        commit_offset = read_offset;
    }
    Ok((out, commit_offset, deferred_partial_line))
}

fn walk_jsonl(provider: &str, dir: &Path, out: &mut Vec<SourceFile>) -> AppResult<()> {
    for entry in fs::read_dir(dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))? {
        let entry = entry.map_err(|e| format!("read_dir entry {}: {e}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            walk_jsonl(provider, &path, out)?;
            continue;
        }
        if path.is_file() && path.extension().is_some_and(|e| e == "jsonl") {
            out.push(SourceFile {
                provider: provider.to_string(),
                path,
            });
        }
    }
    Ok(())
}

fn is_likely_complete_json_line(line: &str) -> bool {
    let s = line.trim();
    if s.is_empty() {
        return false;
    }
    (s.starts_with('{') && s.ends_with('}')) || (s.starts_with('[') && s.ends_with(']'))
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::utils::hex_decode_to_string;

    fn test_temp_dir(tag: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = env::temp_dir().join(format!(
            "chat-archive-rs-test-{tag}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("mkdir temp");
        dir
    }

    #[test]
    fn defers_incomplete_tail_and_resumes_from_safe_offset() {
        let dir = test_temp_dir("collector-partial");
        let path = dir.join("source.jsonl");
        fs::write(&path, "{\"a\":1}\n{\"b\":2").expect("write seed");
        let source = SourceFile {
            provider: "codex".to_string(),
            path: path.clone(),
        };

        let (records, offset, deferred) = read_records_from_source(&source, 0).expect("read pass1");
        assert_eq!(records.len(), 1);
        assert_eq!(offset, "{\"a\":1}\n".len() as u64);
        assert!(deferred);
        let parts: Vec<&str> = records[0].splitn(6, '\t').collect();
        assert_eq!(parts.len(), 6);
        assert_eq!(
            hex_decode_to_string(parts[5]).expect("hex decode"),
            "{\"a\":1}".to_string()
        );

        fs::write(&path, "{\"a\":1}\n{\"b\":2}\n").expect("append completion");
        let (records2, offset2, deferred2) =
            read_records_from_source(&source, offset).expect("read pass2");
        assert_eq!(records2.len(), 1);
        assert!(!deferred2);
        let parts2: Vec<&str> = records2[0].splitn(6, '\t').collect();
        assert_eq!(
            hex_decode_to_string(parts2[5]).expect("hex decode2"),
            "{\"b\":2}".to_string()
        );
        let size2 = fs::metadata(&path).expect("stat").len();
        assert_eq!(offset2, size2);

        fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn accepts_complete_json_without_trailing_newline() {
        let dir = test_temp_dir("collector-no-newline");
        let path = dir.join("source.jsonl");
        fs::write(&path, "{\"a\":1}").expect("write seed");
        let source = SourceFile {
            provider: "claude".to_string(),
            path: path.clone(),
        };

        let (records, offset, deferred) = read_records_from_source(&source, 0).expect("read");
        assert_eq!(records.len(), 1);
        assert!(!deferred);
        assert_eq!(offset, fs::metadata(&path).expect("stat").len());

        fs::remove_dir_all(&dir).expect("cleanup");
    }
}
