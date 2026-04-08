use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
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
) -> AppResult<(Vec<String>, u64)> {
    let file =
        File::open(&source.path).map_err(|e| format!("open {}: {e}", source.path.display()))?;
    let mut reader = BufReader::new(file);
    reader
        .seek(SeekFrom::Start(start_offset))
        .map_err(|e| format!("seek {}: {e}", source.path.display()))?;
    let mut offset = start_offset;
    let mut out = Vec::new();
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| format!("read_line {}: {e}", source.path.display()))?;
        if n == 0 {
            break;
        }
        let line_offset = offset;
        offset += n as u64;
        let trimmed = line.trim_end_matches(&['\n', '\r'][..]).to_string();
        if trimmed.is_empty() {
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
    }
    Ok((out, offset))
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
