use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};

use agent_sessions::{
    Agent, DiscoverFilter, RawReadOptions, Roots, StreamError, discover_directory, history_files,
    read_raw_from,
};

use crate::types::{AppResult, SourceFile};
use crate::utils::{fnv1a_hex, hex_encode};

pub struct SourceReadStats {
    pub commit_offset: u64,
    pub deferred_partial_line: bool,
}

pub fn discover_sources() -> AppResult<Vec<SourceFile>> {
    let roots = Roots::from_env().map_err(|e| format!("resolve session directories: {e}"))?;
    discover_sources_in(&roots)
}

fn discover_sources_in(roots: &Roots) -> AppResult<Vec<SourceFile>> {
    let mut out = Vec::new();
    let filter = DiscoverFilter {
        include_subagents: true,
        ..Default::default()
    };
    // Keep archive scope unchanged: Codex archived_sessions are not part of this
    // collector. Missing session/history roots are optional on either host.
    for (agent, root, subdir) in [
        (Agent::Codex, &roots.codex, "sessions"),
        (Agent::ClaudeCode, &roots.claude, "projects"),
    ] {
        let Some(root) = root else { continue };
        let dir = root.join(subdir);
        if !dir.exists() {
            continue;
        }
        let discovery = discover_directory(agent, &dir, &filter);
        if let Some(error) = discovery.errors.into_iter().next() {
            return Err(format!(
                "read_dir {}: {}",
                error.path.display(),
                error.source
            ));
        }
        for file in discovery.files {
            out.push(SourceFile {
                provider: provider_name(file.agent)?.to_string(),
                path: file.path,
            });
        }
    }
    for (agent, path) in history_files(roots) {
        if path.exists() {
            out.push(SourceFile {
                provider: provider_name(agent)?.to_string(),
                path,
            });
        }
    }

    out.sort_by(|a, b| {
        let pa = format!("{}:{}", a.provider, a.path.display());
        let pb = format!("{}:{}", b.provider, b.path.display());
        pa.cmp(&pb)
    });
    Ok(out)
}

#[cfg(test)]
pub fn read_records_from_source(
    source: &SourceFile,
    start_offset: u64,
) -> AppResult<(Vec<String>, u64, bool)> {
    let mut out = Vec::new();
    let stats = stream_records_from_source(source, start_offset, |record| {
        out.push(record);
        Ok(())
    })?;
    Ok((out, stats.commit_offset, stats.deferred_partial_line))
}

pub fn stream_records_from_source<F>(
    source: &SourceFile,
    start_offset: u64,
    mut on_record: F,
) -> AppResult<SourceReadStats>
where
    F: FnMut(String) -> AppResult<()>,
{
    let mut file =
        File::open(&source.path).map_err(|e| format!("open {}: {e}", source.path.display()))?;
    let snapshot_size = file
        .metadata()
        .map_err(|e| format!("stat {}: {e}", source.path.display()))?
        .len();
    let start = start_offset.min(snapshot_size);
    file.seek(SeekFrom::Start(start))
        .map_err(|e| format!("seek {}: {e}", source.path.display()))?;
    // Preserve the archival reader's bounded-prefix EOF contract even if a
    // writer truncates the source after the snapshot was taken.
    let reader = read_raw_from(
        BufReader::new(file.take(snapshot_size.saturating_sub(start))),
        &RawReadOptions {
            start_offset: start,
            stop_at_byte: None,
            max_read_bytes: None,
            max_line_bytes: None,
        },
    )
    .map_err(|e| format!("read_line {}: {e}", source.path.display()))?;
    let mut commit_offset = start;
    let mut deferred_partial_line = false;
    for record in reader {
        let record = record.map_err(|e| {
            let detail = match e {
                StreamError::Io(error) => error.to_string(),
                error => error.to_string(),
            };
            format!("read_line {}: {detail}", source.path.display())
        })?;
        let line = std::str::from_utf8(&record.bytes).map_err(|_| {
            format!(
                "read_line {}: stream did not contain valid UTF-8",
                source.path.display()
            )
        })?;
        let line_offset = record.byte_start;
        let read_offset = record.byte_end;
        let has_newline = record.terminated;
        let trimmed = line.trim_end_matches(&['\n', '\r'][..]);
        if !has_newline && !is_likely_complete_json_line(trimmed) {
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
        on_record(format!(
            "{record_id}\t{}\t{path_hex}\t{line_offset}\t{raw_hash}\t{raw_hex}",
            source.provider
        ))?;
        commit_offset = read_offset;
    }
    Ok(SourceReadStats {
        commit_offset,
        deferred_partial_line,
    })
}

fn provider_name(agent: Agent) -> AppResult<&'static str> {
    match agent {
        Agent::ClaudeCode => Ok("claude"),
        Agent::Codex => Ok("codex"),
        _ => Err(format!("unsupported archive source: {agent:?}")),
    }
}

fn is_likely_complete_json_line(line: &str) -> bool {
    let s = line.trim();
    if !((s.starts_with('{') && s.ends_with('}')) || (s.starts_with('[') && s.ends_with(']'))) {
        return false;
    }
    // Only EOF errors indicate a partial write. Preserve malformed raw records,
    // and ignore values rather than imposing numeric or nesting limits on them.
    match serde_json::from_str::<serde::de::IgnoredAny>(s) {
        Ok(_) => true,
        Err(error) => !error.is_eof(),
    }
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

    #[test]
    fn defers_nested_json_tails_and_resumes_after_completion() {
        let dir = test_temp_dir("collector-nested-tail");
        let path = dir.join("source.jsonl");
        let source = SourceFile {
            provider: "codex".into(),
            path: path.clone(),
        };
        let prefix = "{\"first\":1}\n";
        let deep_tail = format!("{}0{}", "[".repeat(256), "]".repeat(255));
        for (tail, completion) in [
            (r#"{"a":{"b":1}"#, "}"),
            ("[[1]", "]"),
            (r#"{"a":[{"b":1}"#, "]}"),
            (r#"{"text":"escaped \" quote and }"#, "\"}"),
            (deep_tail.as_str(), "]"),
        ] {
            fs::write(&path, format!("{prefix}{tail}")).expect("write partial");
            let (records, offset, deferred) =
                read_records_from_source(&source, 0).expect("read partial");
            assert_eq!(records.len(), 1, "tail: {tail}");
            assert_eq!(offset, prefix.len() as u64, "tail: {tail}");
            assert!(deferred, "tail: {tail}");
            let (retry, retry_offset, retry_deferred) =
                read_records_from_source(&source, offset).expect("retry partial");
            assert!(retry.is_empty());
            assert_eq!(retry_offset, offset);
            assert!(retry_deferred);

            let complete = format!("{tail}{completion}");
            fs::write(&path, format!("{prefix}{complete}")).expect("complete tail");
            let (resumed, end, deferred) =
                read_records_from_source(&source, offset).expect("read completed tail");
            assert_eq!(resumed.len(), 1);
            assert!(!deferred);
            assert_eq!(end, (prefix.len() + complete.len()) as u64);
            let parts: Vec<_> = resumed[0].splitn(6, '\t').collect();
            assert_eq!(parts[3], offset.to_string());
            assert_eq!(hex_decode_to_string(parts[5]).expect("decode"), complete);
            let (retry, retry_offset, deferred) =
                read_records_from_source(&source, end).expect("retry complete");
            assert!(retry.is_empty());
            assert_eq!(retry_offset, end);
            assert!(!deferred);
        }
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn preserves_complete_and_malformed_container_tails() {
        let dir = test_temp_dir("collector-complete-tail");
        let path = dir.join("source.jsonl");
        let source = SourceFile {
            provider: "claude".into(),
            path: path.clone(),
        };
        for raw in [
            r#" {"a":{"b":[1]},"text":"} ] \""} "#,
            "[1e400]",
            r#"{"a":}"#,
            " {broken} ",
            "[1,]",
        ] {
            fs::write(&path, raw).expect("write tail");
            let (records, end, deferred) = read_records_from_source(&source, 0).expect("read tail");
            assert_eq!(records.len(), 1, "tail: {raw}");
            assert_eq!(end, raw.len() as u64);
            assert!(!deferred);
            let parts: Vec<_> = records[0].splitn(6, '\t').collect();
            assert_eq!(hex_decode_to_string(parts[5]).expect("decode"), raw);
        }
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn keeps_scalar_tails_deferred_until_newline() {
        let dir = test_temp_dir("collector-scalar-tail");
        let path = dir.join("source.jsonl");
        let source = SourceFile {
            provider: "codex".into(),
            path: path.clone(),
        };
        for raw in ["1", "123", "true", "false", "null", "\"text\"", ""] {
            fs::write(&path, raw).expect("write tail");
            let (records, end, deferred) = read_records_from_source(&source, 0).expect("read tail");
            assert!(records.is_empty());
            assert_eq!(end, 0);
            assert_eq!(deferred, !raw.is_empty());
        }
        fs::write(&path, "123\n").expect("terminate number");
        let (records, end, deferred) =
            read_records_from_source(&source, 0).expect("read terminated number");
        assert_eq!(records.len(), 1);
        assert_eq!(end, 4);
        assert!(!deferred);
        let parts: Vec<_> = records[0].splitn(6, '\t').collect();
        assert_eq!(hex_decode_to_string(parts[5]).expect("decode"), "123");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn preserves_unknown_malformed_and_crlf_records_and_exact_identity() {
        let dir = test_temp_dir("collector-identity");
        let path = dir.join("source.jsonl");
        // These records are archival bytes, not a schema or JSON validation input.
        let lines = [
            "{\"type\":\"future_event\",\"text\":\"你好\"}",
            "not json",
            " {broken} ",
            "[1,2]",
        ];
        let bytes = format!(
            "{}\r\n\r\n{}\n{}\r\r\n{}",
            lines[0], lines[1], lines[2], lines[3]
        );
        fs::write(&path, &bytes).expect("write source");
        let source = SourceFile {
            provider: "codex".into(),
            path,
        };
        let (records, offset, deferred) =
            read_records_from_source(&source, 0).expect("read source");
        let offsets = [
            0,
            lines[0].len() + 4,
            lines[0].len() + 4 + lines[1].len() + 1,
            bytes.len() - lines[3].len(),
        ];
        let expected: Vec<String> = lines
            .iter()
            .zip(offsets)
            .map(|(raw, start)| {
                let hash = fnv1a_hex(raw.as_bytes());
                let id =
                    fnv1a_hex(format!("codex|{}|{start}|{hash}", source.path.display()).as_bytes());
                format!(
                    "{id}\tcodex\t{}\t{start}\t{hash}\t{}",
                    hex_encode(source.path.to_string_lossy().as_bytes()),
                    hex_encode(raw.as_bytes())
                )
            })
            .collect();
        assert_eq!(records, expected);
        assert_eq!(offset, bytes.len() as u64);
        assert!(!deferred);
        // Every safe boundary resumes with the same identities and no replay.
        for (index, start) in offsets.into_iter().enumerate() {
            let (resumed, end, deferred) =
                read_records_from_source(&source, start as u64).expect("resume");
            assert_eq!(resumed, expected[index..]);
            assert_eq!(end, offset);
            assert!(!deferred);
        }
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn clamps_past_eof_and_does_not_read_appended_bytes_until_next_pass() {
        use std::io::Write;
        let dir = test_temp_dir("collector-watermark");
        let path = dir.join("source.jsonl");
        let initial = "{\"a\":1}\n";
        fs::write(&path, initial).expect("write source");
        let source = SourceFile {
            provider: "claude".into(),
            path,
        };
        let (empty, end, deferred) = read_records_from_source(&source, u64::MAX).expect("past eof");
        assert!(empty.is_empty());
        assert_eq!(end, initial.len() as u64);
        assert!(!deferred);
        let mut count = 0;
        let stats = stream_records_from_source(&source, 0, |_| {
            count += 1;
            let mut file = fs::OpenOptions::new()
                .append(true)
                .open(&source.path)
                .expect("append open");
            file.write_all(b"{\"b\":2}\n").expect("append");
            Ok(())
        })
        .expect("snapshot read");
        assert_eq!(count, 1);
        assert_eq!(stats.commit_offset, initial.len() as u64);
        let (records, _, _) =
            read_records_from_source(&source, stats.commit_offset).expect("next pass");
        assert_eq!(records.len(), 1);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn invalid_utf8_and_consumer_errors_abort_without_reading_later_records() {
        let dir = test_temp_dir("collector-errors");
        let path = dir.join("source.jsonl");
        fs::write(&path, b"{}\n\xff\n{}\n").expect("write source");
        let source = SourceFile {
            provider: "codex".into(),
            path,
        };
        let mut count = 0;
        let error = stream_records_from_source(&source, 0, |_| {
            count += 1;
            Ok(())
        })
        .err()
        .expect("UTF8 error");
        assert_eq!(count, 1);
        assert!(error.contains("read_line"));
        assert!(error.contains("valid UTF-8"));
        let error =
            stream_records_from_source(&source, 0, |_| Err("archive storage unavailable".into()))
                .err()
                .expect("consumer error");
        assert_eq!(error, "archive storage unavailable");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn discovery_keeps_history_subagents_scope_and_provider_sorting() {
        let dir = test_temp_dir("discovery");
        let roots = Roots::from_home(&dir);
        let expected = [
            ("claude", ".claude/history.jsonl"),
            ("claude", ".claude/projects/p/session/subagents/agent.jsonl"),
            ("codex", ".codex/history.jsonl"),
            ("codex", ".codex/sessions/2026/session.jsonl"),
        ];
        for (_, path) in expected.iter().chain(
            [
                ("codex", ".codex/archived_sessions/old.jsonl"),
                ("claude", ".claude/projects/p/sessions-index.json"),
            ]
            .iter(),
        ) {
            let path = dir.join(path);
            fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
            fs::write(path, "{}\n").expect("write");
        }
        let found = discover_sources_in(&roots).expect("discover");
        let actual: Vec<_> = found
            .iter()
            .map(|s| (s.provider.as_str(), s.path.clone()))
            .collect();
        assert_eq!(
            actual,
            expected
                .iter()
                .map(|(provider, path)| (*provider, dir.join(path)))
                .collect::<Vec<_>>()
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn discovery_allows_missing_roots_but_reports_invalid_session_directory() {
        let dir = test_temp_dir("discovery-missing");
        let roots = Roots::from_home(&dir);
        assert!(
            discover_sources_in(&roots)
                .expect("missing is optional")
                .is_empty()
        );
        fs::create_dir_all(dir.join(".codex")).expect("mkdir");
        fs::write(dir.join(".codex/sessions"), "not a directory").expect("write");
        let error = discover_sources_in(&roots).expect_err("invalid directory");
        assert!(error.contains("read_dir"));
        assert!(error.contains(".codex/sessions"));
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn discovery_skips_symlinked_session_files_and_directories() {
        use std::os::unix::fs::symlink;
        let dir = test_temp_dir("discovery-symlink");
        let sessions = dir.join(".codex/sessions");
        fs::create_dir_all(&sessions).expect("mkdir");
        let external = dir.join("external");
        fs::create_dir(&external).expect("mkdir external");
        fs::write(external.join("s.jsonl"), "{}\n").expect("write");
        symlink(&external, sessions.join("linked-dir")).expect("link dir");
        symlink(external.join("s.jsonl"), sessions.join("linked.jsonl")).expect("link file");
        assert!(
            discover_sources_in(&Roots::from_home(&dir))
                .expect("discover")
                .is_empty()
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }
}
