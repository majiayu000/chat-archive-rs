use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Utc;

use crate::crypto::{openssl_unwrap_b64, sha256_bytes};
use crate::storage::load_env_file;
use crate::types::{AppResult, Cli};
use crate::utils::{json_escape, utc_iso};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VerifySchedule {
    None,
    Daily,
    Weekly,
}

impl VerifySchedule {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            VerifySchedule::None => "none",
            VerifySchedule::Daily => "daily",
            VerifySchedule::Weekly => "weekly",
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct MonitorPolicy {
    pub(super) interval_sec: u64,
    pub(super) verify_every: u64,
    pub(super) verify_schedule: VerifySchedule,
    pub(super) compress_level: i32,
}

#[derive(Debug, Default)]
struct VerifyScheduleState {
    last_daily_slot: Option<String>,
    last_weekly_slot: Option<String>,
}

fn default_monitor_policy() -> MonitorPolicy {
    MonitorPolicy {
        interval_sec: 300,
        verify_every: 0,
        verify_schedule: VerifySchedule::Weekly,
        compress_level: 6,
    }
}

pub(super) fn parse_verify_schedule(raw: &str) -> AppResult<VerifySchedule> {
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "none" => Ok(VerifySchedule::None),
        "daily" => Ok(VerifySchedule::Daily),
        "weekly" => Ok(VerifySchedule::Weekly),
        _ => Err(format!(
            "invalid --verify-schedule: '{raw}' (expected none|daily|weekly)"
        )),
    }
}

pub(super) fn load_or_init_monitor_policy(archive_dir: &Path) -> AppResult<MonitorPolicy> {
    let path = archive_dir.join("config.json");
    let mut policy = default_monitor_policy();

    if path.exists() {
        let raw = fs::read_to_string(&path)
            .map_err(|e| format!("read monitor policy {}: {e}", path.display()))?;
        let scope = extract_json_object(&raw, "monitor").unwrap_or(raw.as_str());

        if let Some(v) = extract_json_u64_value(scope, "interval_sec")
            && (1..=86_400).contains(&v)
        {
            policy.interval_sec = v;
        }
        if let Some(v) = extract_json_u64_value(scope, "verify_every")
            && v <= 10_000_000
        {
            policy.verify_every = v;
        }
        if let Some(v) = extract_json_string_value(scope, "verify_schedule")
            && let Ok(parsed) = parse_verify_schedule(&v)
        {
            policy.verify_schedule = parsed;
        }
        if let Some(v) = extract_json_i32_value(scope, "compress_level")
            && (1..=19).contains(&v)
        {
            policy.compress_level = v;
        }
    }

    persist_monitor_policy(archive_dir, &policy)?;
    Ok(policy)
}

pub(super) fn persist_monitor_policy(archive_dir: &Path, policy: &MonitorPolicy) -> AppResult<()> {
    let path = archive_dir.join("config.json");
    let body = format!(
        "{{\n  \"version\": 1,\n  \"monitor\": {{\n    \"interval_sec\": {},\n    \"verify_schedule\": \"{}\",\n    \"verify_every\": {},\n    \"compress_level\": {}\n  }}\n}}\n",
        policy.interval_sec,
        policy.verify_schedule.as_str(),
        policy.verify_every,
        policy.compress_level
    );
    fs::write(&path, body).map_err(|e| format!("write monitor policy {}: {e}", path.display()))
}

fn verify_schedule_state_path(archive_dir: &Path) -> PathBuf {
    archive_dir.join("state").join("verify-schedule-state.env")
}

fn read_verify_schedule_state(archive_dir: &Path) -> AppResult<VerifyScheduleState> {
    let path = verify_schedule_state_path(archive_dir);
    if !path.exists() {
        return Ok(VerifyScheduleState::default());
    }
    let map = load_env_file(&path)?;
    Ok(VerifyScheduleState {
        last_daily_slot: map
            .get("LAST_DAILY_SLOT")
            .cloned()
            .filter(|v| !v.trim().is_empty()),
        last_weekly_slot: map
            .get("LAST_WEEKLY_SLOT")
            .cloned()
            .filter(|v| !v.trim().is_empty()),
    })
}

fn write_verify_schedule_state(archive_dir: &Path, state: &VerifyScheduleState) -> AppResult<()> {
    let path = verify_schedule_state_path(archive_dir);
    let mut body = String::new();
    if let Some(slot) = &state.last_daily_slot {
        body.push_str(&format!("LAST_DAILY_SLOT={slot}\n"));
    }
    if let Some(slot) = &state.last_weekly_slot {
        body.push_str(&format!("LAST_WEEKLY_SLOT={slot}\n"));
    }
    fs::write(&path, body)
        .map_err(|e| format!("write verify schedule state {}: {e}", path.display()))
}

fn current_daily_slot() -> String {
    Utc::now().format("%Y-%m-%d").to_string()
}

fn current_weekly_slot() -> String {
    Utc::now().format("%G-W%V").to_string()
}

pub(super) fn is_scheduled_verify_due(
    archive_dir: &Path,
    schedule: VerifySchedule,
) -> AppResult<bool> {
    let state = read_verify_schedule_state(archive_dir)?;
    match schedule {
        VerifySchedule::None => Ok(false),
        VerifySchedule::Daily => {
            let slot = current_daily_slot();
            Ok(state.last_daily_slot.as_deref() != Some(slot.as_str()))
        }
        VerifySchedule::Weekly => {
            let slot = current_weekly_slot();
            Ok(state.last_weekly_slot.as_deref() != Some(slot.as_str()))
        }
    }
}

pub(super) fn mark_scheduled_verify_done(
    archive_dir: &Path,
    schedule: VerifySchedule,
) -> AppResult<()> {
    let mut state = read_verify_schedule_state(archive_dir)?;
    match schedule {
        VerifySchedule::None => return Ok(()),
        VerifySchedule::Daily => {
            state.last_daily_slot = Some(current_daily_slot());
        }
        VerifySchedule::Weekly => {
            state.last_weekly_slot = Some(current_weekly_slot());
        }
    }
    write_verify_schedule_state(archive_dir, &state)
}

fn extract_json_object<'a>(raw: &'a str, key: &str) -> Option<&'a str> {
    let key_marker = format!("\"{key}\"");
    let key_idx = raw.find(&key_marker)?;
    let after_key = &raw[key_idx + key_marker.len()..];
    let colon_idx = after_key.find(':')?;
    let value = after_key[colon_idx + 1..].trim_start();
    if !value.starts_with('{') {
        return None;
    }

    let mut depth = 0usize;
    for (idx, ch) in value.char_indices() {
        if ch == '{' {
            depth += 1;
        } else if ch == '}' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(&value[..=idx]);
            }
        }
    }
    None
}

fn extract_json_value_start<'a>(raw: &'a str, key: &str) -> Option<&'a str> {
    let key_marker = format!("\"{key}\"");
    let key_idx = raw.find(&key_marker)?;
    let after_key = &raw[key_idx + key_marker.len()..];
    let colon_idx = after_key.find(':')?;
    Some(after_key[colon_idx + 1..].trim_start())
}

fn extract_json_string_value(raw: &str, key: &str) -> Option<String> {
    let value = extract_json_value_start(raw, key)?;
    let stripped = value.strip_prefix('"')?;
    let end_idx = stripped.find('"')?;
    Some(stripped[..end_idx].to_string())
}

fn extract_json_u64_value(raw: &str, key: &str) -> Option<u64> {
    let value = extract_json_value_start(raw, key)?;
    let bytes = value.as_bytes();
    let mut end = 0usize;
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 {
        return None;
    }
    value[..end].parse::<u64>().ok()
}

fn extract_json_i32_value(raw: &str, key: &str) -> Option<i32> {
    let value = extract_json_value_start(raw, key)?;
    let bytes = value.as_bytes();
    let mut end = 0usize;
    if bytes.first() == Some(&b'-') {
        end = 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 || (end == 1 && bytes.first() == Some(&b'-')) {
        return None;
    }
    value[..end].parse::<i32>().ok()
}

pub(super) fn option_or_env(cli: &Cli, opt: &str, env_key: &str) -> Option<String> {
    cli.options
        .get(opt)
        .cloned()
        .or_else(|| env::var(env_key).ok())
}

pub(super) fn parse_compress_level(v: Option<&String>) -> AppResult<i32> {
    let Some(raw) = v else {
        return Ok(6);
    };
    let parsed = raw
        .parse::<i32>()
        .map_err(|e| format!("invalid --compress-level: {e}"))?;
    if (1..=19).contains(&parsed) {
        Ok(parsed)
    } else {
        Err("invalid --compress-level: must be between 1 and 19".to_string())
    }
}

pub(super) fn parse_u64_option(
    v: Option<&String>,
    default: u64,
    min: u64,
    max: u64,
) -> AppResult<u64> {
    let Some(raw) = v else {
        return Ok(default);
    };
    let parsed = raw
        .parse::<u64>()
        .map_err(|e| format!("invalid numeric option value '{raw}': {e}"))?;
    if (min..=max).contains(&parsed) {
        Ok(parsed)
    } else {
        Err(format!(
            "numeric option value out of range: {parsed} (expected {min}..={max})"
        ))
    }
}

pub(super) fn write_ops_error_log(
    cli: &Cli,
    operation: &str,
    started_at: &str,
    elapsed_ms: u128,
    err: &str,
) {
    write_ops_log(
        cli,
        operation,
        "error",
        started_at,
        elapsed_ms,
        &[format!("\"error\":\"{}\"", json_escape(err))],
    );
}

pub(super) fn write_ops_log(
    cli: &Cli,
    operation: &str,
    status: &str,
    started_at: &str,
    elapsed_ms: u128,
    fields: &[String],
) {
    let mut line = format!(
        "{{\"event_at\":\"{}\",\"operation\":\"{}\",\"status\":\"{}\",\"started_at\":\"{}\",\"elapsed_ms\":{}",
        utc_iso(),
        json_escape(operation),
        json_escape(status),
        json_escape(started_at),
        elapsed_ms
    );
    for field in fields {
        line.push(',');
        line.push_str(field);
    }
    if let Some((rss_kb, cpu_pct)) = sample_self_usage() {
        line.push(',');
        line.push_str(&format!("\"rss_kb\":{}", rss_kb));
        line.push(',');
        line.push_str(&format!("\"cpu_pct\":{:.2}", cpu_pct));
    }
    line.push_str("}\n");

    if let Err(e) = append_ops_log_line(&cli.archive_dir, &line) {
        eprintln!("WARN: ops log write failed: {e}");
    }
}

fn sample_self_usage() -> Option<(u64, f64)> {
    let pid = std::process::id().to_string();
    let out = Command::new("ps")
        .args(["-o", "rss=", "-o", "%cpu=", "-p", &pid])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let mut tokens = text.split_whitespace();
    let rss_kb = tokens.next()?.parse::<u64>().ok()?;
    let cpu_pct = tokens.next()?.parse::<f64>().ok()?;
    Some((rss_kb, cpu_pct))
}

fn append_ops_log_line(archive_dir: &Path, line: &str) -> AppResult<()> {
    let path = archive_dir.join("state").join("ops-log.jsonl");
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("open ops log {}: {e}", path.display()))?;
    f.write_all(line.as_bytes())
        .map_err(|e| format!("append ops log {}: {e}", path.display()))
}

pub(super) fn unlock_archive_key(cli: &Cli) -> AppResult<String> {
    let keys = load_env_file(&cli.archive_dir.join("keys").join("keys.env"))?;
    let expected = keys
        .get("KEY_HASH")
        .ok_or_else(|| "KEY_HASH missing in keys.env".to_string())?
        .clone();
    if let Some(pass) = option_or_env(cli, "--passphrase", "ARCHIVE_PASSPHRASE") {
        let wrapped = keys
            .get("PASS_WRAP_B64")
            .ok_or_else(|| "PASS_WRAP_B64 missing in keys.env".to_string())?;
        let recovered = openssl_unwrap_b64(wrapped, &pass)?;
        let hash = sha256_bytes(&recovered)?;
        if hash != expected {
            return Err("Passphrase unlock failed".to_string());
        }
        return String::from_utf8(recovered).map_err(|e| format!("invalid key bytes: {e}"));
    }
    if let Some(rec) = option_or_env(cli, "--recovery-code", "ARCHIVE_RECOVERY_CODE") {
        let wrapped = keys
            .get("REC_WRAP_B64")
            .ok_or_else(|| "REC_WRAP_B64 missing in keys.env".to_string())?;
        let recovered = openssl_unwrap_b64(wrapped, &rec)?;
        let hash = sha256_bytes(&recovered)?;
        if hash != expected {
            return Err("Recovery-code unlock failed".to_string());
        }
        return String::from_utf8(recovered).map_err(|e| format!("invalid key bytes: {e}"));
    }
    Err("Provide --passphrase or --recovery-code (or env vars)".to_string())
}
