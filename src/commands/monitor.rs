use std::thread;
use std::time::{Duration, Instant};

use crate::types::{AppResult, Cli};
use crate::utils::{json_escape, utc_iso};

use super::backup::run_backup_once;
use super::support::{
    is_scheduled_verify_due, load_or_init_monitor_policy, mark_scheduled_verify_done,
    parse_compress_level, parse_u64_option, parse_verify_schedule, persist_monitor_policy,
    write_ops_log,
};
use super::verify::run_verify_once;

pub fn cmd_monitor(cli: &Cli) -> AppResult<()> {
    let cycles = parse_u64_option(cli.options.get("--cycles"), 0, 0, 10_000_000)?;

    let mut policy = load_or_init_monitor_policy(&cli.archive_dir)?;
    if let Some(raw) = cli.options.get("--interval-sec") {
        policy.interval_sec = parse_u64_option(Some(raw), policy.interval_sec, 1, 86_400)?;
    }
    if let Some(raw) = cli.options.get("--verify-every") {
        policy.verify_every = parse_u64_option(Some(raw), policy.verify_every, 0, 10_000_000)?;
    }
    if let Some(raw) = cli.options.get("--verify-schedule") {
        policy.verify_schedule = parse_verify_schedule(raw)?;
    }
    if let Some(raw) = cli.options.get("--compress-level") {
        policy.compress_level = parse_compress_level(Some(raw))?;
    }
    persist_monitor_policy(&cli.archive_dir, &policy)?;

    println!(
        "Monitor started. interval={}s verify_schedule={} verify_every={} cycles={} (0 means forever)",
        policy.interval_sec,
        policy.verify_schedule.as_str(),
        policy.verify_every,
        cycles
    );
    println!(
        "Monitor policy: {}",
        cli.archive_dir.join("config.json").display()
    );
    println!(
        "Ops log: {}",
        cli.archive_dir.join("state/ops-log.jsonl").display()
    );

    let mut cycle: u64 = 0;
    loop {
        cycle += 1;
        let cycle_ts = utc_iso();
        println!("[monitor] cycle={} at {}", cycle, cycle_ts);

        let scheduled_verify = is_scheduled_verify_due(&cli.archive_dir, policy.verify_schedule)?;
        let cycle_verify = policy.verify_every > 0 && cycle.is_multiple_of(policy.verify_every);
        let should_verify = scheduled_verify || cycle_verify;

        let mut backup_cli = cli.clone();
        backup_cli.options.insert(
            "--compress-level".to_string(),
            policy.compress_level.to_string(),
        );

        let backup_started_at = utc_iso();
        let backup_timer = Instant::now();
        match run_backup_once(&backup_cli) {
            Ok(stats) => {
                println!(
                    "[monitor] backup new_records={} plain={} cipher={}",
                    stats.new_records, stats.plain_bytes, stats.cipher_bytes
                );
                let chunk_json = match stats.chunk_file.as_ref() {
                    Some(p) => format!("\"{}\"", json_escape(&p.to_string_lossy())),
                    None => "null".to_string(),
                };
                let ratio = if stats.plain_bytes > 0 {
                    stats.cipher_bytes as f64 / stats.plain_bytes as f64
                } else {
                    0.0
                };
                write_ops_log(
                    cli,
                    "monitor-backup",
                    "ok",
                    &backup_started_at,
                    backup_timer.elapsed().as_millis(),
                    &[
                        format!("\"cycle\":{}", cycle),
                        format!(
                            "\"verify_schedule\":\"{}\"",
                            policy.verify_schedule.as_str()
                        ),
                        format!("\"scheduled_verify\":{}", scheduled_verify),
                        format!("\"cycle_verify\":{}", cycle_verify),
                        format!("\"should_verify\":{}", should_verify),
                        format!("\"sources_scanned\":{}", stats.sources_scanned),
                        format!("\"checkpoint_rewinds\":{}", stats.checkpoint_rewinds),
                        format!("\"deferred_tail_sources\":{}", stats.deferred_tail_sources),
                        format!("\"new_records\":{}", stats.new_records),
                        format!("\"compress_level\":{}", stats.compress_level),
                        format!("\"chunk_count\":{}", stats.chunk_count),
                        format!("\"plain_bytes\":{}", stats.plain_bytes),
                        format!("\"cipher_bytes\":{}", stats.cipher_bytes),
                        format!("\"compression_ratio\":{:.6}", ratio),
                        format!("\"chunk_file\":{}", chunk_json),
                    ],
                );
            }
            Err(err) => {
                eprintln!("[monitor] backup failed: {err}");
                write_ops_log(
                    cli,
                    "monitor-backup",
                    "error",
                    &backup_started_at,
                    backup_timer.elapsed().as_millis(),
                    &[
                        format!("\"cycle\":{}", cycle),
                        format!(
                            "\"verify_schedule\":\"{}\"",
                            policy.verify_schedule.as_str()
                        ),
                        format!("\"scheduled_verify\":{}", scheduled_verify),
                        format!("\"cycle_verify\":{}", cycle_verify),
                        format!("\"should_verify\":{}", should_verify),
                        format!("\"error\":\"{}\"", json_escape(&err)),
                    ],
                );
            }
        }

        if should_verify {
            let verify_started_at = utc_iso();
            let verify_timer = Instant::now();
            match run_verify_once(cli) {
                Ok(stats) => {
                    println!(
                        "[monitor] verify manifests={} records={}",
                        stats.manifests, stats.records
                    );
                    write_ops_log(
                        cli,
                        "monitor-verify",
                        "ok",
                        &verify_started_at,
                        verify_timer.elapsed().as_millis(),
                        &[
                            format!("\"cycle\":{}", cycle),
                            format!(
                                "\"verify_schedule\":\"{}\"",
                                policy.verify_schedule.as_str()
                            ),
                            format!("\"scheduled_verify\":{}", scheduled_verify),
                            format!("\"cycle_verify\":{}", cycle_verify),
                            format!("\"manifests\":{}", stats.manifests),
                            format!("\"records\":{}", stats.records),
                        ],
                    );
                    if scheduled_verify {
                        mark_scheduled_verify_done(&cli.archive_dir, policy.verify_schedule)?;
                    }
                }
                Err(err) => {
                    eprintln!("[monitor] verify failed: {err}");
                    write_ops_log(
                        cli,
                        "monitor-verify",
                        "error",
                        &verify_started_at,
                        verify_timer.elapsed().as_millis(),
                        &[
                            format!("\"cycle\":{}", cycle),
                            format!(
                                "\"verify_schedule\":\"{}\"",
                                policy.verify_schedule.as_str()
                            ),
                            format!("\"scheduled_verify\":{}", scheduled_verify),
                            format!("\"cycle_verify\":{}", cycle_verify),
                            format!("\"error\":\"{}\"", json_escape(&err)),
                        ],
                    );
                }
            }
        }

        if cycles > 0 && cycle >= cycles {
            println!("Monitor completed after {} cycle(s).", cycle);
            break;
        }

        thread::sleep(Duration::from_secs(policy.interval_sec));
    }

    Ok(())
}
