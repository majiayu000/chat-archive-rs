mod collector;
mod commands;
mod crypto;
mod secrets;
mod storage;
mod types;
mod utils;

use std::collections::HashMap;
use std::env;

use types::{AppResult, Cli};
use utils::expand_tilde;

fn main() {
    if let Err(err) = run() {
        eprintln!("ERROR: {err}");
        std::process::exit(1);
    }
}

fn run() -> AppResult<()> {
    let cli = parse_cli()?;
    storage::ensure_layout(&cli.archive_dir)?;
    match cli.command.as_str() {
        "init" => commands::cmd_init(&cli),
        "show-sources" => commands::cmd_show_sources(),
        "backup" => commands::cmd_backup(&cli),
        "verify" => commands::cmd_verify(&cli),
        "restore" => commands::cmd_restore(&cli),
        "recovery-test" => commands::cmd_recovery_test(&cli),
        "monitor" => commands::cmd_monitor(&cli),
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        other => Err(format!("Unknown command: {other}")),
    }
}

fn parse_cli() -> AppResult<Cli> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        return Err("Missing command".to_string());
    }

    let mut archive_dir = expand_tilde("~/.chat-archive-rs");
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == "--archive-dir" {
            if i + 1 >= args.len() {
                return Err("Missing value for --archive-dir".to_string());
            }
            archive_dir = expand_tilde(&args[i + 1]);
            args.drain(i..=i + 1);
            continue;
        }
        i += 1;
    }

    if args.is_empty() {
        print_usage();
        return Err("Missing command".to_string());
    }

    let command = args[0].clone();
    let mut options = HashMap::new();
    let mut j = 1usize;
    while j < args.len() {
        let key = args[j].clone();
        if !key.starts_with("--") {
            return Err(format!("Invalid option: {}", key));
        }
        if j + 1 >= args.len() {
            return Err(format!("Missing value for option {}", key));
        }
        options.insert(key, args[j + 1].clone());
        j += 2;
    }

    Ok(Cli {
        archive_dir,
        command,
        options,
    })
}

fn print_usage() {
    println!("chat-archive-rs [--archive-dir PATH] <command> [options]");
    println!();
    println!("Commands:");
    println!("  init --passphrase <p> --recovery-code <r> [--recovery-file <file>]");
    println!("  show-sources");
    println!(
        "  backup [--passphrase <p> | --recovery-code <r>] [--remote-dir <dir>] [--compress-level <1-19>]"
    );
    println!("  verify [--passphrase <p> | --recovery-code <r>]");
    println!("  restore --output-dir <dir> [--passphrase <p> | --recovery-code <r>]");
    println!("  recovery-test [--recovery-code <r>]");
    println!(
        "  monitor [--passphrase <p> | --recovery-code <r>] [--interval-sec <n>] [--verify-schedule <none|daily|weekly>] [--verify-every <n>] [--cycles <n>] [--compress-level <1-19>]"
    );
}
