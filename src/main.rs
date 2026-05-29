//! titan-wipe — Enterprise NIST SP 800-88 Rev.1 Storage Sanitization Utility
//!
//! Kailash — https://github.com/kailash

mod cli;
mod devices;
mod engine;
mod error;
mod os_backend;
mod patterns;
mod types;

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::Parser;
use log::LevelFilter;

use cli::{Cli, Commands};
use error::TitanResult;

fn main() {
    let cli = Cli::parse();

    // ── Logging setup ──────────────────────────────────────────────────────────
    let log_level = if cli.verbose { LevelFilter::Debug } else { LevelFilter::Info };
    env_logger::Builder::new()
        .filter_level(log_level)
        .format_timestamp_secs()
        .init();

    // ── Privilege check ────────────────────────────────────────────────────────
    #[cfg(unix)]
    {
        use error::TitanError;
        if unsafe { libc::getuid() } != 0 {
            eprintln!("{}", TitanError::InsufficientPrivileges);
            eprintln!("Hint: re-run with: sudo titan-wipe ...");
            std::process::exit(1);
        }
    }

    // ── Ctrl-C handler (graceful abort, marks all active operations) ───────────
    let abort_flag = Arc::new(AtomicBool::new(false));
    {
        let flag = abort_flag.clone();
        ctrlc::set_handler(move || {
            log::warn!("\n[SIGINT] Abort signal received. Stopping after current block write completes...");
            flag.store(true, Ordering::SeqCst);
        })
        .expect("Failed to set Ctrl-C handler");
    }

    if let Err(e) = run(cli, abort_flag) {
        eprintln!("\n[ERROR] {}", e);
        std::process::exit(2);
    }
}

fn run(cli: Cli, abort_flag: Arc<AtomicBool>) -> TitanResult<()> {
    match cli.command {
        Commands::List => {
            log::info!("Enumerating block devices...");
            let devs = devices::list_block_devices()?;
            if devs.is_empty() {
                println!("No physical block devices found.");
            } else {
                cli::print_device_table(&devs);
            }
        }

        Commands::Inspect { device } => {
            let path = Path::new(&device);
            let disk = os_backend::inspect_device(path)?;
            cli::print_device_inspect(&disk);
        }

        Commands::Wipe {
            device,
            algorithm,
            skip_verify,
            dry_run,
            output,
            force,
        } => {
            let path = Path::new(&device);
            log::info!("Inspecting device: {}", device);
            let disk = os_backend::inspect_device(path)?;

            // Auto-select algorithm if not specified
            let algo = algorithm.unwrap_or_else(|| {
                let recommended = disk.recommended_algorithm();
                log::info!("Auto-selected algorithm: {}", recommended);
                recommended
            });

            cli::print_device_inspect(&disk);
            println!("  Selected Algorithm: {}", algo);
            println!();

            // Dry run skip consent
            if !force && !dry_run {
                if !cli::run_consent_handshake(&disk) {
                    return Err(error::TitanError::UserAborted);
                }
            } else if dry_run {
                log::warn!("DRY-RUN: Skipping consent handshake.");
            }

            let engine = engine::SanitizerEngine::new(disk.clone(), algo, skip_verify, dry_run, abort_flag)?;

            match engine.run() {
                Ok(cert) => {
                    cli::print_certificate(&cert);

                    let json = serde_json::to_string_pretty(&cert)?;

                    // Write to file if requested
                    if let Some(ref out_path) = output {
                        std::fs::write(out_path, &json)?;
                        log::info!("Audit certificate written to: {}", out_path);
                    } else {
                        // Always print JSON to stdout for pipe/automation
                        println!("── Audit Certificate JSON ──");
                        println!("{}", json);
                    }

                    // Exit code 0 = success, 3 = verification failed (partial)
                    if cert.status != types::SanitizationStatus::Success {
                        std::process::exit(3);
                    }
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }

    Ok(())
}
