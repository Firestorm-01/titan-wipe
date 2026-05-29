//! CLI interface — argument parsing, consent handshake, and output formatting.

use clap::{Parser, Subcommand};
use crate::types::WipeAlgorithm;

#[derive(Parser)]
#[command(
    name = "titan-wipe",
    version = "1.0.0",
    author = "Kailash",
    about = "Enterprise-grade NIST SP 800-88 Rev.1 compliant storage sanitization utility",
    long_about = "
TITAN STORAGE SANITIZATION UTILITY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Supports NVMe Cryptographic Erase, ATA Secure Erase, DoD 5220.22-M ECE,
Gutmann 35-pass, NIST Clear, and single-pass random overwrite.

Generates a BLAKE3-verified, JSON-serializable audit certificate on completion.
Requires root/administrator privileges.

WARNING: This utility PERMANENTLY and IRREVERSIBLY destroys all data on the
target device. All guardrails must be cleared before any writes occur.
"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose debug logging
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// List all detected block devices with their metadata
    List,

    /// Wipe a specific device
    Wipe {
        /// Target block device (e.g., /dev/sdb, /dev/nvme1n1)
        #[arg(short, long)]
        device: String,

        /// Wipe algorithm to use (auto-selects best for drive type if omitted)
        #[arg(short, long)]
        algorithm: Option<WipeAlgorithm>,

        /// Skip post-wipe BLAKE3 verification read (faster, less rigorous)
        #[arg(long)]
        skip_verify: bool,

        /// Simulate the entire pipeline without writing anything
        #[arg(long)]
        dry_run: bool,

        /// Write audit certificate JSON to this file path
        #[arg(short, long)]
        output: Option<String>,

        /// Skip interactive consent prompt (use in automated pipelines — dangerous)
        #[arg(long, hide = true)]
        force: bool,
    },

    /// Show full device metadata for a specific device
    Inspect {
        /// Block device to inspect
        device: String,
    },
}

/// Run the multi-step interactive consent handshake.
/// Returns true only if the user provides the exact required string.
pub fn run_consent_handshake(target: &crate::types::DiskTarget) -> bool {
    use std::io::{self, Write};

    let required_phrase = format!("WIPE-{}", &target.serial_number[..target.serial_number.len().min(8)]);

    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║                  ⚠  DESTRUCTIVE OPERATION WARNING  ⚠            ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║  Target:   {:<54} ║", target.path.display());
    println!("║  Model:    {:<54} ║", &target.model[..target.model.len().min(54)]);
    println!("║  Serial:   {:<54} ║", &target.serial_number[..target.serial_number.len().min(54)]);
    println!("║  Size:     {:<54} ║", format!("{:.2} GiB ({} bytes)", target.size_gib(), target.size_bytes));
    println!("║  Type:     {:<54} ║", format!("{}", target.drive_type));
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║  ALL DATA ON THIS DEVICE WILL BE PERMANENTLY DESTROYED.         ║");
    println!("║  This operation CANNOT be undone.                               ║");
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();
    println!("  To confirm, type exactly:  {}", required_phrase);
    println!("  (or type anything else to abort)");
    println!();
    print!("  > ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }

    if input.trim() == required_phrase {
        println!();
        println!("  Consent confirmed. Starting sanitization...");
        println!();
        true
    } else {
        println!();
        println!("  ✗ Input mismatch. Aborting.");
        false
    }
}

/// Print device list table.
pub fn print_device_table(devices: &[crate::types::DiskTarget]) {
    println!();
    println!("{:<20} {:<35} {:<15} {:<12} {:<10}", "DEVICE", "MODEL", "SERIAL", "SIZE", "TYPE");
    println!("{}", "─".repeat(95));
    for d in devices {
        println!(
            "{:<20} {:<35} {:<15} {:<12} {:<10}",
            d.path.display(),
            &d.model[..d.model.len().min(34)],
            &d.serial_number[..d.serial_number.len().min(14)],
            format!("{:.1} GiB", d.size_gib()),
            format!("{:?}", d.drive_type),
        );
    }
    println!();
}

/// Print full inspection output for a single device.
pub fn print_device_inspect(d: &crate::types::DiskTarget) {
    println!();
    println!("  Device Path      : {}", d.path.display());
    println!("  Model            : {}", d.model);
    println!("  Serial Number    : {}", d.serial_number);
    println!("  Firmware Rev     : {}", d.firmware_rev);
    println!("  Size             : {:.3} GiB ({} bytes)", d.size_gib(), d.size_bytes);
    println!("  Drive Type       : {}", d.drive_type);
    println!("  Sector Size      : {} bytes", d.sector_size);
    println!("  NVMe Crypto Erase: {}", if d.supports_crypto_erase { "Supported" } else { "Unsupported / Unknown" });
    println!("  ATA Secure Erase : {}", if d.supports_ata_secure_erase { "Supported" } else { "Unsupported / Unknown" });
    println!("  Recommended Algo : {}", d.recommended_algorithm());
    println!();
}

/// Print the audit certificate in a human-readable format, then the raw JSON.
pub fn print_certificate(cert: &crate::types::SanitizationCertificate) {
    println!();
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║              SANITIZATION AUDIT CERTIFICATE                     ║");
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║  ID:        {:<54} ║", &cert.certificate_id[..cert.certificate_id.len().min(54)]);
    println!("║  Started:   {:<54} ║", &cert.timestamp_start[..cert.timestamp_start.len().min(54)]);
    println!("║  Completed: {:<54} ║", &cert.timestamp_end[..cert.timestamp_end.len().min(54)]);
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║  Device:    {:<54} ║", &cert.device_path[..cert.device_path.len().min(54)]);
    println!("║  Model:     {:<54} ║", &cert.model[..cert.model.len().min(54)]);
    println!("║  Serial:    {:<54} ║", &cert.serial[..cert.serial.len().min(54)]);
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║  Algorithm: {:<54} ║", &cert.algorithm_used[..cert.algorithm_used.len().min(54)]);
    println!("║  Passes:    {:<54} ║", cert.passes_completed);
    println!("╠══════════════════════════════════════════════════════════════════╣");
    println!("║  Pre-wipe BLAKE3:  {:<47} ║", &cert.pre_wipe_hash[..cert.pre_wipe_hash.len().min(47)]);
    println!("║  Post-wipe BLAKE3: {:<47} ║", &cert.post_wipe_hash[..cert.post_wipe_hash.len().min(47)]);
    println!("║  Verification:     {:<47} ║", format!("{:?}", cert.verification_status));
    println!("╠══════════════════════════════════════════════════════════════════╣");
    let status_icon = if cert.status == crate::types::SanitizationStatus::Success { "✓ SUCCESS" } else { "✗ PARTIAL/FAILED" };
    println!("║  Status:    {:<54} ║", status_icon);
    println!("╚══════════════════════════════════════════════════════════════════╝");
    println!();
}
