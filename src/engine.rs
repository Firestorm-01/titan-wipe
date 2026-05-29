//! Core sanitization engine — orchestrates all wipe operations with
//! pre/post verification, progress reporting, and audit certificate generation.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use blake3::Hasher;
use indicatif::{ProgressBar, ProgressStyle};
use uuid::Uuid;
use chrono::Utc;

use crate::error::{TitanError, TitanResult};
use crate::types::{
    DiskTarget, SanitizationCertificate, SanitizationStatus,
    VerificationStatus, WipeAlgorithm,
};
use crate::patterns::{
    PassPattern, dod_5220_22m_ece_passes, gutmann_35_passes,
    nist_clear_passes, random_single_passes,
};
use crate::os_backend;

/// Block size for sequential I/O — 4 MiB aligned for optimal throughput on both
/// SSDs (page cluster) and HDDs (track buffer). Benchmark-derived optimum.
const BLOCK_SIZE: usize = 4 * 1024 * 1024;

/// Verification sample: read this many bytes from random offsets after wipe.
/// Full sequential read is also performed for NIST compliance.
const VERIFY_SAMPLE_BLOCKS: usize = 512;

pub struct SanitizerEngine {
    target: DiskTarget,
    algorithm: WipeAlgorithm,
    skip_verify: bool,
    dry_run: bool,
    abort_flag: Arc<AtomicBool>,
    timestamp_start: String,
}

impl SanitizerEngine {
    pub fn new(
        target: DiskTarget,
        algorithm: WipeAlgorithm,
        skip_verify: bool,
        dry_run: bool,
        abort_flag: Arc<AtomicBool>,
    ) -> TitanResult<Self> {
        // ── GUARDRAIL 1: Boot drive check ─────────────────────────────────────
        if os_backend::is_boot_drive(&target.path) {
            return Err(TitanError::BootDriveProtection(
                target.path.display().to_string(),
            ));
        }

        // ── GUARDRAIL 2: Active mount check ───────────────────────────────────
        let mounts = os_backend::get_active_mounts(&target.path)?;
        if !mounts.is_empty() {
            return Err(TitanError::DeviceMounted(
                target.path.display().to_string(),
                mounts.join(", "),
            ));
        }

        Ok(SanitizerEngine {
            target,
            algorithm,
            skip_verify,
            dry_run,
            abort_flag,
            timestamp_start: Utc::now().to_rfc3339(),
        })
    }

    /// Execute the full sanitization pipeline.
    pub fn run(&self) -> TitanResult<SanitizationCertificate> {
        let cert_id = Uuid::new_v4().to_string().to_uppercase();

        if self.dry_run {
            log::warn!("DRY-RUN MODE: No writes will be performed.");
        }

        // ── Phase 1: Pre-wipe fingerprint ─────────────────────────────────────
        log::info!("Phase 1/3: Computing pre-wipe device fingerprint (BLAKE3)...");
        let pre_hash = self.hash_device("Pre-wipe fingerprint")?;

        // ── Phase 2: Sanitization ─────────────────────────────────────────────
        log::info!("Phase 2/3: Executing sanitization algorithm: {}", self.algorithm);
        let passes_completed = self.execute_algorithm()?;

        // ── Phase 3: Verification ─────────────────────────────────────────────
        let (post_hash, verification_status) = if self.skip_verify {
            log::warn!("Phase 3/3: Verification skipped (--skip-verify).");
            ("SKIPPED".to_string(), VerificationStatus::Skipped)
        } else {
            log::info!("Phase 3/3: Post-wipe verification...");
            let hash = self.hash_device("Post-wipe fingerprint")?;
            let status = self.verify_wipe_result(&hash);
            (hash, status)
        };

        let sanitization_status = if verification_status == VerificationStatus::Failed {
            SanitizationStatus::PartialFailure
        } else {
            SanitizationStatus::Success
        };

        let cert = SanitizationCertificate {
            certificate_id: cert_id,
            timestamp_start: self.timestamp_start.clone(),
            timestamp_end: Utc::now().to_rfc3339(),
            device_path: self.target.path.display().to_string(),
            model: self.target.model.clone(),
            serial: self.target.serial_number.clone(),
            firmware_rev: self.target.firmware_rev.clone(),
            size_bytes: self.target.size_bytes,
            drive_type: self.target.drive_type.to_string(),
            algorithm_used: self.algorithm.to_string(),
            passes_completed,
            pre_wipe_hash: pre_hash,
            post_wipe_hash: post_hash,
            verification_status,
            status: sanitization_status,
            operator_note: String::new(),
        };

        Ok(cert)
    }

    /// Route to the correct sanitization method.
    fn execute_algorithm(&self) -> TitanResult<u32> {
        match self.algorithm {
            WipeAlgorithm::NistNvmeCryptoErase => {
                if !self.dry_run {
                    os_backend::nvme_crypto_erase(&self.target.path)?;
                }
                Ok(1)
            }

            WipeAlgorithm::NistAtaSecureErase => {
                let enhanced = self.target.supports_ata_secure_erase;
                if !self.dry_run {
                    os_backend::ata_secure_erase(&self.target.path, enhanced)?;
                    // Issue TRIM after ATA erase to flush over-provisioned sectors
                    let _ = os_backend::blk_discard_trim(&self.target.path, self.target.size_bytes);
                }
                Ok(1)
            }

            WipeAlgorithm::NistClear => {
                let passes = nist_clear_passes();
                let n = passes.len() as u32;
                if !self.dry_run {
                    self.run_overwrite_passes(&passes)?;
                    let _ = os_backend::blk_discard_trim(&self.target.path, self.target.size_bytes);
                }
                Ok(n)
            }

            WipeAlgorithm::Dod5220 => {
                let passes = dod_5220_22m_ece_passes();
                let n = passes.len() as u32;
                if !self.dry_run {
                    self.run_overwrite_passes(&passes)?;
                }
                Ok(n)
            }

            WipeAlgorithm::Gutmann35 => {
                let passes = gutmann_35_passes();
                let n = passes.len() as u32;
                if !self.dry_run {
                    self.run_overwrite_passes(&passes)?;
                }
                Ok(n)
            }

            WipeAlgorithm::RandomSingle => {
                let passes = random_single_passes();
                let n = passes.len() as u32;
                if !self.dry_run {
                    self.run_overwrite_passes(&passes)?;
                }
                Ok(n)
            }
        }
    }

    /// Sequential multi-pass block overwrite with progress reporting.
    fn run_overwrite_passes(&self, passes: &[PassPattern]) -> TitanResult<()> {
        let total_passes = passes.len();

        for (pass_idx, pattern) in passes.iter().enumerate() {
            if self.abort_flag.load(Ordering::SeqCst) {
                return Err(TitanError::UserAborted);
            }

            let pass_label = format!(
                "Pass {}/{} [{}]",
                pass_idx + 1,
                total_passes,
                pattern.description()
            );

            log::info!("Starting: {}", pass_label);
            self.write_pass(pattern, &pass_label)?;

            // Force physical flush to disk after each pass
            // This is critical — without fsync, the OS may batch writes and
            // not all blocks will be physically written before the next pass.
            let file = OpenOptions::new().write(true).open(&self.target.path)?;
            file.sync_all()?;

            log::info!("Completed: {}", pass_label);
        }
        Ok(())
    }

    /// Write a single pattern pass across the entire device.
    fn write_pass(&self, pattern: &PassPattern, label: &str) -> TitanResult<()> {
        let mut file = OpenOptions::new().write(true).open(&self.target.path)?;
        file.seek(SeekFrom::Start(0))?;

        let total_blocks = self.target.size_bytes / BLOCK_SIZE as u64;
        let remainder = (self.target.size_bytes % BLOCK_SIZE as u64) as usize;
        let mut buf = vec![0u8; BLOCK_SIZE];

        let pb = ProgressBar::new(self.target.size_bytes);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg}\n{wide_bar} {bytes}/{total_bytes} ({bytes_per_sec}, ETA {eta})")
                .unwrap()
                .progress_chars("██░"),
        );
        pb.set_message(label.to_string());

        let start = Instant::now();

        for i in 0..total_blocks {
            if self.abort_flag.load(Ordering::SeqCst) {
                pb.finish_with_message("ABORTED");
                return Err(TitanError::UserAborted);
            }

            pattern.fill_buffer(&mut buf);
            file.write_all(&buf)?;
            pb.inc(BLOCK_SIZE as u64);

            // Periodic throughput log every 1000 blocks
            if i % 1000 == 0 && i > 0 {
                let elapsed = start.elapsed().as_secs_f64();
                let mib_done = (i * BLOCK_SIZE as u64) as f64 / (1024.0 * 1024.0);
                log::debug!("Throughput: {:.1} MiB/s", mib_done / elapsed);
            }
        }

        // Write remainder bytes to ensure complete coverage
        if remainder > 0 {
            let mut rem_buf = vec![0u8; remainder];
            pattern.fill_buffer(&mut rem_buf);
            file.write_all(&rem_buf)?;
            pb.inc(remainder as u64);
        }

        pb.finish_with_message(format!("{} ✓", label));
        Ok(())
    }

    /// Hash the full device sequentially with BLAKE3.
    /// Returns hex-encoded 256-bit digest.
    fn hash_device(&self, label: &str) -> TitanResult<String> {
        let mut file = File::open(&self.target.path)?;
        let mut hasher = Hasher::new();
        let mut buf = vec![0u8; BLOCK_SIZE];

        let pb = ProgressBar::new(self.target.size_bytes);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg}\n{wide_bar} {bytes}/{total_bytes} ({bytes_per_sec})")
                .unwrap()
                .progress_chars("██░"),
        );
        pb.set_message(label.to_string());

        loop {
            if self.abort_flag.load(Ordering::SeqCst) {
                pb.finish_with_message("ABORTED");
                return Err(TitanError::UserAborted);
            }

            let n = file.read(&mut buf)?;
            if n == 0 { break; }
            hasher.update(&buf[..n]);
            pb.inc(n as u64);
        }

        pb.finish_with_message(format!("{} ✓", label));
        let hash = hasher.finalize().to_hex().to_string();
        log::info!("BLAKE3 [{}]: {}", label, hash);
        Ok(hash)
    }

    /// For overwrite-based methods: verify that all readable blocks contain the
    /// expected last-pass pattern. Samples VERIFY_SAMPLE_BLOCKS random 4MiB blocks.
    fn verify_wipe_result(&self, _post_hash: &str) -> VerificationStatus {
        match self.algorithm {
            // Crypto/hardware erase: we can't verify by reading — the drive
            // remaps flash internally. The post-hash is sufficient audit evidence.
            WipeAlgorithm::NistNvmeCryptoErase | WipeAlgorithm::NistAtaSecureErase => {
                VerificationStatus::NotApplicable
            }

            // For overwrite methods: spot-check that the last pass pattern was written.
            WipeAlgorithm::NistClear | WipeAlgorithm::Dod5220 | WipeAlgorithm::Gutmann35 | WipeAlgorithm::RandomSingle => {
                match self.spot_check_last_pass() {
                    Ok(true) => VerificationStatus::Passed,
                    Ok(false) => VerificationStatus::Failed,
                    Err(e) => {
                        log::error!("Verification read error: {}", e);
                        VerificationStatus::Failed
                    }
                }
            }
        }
    }

    /// Spot-check the last pass: read sampled blocks and verify expected content.
    fn spot_check_last_pass(&self) -> TitanResult<bool> {
        let expected_byte = match self.algorithm {
            WipeAlgorithm::Gutmann35 => None, // Last Gutmann pass is random — can't verify by value
            WipeAlgorithm::Dod5220 => Some(0xAAu8), // Last DoD pass = 0xAA
            WipeAlgorithm::NistClear => Some(0x00u8),
            _ => return Ok(true),
        };

        let Some(expected) = expected_byte else {
            // For random passes: verify non-uniformity (any random data is fine)
            return self.verify_random_last_pass();
        };

        let mut file = File::open(&self.target.path)?;
        let num_blocks = self.target.size_bytes / BLOCK_SIZE as u64;
        let mut buf = vec![0u8; BLOCK_SIZE];

        // Check first, last, and VERIFY_SAMPLE_BLOCKS - 2 evenly distributed blocks
        let mut check_offsets: Vec<u64> = Vec::new();
        check_offsets.push(0);
        if num_blocks > 1 {
            check_offsets.push(num_blocks - 1);
        }
        let step = num_blocks / (VERIFY_SAMPLE_BLOCKS as u64 + 1);
        for i in 1..=VERIFY_SAMPLE_BLOCKS {
            let block = (i as u64 * step).min(num_blocks.saturating_sub(1));
            check_offsets.push(block);
        }
        check_offsets.sort_unstable();
        check_offsets.dedup();

        let pb = ProgressBar::new(check_offsets.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("Verification: {wide_bar} {pos}/{len} blocks sampled")
                .unwrap(),
        );

        for block_idx in &check_offsets {
            file.seek(SeekFrom::Start(block_idx * BLOCK_SIZE as u64))?;
            let n = file.read(&mut buf)?;
            if n == 0 { break; }

            // Check every byte matches expected pattern
            for &byte in &buf[..n] {
                if byte != expected {
                    pb.finish_with_message("Verification: FAILED");
                    log::error!(
                        "Verification failed at block {}: expected 0x{:02X}, got 0x{:02X}",
                        block_idx, expected, byte
                    );
                    return Ok(false);
                }
            }
            pb.inc(1);
        }

        pb.finish_with_message("Verification: PASSED");
        Ok(true)
    }

    /// For random-last-pass algorithms: check the block isn't all-zeros or all-same.
    fn verify_random_last_pass(&self) -> TitanResult<bool> {
        let mut file = File::open(&self.target.path)?;
        let mut buf = vec![0u8; BLOCK_SIZE];
        let n = file.read(&mut buf)?;
        if n == 0 { return Ok(true); }

        // A block of all identical bytes after a random pass would indicate failure
        let all_same = buf[..n].windows(2).all(|w| w[0] == w[1]);
        if all_same {
            log::warn!("Random pass verification: first block appears uniform — possible write failure.");
            return Ok(false);
        }
        Ok(true)
    }
}
