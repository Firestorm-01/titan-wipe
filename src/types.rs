use std::fmt;
use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use clap::ValueEnum;

/// Physical storage bus and technology type, detected from kernel sysfs/ioctl.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriveType {
    /// Magnetic rotating disk — multi-pass overwrite required.
    HDD,
    /// SATA/AHCI solid-state drive — ATA Secure Erase + TRIM purge.
    SataSSD,
    /// NVMe PCIe solid-state drive — controller-level Cryptographic Erase.
    NvmeSSD,
    /// Unknown — falls back to safe multi-pass overwrite.
    #[allow(dead_code)]
    Unknown,
}

impl fmt::Display for DriveType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DriveType::HDD => write!(f, "HDD (Magnetic Rotating)"),
            DriveType::SataSSD => write!(f, "SSD (SATA/AHCI Flash)"),
            DriveType::NvmeSSD => write!(f, "SSD (NVMe PCIe Flash)"),
            DriveType::Unknown => write!(f, "Unknown (Safe Fallback)"),
        }
    }
}

/// Wipe algorithm to apply. Auto-selects based on drive type unless overridden.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum WipeAlgorithm {
    /// NIST SP 800-88 Rev.1 Cryptographic Erase via NVMe Format NVM command (NVMe only).
    NistNvmeCryptoErase,
    /// NIST SP 800-88 Rev.1 Purge via ATA SECURITY ERASE UNIT (SATA only).
    NistAtaSecureErase,
    /// NIST SP 800-88 Rev.1 Clear — single-pass zero overwrite + verification.
    NistClear,
    /// DoD 5220.22-M ECE — 7-pass overwrite (legacy, for HDD compliance requirements).
    Dod5220,
    /// Gutmann 35-pass — maximum paranoia for legacy magnetic media.
    Gutmann35,
    /// Single-pass cryptographically random overwrite — fast and effective for SSDs.
    RandomSingle,
}

impl fmt::Display for WipeAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WipeAlgorithm::NistNvmeCryptoErase => write!(f, "NIST SP 800-88 Rev.1 — NVMe Cryptographic Erase"),
            WipeAlgorithm::NistAtaSecureErase => write!(f, "NIST SP 800-88 Rev.1 — ATA Secure Erase Purge"),
            WipeAlgorithm::NistClear => write!(f, "NIST SP 800-88 Rev.1 — Clear (Zero Overwrite + Verify)"),
            WipeAlgorithm::Dod5220 => write!(f, "DoD 5220.22-M ECE — 7-Pass Overwrite"),
            WipeAlgorithm::Gutmann35 => write!(f, "Gutmann — 35-Pass"),
            WipeAlgorithm::RandomSingle => write!(f, "Cryptographic Random — Single Pass"),
        }
    }
}

/// Fully-described physical disk target.
#[derive(Debug, Clone)]
pub struct DiskTarget {
    pub path: PathBuf,
    pub model: String,
    pub serial_number: String,
    pub firmware_rev: String,
    pub size_bytes: u64,
    pub drive_type: DriveType,
    pub sector_size: u32,
    pub supports_crypto_erase: bool,
    pub supports_ata_secure_erase: bool,
}

impl DiskTarget {
    pub fn size_gib(&self) -> f64 {
        self.size_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    }

    pub fn recommended_algorithm(&self) -> WipeAlgorithm {
        match self.drive_type {
            DriveType::NvmeSSD if self.supports_crypto_erase => WipeAlgorithm::NistNvmeCryptoErase,
            DriveType::SataSSD if self.supports_ata_secure_erase => WipeAlgorithm::NistAtaSecureErase,
            DriveType::SataSSD => WipeAlgorithm::NistClear,
            DriveType::HDD => WipeAlgorithm::Dod5220,
            DriveType::NvmeSSD => WipeAlgorithm::NistClear,
            DriveType::Unknown => WipeAlgorithm::Dod5220,
        }
    }
}

/// Cryptographically-signed sanitization audit certificate.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SanitizationCertificate {
    pub certificate_id: String,
    pub timestamp_start: String,
    pub timestamp_end: String,
    pub device_path: String,
    pub model: String,
    pub serial: String,
    pub firmware_rev: String,
    pub size_bytes: u64,
    pub drive_type: String,
    pub algorithm_used: String,
    pub passes_completed: u32,
    pub pre_wipe_hash: String,
    pub post_wipe_hash: String,
    pub verification_status: VerificationStatus,
    pub status: SanitizationStatus,
    pub operator_note: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum VerificationStatus {
    Passed,
    Failed,
    Skipped,
    NotApplicable,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum SanitizationStatus {
    Success,
    PartialFailure,
    Failed,
    Aborted,
}
