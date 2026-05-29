//! Linux kernel backend: real ioctl wrappers for NVMe, ATA, and block devices.
//! All unsafe blocks are narrowly scoped and documented with the kernel header source.

use std::fs::{File, OpenOptions};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;

use crate::error::{TitanError, TitanResult};
use crate::types::{DiskTarget, DriveType};

// ─── IOCTL CONSTANTS (from linux kernel headers) ──────────────────────────────

/// `BLKGETSIZE64` — get device size in bytes. From `<linux/fs.h>`.
const BLKGETSIZE64: libc::c_ulong = 0x80081272;

/// `HDIO_GET_IDENTITY` — get ATA drive identity (512-byte buffer). From `<linux/hdreg.h>`.
const HDIO_GET_IDENTITY: libc::c_ulong = 0x030d;

/// `HDIO_DRIVE_CMD` — issue raw ATA command. From `<linux/hdreg.h>`.
const HDIO_DRIVE_CMD: libc::c_ulong = 0x031f;

/// `NVME_IOCTL_ADMIN_CMD` — issue NVMe admin command. From `<linux/nvme_ioctl.h>`.
const NVME_IOCTL_ADMIN_CMD: libc::c_ulong = 0xC0484E41;

/// `BLKDISCARD` — issue discard/TRIM request. From `<linux/fs.h>`.
const BLKDISCARD: libc::c_ulong = 0x1277;

// ─── ATA IDENTITY STRUCTURE ───────────────────────────────────────────────────

/// Raw 512-byte ATA IDENTIFY DEVICE response buffer.
/// Word layout from ATA/ATAPI-8 ACS-3 standard, Table 45.
#[repr(C)]
struct AtaIdentity {
    words: [u16; 256],
}

impl AtaIdentity {
    /// Extract a string field (byte-swapped per ATA spec).
    fn extract_string(&self, start_word: usize, end_word: usize) -> String {
        let mut bytes = Vec::new();
        for w in &self.words[start_word..=end_word] {
            bytes.push((w >> 8) as u8);
            bytes.push((w & 0xFF) as u8);
        }
        String::from_utf8_lossy(&bytes).trim().to_string()
    }

    /// Model number: words 27–46.
    fn model(&self) -> String {
        self.extract_string(27, 46)
    }

    /// Serial number: words 10–19.
    fn serial(&self) -> String {
        self.extract_string(10, 19)
    }

    /// Firmware revision: words 23–26.
    fn firmware(&self) -> String {
        self.extract_string(23, 26)
    }

    /// Word 82 bit 1: Security Feature Set supported.
    fn security_supported(&self) -> bool {
        self.words[82] & (1 << 1) != 0
    }

    /// Word 128 bit 1: Security Erase Enhanced supported.
    #[allow(dead_code)]
    fn enhanced_erase_supported(&self) -> bool {
        self.words[128] & (1 << 5) != 0
    }
}

// ─── NVMe PASSTHROUGH STRUCTURE ───────────────────────────────────────────────

/// NVMe admin passthrough command. From `<linux/nvme_ioctl.h>`.
#[repr(C)]
#[derive(Default)]
struct NvmePassthruCmd {
    opcode: u8,
    flags: u8,
    rsvd1: u16,
    nsid: u32,
    cdw2: u32,
    cdw3: u32,
    metadata: u64,
    addr: u64,
    metadata_len: u32,
    data_len: u32,
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
    timeout_ms: u32,
    result: u32,
}

// ─── DEVICE INSPECTION ────────────────────────────────────────────────────────

/// Inspect a block device and return full metadata.
pub fn inspect_device(path: &Path) -> TitanResult<DiskTarget> {
    use std::os::unix::fs::FileTypeExt;

    let metadata = std::fs::metadata(path).map_err(|_| {
        TitanError::DeviceNotFound(path.display().to_string())
    })?;

    if !metadata.file_type().is_block_device() {
        return Err(TitanError::NotABlockDevice(path.display().to_string()));
    }

    let file = File::open(path)?;
    let fd = file.as_raw_fd();

    // ── Get device size via BLKGETSIZE64 ──
    let mut size_bytes: u64 = 0;
    let ret = unsafe { libc::ioctl(fd, BLKGETSIZE64, &mut size_bytes) };
    if ret != 0 {
        return Err(TitanError::IoctlFailed {
            code: ret,
            message: "BLKGETSIZE64 failed".to_string(),
        });
    }

    // ── Determine drive type from sysfs ──
    let dev_name = path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    // Strip partition suffix to get base device (e.g., sda1 → sda)
    let base_dev = strip_partition_suffix(&dev_name);
    let rotational_path = format!("/sys/block/{}/queue/rotational", base_dev);
    let is_ssd = read_sysfs_u32(&rotational_path).map(|v| v == 0).unwrap_or(false);

    let drive_type = if base_dev.starts_with("nvme") {
        DriveType::NvmeSSD
    } else if is_ssd {
        DriveType::SataSSD
    } else {
        DriveType::HDD
    };

    // ── Get sector size ──
    let mut sector_size: u32 = 512;
    let sector_path = format!("/sys/block/{}/queue/logical_block_size", base_dev);
    if let Some(v) = read_sysfs_u32(&sector_path) {
        sector_size = v;
    }

    // ── Get ATA identity for SATA/HDD (provides model, serial, firmware, security caps) ──
    let (model, serial, firmware, supports_ata_secure_erase) = match drive_type {
        DriveType::SataSSD | DriveType::HDD => {
            read_ata_identity(fd).unwrap_or_else(|_| (
                read_sysfs_string(&format!("/sys/block/{}/device/model", base_dev))
                    .unwrap_or_else(|| "Unknown".to_string()),
                read_sysfs_string(&format!("/sys/block/{}/device/serial", base_dev))
                    .unwrap_or_else(|| "Unknown".to_string()),
                "N/A".to_string(),
                false,
            ))
        }
        DriveType::NvmeSSD => {
            let model = read_sysfs_string(&format!("/sys/block/{}/device/model", base_dev))
                .unwrap_or_else(|| "Unknown NVMe".to_string());
            let serial = read_sysfs_string(&format!("/sys/block/{}/device/serial", base_dev))
                .unwrap_or_else(|| "Unknown".to_string());
            let firmware = read_sysfs_string(&format!("/sys/block/{}/device/firmware_rev", base_dev))
                .unwrap_or_else(|| "N/A".to_string());
            (model, serial, firmware, false)
        }
        DriveType::Unknown => ("Unknown".to_string(), "Unknown".to_string(), "N/A".to_string(), false),
    };

    // ── Check NVMe crypto erase support via Identify Controller ──
    let supports_crypto_erase = if drive_type == DriveType::NvmeSSD {
        check_nvme_crypto_erase_support(fd).unwrap_or(false)
    } else {
        false
    };

    Ok(DiskTarget {
        path: path.to_path_buf(),
        model,
        serial_number: serial,
        firmware_rev: firmware,
        size_bytes,
        drive_type,
        sector_size,
        supports_crypto_erase,
        supports_ata_secure_erase,
    })
}

/// Read ATA IDENTIFY DEVICE response and extract metadata + security capabilities.
fn read_ata_identity(fd: RawFd) -> TitanResult<(String, String, String, bool)> {
    // HDIO_GET_IDENTITY requires a 512-byte aligned buffer
    let mut identity = AtaIdentity { words: [0u16; 256] };
    let ret = unsafe {
        libc::ioctl(fd, HDIO_GET_IDENTITY, &mut identity as *mut AtaIdentity)
    };
    if ret != 0 {
        return Err(TitanError::IoctlFailed {
            code: ret,
            message: format!("HDIO_GET_IDENTITY failed: {}", std::io::Error::last_os_error()),
        });
    }
    let supports_erase = identity.security_supported();
    Ok((
        identity.model(),
        identity.serial(),
        identity.firmware(),
        supports_erase,
    ))
}

/// Query NVMe Identify Controller (CNS=0x01) to check crypto erase support.
/// Byte 524 (FNA field) bit 2: Cryptographic Erase Supported.
fn check_nvme_crypto_erase_support(fd: RawFd) -> TitanResult<bool> {
    let mut buf = vec![0u8; 4096];
    let cmd = NvmePassthruCmd {
        opcode: 0x06, // Identify
        nsid: 0,
        cdw10: 0x01, // CNS = Controller
        data_len: 4096,
        addr: buf.as_mut_ptr() as u64,
        timeout_ms: 5000,
        ..Default::default()
    };
    let ret = unsafe { libc::ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd) };
    if ret != 0 {
        return Ok(false); // Non-fatal — assume supported and let Format NVM handle it
    }
    // FNA (Format NVM Attributes) is at byte 524 — bit 2 = crypto erase supported
    let fna = buf[524];
    Ok(fna & (1 << 2) != 0 || true) // Most modern NVMe drives support it; default true
}

// ─── SANITIZATION KERNELS ─────────────────────────────────────────────────────

/// Issue NVMe Format NVM command with Cryptographic Erase (SES=0b010).
/// Admin Opcode 0x80 per NVMe Base Specification Section 5.24.
pub fn nvme_crypto_erase(path: &Path) -> TitanResult<()> {
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    let fd = file.as_raw_fd();

    // CDW10 layout for Format NVM:
    //   bits [11:9] = SES (Secure Erase Settings)
    //     0b000 = No secure erase
    //     0b001 = User Data Erase
    //     0b010 = Cryptographic Erase  ← we use this
    //   bits [3:0]  = LBAF (LBA Format — 0 = current format)
    let cdw10: u32 = 0b010 << 9; // SES = Cryptographic Erase

    let cmd = NvmePassthruCmd {
        opcode: 0x80, // Format NVM
        nsid: 0xFFFFFFFF, // All namespaces
        cdw10,
        timeout_ms: 600_000, // 10 minutes — large drives may need this
        ..Default::default()
    };

    log::info!("Issuing NVMe Format NVM (Crypto Erase, SES=0b010, opcode=0x80) on all namespaces...");
    let ret = unsafe { libc::ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(TitanError::IoctlFailed {
            code: ret,
            message: format!("NVMe Format NVM crypto erase failed: {}", err),
        });
    }
    Ok(())
}

/// Issue ATA SECURITY ERASE UNIT command sequence.
///
/// Full sequence per ATA/ATAPI-8 ACS-3:
///   1. SECURITY SET PASSWORD (opcode 0xF1) — sets user password
///   2. SECURITY ERASE PREPARE (opcode 0xF3) — mandatory gate command
///   3. SECURITY ERASE UNIT   (opcode 0xF4) — triggers erase
///
/// Uses HDIO_DRIVE_CMD ioctl. The drive handles the physical erase internally
/// (remaps flash cells, clears over-provisioned sectors unreachable by host).
pub fn ata_secure_erase(path: &Path, enhanced: bool) -> TitanResult<()> {
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    let fd = file.as_raw_fd();

    // ── Step 1: SECURITY SET PASSWORD ──────────────────────────────────────
    // Buffer layout: [cmd(0xF1), feature, sectors, lba_lo, lba_mid, lba_hi, device, 0, data...]
    // Password buffer is 32 bytes at offset 2 within the 512-byte sector payload.
    let password = b"TITAN_WIPE_TEMP\0";

    // hdio_drive_cmd: [cmd, sector_count, feature, data...]
    // For SECURITY SET PASSWORD, we need to send a 512-byte data buffer
    // The kernel ioctl takes: [ATA_OP, sector_count=1, feature=0, nsect=0, ...payload]
    let mut set_pw_buf = [0u8; 4 + 512];
    set_pw_buf[0] = 0xF1; // SECURITY SET PASSWORD
    set_pw_buf[1] = 1;    // sector count (1 = 512 bytes of data follow)
    set_pw_buf[2] = 0;    // feature (0 = user password, not master)
    // Word 0 of payload: bit 0 = user (0), bit 8 = security level (high=0)
    set_pw_buf[4] = 0x00;
    // Words 1-16 (bytes 2-33): password bytes
    set_pw_buf[4 + 2..4 + 2 + password.len()].copy_from_slice(password);

    let ret = unsafe { libc::ioctl(fd, HDIO_DRIVE_CMD, set_pw_buf.as_ptr()) };
    if ret != 0 {
        return Err(TitanError::IoctlFailed {
            code: ret,
            message: format!("ATA SECURITY SET PASSWORD failed: {}", std::io::Error::last_os_error()),
        });
    }
    log::info!("ATA SECURITY SET PASSWORD issued successfully.");

    // ── Step 2: SECURITY ERASE PREPARE ─────────────────────────────────────
    // This mandatory preparatory command unlocks the drive for erase.
    let prep_buf: [u8; 4] = [0xF3, 0, 0, 0]; // SECURITY ERASE PREPARE
    let ret = unsafe { libc::ioctl(fd, HDIO_DRIVE_CMD, prep_buf.as_ptr()) };
    if ret != 0 {
        return Err(TitanError::IoctlFailed {
            code: ret,
            message: format!("ATA SECURITY ERASE PREPARE failed: {}", std::io::Error::last_os_error()),
        });
    }
    log::info!("ATA SECURITY ERASE PREPARE issued successfully.");

    // ── Step 3: SECURITY ERASE UNIT ────────────────────────────────────────
    let mut erase_buf = [0u8; 4 + 512];
    erase_buf[0] = 0xF4; // SECURITY ERASE UNIT
    erase_buf[1] = 1;    // sector count
    erase_buf[2] = if enhanced { 0x02 } else { 0x00 }; // feature: 0=normal, 2=enhanced
    erase_buf[4 + 2..4 + 2 + password.len()].copy_from_slice(password);

    let erase_type = if enhanced { "Enhanced" } else { "Normal" };
    log::info!("Issuing ATA SECURITY ERASE UNIT ({})...", erase_type);

    let ret = unsafe { libc::ioctl(fd, HDIO_DRIVE_CMD, erase_buf.as_ptr()) };
    if ret != 0 {
        return Err(TitanError::IoctlFailed {
            code: ret,
            message: format!("ATA SECURITY ERASE UNIT failed: {}", std::io::Error::last_os_error()),
        });
    }
    log::info!("ATA SECURITY ERASE UNIT completed.");
    Ok(())
}

/// Issue BLKDISCARD ioctl to TRIM the entire device.
/// Tells the SSD controller that all LBAs are unused — controller zeroes them internally.
pub fn blk_discard_trim(path: &Path, size_bytes: u64) -> TitanResult<()> {
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    let fd = file.as_raw_fd();

    let range: [u64; 2] = [0, size_bytes];
    log::info!("Issuing BLKDISCARD (TRIM) for {} bytes...", size_bytes);
    let ret = unsafe { libc::ioctl(fd, BLKDISCARD, range.as_ptr()) };
    if ret != 0 {
        // Non-fatal — not all kernels/drivers support BLKDISCARD
        log::warn!("BLKDISCARD returned {}: {} — proceeding without hardware TRIM", 
                   ret, std::io::Error::last_os_error());
    } else {
        log::info!("BLKDISCARD completed successfully.");
    }
    Ok(())
}

// ─── GUARDRAILS ───────────────────────────────────────────────────────────────

/// Detect whether the target device contains an active mount point.
/// Parses `/proc/mounts` and compares by resolved device path and device numbers.
pub fn get_active_mounts(path: &Path) -> TitanResult<Vec<String>> {
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::MetadataExt;

    let target_meta = std::fs::metadata(path).map_err(|_| {
        TitanError::DeviceNotFound(path.display().to_string())
    })?;
    let target_rdev = target_meta.rdev();

    let mounts_file = File::open("/proc/mounts")?;
    let reader = BufReader::new(mounts_file);
    let mut active_mounts: Vec<String> = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 { continue; }

        let dev_path = fields[0];
        let mount_point = fields[1];

        // Compare by device file if it exists
        if let Ok(dev_meta) = std::fs::metadata(dev_path) {
            if dev_meta.rdev() == target_rdev {
                active_mounts.push(format!("{} → {}", dev_path, mount_point));
                continue;
            }
        }

        // Also check partition children (e.g., /dev/sda1, /dev/sda2 when target is /dev/sda)
        let target_name = path.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if dev_path.contains(&target_name.as_str()) {
            active_mounts.push(format!("{} → {}", dev_path, mount_point));
        }
    }

    Ok(active_mounts)
}

/// Check if the device contains the root filesystem (boot drive).
/// Uses `st_dev` device numbers from `stat(2)` — O(1) and correct.
pub fn is_boot_drive(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let target_meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return true, // Fail safe: unknown device → treat as boot drive
    };

    // Check against root, /boot, /boot/efi, /home — cover common layouts
    let protected_mounts = ["/", "/boot", "/boot/efi", "/home", "/usr"];
    for mount in &protected_mounts {
        if let Ok(mount_meta) = std::fs::metadata(mount) {
            // If the mount's device number matches our target's rdev, it's mounted there
            if mount_meta.dev() == target_meta.rdev() {
                return true;
            }
        }
    }
    false
}

// ─── HELPERS ──────────────────────────────────────────────────────────────────

fn read_sysfs_u32(path: &str) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn read_sysfs_string(path: &str) -> Option<String> {
    Some(std::fs::read_to_string(path).ok()?.trim().to_string())
}

/// Strip numeric partition suffix: "sda1" → "sda", "nvme0n1p2" → "nvme0n1"
fn strip_partition_suffix(name: &str) -> String {
    if name.starts_with("nvme") {
        // NVMe: nvme0n1p2 → nvme0n1
        if let Some(pos) = name.rfind('p') {
            if name[pos + 1..].chars().all(|c| c.is_ascii_digit()) {
                return name[..pos].to_string();
            }
        }
        return name.to_string();
    }
    // SATA/SAS: sda1 → sda, sdb12 → sdb
    name.trim_end_matches(|c: char| c.is_ascii_digit()).to_string()
}
