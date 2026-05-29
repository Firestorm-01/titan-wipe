//! Device enumeration — lists all block devices from /sys/block.

use std::path::PathBuf;
use crate::error::TitanResult;
use crate::types::DiskTarget;
use crate::os_backend;

/// Enumerate all physical block devices on the system.
/// Skips loop devices, device mapper targets, and RAM disks.
pub fn list_block_devices() -> TitanResult<Vec<DiskTarget>> {
    let mut devices = Vec::new();

    let block_dir = std::fs::read_dir("/sys/block")?;

    for entry in block_dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip non-physical device types
        if name.starts_with("loop")
            || name.starts_with("dm-")
            || name.starts_with("ram")
            || name.starts_with("zram")
            || name.starts_with("sr") // optical drives
        {
            continue;
        }

        let dev_path = PathBuf::from(format!("/dev/{}", name));
        if !dev_path.exists() {
            continue;
        }

        match os_backend::inspect_device(&dev_path) {
            Ok(disk) => devices.push(disk),
            Err(e) => {
                log::warn!("Skipping {}: {}", dev_path.display(), e);
            }
        }
    }

    devices.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(devices)
}
