#![allow(dead_code)]
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TitanError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("FATAL GUARDRAIL: Target '{0}' is the active boot/OS drive. Operation aborted.")]
    BootDriveProtection(String),

    #[error("FATAL GUARDRAIL: Target '{0}' has active mounted partitions: {1}. Unmount before proceeding.")]
    DeviceMounted(String, String),

    #[error("Target '{0}' is not a block device.")]
    NotABlockDevice(String),

    #[error("Target device '{0}' not found or inaccessible.")]
    DeviceNotFound(String),

    #[error("Insufficient privileges. This utility requires root/administrator access.")]
    InsufficientPrivileges,

    #[error("Kernel IOCTL error (code {code}): {message}")]
    IoctlFailed { code: i32, message: String },

    #[error("Device inspection failed: {0}")]
    InspectionFailed(String),

    #[error("Sanitization aborted by user.")]
    UserAborted,

    #[error("Verification failed: post-wipe read returned unexpected data. Hash: {0}")]
    VerificationFailed(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type TitanResult<T> = Result<T, TitanError>;
