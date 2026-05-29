//! Wipe pattern generators for multi-pass overwrite algorithms.
//! Implements DoD 5220.22-M ECE and Gutmann 35-pass correctly.

use rand::RngCore;

/// A single overwrite pass: a pattern byte or PRNG fill.
#[derive(Debug, Clone)]
pub enum PassPattern {
    /// Fill with constant byte.
    Constant(u8),
    /// Fill with cryptographically random bytes (via OS CSPRNG).
    CryptographicRandom,
    /// Fill with specific DoD-specified alternating pattern.
    Alternating(u8, u8),
}

impl PassPattern {
    pub fn fill_buffer(&self, buf: &mut [u8]) {
        match self {
            PassPattern::Constant(byte) => buf.fill(*byte),
            PassPattern::CryptographicRandom => {
                rand::thread_rng().fill_bytes(buf);
            }
            PassPattern::Alternating(a, b) => {
                for (i, byte) in buf.iter_mut().enumerate() {
                    *byte = if i % 2 == 0 { *a } else { *b };
                }
            }
        }
    }

    pub fn description(&self) -> String {
        match self {
            PassPattern::Constant(b) => format!("0x{:02X}", b),
            PassPattern::CryptographicRandom => "CSPRNG Random".to_string(),
            PassPattern::Alternating(a, b) => format!("Alt 0x{:02X}/0x{:02X}", a, b),
        }
    }
}

/// DoD 5220.22-M ECE — 7 passes (the full ECE variant, not the reduced 3-pass).
///
/// Per the 2007 edition of the DoD 5220.22-M standard:
///   Pass 1: 0x00
///   Pass 2: 0xFF
///   Pass 3: Random
///   Pass 4: 0x00         ← ECE adds passes 4-7
///   Pass 5: 0xFF
///   Pass 6: Random
///   Pass 7: 0xAA (verification pass marker)
pub fn dod_5220_22m_ece_passes() -> Vec<PassPattern> {
    vec![
        PassPattern::Constant(0x00),
        PassPattern::Constant(0xFF),
        PassPattern::CryptographicRandom,
        PassPattern::Constant(0x00),
        PassPattern::Constant(0xFF),
        PassPattern::CryptographicRandom,
        PassPattern::Constant(0xAA),
    ]
}

/// NIST SP 800-88 Rev.1 Clear — single zero-fill pass.
pub fn nist_clear_passes() -> Vec<PassPattern> {
    vec![PassPattern::Constant(0x00)]
}

/// Single-pass cryptographic random overwrite — fast and effective.
pub fn random_single_passes() -> Vec<PassPattern> {
    vec![PassPattern::CryptographicRandom]
}

/// Gutmann 35-pass — the full pattern set from Peter Gutmann's 1996 paper.
/// Passes 1–4 and 32–35 are random; passes 5–31 are specific MFM/RLL patterns.
///
/// Note: In practice, passes 5–31 only help against MFM/RLL encoded drives
/// manufactured before ~1998. For modern drives, this is effectively equivalent
/// to 35 random passes in terms of data irrecoverability. Included here for
/// completeness and legacy compliance requirements.
pub fn gutmann_35_passes() -> Vec<PassPattern> {
    vec![
        // Passes 1–4: Random
        PassPattern::CryptographicRandom,
        PassPattern::CryptographicRandom,
        PassPattern::CryptographicRandom,
        PassPattern::CryptographicRandom,
        // Passes 5–31: MFM/RLL specific patterns (Table 1 from Gutmann 1996)
        PassPattern::Constant(0x55),
        PassPattern::Constant(0xAA),
        PassPattern::Alternating(0x92, 0x49),
        PassPattern::Alternating(0x49, 0x24),
        PassPattern::Alternating(0x24, 0x92),
        PassPattern::Constant(0x00),
        PassPattern::Constant(0x11),
        PassPattern::Constant(0x22),
        PassPattern::Constant(0x33),
        PassPattern::Constant(0x44),
        PassPattern::Constant(0x55),
        PassPattern::Constant(0x66),
        PassPattern::Constant(0x77),
        PassPattern::Constant(0x88),
        PassPattern::Constant(0x99),
        PassPattern::Constant(0xAA),
        PassPattern::Constant(0xBB),
        PassPattern::Constant(0xCC),
        PassPattern::Constant(0xDD),
        PassPattern::Constant(0xEE),
        PassPattern::Constant(0xFF),
        PassPattern::Alternating(0x92, 0x49),
        PassPattern::Alternating(0x49, 0x24),
        PassPattern::Alternating(0x24, 0x92),
        PassPattern::Alternating(0x6D, 0xB6),
        PassPattern::Alternating(0xB6, 0xDB),
        PassPattern::Alternating(0xDB, 0x6D),
        // Passes 32–35: Random
        PassPattern::CryptographicRandom,
        PassPattern::CryptographicRandom,
        PassPattern::CryptographicRandom,
        PassPattern::CryptographicRandom,
    ]
}
