# titan-wipe
⚠️Entire project needs to be tested before usage.This is a prototype.Please use this tool with caution.Data when wiped is irrecoverable.
**Enterprise-grade, NIST SP 800-88 Rev.1 compliant storage sanitization utility written in Rust.**

Designed to outperform legacy tools like DBAN and `shred` by using hardware-native erase commands where available, implementing correct wipe algorithms, and generating a cryptographically-verified audit certificate on every run.

---

## Why Rust?

Rust's type system eliminates entire classes of bugs that are fatal in a destructive low-level utility:
- No buffer overflows in ioctl buffers
- No use-after-free in device handles
- No data races in the abort flag (Ctrl-C handler runs on a separate thread)
- Explicit, narrowly-scoped `unsafe` blocks — each one is commented with the kernel header it wraps

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│          CLI Layer (clap) — list / inspect / wipe   │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│              Safety Guardrails                      │
│  • Boot drive check (dev number via stat(2))        │
│  • Active mount check (/proc/mounts + rdev)         │
│  • Privilege check (getuid == 0)                    │
│  • Multi-step consent handshake (serial-keyed)      │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│          Hardware Discovery (os_backend)            │
│  • BLKGETSIZE64 ioctl — exact byte size             │
│  • HDIO_GET_IDENTITY — ATA model/serial/security    │
│  • /sys/block/<dev>/queue/rotational — SSD vs HDD   │
│  • NVMe Identify Controller — crypto erase support  │
└──────────┬──────────────┬──────────────┬────────────┘
           │              │              │
    ┌──────▼──────┐ ┌─────▼──────┐ ┌────▼───────────┐
    │   NVMe Path │ │  SATA Path │ │   HDD Path     │
    │             │ │            │ │                │
    │ Format NVM  │ │ ATA SEC    │ │ DoD 5220.22-M  │
    │ opcode 0x80 │ │ ERASE UNIT │ │ ECE 7-pass     │
    │ SES=0b010   │ │ 0xF3+0xF4  │ │ or Gutmann 35  │
    │ (Crypto     │ │ + BLKDIS-  │ │                │
    │  Erase)     │ │ CARD TRIM  │ │                │
    └──────┬──────┘ └─────┬──────┘ └────┬───────────┘
           └──────────────┴──────────────┘
                          │
┌─────────────────────────▼───────────────────────────┐
│     Verification & Audit Certificate                │
│  • Pre-wipe BLAKE3 hash (full sequential read)      │
│  • Post-wipe BLAKE3 hash                            │
│  • Spot-check: 512 sampled blocks vs expected byte  │
│  • JSON certificate — UUID, timestamps, hashes      │
└─────────────────────────────────────────────────────┘
```

---

## Supported Algorithms

| Algorithm | Standard | Best For | Passes |
|---|---|---|---|
| `nist-nvme-crypto-erase` | NIST SP 800-88 Rev.1 Purge | NVMe SSDs | 1 (hardware) |
| `nist-ata-secure-erase` | NIST SP 800-88 Rev.1 Purge | SATA SSDs/HDDs | 1 (hardware) |
| `nist-clear` | NIST SP 800-88 Rev.1 Clear | Any | 1 (zero-fill + verify) |
| `dod5220` | DoD 5220.22-M ECE | HDDs | 7 |
| `gutmann35` | Gutmann 1996 | Legacy magnetic media | 35 |
| `random-single` | Best practice | SSDs (fast path) | 1 (CSPRNG) |

**Auto-selection logic:** titan-wipe detects your drive's bus type, queries ATA security capabilities and NVMe controller identity, and selects the strongest applicable algorithm automatically. You can override with `--algorithm`.

---

## Wipe Quality

### NVMe Cryptographic Erase (strongest for flash)
Issues the NVMe **Format NVM** admin command (opcode `0x80`) with `SES=0b010` (Cryptographic Erase) to all namespaces. The controller:
- Destroys the internal encryption key, rendering all stored data cryptographically irrecoverable
- Erases over-provisioned sectors (hidden from the host) — impossible with software-only approaches
- Completes in seconds regardless of drive capacity

This is the correct NIST SP 800-88 Rev.1 **Purge** method for NVMe. Legacy tools that write zeros to NVMe drives are wrong — the FTL remaps LBAs and old data persists in unmapped flash cells.

### ATA Secure Erase (strongest for SATA)
Issues the full ATA command sequence per ACS-3:
1. `SECURITY SET PASSWORD` (opcode `0xF1`) — sets temporary user password
2. `SECURITY ERASE PREPARE` (opcode `0xF3`) — mandatory gate to prevent accidental erase
3. `SECURITY ERASE UNIT` (opcode `0xF4`) — triggers controller-level physical erase

Uses **Enhanced Secure Erase** when the drive reports support (Word 128 bit 5), which additionally erases remapped sectors and spare areas. Followed by a `BLKDISCARD` TRIM to flush the over-provisioned pool.

### DoD 5220.22-M ECE — 7 passes (correct implementation)
```
Pass 1: 0x00
Pass 2: 0xFF
Pass 3: CSPRNG random
Pass 4: 0x00
Pass 5: 0xFF
Pass 6: CSPRNG random
Pass 7: 0xAA  (verification marker)
```
Note: The original 3-pass variant uses `0xAA` as pass 3 — that is **incorrect**. The ECE (Extended Character Erase) 7-pass variant above is the full standard. Each pass is followed by `fsync` to guarantee physical writes before the next pass begins.

### Gutmann 35-pass
All 35 patterns from Peter Gutmann's 1996 paper, including the MFM/RLL encoding-specific patterns (passes 5–31) for drives manufactured before ~1998, bookended by 4 random passes on each end per the paper's recommendation.

---

## Safety Guardrails

These checks run **before any writes** and are hardcoded — they cannot be bypassed by flags:

**1. Boot drive detection** — uses `stat(2)` device numbers (`st_dev`/`st_rdev`), not string matching. Checks against `/`, `/boot`, `/boot/efi`, `/home`, `/usr`. If the target device's `rdev` matches any protected mount's `dev`, it aborts.

**2. Active mount detection** — parses `/proc/mounts` and compares `rdev` values. Also checks partition children (e.g., rejects `/dev/sda` if `/dev/sda1` is mounted). Returns a list of active mounts in the error message.

**3. Privilege check** — `getuid() == 0` required. Aborts with a clear error otherwise.

**4. Consent handshake** — requires typing `WIPE-<serial_prefix>` (device-specific, generated at runtime). A generic "yes" won't work.

---

## Verification

Post-wipe verification:

- **Full sequential BLAKE3 hash** of the entire device (pre and post)
- **512-block spot check** for overwrite-based methods: reads first block, last block, and 510 evenly-distributed blocks, verifying every byte matches the last-pass pattern
- For NVMe/ATA hardware erase: `VerificationStatus::NotApplicable` — the drive's internal erase is not readable back; the post-wipe hash serves as audit evidence
- Exit code `3` if verification fails (exit `0` = success, `2` = error)

---

## Installation

```bash
# Prerequisites: Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build release binary
git clone https://github.com/kailash/titan-wipe
cd titan-wipe
cargo build --release

# Install to /usr/local/bin
sudo install -m 755 target/release/titan-wipe /usr/local/bin/
```

---

## Usage

```bash
# List all block devices
sudo titan-wipe list

# Inspect a specific device
sudo titan-wipe inspect /dev/sdb

# Wipe with auto-selected algorithm (recommended)
sudo titan-wipe wipe --device /dev/sdb

# Wipe with explicit algorithm
sudo titan-wipe wipe --device /dev/nvme1n1 --algorithm nist-nvme-crypto-erase

# Wipe and save audit certificate
sudo titan-wipe wipe --device /dev/sdb --output /root/cert_sdb.json

# DoD 7-pass HDD wipe, verbose
sudo titan-wipe wipe --device /dev/sdb --algorithm dod5220 --verbose

# Dry run (no writes — tests the full pipeline safely)
sudo titan-wipe wipe --device /dev/sdb --dry-run

# Skip post-wipe verification read (faster, less rigorous)
sudo titan-wipe wipe --device /dev/sdb --skip-verify
```

---

## Audit Certificate

Example output:

```json
{
  "certificate_id": "A3F7B2C1-...",
  "timestamp_start": "2025-04-12T14:23:01Z",
  "timestamp_end": "2025-04-12T14:31:47Z",
  "device_path": "/dev/sdb",
  "model": "Samsung SSD 870 EVO 1TB",
  "serial": "S5YYNGF012345X",
  "firmware_rev": "SVT01B6Q",
  "size_bytes": 1000204886016,
  "drive_type": "SataSSD",
  "algorithm_used": "NIST SP 800-88 Rev.1 — ATA Secure Erase Purge",
  "passes_completed": 1,
  "pre_wipe_hash": "a3f9d2...c8e1",
  "post_wipe_hash": "0000000...0000",
  "verification_status": "NotApplicable",
  "status": "Success",
  "operator_note": ""
}
```

---

## Comparison with Legacy Tools

| Feature | titan-wipe | DBAN | shred | nwipe |
|---|---|---|---|---|
| NVMe Crypto Erase (correct) | ✅ | ❌ | ❌ | ❌ |
| ATA Secure Erase (full sequence) | ✅ | ❌ | ❌ | ✅ |
| Boot drive protection (dev numbers) | ✅ | ✅ | ❌ | ✅ |
| Active mount check (/proc/mounts) | ✅ | N/A | ❌ | ✅ |
| Pre+post BLAKE3 verification | ✅ | ❌ | ❌ | ❌ |
| Correct DoD 5220.22-M ECE 7-pass | ✅ | ✅ | ❌ | ✅ |
| Gutmann 35-pass | ✅ | ✅ | ✅ | ✅ |
| JSON audit certificate | ✅ | ❌ | ❌ | ❌ |
| Dry-run mode | ✅ | ❌ | ❌ | ❌ |
| Memory safe (Rust) | ✅ | ❌ | ❌ | ❌ |
| TRIM/BLKDISCARD after SSD wipe | ✅ | ❌ | ❌ | partial |

---
## FINAL CONCLUSION
NVMe Crypto Erase — no recovery possible. The controller destroys its internal media encryption key. Every cell on the physical NAND — including over-provisioned sectors, wear-leveling reserves, and bad-block remaps that are invisible to the host — stores only ciphertext with a key that no longer exists. There is nothing to recover, even with chip-off NAND forensics or an electron microscope. This is why NIST classifies it as Purge rather than Clear.
ATA Secure Erase (Enhanced) — effectively no recovery. Same story for the sectors the controller actually erases. Enhanced mode covers remapped and spare sectors. Normal mode may leave some controller-internal areas untouched, but host-addressable data is gone. No published forensic technique has recovered data from a properly completed ATA Secure Erase.
DoD 5220.22-M 7-pass and Gutmann 35-pass on an HDD — no practical recovery. The theoretical basis for multi-pass overwrite being necessary (residual magnetic signal on adjacent tracks) was compelling in the 1990s for older MFM/RLL drives with loose track tolerances. For any drive manufactured after roughly 2001, a single overwrite is sufficient — the track density is too high for residual signal recovery to work. Gutmann himself noted this in a 2001 postscript to his original paper. With 7 passes, recovery is not feasible by any currently known method, including professional forensic labs.
NIST Clear (single zero-pass) on an HDD — theoretically a very small risk. A single overwrite on a modern HDD is considered sufficient by NIST for non-classified data. However, it is the one case where a well-resourced adversary might attempt magnetic force microscopy on the platters after disassembly. No lab has demonstrated successful data recovery from a zero-overwritten modern drive publicly, but NIST doesn't certify it as Purge for this reason.
Single zero-pass on an SSD (without hardware erase) — partial recovery is possible. This is the case titan-wipe specifically avoids by detecting drive type and routing to hardware erase. If you ran a software zero-fill on an SSD (what shred does by default), the FTL has redirected your writes to new flash cells and the original cells are sitting in the over-provisioned pool, unmapped but not erased. With direct NAND chip access a forensic lab can read those cells.

Bottom line for titan-wipe specifically: if the hardware erase path ran correctly and the certificate shows Success, the data is gone. The pre/post BLAKE3 hashes in the certificate are your audit evidence that the device state changed. The one thing to watch is whether the drive actually completed the command — some cheap drives acknowledge an ATA Secure Erase immediately without doing the work. That's a firmware bug on the drive side, not something any software tool can fully guard against, which is why post-wipe verification exists.
---


## Platform Support

- **Linux** — full support (NVMe, ATA, block overwrite, BLKDISCARD)
- **macOS/Windows** — architecture designed for extension; OS backend is a separate module (`src/os_backend.rs`). PRs welcome.

---

## Disclaimer

This tool permanently and irreversibly destroys all data on target devices. The author is not responsible for data loss resulting from improper use. Always verify the target device before confirming the consent handshake. Test with `--dry-run` first.

---

## License

MIT
