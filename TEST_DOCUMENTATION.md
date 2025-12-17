# Quantum Origin + Metalvisor Integration Test Suite Documentation

## Overview

This test suite validates the integration of Quantum Origin (QO) with the Mainsail Metalvisor platform. It covers five key areas: entropy generation, cryptographic operations, storage encryption, network security, and virtualization capabilities.

**Purpose:** Verify that enabling Quantum Origin maintains or improves system security and cryptographic operations without introducing performance regressions.

---

## Section 4.1: System Entropy Source Tests

This section validates that the system's entropy sources are functioning correctly and that Quantum Origin is properly integrated as an entropy provider.

### TEST 4.1.1: /dev/random Availability

**What it tests:** Basic availability and accessibility of Linux random number generators.

**How it works:**
- Checks that `/dev/random` and `/dev/urandom` exist as character devices
- Verifies file permissions allow reading (typically mode 666)
- Reads kernel random configuration from `/proc/sys/kernel/random/`
- Attempts to read random bytes to confirm functionality

**Expected results:**
- Both devices exist and are readable
- `entropy_avail` should show available entropy (modern kernels show 256)
- `poolsize` typically 256 bits on modern kernels

**What to look for:**
- PASS: Devices exist, readable, entropy available
- FAIL: Missing devices or permission errors indicate serious system issues

---

### TEST 4.1.2: Entropy Pool Metrics

**What it tests:** Stability of the kernel entropy pool over time.

**How it works:**
- Samples `/proc/sys/kernel/random/entropy_avail` every second for 30 seconds
- Calculates minimum, maximum, and average entropy levels
- Verifies entropy never drops below critical threshold (128 bits)

**Expected results:**
- Modern Linux kernels (5.18+) with BLAKE2s CSPRNG maintain constant 256 bits
- Older kernels may show fluctuation but should stay above 128 bits
- With QO enabled, entropy should remain stable

**What to look for:**
- PASS: Entropy stable, never below 128 bits
- WARN: Entropy drops below 128 bits occasionally
- FAIL: Entropy consistently low, indicating entropy starvation

---

### TEST 4.1.3: Entropy Generation Rate

**What it tests:** Throughput of random number generation.

**How it works:**
- Times how long it takes to read various sizes from `/dev/urandom` (1KB to 1MB)
- Calculates throughput in MB/s for each size
- Also tests `/dev/random` read speed (256 bytes)

**Expected results:**
- `/dev/urandom`: 100-200+ MB/s for large reads on modern systems
- Smaller reads have higher overhead, lower effective throughput
- QO should not significantly impact throughput (within ±5%)

**What to look for:**
- Higher MB/s is better
- Large performance drops with QO may indicate integration issues
- Very low throughput (<10 MB/s) suggests system problems

---

### TEST 4.1.4: Entropy Syscall Trace

**What it tests:** How applications access randomness.

**How it works:**
- Uses `strace` to monitor a test process generating random data
- Looks for direct `/dev/random` or `/dev/urandom` access
- Notes if `getrandom()` syscall is used instead (preferred modern method)

**Expected results:**
- Modern applications use `getrandom()` syscall
- Direct device access is legacy but still valid
- Either method should work correctly

**What to look for:**
- INFO: Documents which method is used
- No action needed unless applications fail to get randomness

---

### TEST 4.1.5: Quantum Origin Detection

**What it tests:** Whether Quantum Origin is installed and active.

**How it works:**
- Checks for QO-related systemd services (`qo-kernel-reseed`, `qo-entropy`, etc.)
- Queries RPM database for installed QO packages
- Looks for QO configuration files and directories
- Checks kernel messages for QO-related output

**Expected results:**
- **Baseline mode:** No QO detected (expected)
- **QO mode:** QO package detected and/or service active

**What to look for:**
- PASS: QO detected when `QO_ENABLED=true`
- INFO: No QO in baseline mode
- WARN: QO expected but not detected

---

### TEST 4.1.6: FIPS 140-2 Statistical Tests (rngtest)

**What it tests:** Statistical quality of random number output.

**How it works:**
- Generates 2.5MB of random data from `/dev/urandom`
- Runs FIPS 140-2 statistical tests via `rngtest`:
  - Monobit test (equal 0s and 1s)
  - Poker test (uniform nibble distribution)
  - Runs test (appropriate run lengths)
  - Long runs test (no excessively long runs)
- Reports success/failure counts

**Expected results:**
- ~99%+ success rate (up to ~1% statistical failures is normal)
- Failure rate >1% may indicate RNG issues
- Both baseline and QO should have similar, high pass rates

**What to look for:**
- PASS: Failure rate <1%
- WARN: Failure rate 1-5%
- FAIL: Failure rate >5% indicates potential RNG weakness

---

### TEST 4.1.7: Entropy Under Load

**What it tests:** Entropy pool stability during heavy consumption.

**How it works:**
- Records initial entropy level
- Spawns multiple processes consuming random data simultaneously
- Monitors entropy pool during load
- Verifies pool recovers after load completes

**Expected results:**
- Entropy should remain above critical threshold (128 bits)
- Modern kernels maintain 256 bits even under load
- Pool should recover quickly after load stops

**What to look for:**
- PASS: Entropy stable under load
- WARN: Entropy drops significantly but recovers
- FAIL: Entropy exhaustion during load

---

### TEST 4.1.8: Kernel Entropy Sources

**What it tests:** Available hardware entropy sources in the system.

**How it works:**
- Checks for `/dev/hwrng` (hardware RNG device)
- Verifies `rngd` service status
- Checks CPU for RDRAND/RDSEED instruction support
- Looks for TPM device availability
- Examines sysfs for hardware RNG information

**Expected results:**
- Modern systems should have multiple entropy sources
- TPM, CPU RDRAND, and hardware RNG provide defense in depth
- More sources = better entropy quality assurance

**What to look for:**
- INFO: Documents available sources
- Having multiple sources is ideal
- Single source is acceptable but less robust

---

## Section 4.2: Cryptographic Key Generation Tests

This section validates that cryptographic key generation works correctly and efficiently with the system's entropy sources.

### TEST 4.2.1: RSA Key Generation

**What it tests:** RSA key pair generation at various key sizes.

**How it works:**
- Generates RSA keys at 2048, 3072, and 4096 bits using OpenSSL
- Times each generation operation
- Verifies generated keys are valid (correct bit length, proper structure)

**Expected results:**
- RSA-2048: ~0.03-0.1 seconds
- RSA-3072: ~0.1-0.3 seconds
- RSA-4096: ~0.3-1.0 seconds
- All keys should verify successfully

**What to look for:**
- PASS: All keys generated and verified
- Timing should be consistent between baseline and QO
- Large timing increases may indicate entropy bottlenecks

---

### TEST 4.2.2: ECDSA Key Generation

**What it tests:** Elliptic curve key generation.

**How it works:**
- Generates ECDSA keys for prime256v1 (P-256), secp384r1 (P-384), and secp521r1 (P-521)
- Verifies each key is valid

**Expected results:**
- All curves: ~0.005-0.01 seconds (much faster than RSA)
- All keys should verify successfully

**What to look for:**
- PASS: All keys generated correctly
- ECDSA is less entropy-intensive than RSA
- Should show minimal difference between baseline and QO

---

### TEST 4.2.3: Ed25519 Key Generation

**What it tests:** Modern Edwards curve key generation.

**How it works:**
- Generates Ed25519 signing keys
- Generates X25519 key exchange keys
- Verifies key structure

**Expected results:**
- Generation time: ~0.005 seconds
- Keys should be valid 32-byte values

**What to look for:**
- PASS: Both key types generated
- Ed25519 is highly efficient
- Minimal performance variation expected

---

### TEST 4.2.4: SSH Key Generation

**What it tests:** SSH key generation for common algorithms.

**How it works:**
- Uses `ssh-keygen` to generate RSA-4096, ECDSA-521, and Ed25519 keys
- Records generation time and fingerprint for each

**Expected results:**
- RSA-4096: ~0.1-0.5 seconds
- ECDSA/Ed25519: ~0.005 seconds
- All keys should have valid fingerprints

**What to look for:**
- PASS: All SSH keys generated with valid fingerprints
- Tests real-world key generation workflow

---

### TEST 4.2.5: X.509 Certificate Generation

**What it tests:** Full PKI certificate chain generation.

**How it works:**
- Creates a Certificate Authority (CA) with self-signed certificate
- Generates a server certificate signing request (CSR)
- Signs server certificate with CA
- Generates and signs client certificate
- Verifies complete certificate chain

**Expected results:**
- All certificates generated successfully
- Chain verification passes
- Demonstrates complete PKI workflow with system entropy

**What to look for:**
- PASS: Full chain created and verified
- FAIL: Certificate operations failed (entropy or OpenSSL issues)

---

### TEST 4.2.6: Key Uniqueness

**What it tests:** Ensures no key collisions occur.

**How it works:**
- Generates 100 random 256-bit keys rapidly
- Checks that all 100 keys are unique (no duplicates)

**Expected results:**
- 100% unique keys (100 out of 100)
- Any collision would indicate serious RNG failure

**What to look for:**
- PASS: All keys unique
- FAIL: Any duplicates indicate catastrophic RNG failure
- This is a critical security test

---

### TEST 4.2.7: AES Key Generation

**What it tests:** Symmetric key generation and usage.

**How it works:**
- Generates AES keys at 128, 192, and 256 bits
- Encrypts and decrypts test data with each key
- Verifies decryption matches original

**Expected results:**
- All key sizes generate correct byte lengths
- Encryption/decryption round-trip succeeds

**What to look for:**
- PASS: All AES operations successful
- Verifies entropy is suitable for symmetric cryptography

---

### TEST 4.2.8: Key Generation Performance

**What it tests:** Throughput of various cryptographic operations.

**How it works:**
- Runs multiple iterations of each key type generation
- Calculates operations per second for:
  - RSA-2048 and RSA-4096
  - ECDSA P-256 and P-384
  - Ed25519
  - Random bytes (32 and 256 bytes)

**Expected results:**
- RSA-2048: 10-30 ops/sec
- RSA-4096: 1-5 ops/sec
- ECDSA/Ed25519: 150-200 ops/sec
- Random bytes: 200+ ops/sec

**What to look for:**
- Higher ops/sec is better
- QO should maintain similar performance to baseline
- >10% degradation may warrant investigation

---

### TEST 4.2.9: Post-Quantum Key Generation

**What it tests:** Availability of post-quantum cryptographic algorithms.

**How it works:**
- Checks for OQS (Open Quantum Safe) provider in OpenSSL
- If available, tests ML-KEM (Kyber) and ML-DSA (Dilithium) key generation

**Expected results:**
- INFO if OQS not installed (common)
- PASS if PQC algorithms available and working

**What to look for:**
- INFO: PQC not available (acceptable for most deployments)
- PASS: PQC working (future-proofed configuration)

---

### TEST 4.2.10: LUKS Key Derivation

**What it tests:** Disk encryption key derivation.

**How it works:**
- Creates a test file and formats it as LUKS2 container
- Uses system entropy for key generation
- Verifies LUKS header and PBKDF settings

**Expected results:**
- LUKS2 format succeeds
- Argon2id PBKDF used (recommended over PBKDF2)
- Key derivation completes without entropy issues

**What to look for:**
- PASS: LUKS container created successfully
- Verifies entropy is suitable for disk encryption

---

## Section 4.3: Storage Encryption Tests

This section validates storage encryption performance and functionality.

### TEST 4.3.1: dm-crypt Encryption Performance

**What it tests:** Raw encryption throughput for disk encryption.

**How it works:**
- Tests AES-XTS encryption at 256 and 512-bit key sizes
- Uses OpenSSL speed tests to measure throughput
- Checks dm-crypt kernel module status

**Expected results:**
- AES-XTS-256: 500-600+ MB/s on modern CPUs with AES-NI
- AES-XTS-512: Similar performance
- Performance depends on CPU AES acceleration

**What to look for:**
- Higher MB/s is better
- Should see similar performance baseline vs QO
- Low performance may indicate missing AES-NI

---

### TEST 4.3.2: LUKS Operations

**What it tests:** Full LUKS container creation performance.

**How it works:**
- Creates LUKS1 format container (legacy compatibility)
- Creates LUKS2 format container (modern, with Argon2)
- Times each format operation
- Verifies cipher and PBKDF settings

**Expected results:**
- LUKS1: ~3-5 seconds (uses PBKDF2)
- LUKS2: ~5-10 seconds (uses Argon2, more secure but slower)
- Both should complete successfully

**What to look for:**
- PASS: Both formats succeed
- Lower format time is better, but security tradeoffs exist
- Argon2 is preferred over PBKDF2

---

### TEST 4.3.3: Encrypted File Operations

**What it tests:** File encryption/decryption throughput.

**How it works:**
- Encrypts and decrypts files of 1MB, 10MB, and 100MB
- Tests AES-256-CBC cipher
- Calculates throughput for each operation

**Expected results:**
- Encryption: 100-600 MB/s depending on file size
- Decryption: Often faster than encryption (100-1000+ MB/s)
- Larger files show better throughput (less overhead)

**What to look for:**
- Higher MB/s is better
- Decryption typically faster than encryption
- Performance scales with file size

---

### TEST 4.3.4: FIO Encrypted Performance

**What it tests:** Realistic storage I/O performance.

**How it works:**
- Uses `fio` (Flexible I/O Tester) for benchmarking
- Tests sequential write and read (1MB blocks)
- Tests random 4K read and write IOPS

**Expected results:**
- Sequential: Hundreds to thousands of MB/s (depends on storage)
- Random 4K: Tens of thousands of IOPS on SSDs

**What to look for:**
- Higher values are better
- Baseline vs QO should be similar
- Tests real-world storage patterns

---

### TEST 4.3.5: Encrypted Backup/Restore

**What it tests:** Backup encryption workflow integrity.

**How it works:**
- Creates test data and generates encrypted backup (tar + openssl)
- Restores backup and verifies integrity via checksum

**Expected results:**
- Backup creation: sub-second for small test data
- Restore and verification: successful integrity check

**What to look for:**
- PASS: Integrity verification matches
- FAIL: Data corruption during encrypt/decrypt cycle

---

### TEST 4.3.6: GPG Encryption

**What it tests:** GPG symmetric encryption functionality.

**How it works:**
- Encrypts test file with GPG symmetric cipher
- Decrypts and verifies content matches original

**Expected results:**
- Encryption and decryption succeed
- Content integrity verified

**What to look for:**
- PASS: GPG operations successful
- Tests common encryption tool with system entropy

---

### TEST 4.3.7: eCryptfs/fscrypt

**What it tests:** Filesystem-level encryption availability.

**How it works:**
- Checks for eCryptfs tools and kernel module
- Checks for fscrypt utility

**Expected results:**
- INFO: Reports which filesystem encryption is available
- At least one method should be available on modern systems

**What to look for:**
- INFO: Documents available options
- Not a pass/fail test, just capability detection

---

## Section 4.4: Network Security Tests

This section validates TLS/SSL and network security functionality.

### TEST 4.4.1: OpenSSL TLS Capabilities

**What it tests:** Available TLS protocols and ciphers.

**How it works:**
- Queries OpenSSL version
- Lists supported TLS protocol versions
- Counts available cipher suites for TLS 1.2 and 1.3

**Expected results:**
- TLS 1.2 and 1.3 supported
- TLS 1.3 ciphersuites: 4-5 (AES-GCM, ChaCha20)
- TLS 1.2 ciphers: 100+ options

**What to look for:**
- PASS: TLS 1.3 with AEAD ciphers available
- Modern security requires TLS 1.2+ support

---

### TEST 4.4.2: TLS 1.3 Connection

**What it tests:** Actual TLS 1.3 handshake functionality.

**How it works:**
- Starts local OpenSSL TLS 1.3 server
- Connects with client and performs handshake
- Verifies TLS 1.3 protocol negotiated

**Expected results:**
- TLS 1.3 connection established
- Strong cipher selected (AES-256-GCM-SHA384)

**What to look for:**
- PASS: TLS 1.3 works end-to-end
- Verifies entropy sufficient for key exchange

---

### TEST 4.4.3: TLS Handshake Performance

**What it tests:** TLS handshake throughput.

**How it works:**
- Performs 20 TLS handshakes with local server
- Measures average handshake time
- Calculates handshakes per second

**Expected results:**
- Handshake time: ~10ms (0.01s)
- Throughput: 80-100+ handshakes/sec

**What to look for:**
- Lower handshake time is better
- Higher handshakes/sec is better
- QO should not significantly impact TLS performance

---

### TEST 4.4.4: SSH Key Exchange

**What it tests:** SSH cryptographic capabilities.

**How it works:**
- Queries SSH version and supported algorithms
- Lists key exchange algorithms (including post-quantum hybrids)
- Lists supported ciphers and MACs

**Expected results:**
- curve25519-sha256 available (preferred)
- AES-GCM and ChaCha20-Poly1305 ciphers
- 15+ key exchange algorithms on modern OpenSSH

**What to look for:**
- PASS: Modern algorithms available
- Post-quantum hybrid KEX is a bonus

---

### TEST 4.4.5: Certificate Validation

**What it tests:** X.509 certificate chain verification.

**How it works:**
- Creates test CA and certificates
- Verifies server certificate against CA
- Verifies client certificate against CA

**Expected results:**
- All certificate verifications pass
- Chain of trust intact

**What to look for:**
- PASS: Certificate chain verification works
- Tests PKI operations with system entropy

---

### TEST 4.4.6: WireGuard

**What it tests:** WireGuard VPN key generation.

**How it works:**
- Checks WireGuard tools availability
- Generates private key
- Derives public key from private key

**Expected results:**
- Private key: 45 bytes (base64)
- Public key: 45 bytes (base64)
- Keys generated successfully

**What to look for:**
- INFO/PASS: WireGuard key generation works
- Kernel module may not be loaded (normal on host)

---

### TEST 4.4.7: Post-Quantum TLS

**What it tests:** PQC TLS capability.

**How it works:**
- Checks for OQS provider
- Tests hybrid key exchange support

**Expected results:**
- INFO if OQS not available (common)
- PASS if PQC TLS working

**What to look for:**
- INFO: Standard configuration
- PASS: Advanced PQC-ready configuration

---

### TEST 4.4.8: External TLS Connections

**What it tests:** Real-world TLS to external servers.

**How it works:**
- Connects to google.com, github.com, cloudflare.com
- Verifies TLS connection succeeds

**Expected results:**
- All connections successful
- Modern TLS negotiated with each

**What to look for:**
- PASS: External TLS works
- FAIL: Network or TLS stack issues

---

### TEST 4.4.9: Session Key Randomness

**What it tests:** TLS session key uniqueness.

**How it works:**
- Captures TLS key log during multiple connections
- Analyzes handshake secrets
- Verifies all session keys are unique

**Expected results:**
- 10 sessions = 10 unique keys
- No key reuse between sessions

**What to look for:**
- PASS: All session keys unique
- FAIL: Key reuse indicates serious RNG problem

---

## Section 4.5: Virtual Machine Operations Tests

This section validates virtualization capabilities and entropy propagation to VMs.

### TEST 4.5.1: Virtualization Capabilities

**What it tests:** Hardware virtualization support.

**How it works:**
- Checks CPU flags for VT-x (Intel) or AMD-V
- Checks for nested virtualization support
- Verifies KVM kernel module status
- Checks for IOMMU support

**Expected results:**
- VT-x or AMD-V supported
- KVM module loaded (or loadable)
- Nested virtualization enabled (optional)

**What to look for:**
- PASS: KVM available and loaded
- WARN: KVM not loaded (load with `modprobe kvm_intel`)
- INFO: Documents available features

---

### TEST 4.5.2: Confidential Computing

**What it tests:** Hardware security extensions.

**How it works:**
- Checks for Intel TDX (Trust Domain Extensions)
- Checks for AMD SEV (Secure Encrypted Virtualization)

**Expected results:**
- INFO: Reports available features
- These are advanced features not present on all hardware

**What to look for:**
- INFO: Documents capabilities
- TDX/SEV enable encrypted VM memory

---

### TEST 4.5.3: libvirt/QEMU

**What it tests:** Virtualization stack availability.

**How it works:**
- Verifies QEMU and virsh are installed
- Checks libvirtd service status
- Lists running VMs
- Checks virtio module status

**Expected results:**
- QEMU and virsh available
- libvirtd service active
- virtio modules available (may not be loaded on host)

**What to look for:**
- PASS: Virtualization stack operational
- Required for running VMs with good entropy

---

### TEST 4.5.4: virtio-rng

**What it tests:** VM random number generator passthrough.

**How it works:**
- Checks virtio_rng module status
- Lists available hardware RNG devices
- Verifies rngd service status
- Documents how to configure virtio-rng for VMs

**Expected results:**
- Hardware RNG available (TPM, CPU, or dedicated)
- rngd service active
- virtio_rng available for VM use

**What to look for:**
- INFO: Documents RNG configuration
- Critical for providing entropy to VMs

---

### TEST 4.5.5: Container Runtime

**What it tests:** Container platform availability.

**How it works:**
- Checks for Podman and Docker
- Verifies OCI runtime (crun/runc)
- Reports storage driver configuration

**Expected results:**
- Podman or Docker available
- Modern OCI runtime (crun preferred)

**What to look for:**
- PASS: Container runtime operational
- Containers share host entropy via `/dev/urandom`

---

### TEST 4.5.6: Memory Encryption

**What it tests:** Hardware memory encryption.

**How it works:**
- Checks for AMD SME (Secure Memory Encryption) CPU flag
- Checks kernel command line for `mem_encrypt=on`

**Expected results:**
- SME flag present on AMD EPYC/Ryzen Pro
- mem_encrypt=on in kernel cmdline enables it

**What to look for:**
- INFO: Documents memory encryption status
- Protects against physical memory attacks

---

### TEST 4.5.7: VM Image Encryption

**What it tests:** Encrypted VM disk image creation.

**How it works:**
- Creates standard qcow2 test image
- Creates LUKS-encrypted qcow2 image
- Verifies encryption is applied

**Expected results:**
- Both images created successfully
- Encrypted image shows LUKS encryption in metadata

**What to look for:**
- PASS: Encrypted VM images can be created
- Important for VM data-at-rest security

---

### TEST 4.5.8: Namespace Isolation

**What it tests:** Linux namespace support for containers.

**How it works:**
- Checks for all namespace types in kernel
- Verifies user namespace limits

**Expected results:**
- All namespace types supported:
  - cgroup, ipc, mnt, net, pid, time, user, uts
- High user namespace limit (1M+)

**What to look for:**
- PASS: Full namespace support
- Required for secure container isolation

---

## Interpreting Results

### Pass Rates

- **100% PASS:** Ideal configuration
- **>95% PASS:** Good, investigate any failures
- **<95% PASS:** Issues requiring attention

### Performance Comparison (Baseline vs QO)

| Change | Interpretation |
|--------|----------------|
| ±2% | Within noise, no real difference |
| ±2-5% | Minor variation, likely acceptable |
| ±5-10% | Notable change, investigate if regression |
| >10% | Significant change, requires investigation |

### Critical Tests

These tests must PASS for a secure configuration:

1. **Key Uniqueness (4.2.6)** - Any failure indicates RNG catastrophe
2. **FIPS Statistical Tests (4.1.6)** - High failure rate indicates weak RNG
3. **Session Key Randomness (4.4.9)** - Failures indicate TLS vulnerability
4. **Entropy Pool Metrics (4.1.2)** - Persistent low entropy is dangerous

### Acceptable INFO/WARN

These are typically acceptable:

- **PQC not available** - Optional, not widely deployed yet
- **KVM not loaded** - Load on demand when needed
- **WireGuard module not loaded** - Tools available, module loads when used
- **virtio modules not loaded** - Normal on host systems

---

## Recommendations

### Before Deployment

1. Run baseline tests without QO
2. Enable QO and run tests again
3. Compare results using `compare_results.sh`
4. Investigate any >5% performance regressions
5. Verify all critical tests pass in both configurations

### Monitoring

- Run tests periodically to detect drift
- Monitor entropy_avail in production
- Alert on FIPS test failure rates >1%

### Troubleshooting

| Symptom | Possible Cause | Resolution |
|---------|----------------|------------|
| Low entropy | rngd not running | `systemctl start rngd` |
| Slow key generation | Entropy starvation | Check entropy sources |
| FIPS failures >5% | RNG issues | Investigate hardware RNG |
| TLS handshake slow | Entropy bottleneck | Add entropy sources |

---

*Document Version: 1.0*
*Last Updated: December 2025*
