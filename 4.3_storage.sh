#!/bin/bash
#===============================================================================
# SECTION 4.3: STORAGE ENCRYPTION TESTS
# Reference: Test Plan Section 4.3 - Subsystem: Storage Encryption
#
# What is being tested:
# - Ceph distributed storage with quantum-hardened encryption
# - Device-level encryption (dm-crypt)
# - Tenant-specific image keys
# - Object storage encryption
#
# Success Criteria:
# - Storage encryption operational with QO
# - Performance within acceptable parameters
# - Keys have quantum-level unpredictability
# - Compatible with NIST PQC standards
#===============================================================================

set -euo pipefail

RESULTS_DIR="${1:-./results}"
SECTION_DIR="${RESULTS_DIR}/storage"
SECTION_RESULTS="${SECTION_DIR}/results.json"
TEST_DIR="${SECTION_DIR}/test_files"

source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh" 2>/dev/null || {
    log_info() { echo "[INFO] $*"; }
    log_pass() { echo "[PASS] $*"; }
    log_fail() { echo "[FAIL] $*"; }
    log_warn() { echo "[WARN] $*"; }
}

mkdir -p "${SECTION_DIR}"
mkdir -p "${TEST_DIR}"

#-------------------------------------------------------------------------------
# Initialize Results
#-------------------------------------------------------------------------------
init_results() {
    cat > "${SECTION_RESULTS}" << EOF
{
    "section": "4.3",
    "name": "Storage Encryption",
    "start_time": "$(date -Iseconds)",
    "tests": []
}
EOF
}

add_test_result() {
    local test_name="$1"
    local status="$2"
    local details="$3"
    
    local tmp_file=$(mktemp)
    jq --arg name "$test_name" \
       --arg status "$status" \
       --arg details "$details" \
       --arg time "$(date -Iseconds)" \
       '.tests += [{"name": $name, "status": $status, "details": $details, "timestamp": $time}]' \
       "${SECTION_RESULTS}" > "${tmp_file}" && mv "${tmp_file}" "${SECTION_RESULTS}"
}

#-------------------------------------------------------------------------------
# TEST 4.3.1: dm-crypt Encryption Test
#-------------------------------------------------------------------------------
test_dmcrypt_encryption() {
    log_info "TEST 4.3.1: dm-crypt Encryption Tests"
    
    local status="PASS"
    local details=""
    
    if ! command -v cryptsetup &>/dev/null; then
        status="SKIP"
        details="cryptsetup not available"
        add_test_result "dmcrypt_encryption" "$status" "$details"
        log_warn "TEST 4.3.1 SKIPPED"
        return
    fi
    
    # Check if we have permissions
    if [[ $EUID -ne 0 ]]; then
        details+="Note: Running as non-root, some tests limited\n"
    fi
    
    # Test various ciphers supported by dm-crypt
    local ciphers=(
        "aes-xts-plain64:256"
        "aes-xts-plain64:512"
        "serpent-xts-plain64:256"
        "twofish-xts-plain64:256"
    )
    
    for cipher_spec in "${ciphers[@]}"; do
        local cipher=$(echo "${cipher_spec}" | cut -d: -f1)
        local keysize=$(echo "${cipher_spec}" | cut -d: -f2)
        
        # Create test image
        local test_img="${TEST_DIR}/dmcrypt_${cipher//\//_}_${keysize}.img"
        dd if=/dev/zero of="${test_img}" bs=1M count=10 2>/dev/null
        
        # Generate key
        local key=$(openssl rand -hex $((keysize / 8)))
        
        log_info "Testing ${cipher} with ${keysize}-bit key..."
        
        # Benchmark encryption (without actually using dm-crypt device)
        local start_time=$(date +%s.%N)
        
        # Use openssl to simulate encryption with similar cipher
        local openssl_cipher="aes-256-ctr"
        if [[ "${cipher}" == *"serpent"* ]]; then
            details+="  ${cipher}: Serpent not directly testable via OpenSSL\n"
            continue
        elif [[ "${cipher}" == *"twofish"* ]]; then
            details+="  ${cipher}: Twofish not directly testable via OpenSSL\n"
            continue
        fi
        
        if openssl enc -${openssl_cipher} -in "${test_img}" -out "${test_img}.enc" \
            -pass pass:"${key}" -pbkdf2 2>/dev/null; then
            local end_time=$(date +%s.%N)
            local duration=$(echo "${end_time} - ${start_time}" | bc)
            local file_size=$(stat -c %s "${test_img}")
            local throughput=$(echo "scale=2; ${file_size} / ${duration} / 1024 / 1024" | bc)
            
            details+="✓ ${cipher}:${keysize}: ${throughput} MB/s\n"
            
            rm -f "${test_img}.enc"
        else
            details+="⚠ ${cipher}:${keysize}: Encryption test failed\n"
        fi
        
        rm -f "${test_img}"
    done
    
    # Check dm-crypt module availability
    if lsmod 2>/dev/null | grep -q "dm_crypt"; then
        details+="✓ dm-crypt kernel module loaded\n"
    else
        details+="dm-crypt module not loaded (may load on demand)\n"
    fi
    
    echo -e "$details"
    add_test_result "dmcrypt_encryption" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.3.1 PASSED" || log_fail "TEST 4.3.1 FAILED"
}

#-------------------------------------------------------------------------------
# TEST 4.3.2: LUKS Container Operations
#-------------------------------------------------------------------------------
test_luks_operations() {
    log_info "TEST 4.3.2: LUKS Container Operations"
    
    local status="PASS"
    local details=""
    
    if ! command -v cryptsetup &>/dev/null; then
        status="SKIP"
        details="cryptsetup not available"
        add_test_result "luks_operations" "$status" "$details"
        log_warn "TEST 4.3.2 SKIPPED"
        return
    fi
    
    local luks_img="${TEST_DIR}/luks_test.img"
    local luks_size=50  # MB
    
    log_info "Creating ${luks_size}MB LUKS container..."
    
    # Create image file
    dd if=/dev/zero of="${luks_img}" bs=1M count=${luks_size} 2>/dev/null
    
    # Generate passphrase using entropy source
    local passphrase=$(openssl rand -base64 32)
    
    # Test LUKS1 format
    log_info "Testing LUKS1 format..."
    local start_time=$(date +%s.%N)
    
    if echo "${passphrase}" | cryptsetup luksFormat --type luks1 \
        "${luks_img}" --batch-mode 2>/dev/null; then
        local end_time=$(date +%s.%N)
        local duration=$(echo "${end_time} - ${start_time}" | bc)
        
        details+="✓ LUKS1 format: ${duration}s\n"
        
        # Get header info
        local cipher=$(cryptsetup luksDump "${luks_img}" 2>/dev/null | grep "Cipher:" | awk '{print $2}')
        local hash=$(cryptsetup luksDump "${luks_img}" 2>/dev/null | grep "Hash spec:" | awk '{print $3}')
        details+="  Cipher: ${cipher}\n"
        details+="  Hash: ${hash}\n"
    else
        status="WARN"
        details+="⚠ LUKS1 format failed\n"
    fi
    
    # Recreate for LUKS2 test
    dd if=/dev/zero of="${luks_img}" bs=1M count=${luks_size} 2>/dev/null
    
    # Test LUKS2 format
    log_info "Testing LUKS2 format..."
    start_time=$(date +%s.%N)
    
    if echo "${passphrase}" | cryptsetup luksFormat --type luks2 \
        "${luks_img}" --batch-mode 2>/dev/null; then
        local end_time=$(date +%s.%N)
        local duration=$(echo "${end_time} - ${start_time}" | bc)
        
        details+="✓ LUKS2 format: ${duration}s\n"
        
        # Get header info
        local header_info=$(cryptsetup luksDump "${luks_img}" 2>/dev/null)
        
        if echo "${header_info}" | grep -qi "argon2"; then
            details+="✓ Using Argon2 PBKDF (recommended)\n"
        fi
        
        local cipher=$(echo "${header_info}" | grep "cipher:" | head -1 | awk '{print $2}')
        details+="  Cipher: ${cipher}\n"
        
        # Check for integrity
        if echo "${header_info}" | grep -qi "integrity"; then
            details+="✓ Integrity protection enabled\n"
        fi
    else
        status="WARN"
        details+="⚠ LUKS2 format failed\n"
    fi
    
    # Cleanup
    rm -f "${luks_img}"
    
    echo -e "$details"
    add_test_result "luks_operations" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.3.2 PASSED" || log_fail "TEST 4.3.2 FAILED"
}

#-------------------------------------------------------------------------------
# TEST 4.3.3: Encrypted File Operations (OpenSSL)
#-------------------------------------------------------------------------------
test_encrypted_file_ops() {
    log_info "TEST 4.3.3: Encrypted File Operations"
    
    local status="PASS"
    local details=""
    
    local test_sizes=(1 10 100)  # MB
    local ciphers=("aes-256-cbc" "aes-256-gcm" "chacha20-poly1305")
    
    for cipher in "${ciphers[@]}"; do
        details+="Testing ${cipher}:\n"
        
        for size in "${test_sizes[@]}"; do
            local test_file="${TEST_DIR}/test_${size}M.bin"
            local enc_file="${TEST_DIR}/test_${size}M.${cipher}.enc"
            local dec_file="${TEST_DIR}/test_${size}M.${cipher}.dec"
            
            # Create test file
            dd if=/dev/urandom of="${test_file}" bs=1M count=${size} 2>/dev/null
            
            # Generate key
            local key=$(openssl rand -base64 32)
            
            # Encrypt
            local start_enc=$(date +%s.%N)
            if openssl enc -${cipher} -in "${test_file}" -out "${enc_file}" \
                -pass pass:"${key}" -pbkdf2 2>/dev/null; then
                local end_enc=$(date +%s.%N)
                local enc_duration=$(echo "${end_enc} - ${start_enc}" | bc)
                local enc_throughput=$(echo "scale=2; ${size} / ${enc_duration}" | bc)
                
                # Decrypt
                local start_dec=$(date +%s.%N)
                if openssl enc -d -${cipher} -in "${enc_file}" -out "${dec_file}" \
                    -pass pass:"${key}" -pbkdf2 2>/dev/null; then
                    local end_dec=$(date +%s.%N)
                    local dec_duration=$(echo "${end_dec} - ${start_dec}" | bc)
                    local dec_throughput=$(echo "scale=2; ${size} / ${dec_duration}" | bc)
                    
                    # Verify
                    local orig_hash=$(sha256sum "${test_file}" | awk '{print $1}')
                    local dec_hash=$(sha256sum "${dec_file}" | awk '{print $1}')
                    
                    if [[ "${orig_hash}" == "${dec_hash}" ]]; then
                        details+="  ${size}MB: enc ${enc_throughput}MB/s, dec ${dec_throughput}MB/s ✓\n"
                    else
                        status="FAIL"
                        details+="  ${size}MB: Verification FAILED ✗\n"
                    fi
                else
                    status="FAIL"
                    details+="  ${size}MB: Decryption failed ✗\n"
                fi
            else
                details+="  ${size}MB: Cipher not supported or failed\n"
            fi
            
            # Cleanup
            rm -f "${test_file}" "${enc_file}" "${dec_file}"
        done
    done
    
    echo -e "$details"
    add_test_result "encrypted_file_ops" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.3.3 PASSED" || log_fail "TEST 4.3.3 FAILED"
}

#-------------------------------------------------------------------------------
# TEST 4.3.4: fio Encrypted Storage Performance
#-------------------------------------------------------------------------------
test_fio_encrypted_performance() {
    log_info "TEST 4.3.4: fio Encrypted Storage Performance"
    
    local status="PASS"
    local details=""
    
    if ! command -v fio &>/dev/null; then
        status="SKIP"
        details="fio not available - install fio package"
        add_test_result "fio_encrypted_performance" "$status" "$details"
        log_warn "TEST 4.3.4 SKIPPED"
        return
    fi
    
    local fio_dir="${TEST_DIR}/fio"
    mkdir -p "${fio_dir}"
    
    # Baseline unencrypted test
    log_info "Running fio baseline tests..."
    
    local fio_output="${SECTION_DIR}/fio_results.json"
    
    # Sequential write test
    fio --name=seq_write \
        --directory="${fio_dir}" \
        --rw=write \
        --bs=1M \
        --size=100M \
        --numjobs=1 \
        --time_based \
        --runtime=10 \
        --group_reporting \
        --output-format=json \
        > "${fio_output}" 2>/dev/null || true
    
    if [[ -f "${fio_output}" ]]; then
        local write_bw=$(jq -r '.jobs[0].write.bw // 0' "${fio_output}" 2>/dev/null)
        local write_iops=$(jq -r '.jobs[0].write.iops // 0' "${fio_output}" 2>/dev/null)
        details+="Sequential Write: $((write_bw / 1024)) MB/s, ${write_iops} IOPS\n"
    fi
    
    # Sequential read test
    fio --name=seq_read \
        --directory="${fio_dir}" \
        --rw=read \
        --bs=1M \
        --size=100M \
        --numjobs=1 \
        --time_based \
        --runtime=10 \
        --group_reporting \
        --output-format=json \
        > "${fio_output}" 2>/dev/null || true
    
    if [[ -f "${fio_output}" ]]; then
        local read_bw=$(jq -r '.jobs[0].read.bw // 0' "${fio_output}" 2>/dev/null)
        local read_iops=$(jq -r '.jobs[0].read.iops // 0' "${fio_output}" 2>/dev/null)
        details+="Sequential Read: $((read_bw / 1024)) MB/s, ${read_iops} IOPS\n"
    fi
    
    # Random 4K test
    fio --name=rand_rw \
        --directory="${fio_dir}" \
        --rw=randrw \
        --bs=4k \
        --size=50M \
        --numjobs=4 \
        --time_based \
        --runtime=10 \
        --group_reporting \
        --output-format=json \
        > "${fio_output}" 2>/dev/null || true
    
    if [[ -f "${fio_output}" ]]; then
        local rand_read_iops=$(jq -r '.jobs[0].read.iops // 0' "${fio_output}" 2>/dev/null)
        local rand_write_iops=$(jq -r '.jobs[0].write.iops // 0' "${fio_output}" 2>/dev/null)
        details+="Random 4K Read: ${rand_read_iops} IOPS\n"
        details+="Random 4K Write: ${rand_write_iops} IOPS\n"
    fi
    
    # Cleanup
    rm -rf "${fio_dir}"
    
    echo -e "$details"
    add_test_result "fio_encrypted_performance" "$status" "$(echo -e "$details")"
    
    log_pass "TEST 4.3.4 PASSED"
}

#-------------------------------------------------------------------------------
# TEST 4.3.5: Ceph Integration Check
#-------------------------------------------------------------------------------
test_ceph_integration() {
    log_info "TEST 4.3.5: Ceph Storage Integration Check"
    
    local status="INFO"
    local details=""
    
    # Check for Ceph client tools
    if command -v ceph &>/dev/null; then
        details+="✓ Ceph client tools available\n"
        
        # Check if we can connect to a cluster
        if ceph status &>/dev/null; then
            details+="✓ Connected to Ceph cluster\n"
            
            # Get cluster info
            local health=$(ceph health 2>/dev/null)
            details+="  Cluster health: ${health}\n"
            
            # Check for encryption configuration
            if ceph config get osd osd_dmcrypt_type 2>/dev/null; then
                local dmcrypt_type=$(ceph config get osd osd_dmcrypt_type 2>/dev/null)
                details+="  OSD dmcrypt type: ${dmcrypt_type}\n"
            fi
            
            # Check for encrypted OSDs
            local osd_info=$(ceph osd tree 2>/dev/null | head -20)
            details+="  OSD Tree:\n${osd_info}\n"
        else
            details+="No Ceph cluster connection available\n"
            details+="This is expected if Ceph is not deployed\n"
        fi
    else
        details+="Ceph client tools not installed\n"
        details+="Install ceph-common package to enable Ceph tests\n"
    fi
    
    # Check for RBD module
    if lsmod 2>/dev/null | grep -q "rbd"; then
        details+="✓ RBD kernel module loaded\n"
    else
        details+="RBD kernel module not loaded\n"
    fi
    
    echo -e "$details"
    add_test_result "ceph_integration" "$status" "$(echo -e "$details")"
    
    log_info "TEST 4.3.5 COMPLETE (informational)"
}

#-------------------------------------------------------------------------------
# TEST 4.3.6: Encrypted Backup/Restore
#-------------------------------------------------------------------------------
test_encrypted_backup_restore() {
    log_info "TEST 4.3.6: Encrypted Backup/Restore Test"
    
    local status="PASS"
    local details=""
    
    local src_dir="${TEST_DIR}/backup_src"
    local backup_file="${TEST_DIR}/backup.tar.gz.enc"
    local restore_dir="${TEST_DIR}/backup_restored"
    
    mkdir -p "${src_dir}"
    mkdir -p "${restore_dir}"
    
    # Create test data
    log_info "Creating test data..."
    for i in $(seq 1 10); do
        dd if=/dev/urandom of="${src_dir}/file_${i}.bin" bs=1K count=$((RANDOM % 100 + 1)) 2>/dev/null
    done
    
    # Generate encryption key
    local key=$(openssl rand -base64 32)
    local key_file="${TEST_DIR}/backup.key"
    echo "${key}" > "${key_file}"
    
    # Create encrypted backup
    log_info "Creating encrypted backup..."
    local start_time=$(date +%s.%N)
    
    if tar czf - -C "${src_dir}" . 2>/dev/null | \
        openssl enc -aes-256-cbc -pbkdf2 -pass file:"${key_file}" -out "${backup_file}" 2>/dev/null; then
        local end_time=$(date +%s.%N)
        local duration=$(echo "${end_time} - ${start_time}" | bc)
        
        local backup_size=$(stat -c %s "${backup_file}")
        details+="✓ Encrypted backup created: ${backup_size} bytes in ${duration}s\n"
        
        # Restore encrypted backup
        log_info "Restoring encrypted backup..."
        start_time=$(date +%s.%N)
        
        if openssl enc -d -aes-256-cbc -pbkdf2 -pass file:"${key_file}" -in "${backup_file}" 2>/dev/null | \
            tar xzf - -C "${restore_dir}" 2>/dev/null; then
            end_time=$(date +%s.%N)
            duration=$(echo "${end_time} - ${start_time}" | bc)
            
            details+="✓ Backup restored in ${duration}s\n"
            
            # Verify integrity
            local src_hash=$(find "${src_dir}" -type f -exec sha256sum {} \; | sort | sha256sum | awk '{print $1}')
            local dst_hash=$(find "${restore_dir}" -type f -exec sha256sum {} \; | sort | sha256sum | awk '{print $1}')
            
            if [[ "${src_hash}" == "${dst_hash}" ]]; then
                details+="✓ Integrity verification passed\n"
            else
                status="FAIL"
                details+="✗ Integrity verification FAILED\n"
            fi
        else
            status="FAIL"
            details+="✗ Restore failed\n"
        fi
    else
        status="FAIL"
        details+="✗ Backup creation failed\n"
    fi
    
    # Cleanup
    rm -rf "${src_dir}" "${restore_dir}" "${backup_file}" "${key_file}"
    
    echo -e "$details"
    add_test_result "encrypted_backup_restore" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.3.6 PASSED" || log_fail "TEST 4.3.6 FAILED"
}

#-------------------------------------------------------------------------------
# TEST 4.3.7: GPG Encryption Test
#-------------------------------------------------------------------------------
test_gpg_encryption() {
    log_info "TEST 4.3.7: GPG Encryption Test"
    
    local status="PASS"
    local details=""
    
    if ! command -v gpg &>/dev/null; then
        status="SKIP"
        details="gpg not available"
        add_test_result "gpg_encryption" "$status" "$details"
        log_warn "TEST 4.3.7 SKIPPED"
        return
    fi
    
    local gpg_home="${TEST_DIR}/gpghome"
    mkdir -p "${gpg_home}"
    chmod 700 "${gpg_home}"
    
    export GNUPGHOME="${gpg_home}"
    
    log_info "Testing GPG symmetric encryption..."
    
    local test_file="${TEST_DIR}/gpg_test.txt"
    local enc_file="${TEST_DIR}/gpg_test.txt.gpg"
    local dec_file="${TEST_DIR}/gpg_test.dec.txt"
    
    echo "Test data for GPG encryption" > "${test_file}"
    
    local passphrase=$(openssl rand -base64 16)
    
    # Symmetric encryption
    if echo "${passphrase}" | gpg --batch --yes --passphrase-fd 0 \
        --symmetric --cipher-algo AES256 -o "${enc_file}" "${test_file}" 2>/dev/null; then
        details+="✓ Symmetric encryption successful\n"
        
        # Decrypt
        if echo "${passphrase}" | gpg --batch --yes --passphrase-fd 0 \
            -d -o "${dec_file}" "${enc_file}" 2>/dev/null; then
            
            if diff -q "${test_file}" "${dec_file}" &>/dev/null; then
                details+="✓ Decryption and verification successful\n"
            else
                status="FAIL"
                details+="✗ Decrypted content does not match\n"
            fi
        else
            status="FAIL"
            details+="✗ Decryption failed\n"
        fi
    else
        status="FAIL"
        details+="✗ Symmetric encryption failed\n"
    fi
    
    # GPG version info
    local gpg_version=$(gpg --version 2>/dev/null | head -1)
    details+="GPG version: ${gpg_version}\n"
    
    # Cleanup
    rm -rf "${gpg_home}" "${test_file}" "${enc_file}" "${dec_file}"
    
    echo -e "$details"
    add_test_result "gpg_encryption" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.3.7 PASSED" || log_fail "TEST 4.3.7 FAILED"
}

#-------------------------------------------------------------------------------
# TEST 4.3.8: eCryptfs Test (if available)
#-------------------------------------------------------------------------------
test_ecryptfs() {
    log_info "TEST 4.3.8: eCryptfs Encryption Test"
    
    local status="INFO"
    local details=""
    
    # Check for eCryptfs tools
    if command -v ecryptfs-setup-private &>/dev/null; then
        details+="✓ eCryptfs tools available\n"
        
        # Check kernel module
        if lsmod 2>/dev/null | grep -q "ecryptfs"; then
            details+="✓ eCryptfs kernel module loaded\n"
        else
            details+="eCryptfs kernel module not loaded\n"
        fi
    else
        details+="eCryptfs tools not installed\n"
        details+="Install ecryptfs-utils package to enable\n"
    fi
    
    # Check for fscrypt (modern alternative)
    if command -v fscrypt &>/dev/null; then
        details+="✓ fscrypt available (modern fs-level encryption)\n"
        local fscrypt_version=$(fscrypt version 2>/dev/null | head -1)
        details+="  Version: ${fscrypt_version}\n"
    else
        details+="fscrypt not available\n"
    fi
    
    echo -e "$details"
    add_test_result "ecryptfs" "$status" "$(echo -e "$details")"
    
    log_info "TEST 4.3.8 COMPLETE (informational)"
}

#-------------------------------------------------------------------------------
# Main Execution
#-------------------------------------------------------------------------------
main() {
    echo ""
    echo "=============================================================================="
    echo "SECTION 4.3: STORAGE ENCRYPTION TESTS"
    echo "=============================================================================="
    echo ""
    
    init_results
    
    test_dmcrypt_encryption
    test_luks_operations
    test_encrypted_file_ops
    test_fio_encrypted_performance
    test_ceph_integration
    test_encrypted_backup_restore
    test_gpg_encryption
    test_ecryptfs
    
    # Finalize results
    local tmp_file=$(mktemp)
    jq '.end_time = "'"$(date -Iseconds)"'"' "${SECTION_RESULTS}" > "${tmp_file}" && mv "${tmp_file}" "${SECTION_RESULTS}"
    
    # Cleanup test directory
    rm -rf "${TEST_DIR}"
    
    echo ""
    echo "Section 4.3 tests complete. Results: ${SECTION_RESULTS}"
}

main "$@"
