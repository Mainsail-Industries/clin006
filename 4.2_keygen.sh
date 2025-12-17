#!/bin/bash
#===============================================================================
# SECTION 4.2: CRYPTOGRAPHIC KEY GENERATION TESTS
# Reference: Test Plan Section 4.2 - Subsystem: Cryptographic Key Generation
#
# What is being tested:
# - Keys generated for TLS/SSL connections
# - SSH key generation
# - Certificate signing requests (CSRs)
# - Storage encryption keys (dm-crypt, LUKS)
# - Virtual machine encryption keys
#
# Success Criteria:
# - Keys generated successfully with QO
# - Keys meet all standard format requirements
# - No application errors or rejections
# - Cryptographic operations function correctly
# - Demonstrable entropy quality improvement
#===============================================================================

set -euo pipefail

RESULTS_DIR="${1:-./results}"
SECTION_DIR="${RESULTS_DIR}/crypto"
SECTION_RESULTS="${SECTION_DIR}/results.json"
KEY_DIR="${SECTION_DIR}/keys"

source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh" 2>/dev/null || {
    log_info() { echo "[INFO] $*"; }
    log_pass() { echo "[PASS] $*"; }
    log_fail() { echo "[FAIL] $*"; }
    log_warn() { echo "[WARN] $*"; }
}

mkdir -p "${SECTION_DIR}"
mkdir -p "${KEY_DIR}"

#-------------------------------------------------------------------------------
# Initialize Results
#-------------------------------------------------------------------------------
init_results() {
    cat > "${SECTION_RESULTS}" << EOF
{
    "section": "4.2",
    "name": "Cryptographic Key Generation",
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
# TEST 4.2.1: RSA Key Generation
#-------------------------------------------------------------------------------
test_rsa_key_generation() {
    log_info "TEST 4.2.1: RSA Key Generation Tests"
    
    local status="PASS"
    local details=""
    local key_sizes=(2048 3072 4096)
    
    for size in "${key_sizes[@]}"; do
        log_info "Generating RSA-${size} key..."
        
        local key_file="${KEY_DIR}/rsa_${size}.key"
        local pub_file="${KEY_DIR}/rsa_${size}.pub"
        local start_time=$(date +%s.%N)
        
        if openssl genrsa -out "${key_file}" ${size} 2>/dev/null; then
            local end_time=$(date +%s.%N)
            local duration=$(echo "${end_time} - ${start_time}" | bc)
            
            # Extract public key
            openssl rsa -in "${key_file}" -pubout -out "${pub_file}" 2>/dev/null
            
            # Verify key
            if openssl rsa -in "${key_file}" -check -noout 2>/dev/null; then
                details+="✓ RSA-${size}: Generated in ${duration}s, verified OK\n"
            else
                status="FAIL"
                details+="✗ RSA-${size}: Key verification failed\n"
            fi
            
            # Get key info
            local modulus_bits=$(openssl rsa -in "${key_file}" -text -noout 2>/dev/null | grep "Private-Key" | grep -oP '\d+')
            details+="  Modulus bits: ${modulus_bits}\n"
        else
            status="FAIL"
            details+="✗ RSA-${size}: Generation failed\n"
        fi
    done
    
    echo -e "$details"
    add_test_result "rsa_key_generation" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.2.1 PASSED" || log_fail "TEST 4.2.1 FAILED"
}

#-------------------------------------------------------------------------------
# TEST 4.2.2: ECDSA Key Generation
#-------------------------------------------------------------------------------
test_ecdsa_key_generation() {
    log_info "TEST 4.2.2: ECDSA Key Generation Tests"
    
    local status="PASS"
    local details=""
    local curves=("prime256v1" "secp384r1" "secp521r1")
    
    for curve in "${curves[@]}"; do
        log_info "Generating ECDSA key with curve ${curve}..."
        
        local key_file="${KEY_DIR}/ecdsa_${curve}.key"
        local pub_file="${KEY_DIR}/ecdsa_${curve}.pub"
        local start_time=$(date +%s.%N)
        
        if openssl ecparam -genkey -name ${curve} -out "${key_file}" 2>/dev/null; then
            local end_time=$(date +%s.%N)
            local duration=$(echo "${end_time} - ${start_time}" | bc)
            
            # Extract public key
            openssl ec -in "${key_file}" -pubout -out "${pub_file}" 2>/dev/null
            
            # Verify key
            if openssl ec -in "${key_file}" -check -noout 2>/dev/null; then
                details+="✓ ECDSA-${curve}: Generated in ${duration}s, verified OK\n"
            else
                status="FAIL"
                details+="✗ ECDSA-${curve}: Key verification failed\n"
            fi
        else
            status="FAIL"
            details+="✗ ECDSA-${curve}: Generation failed\n"
        fi
    done
    
    echo -e "$details"
    add_test_result "ecdsa_key_generation" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.2.2 PASSED" || log_fail "TEST 4.2.2 FAILED"
}

#-------------------------------------------------------------------------------
# TEST 4.2.3: Ed25519 Key Generation
#-------------------------------------------------------------------------------
test_ed25519_key_generation() {
    log_info "TEST 4.2.3: Ed25519 Key Generation Tests"
    
    local status="PASS"
    local details=""
    
    local key_file="${KEY_DIR}/ed25519.key"
    local pub_file="${KEY_DIR}/ed25519.pub"
    local start_time=$(date +%s.%N)
    
    if openssl genpkey -algorithm Ed25519 -out "${key_file}" 2>/dev/null; then
        local end_time=$(date +%s.%N)
        local duration=$(echo "${end_time} - ${start_time}" | bc)
        
        # Extract public key
        openssl pkey -in "${key_file}" -pubout -out "${pub_file}" 2>/dev/null
        
        details+="✓ Ed25519: Generated in ${duration}s\n"
        
        # Show key info
        local key_info=$(openssl pkey -in "${key_file}" -text -noout 2>/dev/null | head -5)
        details+="Key info:\n${key_info}\n"
    else
        status="FAIL"
        details+="✗ Ed25519: Generation failed (may not be supported)\n"
    fi
    
    # Also test X25519 for key exchange
    local x25519_file="${KEY_DIR}/x25519.key"
    if openssl genpkey -algorithm X25519 -out "${x25519_file}" 2>/dev/null; then
        details+="✓ X25519: Generated successfully\n"
    else
        details+="⚠ X25519: Not supported or failed\n"
    fi
    
    echo -e "$details"
    add_test_result "ed25519_key_generation" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.2.3 PASSED" || log_fail "TEST 4.2.3 FAILED"
}

#-------------------------------------------------------------------------------
# TEST 4.2.4: SSH Key Generation
#-------------------------------------------------------------------------------
test_ssh_key_generation() {
    log_info "TEST 4.2.4: SSH Key Generation Tests"
    
    local status="PASS"
    local details=""
    
    if ! command -v ssh-keygen &>/dev/null; then
        status="SKIP"
        details="ssh-keygen not available"
        add_test_result "ssh_key_generation" "$status" "$details"
        log_warn "TEST 4.2.4 SKIPPED"
        return
    fi
    
    # Test different SSH key types
    local key_types=("rsa:4096" "ecdsa:521" "ed25519")
    
    for key_spec in "${key_types[@]}"; do
        local key_type=$(echo "${key_spec}" | cut -d: -f1)
        local key_bits=$(echo "${key_spec}" | cut -d: -f2)
        
        local key_file="${KEY_DIR}/ssh_${key_type}"
        rm -f "${key_file}" "${key_file}.pub" 2>/dev/null
        
        log_info "Generating SSH ${key_type} key..."
        local start_time=$(date +%s.%N)
        
        local ssh_cmd="ssh-keygen -t ${key_type} -f ${key_file} -N '' -q"
        if [[ -n "${key_bits}" && "${key_type}" != "ed25519" ]]; then
            ssh_cmd="ssh-keygen -t ${key_type} -b ${key_bits} -f ${key_file} -N '' -q"
        fi
        
        if eval "${ssh_cmd}"; then
            local end_time=$(date +%s.%N)
            local duration=$(echo "${end_time} - ${start_time}" | bc)
            
            # Verify key
            if ssh-keygen -l -f "${key_file}" &>/dev/null; then
                local fingerprint=$(ssh-keygen -l -f "${key_file}" 2>/dev/null)
                details+="✓ SSH-${key_type}: Generated in ${duration}s\n"
                details+="  Fingerprint: ${fingerprint}\n"
            else
                status="FAIL"
                details+="✗ SSH-${key_type}: Verification failed\n"
            fi
        else
            status="FAIL"
            details+="✗ SSH-${key_type}: Generation failed\n"
        fi
    done
    
    echo -e "$details"
    add_test_result "ssh_key_generation" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.2.4 PASSED" || log_fail "TEST 4.2.4 FAILED"
}

#-------------------------------------------------------------------------------
# TEST 4.2.5: X.509 Certificate Generation
#-------------------------------------------------------------------------------
test_certificate_generation() {
    log_info "TEST 4.2.5: X.509 Certificate Generation Tests"
    
    local status="PASS"
    local details=""
    
    # Generate CA key and self-signed certificate
    local ca_key="${KEY_DIR}/ca.key"
    local ca_cert="${KEY_DIR}/ca.crt"
    
    log_info "Generating CA certificate..."
    
    if openssl req -x509 -newkey rsa:4096 -keyout "${ca_key}" -out "${ca_cert}" \
        -days 365 -nodes -subj "/CN=Test CA/O=Mainsail/C=US" 2>/dev/null; then
        details+="✓ CA certificate generated\n"
        
        # Verify CA cert
        if openssl x509 -in "${ca_cert}" -noout -text &>/dev/null; then
            local ca_subject=$(openssl x509 -in "${ca_cert}" -noout -subject 2>/dev/null)
            details+="  CA Subject: ${ca_subject}\n"
        fi
    else
        status="FAIL"
        details+="✗ CA certificate generation failed\n"
    fi
    
    # Generate server key and CSR
    local server_key="${KEY_DIR}/server.key"
    local server_csr="${KEY_DIR}/server.csr"
    local server_cert="${KEY_DIR}/server.crt"
    
    log_info "Generating server certificate..."
    
    if openssl req -newkey rsa:2048 -keyout "${server_key}" -out "${server_csr}" \
        -nodes -subj "/CN=server.test/O=Mainsail/C=US" 2>/dev/null; then
        details+="✓ Server CSR generated\n"
        
        # Sign with CA
        if openssl x509 -req -in "${server_csr}" -CA "${ca_cert}" -CAkey "${ca_key}" \
            -CAcreateserial -out "${server_cert}" -days 365 2>/dev/null; then
            details+="✓ Server certificate signed by CA\n"
            
            # Verify chain
            if openssl verify -CAfile "${ca_cert}" "${server_cert}" 2>/dev/null | grep -q "OK"; then
                details+="✓ Certificate chain verification OK\n"
            else
                status="WARN"
                details+="⚠ Certificate chain verification issues\n"
            fi
        else
            status="FAIL"
            details+="✗ Server certificate signing failed\n"
        fi
    else
        status="FAIL"
        details+="✗ Server CSR generation failed\n"
    fi
    
    # Generate client certificate (for mutual TLS)
    local client_key="${KEY_DIR}/client.key"
    local client_csr="${KEY_DIR}/client.csr"
    local client_cert="${KEY_DIR}/client.crt"
    
    log_info "Generating client certificate..."
    
    if openssl req -newkey rsa:2048 -keyout "${client_key}" -out "${client_csr}" \
        -nodes -subj "/CN=client.test/O=Mainsail/C=US" 2>/dev/null; then
        if openssl x509 -req -in "${client_csr}" -CA "${ca_cert}" -CAkey "${ca_key}" \
            -CAcreateserial -out "${client_cert}" -days 365 2>/dev/null; then
            details+="✓ Client certificate generated and signed\n"
        fi
    fi
    
    echo -e "$details"
    add_test_result "certificate_generation" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.2.5 PASSED" || log_fail "TEST 4.2.5 FAILED"
}

#-------------------------------------------------------------------------------
# TEST 4.2.6: Key Uniqueness Test
#-------------------------------------------------------------------------------
test_key_uniqueness() {
    log_info "TEST 4.2.6: Key Uniqueness Test (checking for collisions)"
    
    local status="PASS"
    local details=""
    local num_keys=100
    local key_hashes_file="${SECTION_DIR}/key_hashes.txt"
    
    log_info "Generating ${num_keys} keys to check for collisions..."
    
    > "${key_hashes_file}"
    
    for i in $(seq 1 ${num_keys}); do
        # Generate a key and hash it
        local key_data=$(openssl genrsa 2048 2>/dev/null)
        local key_hash=$(echo "${key_data}" | openssl dgst -sha256 | awk '{print $2}')
        echo "${key_hash}" >> "${key_hashes_file}"
        
        # Show progress
        if (( i % 20 == 0 )); then
            log_info "  Generated ${i}/${num_keys} keys..."
        fi
    done
    
    # Check for duplicates
    local unique_count=$(sort "${key_hashes_file}" | uniq | wc -l)
    local total_count=$(wc -l < "${key_hashes_file}")
    
    details+="Keys generated: ${total_count}\n"
    details+="Unique keys: ${unique_count}\n"
    
    if [[ ${unique_count} -eq ${total_count} ]]; then
        details+="✓ All keys are unique - no collisions detected\n"
    else
        status="FAIL"
        local dupes=$((total_count - unique_count))
        details+="✗ COLLISION DETECTED: ${dupes} duplicate keys found!\n"
        details+="This indicates a serious entropy problem!\n"
    fi
    
    echo -e "$details"
    add_test_result "key_uniqueness" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.2.6 PASSED" || log_fail "TEST 4.2.6 FAILED"
}

#-------------------------------------------------------------------------------
# TEST 4.2.7: AES Key Generation
#-------------------------------------------------------------------------------
test_aes_key_generation() {
    log_info "TEST 4.2.7: AES Key Generation Tests"
    
    local status="PASS"
    local details=""
    local key_sizes=(128 192 256)
    
    for size in "${key_sizes[@]}"; do
        local bytes=$((size / 8))
        local key_file="${KEY_DIR}/aes_${size}.key"
        
        log_info "Generating AES-${size} key..."
        
        # Generate raw key bytes
        if openssl rand -out "${key_file}" ${bytes} 2>/dev/null; then
            local actual_size=$(stat -c %s "${key_file}")
            
            if [[ ${actual_size} -eq ${bytes} ]]; then
                details+="✓ AES-${size}: Generated ${bytes} bytes\n"
                
                # Test encryption/decryption with the key
                local test_data="Test encryption data for AES-${size}"
                local enc_file="${KEY_DIR}/aes_${size}_test.enc"
                local dec_file="${KEY_DIR}/aes_${size}_test.dec"
                
                echo "${test_data}" | openssl enc -aes-${size}-cbc -pbkdf2 \
                    -pass file:"${key_file}" -out "${enc_file}" 2>/dev/null
                
                openssl enc -d -aes-${size}-cbc -pbkdf2 \
                    -pass file:"${key_file}" -in "${enc_file}" -out "${dec_file}" 2>/dev/null
                
                local decrypted=$(cat "${dec_file}")
                if [[ "${decrypted}" == "${test_data}" ]]; then
                    details+="  Encryption/decryption verified OK\n"
                else
                    status="WARN"
                    details+="  ⚠ Encryption/decryption mismatch\n"
                fi
            else
                status="FAIL"
                details+="✗ AES-${size}: Wrong size (expected ${bytes}, got ${actual_size})\n"
            fi
        else
            status="FAIL"
            details+="✗ AES-${size}: Generation failed\n"
        fi
    done
    
    echo -e "$details"
    add_test_result "aes_key_generation" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.2.7 PASSED" || log_fail "TEST 4.2.7 FAILED"
}

#-------------------------------------------------------------------------------
# TEST 4.2.8: Key Generation Performance Benchmark
#-------------------------------------------------------------------------------
test_keygen_performance() {
    log_info "TEST 4.2.8: Key Generation Performance Benchmark"
    
    local status="PASS"
    local details=""
    local perf_file="${SECTION_DIR}/keygen_performance.json"
    
    echo '{"benchmarks": [' > "${perf_file}"
    local first=true
    
    # Benchmark different key types
    local benchmarks=(
        "rsa:2048:openssl genrsa 2048"
        "rsa:4096:openssl genrsa 4096"
        "ecdsa:p256:openssl ecparam -genkey -name prime256v1"
        "ecdsa:p384:openssl ecparam -genkey -name secp384r1"
        "ed25519::openssl genpkey -algorithm Ed25519"
        "random:32:openssl rand 32"
        "random:256:openssl rand 256"
    )
    
    for bench in "${benchmarks[@]}"; do
        local key_type=$(echo "${bench}" | cut -d: -f1)
        local param=$(echo "${bench}" | cut -d: -f2)
        local cmd=$(echo "${bench}" | cut -d: -f3-)
        
        log_info "Benchmarking ${key_type} ${param}..."
        
        local iterations=10
        local total_time=0
        
        for i in $(seq 1 ${iterations}); do
            local start=$(date +%s.%N)
            eval "${cmd}" > /dev/null 2>&1 || true
            local end=$(date +%s.%N)
            local duration=$(echo "${end} - ${start}" | bc)
            total_time=$(echo "${total_time} + ${duration}" | bc)
        done
        
        local avg_time=$(echo "scale=4; ${total_time} / ${iterations}" | bc)
        local ops_per_sec=$(echo "scale=2; ${iterations} / ${total_time}" | bc)
        
        details+="${key_type}-${param}: avg ${avg_time}s (${ops_per_sec} ops/sec)\n"
        
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo "," >> "${perf_file}"
        fi
        
        cat >> "${perf_file}" << EOF
    {
        "type": "${key_type}",
        "param": "${param}",
        "iterations": ${iterations},
        "avg_time_sec": ${avg_time},
        "ops_per_sec": ${ops_per_sec}
    }
EOF
    done
    
    echo "]}" >> "${perf_file}"
    
    echo -e "$details"
    add_test_result "keygen_performance" "$status" "$(echo -e "$details")"
    
    log_pass "TEST 4.2.8 PASSED"
}

#-------------------------------------------------------------------------------
# TEST 4.2.9: Post-Quantum Cryptography Keys (if available)
#-------------------------------------------------------------------------------
test_pqc_key_generation() {
    log_info "TEST 4.2.9: Post-Quantum Cryptography Key Generation"
    
    local status="INFO"
    local details=""
    
    # Check for liboqs/oqsprovider
    if openssl list -providers 2>/dev/null | grep -qi "oqs\|liboqs"; then
        details+="✓ OQS provider detected in OpenSSL\n"
        
        # Try to generate ML-KEM (Kyber) keys
        local pqc_algorithms=("mlkem512" "mlkem768" "mlkem1024" "mldsa44" "mldsa65" "mldsa87")
        
        for alg in "${pqc_algorithms[@]}"; do
            local pqc_key="${KEY_DIR}/pqc_${alg}.key"
            
            if openssl genpkey -algorithm "${alg}" -out "${pqc_key}" 2>/dev/null; then
                details+="✓ ${alg}: Key generated successfully\n"
            else
                details+="  ${alg}: Not available or failed\n"
            fi
        done
    else
        details+="OQS provider not detected\n"
        details+="Post-quantum algorithms not available in this OpenSSL build\n"
        details+="To enable: Install liboqs and oqsprovider\n"
    fi
    
    # Check for standalone PQC tools
    if command -v oqskeygen &>/dev/null; then
        details+="✓ Standalone OQS keygen tool available\n"
    fi
    
    echo -e "$details"
    add_test_result "pqc_key_generation" "$status" "$(echo -e "$details")"
    
    log_info "TEST 4.2.9 COMPLETE (informational)"
}

#-------------------------------------------------------------------------------
# TEST 4.2.10: LUKS Key Derivation Test
#-------------------------------------------------------------------------------
test_luks_key_derivation() {
    log_info "TEST 4.2.10: LUKS Key Derivation Test"
    
    local status="PASS"
    local details=""
    
    if ! command -v cryptsetup &>/dev/null; then
        status="SKIP"
        details="cryptsetup not available - skipping LUKS test"
        add_test_result "luks_key_derivation" "$status" "$details"
        log_warn "TEST 4.2.10 SKIPPED"
        return
    fi
    
    # Create a test file for LUKS container
    local test_file="${SECTION_DIR}/luks_test.img"
    local test_size=32  # MB (LUKS2 header requires ~16MB)
    
    log_info "Creating test LUKS container..."
    
    # Create sparse file
    dd if=/dev/zero of="${test_file}" bs=1M count=${test_size} 2>/dev/null
    
    # Generate a passphrase using the entropy source
    local passphrase=$(openssl rand -base64 32)
    
    # Format as LUKS
    if echo "${passphrase}" | cryptsetup luksFormat "${test_file}" --batch-mode 2>/dev/null; then
        details+="✓ LUKS container formatted successfully\n"
        
        # Dump header info
        local header_info=$(cryptsetup luksDump "${test_file}" 2>/dev/null | head -20)
        details+="LUKS Header:\n${header_info}\n"
        
        # Check PBKDF type
        if echo "${header_info}" | grep -qi "argon2"; then
            details+="✓ Using Argon2 key derivation function\n"
        elif echo "${header_info}" | grep -qi "pbkdf2"; then
            details+="Using PBKDF2 key derivation function\n"
        fi
    else
        status="FAIL"
        details+="✗ LUKS format failed\n"
    fi
    
    # Cleanup
    rm -f "${test_file}" 2>/dev/null
    
    echo -e "$details"
    add_test_result "luks_key_derivation" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.2.10 PASSED" || log_fail "TEST 4.2.10 FAILED"
}

#-------------------------------------------------------------------------------
# Main Execution
#-------------------------------------------------------------------------------
main() {
    echo ""
    echo "=============================================================================="
    echo "SECTION 4.2: CRYPTOGRAPHIC KEY GENERATION TESTS"
    echo "=============================================================================="
    echo ""
    
    init_results
    
    test_rsa_key_generation
    test_ecdsa_key_generation
    test_ed25519_key_generation
    test_ssh_key_generation
    test_certificate_generation
    test_key_uniqueness
    test_aes_key_generation
    test_keygen_performance
    test_pqc_key_generation
    test_luks_key_derivation
    
    # Finalize results
    local tmp_file=$(mktemp)
    jq '.end_time = "'"$(date -Iseconds)"'"' "${SECTION_RESULTS}" > "${tmp_file}" && mv "${tmp_file}" "${SECTION_RESULTS}"
    
    # Cleanup sensitive keys
    log_info "Cleaning up generated keys..."
    rm -rf "${KEY_DIR}"/* 2>/dev/null || true
    
    echo ""
    echo "Section 4.2 tests complete. Results: ${SECTION_RESULTS}"
}

main "$@"
