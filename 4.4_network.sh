#!/bin/bash
#===============================================================================
# SECTION 4.4: NETWORK SECURITY (TLS/VPN) TESTS
# Reference: Test Plan Section 4.4 - Subsystem: Network Security (TLS/VPN)
#
# What is being tested:
# - TLS 1.3 session establishment
# - Post-quantum key encapsulation (ML-KEM)
# - VPN tunnel establishment
# - SSH connections
#
# Success Criteria:
# - TLS connections establish successfully
# - Session keys use quantum-enhanced entropy
# - PQC algorithms work correctly with QO
# - No compatibility issues with standard clients
# - Performance acceptable for production use
#===============================================================================

set -euo pipefail

RESULTS_DIR="${1:-./results}"
SECTION_DIR="${RESULTS_DIR}/network"
SECTION_RESULTS="${SECTION_DIR}/results.json"
CERTS_DIR="${SECTION_DIR}/certs"
TEST_PORT=18443

source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh" 2>/dev/null || {
    log_info() { echo "[INFO] $*"; }
    log_pass() { echo "[PASS] $*"; }
    log_fail() { echo "[FAIL] $*"; }
    log_warn() { echo "[WARN] $*"; }
}

mkdir -p "${SECTION_DIR}"
mkdir -p "${CERTS_DIR}"

#-------------------------------------------------------------------------------
# Initialize Results
#-------------------------------------------------------------------------------
init_results() {
    cat > "${SECTION_RESULTS}" << EOF
{
    "section": "4.4",
    "name": "Network Security (TLS/VPN)",
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
# Helper: Generate Test Certificates
#-------------------------------------------------------------------------------
generate_test_certs() {
    log_info "Generating test certificates..."
    
    # CA certificate
    openssl req -x509 -newkey rsa:4096 \
        -keyout "${CERTS_DIR}/ca.key" \
        -out "${CERTS_DIR}/ca.crt" \
        -days 365 -nodes \
        -subj "/CN=Test CA/O=Mainsail Test/C=US" 2>/dev/null
    
    # Server certificate
    openssl req -newkey rsa:2048 \
        -keyout "${CERTS_DIR}/server.key" \
        -out "${CERTS_DIR}/server.csr" \
        -nodes \
        -subj "/CN=localhost/O=Mainsail Test/C=US" 2>/dev/null
    
    openssl x509 -req \
        -in "${CERTS_DIR}/server.csr" \
        -CA "${CERTS_DIR}/ca.crt" \
        -CAkey "${CERTS_DIR}/ca.key" \
        -CAcreateserial \
        -out "${CERTS_DIR}/server.crt" \
        -days 365 2>/dev/null
    
    # Client certificate
    openssl req -newkey rsa:2048 \
        -keyout "${CERTS_DIR}/client.key" \
        -out "${CERTS_DIR}/client.csr" \
        -nodes \
        -subj "/CN=client/O=Mainsail Test/C=US" 2>/dev/null
    
    openssl x509 -req \
        -in "${CERTS_DIR}/client.csr" \
        -CA "${CERTS_DIR}/ca.crt" \
        -CAkey "${CERTS_DIR}/ca.key" \
        -CAcreateserial \
        -out "${CERTS_DIR}/client.crt" \
        -days 365 2>/dev/null
}

#-------------------------------------------------------------------------------
# TEST 4.4.1: OpenSSL TLS Capabilities
#-------------------------------------------------------------------------------
test_openssl_tls_capabilities() {
    log_info "TEST 4.4.1: OpenSSL TLS Capabilities"
    
    local status="PASS"
    local details=""
    
    # OpenSSL version
    local openssl_version=$(openssl version 2>/dev/null)
    details+="OpenSSL version: ${openssl_version}\n"
    
    # Supported protocols
    details+="Supported TLS protocols:\n"
    for proto in tls1 tls1_1 tls1_2 tls1_3; do
        if openssl s_client -help 2>&1 | grep -q "\-${proto}"; then
            details+="  ✓ ${proto}\n"
        else
            details+="  ✗ ${proto}\n"
        fi
    done
    
    # List ciphers
    log_info "Checking available cipher suites..."

    # TLS 1.3 ciphersuites are handled separately in OpenSSL 3.x
    local tls13_ciphers=$(openssl ciphers -s -tls1_3 2>/dev/null | tr ':' '\n' | wc -l)
    local tls12_ciphers=$(openssl ciphers -v 'HIGH:!aNULL:!MD5' 2>/dev/null | wc -l)

    details+="Available cipher suites:\n"
    details+="  TLS 1.3: ${tls13_ciphers} ciphersuites\n"
    details+="  TLS 1.2: ${tls12_ciphers} ciphers\n"

    # Check for strong AEAD ciphers (TLS 1.3 always uses AEAD)
    local tls13_list=$(openssl ciphers -s -tls1_3 2>/dev/null)
    if [[ -n "${tls13_list}" ]] && echo "${tls13_list}" | grep -qi "AES.*GCM\|CHACHA20"; then
        details+="✓ Strong AEAD ciphers available (TLS 1.3)\n"
    elif openssl ciphers 'AESGCM:CHACHA20' 2>/dev/null | grep -qi "AES\|CHACHA"; then
        details+="✓ Strong AEAD ciphers available\n"
    else
        status="WARN"
        details+="⚠ Strong AEAD ciphers may be missing\n"
    fi
    
    # Save cipher list
    openssl ciphers -v 'ALL:@STRENGTH' > "${SECTION_DIR}/cipher_list.txt" 2>/dev/null
    
    echo -e "$details"
    add_test_result "openssl_tls_capabilities" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.4.1 PASSED" || log_warn "TEST 4.4.1 WARNING"
}

#-------------------------------------------------------------------------------
# TEST 4.4.2: TLS 1.3 Connection Test
#-------------------------------------------------------------------------------
test_tls13_connection() {
    log_info "TEST 4.4.2: TLS 1.3 Connection Test"
    
    local status="PASS"
    local details=""
    
    generate_test_certs
    
    # Start TLS server in background
    local server_pid=""
    log_info "Starting TLS 1.3 test server on port ${TEST_PORT}..."
    
    openssl s_server -accept ${TEST_PORT} \
        -cert "${CERTS_DIR}/server.crt" \
        -key "${CERTS_DIR}/server.key" \
        -tls1_3 \
        -www \
        > "${SECTION_DIR}/server.log" 2>&1 &
    server_pid=$!
    
    sleep 2
    
    if kill -0 ${server_pid} 2>/dev/null; then
        details+="✓ TLS 1.3 server started\n"
        
        # Connect with client
        log_info "Testing TLS 1.3 client connection..."
        
        local client_output="${SECTION_DIR}/client_output.txt"
        
        echo "GET / HTTP/1.0" | timeout 10 openssl s_client \
            -connect localhost:${TEST_PORT} \
            -tls1_3 \
            -CAfile "${CERTS_DIR}/ca.crt" \
            > "${client_output}" 2>&1 || true
        
        if grep -q "TLSv1.3" "${client_output}"; then
            details+="✓ TLS 1.3 connection established\n"
            
            # Extract cipher info
            local cipher=$(grep "Cipher is" "${client_output}" | head -1)
            details+="  ${cipher}\n"
            
            # Extract session info
            local session_info=$(grep -A5 "New, TLSv1.3" "${client_output}" 2>/dev/null | head -6)
            if [[ -n "${session_info}" ]]; then
                details+="Session info:\n${session_info}\n"
            fi
        else
            status="FAIL"
            details+="✗ TLS 1.3 connection failed\n"
            if [[ -f "${client_output}" ]]; then
                local error=$(tail -5 "${client_output}")
                details+="Error: ${error}\n"
            fi
        fi
        
        # Cleanup server
        kill ${server_pid} 2>/dev/null || true
        wait ${server_pid} 2>/dev/null || true
    else
        status="FAIL"
        details+="✗ Failed to start TLS server\n"
    fi
    
    echo -e "$details"
    add_test_result "tls13_connection" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.4.2 PASSED" || log_fail "TEST 4.4.2 FAILED"
}

#-------------------------------------------------------------------------------
# TEST 4.4.3: TLS Connection Performance
#-------------------------------------------------------------------------------
test_tls_performance() {
    log_info "TEST 4.4.3: TLS Connection Performance"
    
    local status="PASS"
    local details=""
    
    # Start TLS server
    openssl s_server -accept ${TEST_PORT} \
        -cert "${CERTS_DIR}/server.crt" \
        -key "${CERTS_DIR}/server.key" \
        -tls1_3 \
        -www \
        > /dev/null 2>&1 &
    local server_pid=$!
    
    sleep 2
    
    if kill -0 ${server_pid} 2>/dev/null; then
        # Measure handshake time
        log_info "Measuring TLS handshake performance..."
        
        local iterations=20
        local total_time=0
        local successful=0
        
        for i in $(seq 1 ${iterations}); do
            local start=$(date +%s.%N)

            if echo "Q" | timeout 5 openssl s_client \
                -connect localhost:${TEST_PORT} \
                -tls1_3 \
                -CAfile "${CERTS_DIR}/ca.crt" \
                > /dev/null 2>&1; then

                local end=$(date +%s.%N)
                local duration=$(echo "${end} - ${start}" | bc)
                total_time=$(echo "${total_time} + ${duration}" | bc)
                successful=$((successful + 1))
            fi
        done
        
        if [[ ${successful} -gt 0 ]]; then
            local avg_time=$(echo "scale=4; ${total_time} / ${successful}" | bc)
            local handshakes_per_sec=$(echo "scale=2; ${successful} / ${total_time}" | bc)
            
            details+="TLS Handshake Performance:\n"
            details+="  Iterations: ${iterations}\n"
            details+="  Successful: ${successful}\n"
            details+="  Average handshake time: ${avg_time}s\n"
            details+="  Handshakes/sec: ${handshakes_per_sec}\n"
            
            # Check if performance is acceptable (< 100ms average)
            if (( $(echo "${avg_time} < 0.1" | bc -l) )); then
                details+="✓ Handshake performance acceptable (<100ms)\n"
            elif (( $(echo "${avg_time} < 0.5" | bc -l) )); then
                details+="⚠ Handshake performance marginal (100-500ms)\n"
            else
                status="WARN"
                details+="⚠ Handshake performance slow (>500ms)\n"
            fi
        else
            status="FAIL"
            details+="✗ No successful handshakes\n"
        fi
        
        kill ${server_pid} 2>/dev/null || true
    else
        status="FAIL"
        details+="✗ Server failed to start\n"
    fi
    
    echo -e "$details"
    add_test_result "tls_performance" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.4.3 PASSED" || log_fail "TEST 4.4.3 FAILED"
}

#-------------------------------------------------------------------------------
# TEST 4.4.4: SSH Key Exchange Test
#-------------------------------------------------------------------------------
test_ssh_key_exchange() {
    log_info "TEST 4.4.4: SSH Key Exchange Test"
    
    local status="PASS"
    local details=""
    
    if ! command -v ssh &>/dev/null; then
        status="SKIP"
        details="SSH client not available"
        add_test_result "ssh_key_exchange" "$status" "$details"
        log_warn "TEST 4.4.4 SKIPPED"
        return
    fi
    
    # Check SSH client capabilities
    local ssh_version=$(ssh -V 2>&1)
    details+="SSH version: ${ssh_version}\n"
    
    # List supported key exchange algorithms
    details+="Supported key exchange algorithms:\n"
    
    local kex_algorithms=$(ssh -Q kex 2>/dev/null || echo "Unable to query")
    if [[ "${kex_algorithms}" != "Unable to query" ]]; then
        local kex_count=$(echo "${kex_algorithms}" | wc -l)
        details+="  Total: ${kex_count} algorithms\n"
        
        # Check for specific algorithms
        if echo "${kex_algorithms}" | grep -q "curve25519"; then
            details+="  ✓ curve25519 available\n"
        fi
        if echo "${kex_algorithms}" | grep -q "ecdh-sha2"; then
            details+="  ✓ ECDH-SHA2 available\n"
        fi
        if echo "${kex_algorithms}" | grep -q "diffie-hellman-group16"; then
            details+="  ✓ DH Group 16 (4096-bit) available\n"
        fi
        if echo "${kex_algorithms}" | grep -qi "sntrup\|mlkem"; then
            details+="  ✓ Post-quantum hybrid KEX available\n"
        else
            details+="  ⚠ No post-quantum KEX detected\n"
        fi
        
        # Save full list
        echo "${kex_algorithms}" > "${SECTION_DIR}/ssh_kex_algorithms.txt"
    fi
    
    # List supported ciphers
    local ciphers=$(ssh -Q cipher 2>/dev/null || echo "Unable to query")
    if [[ "${ciphers}" != "Unable to query" ]]; then
        local cipher_count=$(echo "${ciphers}" | wc -l)
        details+="Supported ciphers: ${cipher_count}\n"
        
        if echo "${ciphers}" | grep -q "chacha20"; then
            details+="  ✓ ChaCha20-Poly1305 available\n"
        fi
        if echo "${ciphers}" | grep -q "aes.*-gcm"; then
            details+="  ✓ AES-GCM available\n"
        fi
    fi
    
    # List supported MACs
    local macs=$(ssh -Q mac 2>/dev/null || echo "Unable to query")
    if [[ "${macs}" != "Unable to query" ]]; then
        local mac_count=$(echo "${macs}" | wc -l)
        details+="Supported MACs: ${mac_count}\n"
    fi
    
    echo -e "$details"
    add_test_result "ssh_key_exchange" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.4.4 PASSED" || log_fail "TEST 4.4.4 FAILED"
}

#-------------------------------------------------------------------------------
# TEST 4.4.5: Certificate Validation
#-------------------------------------------------------------------------------
test_certificate_validation() {
    log_info "TEST 4.4.5: Certificate Validation"
    
    local status="PASS"
    local details=""
    
    # Validate generated certificates
    log_info "Validating test certificates..."
    
    # Check CA certificate
    if openssl x509 -in "${CERTS_DIR}/ca.crt" -noout -text &>/dev/null; then
        details+="✓ CA certificate valid\n"
        
        local ca_subject=$(openssl x509 -in "${CERTS_DIR}/ca.crt" -noout -subject 2>/dev/null)
        local ca_issuer=$(openssl x509 -in "${CERTS_DIR}/ca.crt" -noout -issuer 2>/dev/null)
        details+="  ${ca_subject}\n"
    else
        status="FAIL"
        details+="✗ CA certificate invalid\n"
    fi
    
    # Verify server cert against CA
    if openssl verify -CAfile "${CERTS_DIR}/ca.crt" "${CERTS_DIR}/server.crt" 2>/dev/null | grep -q "OK"; then
        details+="✓ Server certificate verified against CA\n"
    else
        status="FAIL"
        details+="✗ Server certificate verification failed\n"
    fi
    
    # Verify client cert against CA
    if openssl verify -CAfile "${CERTS_DIR}/ca.crt" "${CERTS_DIR}/client.crt" 2>/dev/null | grep -q "OK"; then
        details+="✓ Client certificate verified against CA\n"
    else
        status="FAIL"
        details+="✗ Client certificate verification failed\n"
    fi
    
    # Check key usage
    local server_ku=$(openssl x509 -in "${CERTS_DIR}/server.crt" -noout -text 2>/dev/null | grep -A1 "Key Usage")
    if [[ -n "${server_ku}" ]]; then
        details+="Server key usage: ${server_ku}\n"
    fi
    
    echo -e "$details"
    add_test_result "certificate_validation" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.4.5 PASSED" || log_fail "TEST 4.4.5 FAILED"
}

#-------------------------------------------------------------------------------
# TEST 4.4.6: WireGuard Check
#-------------------------------------------------------------------------------
test_wireguard() {
    log_info "TEST 4.4.6: WireGuard VPN Check"
    
    local status="INFO"
    local details=""
    
    # Check for WireGuard tools
    if command -v wg &>/dev/null; then
        details+="✓ WireGuard tools available\n"
        
        local wg_version=$(wg --version 2>/dev/null || echo "Unknown")
        details+="Version: ${wg_version}\n"
        
        # Check kernel module
        if lsmod 2>/dev/null | grep -q "wireguard"; then
            details+="✓ WireGuard kernel module loaded\n"
        else
            details+="WireGuard kernel module not loaded\n"
        fi
        
        # Test key generation
        log_info "Testing WireGuard key generation..."
        local wg_privkey="${SECTION_DIR}/wg_test.key"
        local wg_pubkey="${SECTION_DIR}/wg_test.pub"
        
        if wg genkey > "${wg_privkey}" 2>/dev/null; then
            details+="✓ Private key generation successful\n"
            
            if wg pubkey < "${wg_privkey}" > "${wg_pubkey}" 2>/dev/null; then
                details+="✓ Public key derivation successful\n"
                
                local privkey_len=$(wc -c < "${wg_privkey}")
                local pubkey_len=$(wc -c < "${wg_pubkey}")
                details+="  Private key: ${privkey_len} bytes\n"
                details+="  Public key: ${pubkey_len} bytes\n"
            fi
            
            rm -f "${wg_privkey}" "${wg_pubkey}"
        else
            details+="⚠ Key generation failed\n"
        fi
    else
        details+="WireGuard tools not installed\n"
        details+="Install wireguard-tools package to enable\n"
    fi
    
    echo -e "$details"
    add_test_result "wireguard" "$status" "$(echo -e "$details")"
    
    log_info "TEST 4.4.6 COMPLETE (informational)"
}

#-------------------------------------------------------------------------------
# TEST 4.4.7: Post-Quantum TLS Check
#-------------------------------------------------------------------------------
test_pqc_tls() {
    log_info "TEST 4.4.7: Post-Quantum TLS Check"
    
    local status="INFO"
    local details=""
    
    # Check for OQS provider
    if openssl list -providers 2>/dev/null | grep -qi "oqs"; then
        details+="✓ OQS provider detected\n"
        
        # List PQC algorithms
        local pqc_kems=$(openssl list -kem-algorithms 2>/dev/null | grep -i "ml-kem\|kyber\|sntrup" | head -10)
        if [[ -n "${pqc_kems}" ]]; then
            details+="Available PQC KEMs:\n${pqc_kems}\n"
        fi
        
        local pqc_sigs=$(openssl list -signature-algorithms 2>/dev/null | grep -i "ml-dsa\|dilithium\|sphincs" | head -10)
        if [[ -n "${pqc_sigs}" ]]; then
            details+="Available PQC signatures:\n${pqc_sigs}\n"
        fi
    else
        details+="OQS provider not detected\n"
        details+="Post-quantum TLS not available in this build\n"
    fi
    
    # Check for s_client PQ options
    if openssl s_client -help 2>&1 | grep -qi "groups"; then
        details+="✓ OpenSSL supports group selection for hybrid KEX\n"
    fi
    
    echo -e "$details"
    add_test_result "pqc_tls" "$status" "$(echo -e "$details")"
    
    log_info "TEST 4.4.7 COMPLETE (informational)"
}

#-------------------------------------------------------------------------------
# TEST 4.4.8: External TLS Test (Public Server)
#-------------------------------------------------------------------------------
test_external_tls() {
    log_info "TEST 4.4.8: External TLS Connection Test"
    
    local status="PASS"
    local details=""
    
    local test_hosts=(
        "www.google.com:443"
        "github.com:443"
        "www.cloudflare.com:443"
    )
    
    for host_port in "${test_hosts[@]}"; do
        local host=$(echo "${host_port}" | cut -d: -f1)
        local port=$(echo "${host_port}" | cut -d: -f2)
        
        log_info "Testing connection to ${host}..."
        
        local output="${SECTION_DIR}/ext_${host}.txt"
        
        if echo "Q" | timeout 10 openssl s_client \
            -connect "${host_port}" \
            -servername "${host}" \
            > "${output}" 2>&1; then
            
            if grep -q "Verify return code: 0" "${output}"; then
                local protocol=$(grep "Protocol" "${output}" | head -1 | awk '{print $3}')
                local cipher=$(grep "Cipher" "${output}" | head -1 | awk '{print $3}')
                details+="✓ ${host}: ${protocol}, ${cipher}\n"
            else
                local verify_code=$(grep "Verify return code" "${output}" | head -1)
                details+="⚠ ${host}: Certificate issue - ${verify_code}\n"
            fi
        else
            status="WARN"
            details+="⚠ ${host}: Connection failed\n"
        fi
    done
    
    echo -e "$details"
    add_test_result "external_tls" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.4.8 PASSED" || log_warn "TEST 4.4.8 WARNING"
}

#-------------------------------------------------------------------------------
# TEST 4.4.9: Session Key Randomness
#-------------------------------------------------------------------------------
test_session_key_randomness() {
    log_info "TEST 4.4.9: TLS Session Key Randomness Analysis"
    
    local status="PASS"
    local details=""
    
    # Start TLS server
    openssl s_server -accept ${TEST_PORT} \
        -cert "${CERTS_DIR}/server.crt" \
        -key "${CERTS_DIR}/server.key" \
        -tls1_3 \
        -keylogfile "${SECTION_DIR}/keylog.txt" \
        -www \
        > /dev/null 2>&1 &
    local server_pid=$!
    
    sleep 2
    
    if kill -0 ${server_pid} 2>/dev/null; then
        # Make multiple connections
        log_info "Making multiple TLS connections for key analysis..."
        
        for i in $(seq 1 10); do
            echo "Q" | timeout 5 openssl s_client \
                -connect localhost:${TEST_PORT} \
                -tls1_3 \
                -CAfile "${CERTS_DIR}/ca.crt" \
                > /dev/null 2>&1 || true
            sleep 0.5
        done
        
        kill ${server_pid} 2>/dev/null || true
        
        # Analyze key log
        if [[ -f "${SECTION_DIR}/keylog.txt" ]]; then
            local key_count=$(wc -l < "${SECTION_DIR}/keylog.txt")
            details+="Captured ${key_count} key log entries\n"
            
            # Check for unique master secrets
            local unique_secrets=$(grep "CLIENT_HANDSHAKE_TRAFFIC_SECRET" "${SECTION_DIR}/keylog.txt" | \
                awk '{print $3}' | sort -u | wc -l)
            local total_secrets=$(grep "CLIENT_HANDSHAKE_TRAFFIC_SECRET" "${SECTION_DIR}/keylog.txt" | wc -l)
            
            details+="Handshake secrets: ${total_secrets} total, ${unique_secrets} unique\n"
            
            if [[ ${unique_secrets} -eq ${total_secrets} ]]; then
                details+="✓ All session keys are unique\n"
            else
                status="FAIL"
                details+="✗ Duplicate session keys detected!\n"
            fi
            
            # Remove sensitive keylog
            rm -f "${SECTION_DIR}/keylog.txt"
        else
            details+="⚠ Key log not captured (server may not support -keylogfile)\n"
        fi
    else
        status="FAIL"
        details+="✗ Server failed to start\n"
    fi
    
    echo -e "$details"
    add_test_result "session_key_randomness" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.4.9 PASSED" || log_fail "TEST 4.4.9 FAILED"
}

#-------------------------------------------------------------------------------
# Cleanup Function
#-------------------------------------------------------------------------------
cleanup() {
    # Kill any remaining server processes
    pkill -f "openssl s_server.*${TEST_PORT}" 2>/dev/null || true
}

#-------------------------------------------------------------------------------
# Main Execution
#-------------------------------------------------------------------------------
main() {
    echo ""
    echo "=============================================================================="
    echo "SECTION 4.4: NETWORK SECURITY (TLS/VPN) TESTS"
    echo "=============================================================================="
    echo ""
    
    trap cleanup EXIT
    
    init_results
    
    test_openssl_tls_capabilities
    test_tls13_connection
    test_tls_performance
    test_ssh_key_exchange
    test_certificate_validation
    test_wireguard
    test_pqc_tls
    test_external_tls
    test_session_key_randomness
    
    # Finalize results
    local tmp_file=$(mktemp)
    jq '.end_time = "'"$(date -Iseconds)"'"' "${SECTION_RESULTS}" > "${tmp_file}" && mv "${tmp_file}" "${SECTION_RESULTS}"
    
    # Cleanup certificates
    rm -rf "${CERTS_DIR}"
    
    echo ""
    echo "Section 4.4 tests complete. Results: ${SECTION_RESULTS}"
}

main "$@"
