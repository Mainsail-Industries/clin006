#!/bin/bash
#===============================================================================
# SECTION 4.1: SYSTEM ENTROPY SOURCE TESTS
# Reference: Test Plan Section 4.1 - Subsystem: System Entropy Source
#
# What is being tested:
# - The /dev/random interface and kernel entropy pool
# - Quantum Origin as the primary randomness provider
# - Randomness extractor functionality
#
# Success Criteria:
# - System recognizes QO as entropy source
# - /dev/random behavior meets or exceeds baseline performance
# - Entropy never exhausted or degraded
# - Legacy RNG demonstrably inactive
#===============================================================================

set -euo pipefail

RESULTS_DIR="${1:-./results}"
SECTION_DIR="${RESULTS_DIR}/entropy"
SECTION_RESULTS="${SECTION_DIR}/results.json"

source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh" 2>/dev/null || {
    # Inline common functions if lib not available
    log_info() { echo "[INFO] $*"; }
    log_pass() { echo "[PASS] $*"; }
    log_fail() { echo "[FAIL] $*"; }
    log_warn() { echo "[WARN] $*"; }
}

mkdir -p "${SECTION_DIR}"

#-------------------------------------------------------------------------------
# Initialize Results
#-------------------------------------------------------------------------------
init_results() {
    cat > "${SECTION_RESULTS}" << EOF
{
    "section": "4.1",
    "name": "System Entropy Source",
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
# TEST 4.1.1: Verify /dev/random Availability and Configuration
#-------------------------------------------------------------------------------
test_dev_random_availability() {
    log_info "TEST 4.1.1: Verifying /dev/random availability and configuration"
    
    local status="PASS"
    local details=""
    
    # Check /dev/random exists and is a character device
    if [[ -c /dev/random ]]; then
        details+="✓ /dev/random exists as character device\n"
    else
        status="FAIL"
        details+="✗ /dev/random not found or not a character device\n"
    fi
    
    # Check /dev/urandom exists
    if [[ -c /dev/urandom ]]; then
        details+="✓ /dev/urandom exists as character device\n"
    else
        status="FAIL"
        details+="✗ /dev/urandom not found\n"
    fi
    
    # Check permissions
    local random_perms=$(stat -c '%a' /dev/random 2>/dev/null || echo "N/A")
    details+="Permissions: /dev/random = ${random_perms}\n"
    
    # Check if readable
    if dd if=/dev/random bs=1 count=1 iflag=nonblock of=/dev/null 2>/dev/null; then
        details+="✓ /dev/random is readable\n"
    else
        status="WARN"
        details+="⚠ /dev/random blocking or not readable\n"
    fi
    
    # Save kernel random configuration
    if [[ -d /proc/sys/kernel/random ]]; then
        details+="Kernel random config:\n"
        for param in entropy_avail poolsize read_wakeup_threshold write_wakeup_threshold; do
            if [[ -f "/proc/sys/kernel/random/${param}" ]]; then
                local val=$(cat "/proc/sys/kernel/random/${param}")
                details+="  ${param} = ${val}\n"
                echo "${param}=${val}" >> "${SECTION_DIR}/kernel_random_config.txt"
            fi
        done
    fi
    
    echo -e "$details"
    add_test_result "dev_random_availability" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.1.1 PASSED" || log_fail "TEST 4.1.1 FAILED"
}

#-------------------------------------------------------------------------------
# TEST 4.1.2: Entropy Pool Metrics Collection
#-------------------------------------------------------------------------------
test_entropy_pool_metrics() {
    log_info "TEST 4.1.2: Collecting entropy pool metrics"
    
    local status="PASS"
    local details=""
    local metrics_file="${SECTION_DIR}/entropy_metrics.csv"
    
    # Header
    echo "timestamp,entropy_avail,poolsize" > "${metrics_file}"
    
    log_info "Collecting entropy pool samples over 30 seconds..."
    
    local min_entropy=999999
    local max_entropy=0
    local sum_entropy=0
    local samples=0
    
    for i in $(seq 1 30); do
        local entropy=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo "0")
        local poolsize=$(cat /proc/sys/kernel/random/poolsize 2>/dev/null || echo "0")
        
        echo "$(date +%s),${entropy},${poolsize}" >> "${metrics_file}"
        
        if [[ ${entropy} -lt ${min_entropy} ]]; then min_entropy=${entropy}; fi
        if [[ ${entropy} -gt ${max_entropy} ]]; then max_entropy=${entropy}; fi
        sum_entropy=$((sum_entropy + entropy))
        samples=$((samples + 1))
        
        sleep 1
    done
    
    local avg_entropy=$((sum_entropy / samples))
    
    details+="Entropy pool statistics (30s sample):\n"
    details+="  Minimum: ${min_entropy} bits\n"
    details+="  Maximum: ${max_entropy} bits\n"
    details+="  Average: ${avg_entropy} bits\n"
    details+="  Samples: ${samples}\n"
    
    # Check if entropy stayed healthy
    if [[ ${min_entropy} -gt 128 ]]; then
        details+="✓ Entropy pool never dropped below 128 bits\n"
    else
        status="WARN"
        details+="⚠ Entropy pool dropped below 128 bits (min: ${min_entropy})\n"
    fi
    
    # Save summary
    cat > "${SECTION_DIR}/entropy_summary.json" << EOF
{
    "min_entropy": ${min_entropy},
    "max_entropy": ${max_entropy},
    "avg_entropy": ${avg_entropy},
    "samples": ${samples},
    "sample_duration_sec": 30
}
EOF
    
    echo -e "$details"
    add_test_result "entropy_pool_metrics" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.1.2 PASSED" || log_warn "TEST 4.1.2 WARNING"
}

#-------------------------------------------------------------------------------
# TEST 4.1.3: Entropy Generation Rate
#-------------------------------------------------------------------------------
test_entropy_generation_rate() {
    log_info "TEST 4.1.3: Measuring entropy generation rate"
    
    local status="PASS"
    local details=""
    
    # Measure time to generate various amounts of random data
    local output_file="${SECTION_DIR}/entropy_rate.json"
    
    local sizes=(1024 4096 16384 65536 262144 1048576)  # 1K, 4K, 16K, 64K, 256K, 1M
    
    echo "{\"measurements\": [" > "${output_file}"
    local first=true
    
    for size in "${sizes[@]}"; do
        local start_time=$(date +%s.%N)
        dd if=/dev/urandom of=/dev/null bs=${size} count=1 2>/dev/null
        local end_time=$(date +%s.%N)
        
        local duration=$(echo "${end_time} - ${start_time}" | bc)
        local rate=$(echo "scale=2; ${size} / ${duration} / 1024 / 1024" | bc)
        
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo "," >> "${output_file}"
        fi
        
        echo "{\"size_bytes\": ${size}, \"duration_sec\": ${duration}, \"rate_mbps\": ${rate}}" >> "${output_file}"
        details+="  ${size} bytes: ${duration}s (${rate} MB/s)\n"
    done
    
    echo "]}" >> "${output_file}"
    
    details="Entropy generation rates (/dev/urandom):\n${details}"
    
    # Test /dev/random (may block)
    log_info "Testing /dev/random (small sample to avoid blocking)..."
    local start_time=$(date +%s.%N)
    timeout 5s dd if=/dev/random of=/dev/null bs=256 count=1 iflag=nonblock 2>/dev/null || true
    local end_time=$(date +%s.%N)
    local random_duration=$(echo "${end_time} - ${start_time}" | bc)
    details+="/dev/random 256 bytes: ${random_duration}s\n"
    
    echo -e "$details"
    add_test_result "entropy_generation_rate" "$status" "$(echo -e "$details")"
    
    log_pass "TEST 4.1.3 PASSED"
}

#-------------------------------------------------------------------------------
# TEST 4.1.4: System Call Tracing for Entropy Usage
#-------------------------------------------------------------------------------
test_entropy_syscall_trace() {
    log_info "TEST 4.1.4: Tracing system calls for entropy source usage"
    
    local status="PASS"
    local details=""
    local trace_file="${SECTION_DIR}/entropy_strace.txt"
    
    if ! command -v strace &>/dev/null; then
        status="SKIP"
        details="strace not available - skipping syscall trace test"
        add_test_result "entropy_syscall_trace" "$status" "$details"
        log_warn "TEST 4.1.4 SKIPPED"
        return
    fi
    
    # Trace openssl generating random data
    log_info "Tracing OpenSSL random generation..."
    strace -f -e trace=openat,read -o "${trace_file}" \
        openssl rand -out /dev/null 1024 2>&1 || true
    
    # Analyze the trace
    if grep -q "/dev/random\|/dev/urandom\|getrandom" "${trace_file}"; then
        details+="✓ Detected entropy source access in trace\n"
        
        # Count accesses
        local random_count=$(grep -c "/dev/random" "${trace_file}" 2>/dev/null || echo "0")
        local urandom_count=$(grep -c "/dev/urandom" "${trace_file}" 2>/dev/null || echo "0")
        
        details+="  /dev/random accesses: ${random_count}\n"
        details+="  /dev/urandom accesses: ${urandom_count}\n"
    else
        details+="⚠ No direct /dev/random or /dev/urandom access detected\n"
        details+="  (May use getrandom() syscall instead)\n"
    fi
    
    # Check for getrandom syscall usage
    if grep -q "getrandom" "${trace_file}"; then
        local getrandom_count=$(grep -c "getrandom" "${trace_file}" 2>/dev/null || echo "0")
        details+="  getrandom() calls: ${getrandom_count}\n"
    fi
    
    echo -e "$details"
    add_test_result "entropy_syscall_trace" "$status" "$(echo -e "$details")"
    
    log_pass "TEST 4.1.4 PASSED"
}

#-------------------------------------------------------------------------------
# TEST 4.1.5: Quantum Origin Detection (if enabled)
#-------------------------------------------------------------------------------
test_quantum_origin_detection() {
    log_info "TEST 4.1.5: Detecting Quantum Origin integration"
    
    local status="INFO"
    local details=""
    
    # Check for QO-specific services
    local qo_services=("qo-entropy" "quantum-origin" "qo-daemon")
    local found_service=""
    
    for svc in "${qo_services[@]}"; do
        if systemctl list-units --type=service --all 2>/dev/null | grep -q "${svc}"; then
            found_service="${svc}"
            if systemctl is-active --quiet "${svc}" 2>/dev/null; then
                details+="✓ Quantum Origin service '${svc}' is active\n"
                status="PASS"
            else
                details+="⚠ Quantum Origin service '${svc}' found but not active\n"
                status="WARN"
            fi
            break
        fi
    done
    
    if [[ -z "$found_service" ]]; then
        details+="No Quantum Origin service detected\n"
        details+="This may be expected in baseline configuration\n"
    fi
    
    # Check for QO-related files
    local qo_paths=(
        "/etc/quantum-origin"
        "/var/lib/quantum-origin"
        "/opt/quantinuum"
        "/usr/local/lib/qo"
    )
    
    for path in "${qo_paths[@]}"; do
        if [[ -d "$path" || -f "$path" ]]; then
            details+="Found QO path: ${path}\n"
        fi
    done
    
    # Check for QO seed file
    if [[ -f "/var/lib/quantum-origin/seed" || -f "/etc/quantum-origin/seed.bin" ]]; then
        details+="✓ Quantum seed file detected\n"
    fi
    
    # Check dmesg for QO-related messages
    if dmesg 2>/dev/null | grep -qi "quantum\|qo\|quantinuum"; then
        details+="Kernel messages mention quantum-related terms\n"
        dmesg 2>/dev/null | grep -i "quantum\|qo\|quantinuum" | head -5 >> "${SECTION_DIR}/dmesg_qo.txt"
    fi
    
    # Record QO_ENABLED environment
    details+="QO_ENABLED environment: ${QO_ENABLED:-not set}\n"
    
    echo -e "$details"
    add_test_result "quantum_origin_detection" "$status" "$(echo -e "$details")"
    
    log_info "TEST 4.1.5 COMPLETE (informational)"
}

#-------------------------------------------------------------------------------
# TEST 4.1.6: rngtest Statistical Tests
#-------------------------------------------------------------------------------
test_rngtest_statistical() {
    log_info "TEST 4.1.6: Running rngtest statistical tests"
    
    local status="PASS"
    local details=""
    local rngtest_output="${SECTION_DIR}/rngtest_output.txt"
    
    if ! command -v rngtest &>/dev/null; then
        # Try to find rngtest in common locations
        if [[ -x /usr/bin/rngtest ]] || [[ -x /usr/sbin/rngtest ]]; then
            :
        else
            status="SKIP"
            details="rngtest not available - install rng-tools package"
            add_test_result "rngtest_statistical" "$status" "$details"
            log_warn "TEST 4.1.6 SKIPPED"
            return
        fi
    fi
    
    log_info "Running FIPS 140-2 statistical tests on /dev/urandom..."
    
    # Generate 2.5MB of random data (enough for rngtest)
    dd if=/dev/urandom bs=2500 count=1000 2>/dev/null | rngtest -c 1000 2>&1 | tee "${rngtest_output}"
    
    # Parse results
    local success_count=$(grep -oP 'successes:\s*\K\d+' "${rngtest_output}" 2>/dev/null || echo "0")
    local failure_count=$(grep -oP 'failures:\s*\K\d+' "${rngtest_output}" 2>/dev/null || echo "0")
    
    details+="rngtest Results:\n"
    details+="  Successes: ${success_count}\n"
    details+="  Failures: ${failure_count}\n"
    
    # Calculate failure rate
    if [[ ${success_count} -gt 0 ]]; then
        local total=$((success_count + failure_count))
        local fail_rate=$(echo "scale=4; ${failure_count} * 100 / ${total}" | bc)
        details+="  Failure rate: ${fail_rate}%\n"
        
        # Fail rate should be very low (< 1%)
        if (( $(echo "${fail_rate} > 1.0" | bc -l) )); then
            status="WARN"
            details+="⚠ Failure rate above 1% - investigate\n"
        else
            details+="✓ Failure rate within acceptable limits\n"
        fi
    fi
    
    echo -e "$details"
    add_test_result "rngtest_statistical" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.1.6 PASSED" || log_warn "TEST 4.1.6 WARNING"
}

#-------------------------------------------------------------------------------
# TEST 4.1.7: Entropy Under Load
#-------------------------------------------------------------------------------
test_entropy_under_load() {
    log_info "TEST 4.1.7: Testing entropy availability under load"
    
    local status="PASS"
    local details=""
    local load_results="${SECTION_DIR}/entropy_load_test.csv"
    
    echo "timestamp,entropy_avail,load_type" > "${load_results}"
    
    # Record initial entropy
    local initial_entropy=$(cat /proc/sys/kernel/random/entropy_avail)
    details+="Initial entropy: ${initial_entropy} bits\n"
    
    # Consume entropy heavily while monitoring
    log_info "Consuming entropy while monitoring pool levels..."
    
    (
        # Background process consuming entropy
        for i in $(seq 1 10); do
            dd if=/dev/urandom of=/dev/null bs=1M count=10 2>/dev/null
            sleep 0.5
        done
    ) &
    local consumer_pid=$!
    
    # Monitor entropy during consumption
    local min_during=999999
    for i in $(seq 1 20); do
        local current=$(cat /proc/sys/kernel/random/entropy_avail)
        echo "$(date +%s),${current},consuming" >> "${load_results}"
        if [[ ${current} -lt ${min_during} ]]; then
            min_during=${current}
        fi
        sleep 0.5
    done
    
    wait ${consumer_pid} 2>/dev/null || true
    
    details+="Minimum during load: ${min_during} bits\n"
    
    # Wait for recovery
    sleep 2
    local recovered_entropy=$(cat /proc/sys/kernel/random/entropy_avail)
    details+="Recovered entropy: ${recovered_entropy} bits\n"
    
    # Assess
    if [[ ${min_during} -gt 64 ]]; then
        details+="✓ Entropy pool remained above critical threshold under load\n"
    else
        status="WARN"
        details+="⚠ Entropy dropped below 64 bits during heavy consumption\n"
    fi
    
    echo -e "$details"
    add_test_result "entropy_under_load" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.1.7 PASSED" || log_warn "TEST 4.1.7 WARNING"
}

#-------------------------------------------------------------------------------
# TEST 4.1.8: Kernel Entropy Source Identification
#-------------------------------------------------------------------------------
test_kernel_entropy_sources() {
    log_info "TEST 4.1.8: Identifying kernel entropy input sources"
    
    local status="INFO"
    local details=""
    local sources_file="${SECTION_DIR}/entropy_sources.txt"
    
    # Check for hardware RNG
    if [[ -c /dev/hwrng ]]; then
        details+="✓ Hardware RNG device available (/dev/hwrng)\n"
        ls -la /dev/hwrng >> "${sources_file}" 2>&1
    else
        details+="Hardware RNG device not present\n"
    fi
    
    # Check rngd status
    if systemctl is-active --quiet rngd 2>/dev/null; then
        details+="✓ rngd service is active\n"
        systemctl status rngd 2>&1 | head -10 >> "${sources_file}"
    else
        details+="rngd service not active\n"
    fi
    
    # Check for CPU RDRAND/RDSEED
    if grep -q "rdrand\|rdseed" /proc/cpuinfo 2>/dev/null; then
        details+="✓ CPU supports RDRAND/RDSEED instructions\n"
        grep -E "rdrand|rdseed" /proc/cpuinfo | head -1 >> "${sources_file}"
    else
        details+="CPU RDRAND/RDSEED not detected\n"
    fi
    
    # Check for TPM
    if [[ -c /dev/tpm0 || -c /dev/tpmrm0 ]]; then
        details+="✓ TPM device available\n"
    else
        details+="TPM device not present\n"
    fi
    
    # Check kernel random initialization
    if [[ -f /proc/sys/kernel/random/uuid ]]; then
        local uuid=$(cat /proc/sys/kernel/random/uuid)
        details+="Kernel random UUID generation working\n"
    fi
    
    # List available entropy sources from sysfs if available
    if [[ -d /sys/devices/virtual/misc/hw_random ]]; then
        details+="Hardware random device info available in sysfs\n"
        find /sys/devices/virtual/misc/hw_random -type f -exec sh -c 'echo "{}:"; cat "{}"' \; >> "${sources_file}" 2>/dev/null || true
    fi
    
    echo -e "$details"
    add_test_result "kernel_entropy_sources" "$status" "$(echo -e "$details")"
    
    log_info "TEST 4.1.8 COMPLETE (informational)"
}

#-------------------------------------------------------------------------------
# Main Execution
#-------------------------------------------------------------------------------
main() {
    echo ""
    echo "=============================================================================="
    echo "SECTION 4.1: SYSTEM ENTROPY SOURCE TESTS"
    echo "=============================================================================="
    echo ""
    
    init_results
    
    test_dev_random_availability
    test_entropy_pool_metrics
    test_entropy_generation_rate
    test_entropy_syscall_trace
    test_quantum_origin_detection
    test_rngtest_statistical
    test_entropy_under_load
    test_kernel_entropy_sources
    
    # Finalize results
    local tmp_file=$(mktemp)
    jq '.end_time = "'"$(date -Iseconds)"'"' "${SECTION_RESULTS}" > "${tmp_file}" && mv "${tmp_file}" "${SECTION_RESULTS}"
    
    echo ""
    echo "Section 4.1 tests complete. Results: ${SECTION_RESULTS}"
}

main "$@"
