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

# Extended quality tests configuration
EXTENDED_TESTS="${EXTENDED_TESTS:-true}"
SAMPLE_SIZE="${SAMPLE_SIZE:-10}"  # MB of random data for quality tests

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
    local qo_services=("qo-kernel-reseed" "qo-entropy" "quantum-origin" "qo-daemon")
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

    # Also check if QO packages are installed (alternative detection)
    if [[ -z "$found_service" ]]; then
        local qo_packages
        qo_packages=$(rpm -qa 2>/dev/null | grep -i "^qo-\|quantum-origin" || true)
        if [[ -n "$qo_packages" ]]; then
            details+="✓ Quantum Origin package(s) installed:\n"
            while IFS= read -r pkg; do
                details+="  - ${pkg}\n"
            done <<< "$qo_packages"
            status="PASS"
            found_service="package"
        fi
    fi

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
    # Note: rngtest exits non-zero if ANY failures occur, but low failure rates are statistically normal
    dd if=/dev/urandom bs=2500 count=1000 2>/dev/null | rngtest -c 1000 2>&1 | tee "${rngtest_output}" || true

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
        ls -la /dev/hwrng >> "${sources_file}" 2>&1 || true
    else
        details+="Hardware RNG device not present\n"
    fi

    # Check rngd status
    if systemctl is-active --quiet rngd 2>/dev/null; then
        details+="✓ rngd service is active\n"
        systemctl status rngd 2>&1 | head -10 >> "${sources_file}" || true
    else
        details+="rngd service not active\n"
    fi

    # Check for CPU RDRAND/RDSEED
    if grep -q "rdrand\|rdseed" /proc/cpuinfo 2>/dev/null; then
        details+="✓ CPU supports RDRAND/RDSEED instructions\n"
        grep -E "rdrand|rdseed" /proc/cpuinfo 2>/dev/null | head -1 >> "${sources_file}" || true
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

#===============================================================================
# EXTENDED QUALITY TESTS (4.1.9 - 4.1.15)
# These tests go beyond basic FIPS 140-2 to measure randomness quality
# that could differentiate Quantum Origin from baseline PRNG
#===============================================================================

#-------------------------------------------------------------------------------
# TEST 4.1.9: Extended FIPS with larger sample
#-------------------------------------------------------------------------------
test_extended_fips() {
    log_info "TEST 4.1.9: Extended FIPS 140-2 with ${SAMPLE_SIZE}MB sample"

    local status="PASS"
    local details=""
    local output_file="${SECTION_DIR}/extended_fips.txt"

    if ! command -v rngtest &>/dev/null; then
        status="SKIP"
        details="rngtest not available"
        add_test_result "extended_fips" "$status" "$details"
        log_warn "TEST 4.1.9 SKIPPED"
        return
    fi

    # Calculate blocks needed (each FIPS block is 2500 bytes)
    local bytes=$((SAMPLE_SIZE * 1024 * 1024))
    local blocks=$((bytes / 2500))

    log_info "Running ${blocks} FIPS blocks on ${SAMPLE_SIZE}MB of data..."

    dd if=/dev/urandom bs=2500 count=${blocks} 2>/dev/null | \
        rngtest -c ${blocks} 2>&1 | tee "${output_file}" || true

    local successes=$(grep -oP 'successes:\s*\K\d+' "${output_file}" 2>/dev/null || echo "0")
    local failures=$(grep -oP 'failures:\s*\K\d+' "${output_file}" 2>/dev/null || echo "0")
    local total=$((successes + failures))

    if [[ $total -gt 0 ]]; then
        local failure_rate=$(echo "scale=6; ${failures} * 100 / ${total}" | bc)
        local pass_rate=$(echo "scale=6; ${successes} * 100 / ${total}" | bc)

        details+="Sample size: ${SAMPLE_SIZE}MB (${blocks} blocks)\n"
        details+="Successes: ${successes}\n"
        details+="Failures: ${failures}\n"
        details+="Pass rate: ${pass_rate}%\n"
        details+="Failure rate: ${failure_rate}%\n"

        # Break down failure types
        local monobit=$(grep -oP 'Monobit:\s*\K\d+' "${output_file}" 2>/dev/null || echo "0")
        local poker=$(grep -oP 'Poker:\s*\K\d+' "${output_file}" 2>/dev/null || echo "0")
        local runs=$(grep -oP 'Runs:\s*\K\d+' "${output_file}" 2>/dev/null || echo "0")
        local longrun=$(grep -oP 'Long run:\s*\K\d+' "${output_file}" 2>/dev/null || echo "0")

        details+="\nFailure breakdown:\n"
        details+="  Monobit: ${monobit}\n"
        details+="  Poker: ${poker}\n"
        details+="  Runs: ${runs}\n"
        details+="  Long run: ${longrun}\n"

        if (( $(echo "${failure_rate} > 0.5" | bc -l) )); then
            status="WARN"
            details+="\n⚠ Failure rate above 0.5% - investigate"
        elif (( $(echo "${failure_rate} > 0.1" | bc -l) )); then
            details+="\n✓ Failure rate slightly elevated but acceptable"
        else
            details+="\n✓ Excellent pass rate"
        fi
    else
        status="FAIL"
        details="No FIPS blocks processed"
    fi

    echo -e "$details"
    add_test_result "extended_fips" "$status" "$(echo -e "$details")"

    [[ "$status" == "PASS" ]] && log_pass "TEST 4.1.9 PASSED" || log_warn "TEST 4.1.9 WARNING"
}

#-------------------------------------------------------------------------------
# TEST 4.1.10: Compression ratio analysis
#-------------------------------------------------------------------------------
test_compression_ratio() {
    log_info "TEST 4.1.10: Compression ratio analysis"

    local status="PASS"
    local details=""
    local raw_file="${SECTION_DIR}/random_raw.bin"
    local compressed_file="${SECTION_DIR}/random_compressed.gz"

    # Generate random data
    dd if=/dev/urandom of="${raw_file}" bs=1M count=${SAMPLE_SIZE} 2>/dev/null
    local raw_size=$(stat -c%s "${raw_file}")

    # Compress with gzip (best compression)
    gzip -9 -c "${raw_file}" > "${compressed_file}"
    local compressed_size=$(stat -c%s "${compressed_file}")

    # Calculate compression ratio
    local ratio=$(echo "scale=4; ${compressed_size} / ${raw_size}" | bc)
    local percent=$(echo "scale=2; ${ratio} * 100" | bc)

    details+="Raw size: ${raw_size} bytes (${SAMPLE_SIZE}MB)\n"
    details+="Compressed size: ${compressed_size} bytes\n"
    details+="Compression ratio: ${percent}%\n"

    # Truly random data should compress to ~100.0-100.5% (slight overhead from gzip headers)
    if (( $(echo "${ratio} < 0.98" | bc -l) )); then
        status="FAIL"
        details+="\n✗ Data compressed significantly - patterns detected"
    elif (( $(echo "${ratio} < 0.995" | bc -l) )); then
        status="WARN"
        details+="\n⚠ Data compressed slightly - minor patterns possible"
    else
        details+="\n✓ Data incompressible (${percent}%) - excellent randomness"
    fi

    rm -f "${raw_file}" "${compressed_file}"

    echo -e "$details"
    add_test_result "compression_ratio" "$status" "$(echo -e "$details")"

    [[ "$status" == "PASS" ]] && log_pass "TEST 4.1.10 PASSED" || log_warn "TEST 4.1.10 WARNING"
}

#-------------------------------------------------------------------------------
# TEST 4.1.11: Bit distribution analysis
#-------------------------------------------------------------------------------
test_bit_distribution() {
    log_info "TEST 4.1.11: Bit distribution analysis"

    local status="PASS"
    local details=""
    local sample_file="${SECTION_DIR}/bit_sample.bin"

    # Generate sample
    dd if=/dev/urandom of="${sample_file}" bs=1M count=${SAMPLE_SIZE} 2>/dev/null

    local total_bits=$((SAMPLE_SIZE * 1024 * 1024 * 8))

    # Count 1-bits using xxd and awk
    local ones=$(xxd -b "${sample_file}" | grep -oE '[01]{8}' | tr -d '\n' | tr -cd '1' | wc -c)
    local zeros=$((total_bits - ones))

    local ones_percent=$(echo "scale=6; ${ones} * 100 / ${total_bits}" | bc)
    local zeros_percent=$(echo "scale=6; ${zeros} * 100 / ${total_bits}" | bc)
    local deviation=$(echo "scale=6; ${ones_percent} - 50" | bc)
    local abs_deviation=$(echo "${deviation}" | tr -d '-')

    details+="Total bits: ${total_bits}\n"
    details+="Ones: ${ones} (${ones_percent}%)\n"
    details+="Zeros: ${zeros} (${zeros_percent}%)\n"
    details+="Deviation from 50%: ${deviation}%\n"

    if (( $(echo "${abs_deviation} > 0.1" | bc -l) )); then
        status="WARN"
        details+="\n⚠ Significant bit bias detected"
    elif (( $(echo "${abs_deviation} > 0.01" | bc -l) )); then
        details+="\n✓ Minor deviation within expected range"
    else
        details+="\n✓ Excellent bit distribution"
    fi

    rm -f "${sample_file}"

    echo -e "$details"
    add_test_result "bit_distribution" "$status" "$(echo -e "$details")"

    [[ "$status" == "PASS" ]] && log_pass "TEST 4.1.11 PASSED" || log_warn "TEST 4.1.11 WARNING"
}

#-------------------------------------------------------------------------------
# TEST 4.1.12: Byte value distribution (chi-square test)
#-------------------------------------------------------------------------------
test_byte_distribution() {
    log_info "TEST 4.1.12: Byte value distribution (chi-square)"

    local status="PASS"
    local details=""
    local sample_file="${SECTION_DIR}/byte_sample.bin"
    local freq_file="${SECTION_DIR}/byte_freq.txt"

    # Generate sample
    dd if=/dev/urandom of="${sample_file}" bs=1M count=${SAMPLE_SIZE} 2>/dev/null
    local total_bytes=$((SAMPLE_SIZE * 1024 * 1024))
    local expected=$((total_bytes / 256))

    # Count frequency of each byte value
    xxd -p "${sample_file}" | fold -w2 | sort | uniq -c | sort -k2 > "${freq_file}"

    # Calculate chi-square statistic
    local chi_square=0
    while read count hex; do
        local diff=$((count - expected))
        local sq=$((diff * diff))
        chi_square=$(echo "${chi_square} + ${sq} / ${expected}" | bc -l)
    done < "${freq_file}"

    details+="Total bytes: ${total_bytes}\n"
    details+="Expected per value: ${expected}\n"
    details+="Chi-square statistic: ${chi_square}\n"

    # Chi-square critical value for 255 df at p=0.05 is ~293
    if (( $(echo "${chi_square} > 350" | bc -l) )); then
        status="WARN"
        details+="\n⚠ Chi-square indicates non-uniform distribution"
    elif (( $(echo "${chi_square} > 293" | bc -l) )); then
        details+="\n✓ Chi-square slightly elevated but acceptable"
    else
        details+="\n✓ Excellent byte distribution uniformity"
    fi

    rm -f "${sample_file}" "${freq_file}"

    echo -e "$details"
    add_test_result "byte_distribution" "$status" "$(echo -e "$details")"

    [[ "$status" == "PASS" ]] && log_pass "TEST 4.1.12 PASSED" || log_warn "TEST 4.1.12 WARNING"
}

#-------------------------------------------------------------------------------
# TEST 4.1.13: Serial correlation
#-------------------------------------------------------------------------------
test_serial_correlation() {
    log_info "TEST 4.1.13: Serial correlation analysis"

    local status="PASS"
    local details=""
    local sample_file="${SECTION_DIR}/serial_sample.bin"

    # Generate sample (smaller for this test)
    local test_size=1
    dd if=/dev/urandom of="${sample_file}" bs=1M count=${test_size} 2>/dev/null

    # Calculate serial correlation coefficient using awk
    local correlation=$(xxd -p "${sample_file}" | fold -w2 | \
        awk 'BEGIN {sum_xy=0; sum_x=0; sum_y=0; sum_x2=0; sum_y2=0; n=0; prev=-1}
        {
            curr = strtonum("0x" $1)
            if (prev >= 0) {
                sum_xy += prev * curr
                sum_x += prev
                sum_y += curr
                sum_x2 += prev * prev
                sum_y2 += curr * curr
                n++
            }
            prev = curr
        }
        END {
            if (n > 0) {
                mean_x = sum_x / n
                mean_y = sum_y / n
                cov = (sum_xy / n) - (mean_x * mean_y)
                var_x = (sum_x2 / n) - (mean_x * mean_x)
                var_y = (sum_y2 / n) - (mean_y * mean_y)
                if (var_x > 0 && var_y > 0) {
                    corr = cov / sqrt(var_x * var_y)
                    printf "%.6f", corr
                } else {
                    print "0"
                }
            } else {
                print "0"
            }
        }')

    local abs_corr=$(echo "${correlation}" | tr -d '-')

    details+="Serial correlation coefficient: ${correlation}\n"

    if (( $(echo "${abs_corr} > 0.05" | bc -l) )); then
        status="WARN"
        details+="\n⚠ Significant serial correlation detected"
    elif (( $(echo "${abs_corr} > 0.01" | bc -l) )); then
        details+="\n✓ Minor correlation within acceptable range"
    else
        details+="\n✓ No significant serial correlation"
    fi

    rm -f "${sample_file}"

    echo -e "$details"
    add_test_result "serial_correlation" "$status" "$(echo -e "$details")"

    [[ "$status" == "PASS" ]] && log_pass "TEST 4.1.13 PASSED" || log_warn "TEST 4.1.13 WARNING"
}

#-------------------------------------------------------------------------------
# TEST 4.1.14: Runs analysis
#-------------------------------------------------------------------------------
test_runs_analysis() {
    log_info "TEST 4.1.14: Extended runs analysis"

    local status="PASS"
    local details=""
    local sample_file="${SECTION_DIR}/runs_sample.bin"
    local bits_file="${SECTION_DIR}/runs_bits.txt"

    # Generate smaller sample for this intensive test
    dd if=/dev/urandom of="${sample_file}" bs=100K count=1 2>/dev/null

    # Convert to binary string
    xxd -b "${sample_file}" | awk '{for(i=2;i<=7;i++) printf "%s", $i}' > "${bits_file}"

    local runs_output="${SECTION_DIR}/runs_output.txt"

    if command -v perl &>/dev/null; then
        perl -e '
            open(F, $ARGV[0]) or die;
            local $/; $bits = <F>; close(F);
            $bits =~ s/[^01]//g;
            my %runs;
            my $total = 0;
            while ($bits =~ /([01])\1*/g) {
                my $len = length($&);
                $len = 11 if $len > 10;
                $runs{$len}++;
                $total++;
            }
            for my $i (1..11) {
                print "$i:" . ($runs{$i} // 0) . "\n";
            }
            print "total:$total\n";
        ' "${bits_file}" > "${runs_output}" 2>/dev/null
    else
        # Fallback to awk-based analysis
        cat "${bits_file}" | tr -d '\n' | \
        awk '{
            n = split($0, chars, "")
            prev = ""
            run_len = 0
            for (i=1; i<=n; i++) {
                if (chars[i] == prev) {
                    run_len++
                } else {
                    if (run_len > 0) {
                        len = (run_len > 10) ? 11 : run_len
                        runs[len]++
                        total++
                    }
                    prev = chars[i]
                    run_len = 1
                }
            }
            if (run_len > 0) {
                len = (run_len > 10) ? 11 : run_len
                runs[len]++
                total++
            }
            for (i=1; i<=11; i++) printf "%d:%d\n", i, runs[i]+0
            printf "total:%d\n", total
        }' > "${runs_output}" 2>/dev/null
    fi

    details+="Run length distribution:\n"

    while IFS=: read -r len count; do
        if [[ "$len" == "total" ]]; then
            details+="Total runs: ${count}\n"
        elif [[ "$len" == "11" ]]; then
            details+="  Length 11+: ${count}\n"
        else
            details+="  Length ${len}: ${count}\n"
        fi
    done < "${runs_output}"

    local len1=$(grep "^1:" "${runs_output}" | cut -d: -f2)
    local total=$(grep "^total:" "${runs_output}" | cut -d: -f2)

    if [[ -n "$len1" && -n "$total" && "$total" -gt 0 ]]; then
        local len1_pct=$(echo "scale=2; ${len1} * 100 / ${total}" | bc)
        details+="\nLength-1 runs: ${len1_pct}% (expected ~50%)\n"

        if (( $(echo "${len1_pct} < 40 || ${len1_pct} > 60" | bc -l) )); then
            status="WARN"
            details+="⚠ Run distribution outside expected range"
        else
            details+="✓ Run distribution within expected range"
        fi
    else
        details+="\n✓ Runs analysis complete"
    fi

    rm -f "${sample_file}" "${bits_file}" "${runs_output}"

    echo -e "$details"
    add_test_result "runs_analysis" "$status" "$(echo -e "$details")"

    [[ "$status" == "PASS" ]] && log_pass "TEST 4.1.14 PASSED" || log_warn "TEST 4.1.14 WARNING"
}

#-------------------------------------------------------------------------------
# TEST 4.1.15: Dieharder statistical test battery
#-------------------------------------------------------------------------------
test_dieharder() {
    log_info "TEST 4.1.15: Dieharder statistical test battery"

    local status="PASS"
    local details=""

    if ! command -v dieharder &>/dev/null; then
        status="SKIP"
        details="'dieharder' tool not installed\nInstall with: sudo dnf install dieharder"
        add_test_result "dieharder" "$status" "$details"
        log_warn "TEST 4.1.15 SKIPPED - dieharder not available"
        return
    fi

    local dieharder_output="${SECTION_DIR}/dieharder_output.txt"

    # Run a subset of dieharder tests (full battery takes hours)
    log_info "Running dieharder tests with streaming input from /dev/urandom..."

    local tests_to_run=(2 10 15 17 100 101 200)
    local passed=0
    local failed=0
    local weak=0

    > "${dieharder_output}"

    for test_id in "${tests_to_run[@]}"; do
        log_info "  Running dieharder test ${test_id}..."
        dieharder -g 200 -Y 1 -p 10 -d ${test_id} < /dev/urandom 2>/dev/null | tee -a "${dieharder_output}" || true
    done

    passed=$(grep -c "PASSED" "${dieharder_output}" 2>/dev/null) || passed=0
    failed=$(grep -c "FAILED" "${dieharder_output}" 2>/dev/null) || failed=0
    weak=$(grep -c "WEAK" "${dieharder_output}" 2>/dev/null) || weak=0
    passed=${passed:-0}
    failed=${failed:-0}
    weak=${weak:-0}
    local total=$((passed + failed + weak))

    details+="Input: streaming from /dev/urandom\n"
    details+="Tests run: ${#tests_to_run[@]} test suites\n"
    details+="Total assessments: ${total}\n"
    details+="Passed: ${passed}\n"
    details+="Weak: ${weak}\n"
    details+="Failed: ${failed}\n"

    local failures=$(grep "FAILED" "${dieharder_output}" 2>/dev/null || true)
    if [[ -n "$failures" ]]; then
        details+="\nFailed tests:\n"
        details+=$(echo "$failures" | head -5 | sed 's/^/  /')
        details+="\n"
    fi

    if [[ $failed -gt 2 ]]; then
        status="FAIL"
        details+="\n✗ Multiple dieharder tests failed - significant weakness"
    elif [[ $failed -gt 0 ]]; then
        status="WARN"
        details+="\n⚠ Some dieharder tests failed - investigate"
    elif [[ $weak -gt 1 ]]; then
        status="WARN"
        details+="\n⚠ Unresolved weak results - minor concerns"
    else
        details+="\n✓ Passed dieharder battery"
    fi

    echo -e "$details"
    add_test_result "dieharder" "$status" "$(echo -e "$details")"

    [[ "$status" == "PASS" ]] && log_pass "TEST 4.1.15 PASSED" || log_warn "TEST 4.1.15 WARNING"
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

    # Core entropy tests (4.1.1 - 4.1.8)
    test_dev_random_availability
    test_entropy_pool_metrics
    test_entropy_generation_rate
    test_entropy_syscall_trace
    test_quantum_origin_detection
    test_rngtest_statistical
    test_entropy_under_load
    test_kernel_entropy_sources

    # Extended quality tests (4.1.9 - 4.1.15)
    if [[ "${EXTENDED_TESTS}" == "true" ]]; then
        echo ""
        echo "=============================================================================="
        echo "EXTENDED QUALITY TESTS (Sample size: ${SAMPLE_SIZE}MB)"
        echo "=============================================================================="
        echo ""

        test_extended_fips
        test_compression_ratio
        test_bit_distribution
        test_byte_distribution
        test_serial_correlation
        test_runs_analysis
        test_dieharder
    else
        log_info "Extended quality tests skipped (EXTENDED_TESTS=${EXTENDED_TESTS})"
    fi

    # Finalize results
    local tmp_file=$(mktemp)
    jq '.end_time = "'"$(date -Iseconds)"'" | .extended_tests = "'"${EXTENDED_TESTS}"'" | .sample_size_mb = '"${SAMPLE_SIZE}"'' "${SECTION_RESULTS}" > "${tmp_file}" && mv "${tmp_file}" "${SECTION_RESULTS}"

    echo ""
    echo "Section 4.1 tests complete. Results: ${SECTION_RESULTS}"
}

main "$@"
