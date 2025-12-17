#!/bin/bash
#===============================================================================
# UNIFIED REPORT GENERATOR
# Generates a side-by-side comparison report of baseline vs QO test results
# with What/Why/How documentation for each test section
#===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASELINE_DIR="${SCRIPT_DIR}/results/baseline"
QO_DIR="${SCRIPT_DIR}/results/qo"
OUTPUT_FILE="${SCRIPT_DIR}/results/unified_report.md"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

#-------------------------------------------------------------------------------
# Utility Functions
#-------------------------------------------------------------------------------
log_info()  { echo -e "[INFO] $*"; }
log_error() { echo -e "${RED}[ERROR] $*${NC}"; }
log_pass()  { echo -e "${GREEN}[OK] $*${NC}"; }

check_dependencies() {
    local missing=()
    for cmd in jq bc; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing[*]}"
        exit 1
    fi
}

#-------------------------------------------------------------------------------
# Extract test results from JSON
#-------------------------------------------------------------------------------
get_test_status() {
    local json_file="$1"
    local test_name="$2"
    if [[ -f "$json_file" ]]; then
        jq -r --arg name "$test_name" '.tests[] | select(.name == $name) | .status // "N/A"' "$json_file" 2>/dev/null || echo "N/A"
    else
        echo "N/A"
    fi
}

get_test_count() {
    local json_file="$1"
    local status="$2"
    if [[ -f "$json_file" ]]; then
        jq -r --arg status "$status" '[.tests[] | select(.status == $status)] | length' "$json_file" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

get_total_tests() {
    local json_file="$1"
    if [[ -f "$json_file" ]]; then
        jq -r '.tests | length' "$json_file" 2>/dev/null || echo "0"
    else
        echo "0"
    fi
}

extract_metric() {
    local json_file="$1"
    local test_name="$2"
    local pattern="$3"
    if [[ -f "$json_file" ]]; then
        local details=$(jq -r --arg name "$test_name" '.tests[] | select(.name == $name) | .details // ""' "$json_file" 2>/dev/null)
        echo "$details" | grep -oP "$pattern" | head -1 || echo "N/A"
    else
        echo "N/A"
    fi
}

#-------------------------------------------------------------------------------
# Generate Section Header
#-------------------------------------------------------------------------------
generate_section_header() {
    local section_num="$1"
    local section_name="$2"
    local what="$3"
    local why="$4"
    local how="$5"

    cat << EOF

---

## Section ${section_num}: ${section_name}

### What
${what}

### Why
${why}

### How
${how}

### Results

EOF
}

#-------------------------------------------------------------------------------
# Generate Comparison Table
#-------------------------------------------------------------------------------
generate_comparison_table() {
    local baseline_json="$1"
    local qo_json="$2"

    echo "| Test | Baseline | QO | Status |"
    echo "|------|----------|-----|--------|"

    # Get all test names from both files
    local tests=""
    if [[ -f "$baseline_json" ]]; then
        tests=$(jq -r '.tests[].name' "$baseline_json" 2>/dev/null | sort -u)
    fi
    if [[ -f "$qo_json" ]]; then
        tests=$(echo -e "$tests\n$(jq -r '.tests[].name' "$qo_json" 2>/dev/null)" | sort -u)
    fi

    for test_name in $tests; do
        local baseline_status=$(get_test_status "$baseline_json" "$test_name")
        local qo_status=$(get_test_status "$qo_json" "$test_name")

        # Determine overall status
        local overall=""
        if [[ "$baseline_status" == "PASS" && "$qo_status" == "PASS" ]]; then
            overall="✅ Both Pass"
        elif [[ "$baseline_status" == "PASS" && "$qo_status" != "PASS" ]]; then
            overall="⚠️ QO Regression"
        elif [[ "$baseline_status" != "PASS" && "$qo_status" == "PASS" ]]; then
            overall="✅ QO Improved"
        elif [[ "$baseline_status" == "SKIP" || "$qo_status" == "SKIP" ]]; then
            overall="⏭️ Skipped"
        elif [[ "$baseline_status" == "INFO" || "$qo_status" == "INFO" ]]; then
            overall="ℹ️ Info"
        else
            overall="⚠️ Review"
        fi

        # Format test name for display
        local display_name=$(echo "$test_name" | sed 's/_/ /g' | sed 's/\b\(.\)/\u\1/g')

        echo "| ${display_name} | ${baseline_status} | ${qo_status} | ${overall} |"
    done
}

#-------------------------------------------------------------------------------
# Calculate Statistics
#-------------------------------------------------------------------------------
calculate_stats() {
    local dir="$1"
    local total_pass=0
    local total_fail=0
    local total_warn=0
    local total_skip=0
    local total_tests=0

    for section in entropy crypto storage network vm; do
        local json_file="${dir}/${section}/results.json"
        if [[ -f "$json_file" ]]; then
            total_pass=$((total_pass + $(get_test_count "$json_file" "PASS")))
            total_fail=$((total_fail + $(get_test_count "$json_file" "FAIL")))
            total_warn=$((total_warn + $(get_test_count "$json_file" "WARN")))
            total_skip=$((total_skip + $(get_test_count "$json_file" "SKIP")))
            total_tests=$((total_tests + $(get_total_tests "$json_file")))
        fi
    done

    echo "${total_tests}:${total_pass}:${total_fail}:${total_warn}:${total_skip}"
}

#-------------------------------------------------------------------------------
# Main Report Generation
#-------------------------------------------------------------------------------
generate_report() {
    log_info "Generating unified report..."

    # Check if results exist
    if [[ ! -d "$BASELINE_DIR" ]]; then
        log_error "Baseline results not found at: $BASELINE_DIR"
        log_info "Run: ./run_all.sh baseline"
        exit 1
    fi

    if [[ ! -d "$QO_DIR" ]]; then
        log_error "QO results not found at: $QO_DIR"
        log_info "Run: ./run_all.sh qo"
        exit 1
    fi

    # Create results directory if needed
    mkdir -p "$(dirname "$OUTPUT_FILE")"

    # Calculate statistics
    local baseline_stats=$(calculate_stats "$BASELINE_DIR")
    local qo_stats=$(calculate_stats "$QO_DIR")

    IFS=':' read -r b_total b_pass b_fail b_warn b_skip <<< "$baseline_stats"
    IFS=':' read -r q_total q_pass q_fail q_warn q_skip <<< "$qo_stats"

    local b_pass_rate=0
    local q_pass_rate=0
    if [[ $b_total -gt 0 ]]; then
        b_pass_rate=$(echo "scale=1; $b_pass * 100 / $b_total" | bc)
    fi
    if [[ $q_total -gt 0 ]]; then
        q_pass_rate=$(echo "scale=1; $q_pass * 100 / $q_total" | bc)
    fi

    # Get timestamps
    local baseline_time="N/A"
    local qo_time="N/A"
    if [[ -f "${BASELINE_DIR}/summary.json" ]]; then
        baseline_time=$(jq -r '.test_run.start_time // "N/A"' "${BASELINE_DIR}/summary.json" 2>/dev/null)
    fi
    if [[ -f "${QO_DIR}/summary.json" ]]; then
        qo_time=$(jq -r '.test_run.start_time // "N/A"' "${QO_DIR}/summary.json" 2>/dev/null)
    fi

    # Start report
    cat > "$OUTPUT_FILE" << EOF
# CLIN006 Test Results: Baseline vs Quantum Origin

**Report Generated:** $(date -Iseconds)
**Host:** $(hostname)
**Kernel:** $(uname -r)

## Executive Summary

This report compares test results between the **baseline** system configuration (standard entropy sources) and the **Quantum Origin (QO)** enhanced configuration.

### Test Run Information

| Metric | Baseline | Quantum Origin |
|--------|----------|----------------|
| **Test Time** | ${baseline_time} | ${qo_time} |
| **Total Tests** | ${b_total} | ${q_total} |
| **Passed** | ${b_pass} (${b_pass_rate}%) | ${q_pass} (${q_pass_rate}%) |
| **Failed** | ${b_fail} | ${q_fail} |
| **Warnings** | ${b_warn} | ${q_warn} |
| **Skipped** | ${b_skip} | ${q_skip} |

### Key Findings

EOF

    # Add key findings based on comparison
    if (( $(echo "$q_pass_rate >= $b_pass_rate" | bc -l) )); then
        echo "- ✅ QO configuration maintains or improves test pass rate" >> "$OUTPUT_FILE"
    else
        echo "- ⚠️ QO configuration shows lower pass rate than baseline" >> "$OUTPUT_FILE"
    fi

    if [[ $q_fail -le $b_fail ]]; then
        echo "- ✅ No increase in test failures with QO enabled" >> "$OUTPUT_FILE"
    else
        echo "- ⚠️ More test failures with QO enabled (investigate)" >> "$OUTPUT_FILE"
    fi

    echo "" >> "$OUTPUT_FILE"

    #---------------------------------------------------------------------------
    # Section 4.1: Entropy
    #---------------------------------------------------------------------------
    generate_section_header "4.1" "System Entropy Source" \
        "These tests validate the system's entropy sources - the foundation of all cryptographic security. They verify that /dev/random and /dev/urandom provide high-quality random numbers, measure generation rates, and detect Quantum Origin integration." \
        "Entropy quality directly impacts the security of all cryptographic operations. Weak or predictable randomness can compromise encryption keys, TLS sessions, and authentication tokens. Quantum Origin provides true quantum randomness that is theoretically unpredictable." \
        "Tests read from /dev/urandom at various rates, monitor the kernel entropy pool over time, trace system calls for entropy access, run FIPS 140-2 statistical tests (monobit, poker, runs), and verify QO service/package detection." >> "$OUTPUT_FILE"

    generate_comparison_table "${BASELINE_DIR}/entropy/results.json" "${QO_DIR}/entropy/results.json" >> "$OUTPUT_FILE"

    # Add entropy-specific metrics
    echo "" >> "$OUTPUT_FILE"
    echo "#### Key Entropy Metrics" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"

    local b_entropy_file="${BASELINE_DIR}/entropy/results.json"
    local q_entropy_file="${QO_DIR}/entropy/results.json"

    # Extract FIPS pass rates if available
    local b_fips=$(extract_metric "$b_entropy_file" "rngtest_statistical" 'Failure rate: [0-9.]+%' | grep -oP '[0-9.]+' || echo "N/A")
    local q_fips=$(extract_metric "$q_entropy_file" "rngtest_statistical" 'Failure rate: [0-9.]+%' | grep -oP '[0-9.]+' || echo "N/A")

    echo "| Metric | Baseline | QO |" >> "$OUTPUT_FILE"
    echo "|--------|----------|-----|" >> "$OUTPUT_FILE"
    echo "| FIPS Failure Rate | ${b_fips}% | ${q_fips}% |" >> "$OUTPUT_FILE"

    #---------------------------------------------------------------------------
    # Section 4.2: Crypto
    #---------------------------------------------------------------------------
    generate_section_header "4.2" "Cryptographic Key Generation" \
        "These tests verify that cryptographic key generation works correctly and efficiently. They test RSA, ECDSA, and Ed25519 key generation, AES operations, and key uniqueness." \
        "Keys generated with poor entropy are vulnerable to prediction attacks. This section ensures that cryptographic operations complete successfully and that generated keys are unique (no collisions from entropy reuse)." \
        "Tests use OpenSSL to generate keys at various sizes, time the operations, verify key validity, and compare generated keys to detect any duplicates that would indicate entropy problems." >> "$OUTPUT_FILE"

    generate_comparison_table "${BASELINE_DIR}/crypto/results.json" "${QO_DIR}/crypto/results.json" >> "$OUTPUT_FILE"

    #---------------------------------------------------------------------------
    # Section 4.3: Storage
    #---------------------------------------------------------------------------
    generate_section_header "4.3" "Storage Encryption" \
        "These tests validate storage encryption capabilities including dm-crypt/LUKS operations, encrypted file creation, and backup encryption." \
        "Storage encryption protects data at rest. The encryption keys are derived using entropy from the system's random number generators. QO integration ensures these keys are generated with quantum-quality randomness." \
        "Tests check for LUKS/dm-crypt availability, create test encrypted volumes, measure encryption/decryption performance, and verify encrypted backup operations." >> "$OUTPUT_FILE"

    generate_comparison_table "${BASELINE_DIR}/storage/results.json" "${QO_DIR}/storage/results.json" >> "$OUTPUT_FILE"

    #---------------------------------------------------------------------------
    # Section 4.4: Network
    #---------------------------------------------------------------------------
    generate_section_header "4.4" "Network Security (TLS/SSH)" \
        "These tests validate network security protocols including TLS configuration, certificate generation, SSH key exchange algorithms, and secure connection establishment." \
        "Network security relies on secure key exchange and session establishment. TLS and SSH both require high-quality random numbers for session keys, nonces, and ephemeral keys. QO ensures these are generated with quantum randomness." \
        "Tests verify TLS cipher suites, generate test certificates, check SSH configuration, measure TLS handshake performance, and verify that secure protocols are properly configured." >> "$OUTPUT_FILE"

    generate_comparison_table "${BASELINE_DIR}/network/results.json" "${QO_DIR}/network/results.json" >> "$OUTPUT_FILE"

    #---------------------------------------------------------------------------
    # Section 4.5: VM Operations
    #---------------------------------------------------------------------------
    generate_section_header "4.5" "Virtual Machine Operations" \
        "These tests verify virtualization capabilities, container operations, entropy propagation to guests, and performance overhead of virtualized environments." \
        "VMs and containers need access to quality entropy for their own cryptographic operations. Virtio-RNG allows guests to receive entropy from the host. This section verifies that QO-enhanced entropy is properly available in virtualized environments without performance penalties." \
        "Tests check virtualization hardware support (VT-x/AMD-V), verify virtio-rng configuration, measure container startup times, test crypto operations inside containers, and verify multi-tenant isolation." >> "$OUTPUT_FILE"

    generate_comparison_table "${BASELINE_DIR}/vm/results.json" "${QO_DIR}/vm/results.json" >> "$OUTPUT_FILE"

    # Add VM performance metrics if available
    echo "" >> "$OUTPUT_FILE"
    echo "#### Container Performance Metrics" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"

    local b_vm_file="${BASELINE_DIR}/vm/results.json"
    local q_vm_file="${QO_DIR}/vm/results.json"

    local b_startup=$(extract_metric "$b_vm_file" "container_creation_performance" 'startup time: [0-9.]+s' | grep -oP '[0-9.]+' || echo "N/A")
    local q_startup=$(extract_metric "$q_vm_file" "container_creation_performance" 'startup time: [0-9.]+s' | grep -oP '[0-9.]+' || echo "N/A")

    echo "| Metric | Baseline | QO | Delta |" >> "$OUTPUT_FILE"
    echo "|--------|----------|-----|-------|" >> "$OUTPUT_FILE"
    if [[ "$b_startup" != "N/A" && "$q_startup" != "N/A" ]]; then
        local startup_delta=$(echo "scale=1; ($q_startup - $b_startup) / $b_startup * 100" | bc 2>/dev/null || echo "N/A")
        echo "| Container Startup | ${b_startup}s | ${q_startup}s | ${startup_delta}% |" >> "$OUTPUT_FILE"
    else
        echo "| Container Startup | ${b_startup}s | ${q_startup}s | N/A |" >> "$OUTPUT_FILE"
    fi

    #---------------------------------------------------------------------------
    # Appendix
    #---------------------------------------------------------------------------
    cat >> "$OUTPUT_FILE" << EOF

---

## Appendix: Raw Data Locations

### Baseline Results
- Entropy: \`results/baseline/entropy/results.json\`
- Crypto: \`results/baseline/crypto/results.json\`
- Storage: \`results/baseline/storage/results.json\`
- Network: \`results/baseline/network/results.json\`
- VM: \`results/baseline/vm/results.json\`
- Full Log: \`results/baseline/test_run.log\`

### Quantum Origin Results
- Entropy: \`results/qo/entropy/results.json\`
- Crypto: \`results/qo/crypto/results.json\`
- Storage: \`results/qo/storage/results.json\`
- Network: \`results/qo/network/results.json\`
- VM: \`results/qo/vm/results.json\`
- Full Log: \`results/qo/test_run.log\`

---

## Interpretation Guide

### Status Indicators
- **PASS**: Test completed successfully, all criteria met
- **FAIL**: Test failed, indicates a problem that needs investigation
- **WARN**: Test passed with caveats, minor issues detected
- **SKIP**: Test skipped due to missing dependencies or prerequisites
- **INFO**: Informational test, no pass/fail criteria

### Comparison Indicators
- ✅ **Both Pass**: Test passes in both configurations
- ✅ **QO Improved**: Test passes with QO but not baseline
- ⚠️ **QO Regression**: Test passes baseline but not QO (investigate)
- ⏭️ **Skipped**: Test skipped in one or both configurations
- ℹ️ **Info**: Informational test

### Performance Guidelines
- **Entropy throughput**: Should be >100 MB/s, QO should not reduce by >5%
- **Container startup**: Should be <2s, QO should not add >10% overhead
- **Key generation**: QO may add slight overhead due to quantum seeding

---

*Report generated by generate_unified_report.sh*
*🤖 Generated with [Claude Code](https://claude.com/claude-code)*
EOF

    log_pass "Report generated: $OUTPUT_FILE"
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------
main() {
    echo ""
    echo "=============================================================================="
    echo "CLIN006 UNIFIED REPORT GENERATOR"
    echo "=============================================================================="
    echo ""

    check_dependencies

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --baseline)
                BASELINE_DIR="$2"
                shift 2
                ;;
            --qo)
                QO_DIR="$2"
                shift 2
                ;;
            --output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --baseline DIR   Path to baseline results (default: results/baseline)"
                echo "  --qo DIR         Path to QO results (default: results/qo)"
                echo "  --output FILE    Output file path (default: results/unified_report.md)"
                echo "  --help           Show this help message"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    generate_report

    echo ""
    echo "=============================================================================="
    echo "REPORT COMPLETE"
    echo "View: ${OUTPUT_FILE}"
    echo "=============================================================================="
}

main "$@"
