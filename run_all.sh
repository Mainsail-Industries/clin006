#!/bin/bash
#===============================================================================
# QUANTUM ORIGIN + METALVISOR INTEGRATION TEST SUITE
# Master Test Runner
#
# Reference: Test Plan Document - Sections 3-6
# Purpose: Execute all test phases for QO integration validation
#===============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Test configuration - defaults, may be overridden by command-line arguments
export TEST_MODE="${TEST_MODE:-baseline}"  # baseline or qo_enabled
export QO_ENABLED="${QO_ENABLED:-false}"
export VERBOSE="${VERBOSE:-false}"

# Results directory will be set in setup_environment() after TEST_MODE is finalized
RESULTS_DIR=""
LOG_FILE=""
SUMMARY_FILE=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

#-------------------------------------------------------------------------------
# Logging Functions
#-------------------------------------------------------------------------------
log() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${msg}" | tee -a "${LOG_FILE}"
}

log_info()  { log "INFO"  "$*"; }
log_warn()  { log "WARN"  "${YELLOW}$*${NC}"; }
log_error() { log "ERROR" "${RED}$*${NC}"; }
log_pass()  { log "PASS"  "${GREEN}$*${NC}"; }
log_fail()  { log "FAIL"  "${RED}$*${NC}"; }

header() {
    echo ""
    echo "=============================================================================="
    echo -e "${BLUE}$*${NC}"
    echo "=============================================================================="
    log_info "$*"
}

#-------------------------------------------------------------------------------
# Setup
#-------------------------------------------------------------------------------
setup_environment() {
    # Set results directory based on test mode (baseline or qo)
    if [[ "${TEST_MODE}" == "qo_enabled" ]]; then
        RESULTS_DIR="${SCRIPT_DIR}/results/qo"
    else
        RESULTS_DIR="${SCRIPT_DIR}/results/baseline"
    fi
    LOG_FILE="${RESULTS_DIR}/test_run.log"
    SUMMARY_FILE="${RESULTS_DIR}/summary.json"

    # Clear previous results for this mode (single run per type)
    if [[ -d "${RESULTS_DIR}" ]]; then
        rm -rf "${RESULTS_DIR}"
    fi

    # Create results directory first, before any logging
    mkdir -p "${RESULTS_DIR}"

    header "Setting Up Test Environment"
    mkdir -p "${RESULTS_DIR}/entropy"
    mkdir -p "${RESULTS_DIR}/crypto"
    mkdir -p "${RESULTS_DIR}/storage"
    mkdir -p "${RESULTS_DIR}/network"
    mkdir -p "${RESULTS_DIR}/vm"
    mkdir -p "${RESULTS_DIR}/performance"
    
    # Initialize summary
    cat > "${SUMMARY_FILE}" << EOF
{
    "test_run": {
        "start_time": "$(date -Iseconds)",
        "mode": "${TEST_MODE}",
        "qo_enabled": ${QO_ENABLED},
        "hostname": "$(hostname)",
        "kernel": "$(uname -r)"
    },
    "sections": {}
}
EOF
    
    log_info "Results directory: ${RESULTS_DIR}"
    log_info "Test mode: ${TEST_MODE}"
    log_info "Quantum Origin enabled: ${QO_ENABLED}"
}

#-------------------------------------------------------------------------------
# Pre-flight Checks
#-------------------------------------------------------------------------------
preflight_checks() {
    header "Running Pre-flight Checks"
    
    local checks_passed=0
    local checks_failed=0
    
    # Check required tools
    local required_tools=(
        "openssl"
        "dd"
        "strace"
        "fio"
    )
    
    local optional_tools=(
        "rngtest"
        "testssl.sh"
        "bpftrace"
        "sysbench"
    )
    
    log_info "Checking required tools..."
    for tool in "${required_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_pass "Found: $tool"
            checks_passed=$((checks_passed + 1))
        else
            log_fail "Missing required tool: $tool"
            checks_failed=$((checks_failed + 1))
        fi
    done
    
    log_info "Checking optional tools..."
    for tool in "${optional_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            log_pass "Found: $tool"
        else
            log_warn "Optional tool not found: $tool"
        fi
    done
    
    # Check entropy source
    log_info "Checking entropy sources..."
    if [[ -c /dev/random ]]; then
        log_pass "/dev/random available"
        checks_passed=$((checks_passed + 1))
    else
        log_fail "/dev/random not available"
        checks_failed=$((checks_failed + 1))
    fi

    if [[ -c /dev/urandom ]]; then
        log_pass "/dev/urandom available"
        checks_passed=$((checks_passed + 1))
    else
        log_fail "/dev/urandom not available"
        checks_failed=$((checks_failed + 1))
    fi

    # Check for Quantum Origin (if expected)
    if [[ "${QO_ENABLED}" == "true" ]]; then
        log_info "Checking for Quantum Origin..."
        local qo_found=false
        # Check for QO-specific services
        for svc in qo-kernel-reseed qo-entropy quantum-origin qo-daemon; do
            if systemctl is-active --quiet "${svc}" 2>/dev/null; then
                log_pass "Quantum Origin service '${svc}' is active"
                checks_passed=$((checks_passed + 1))
                qo_found=true
                break
            fi
        done
        # Fallback: check for installed QO packages
        if [[ "$qo_found" == "false" ]]; then
            local qo_pkg
            qo_pkg=$(rpm -qa 2>/dev/null | grep -i "^qo-\|quantum-origin" | head -1 || true)
            if [[ -n "$qo_pkg" ]]; then
                log_pass "Quantum Origin package detected: ${qo_pkg}"
                checks_passed=$((checks_passed + 1))
                qo_found=true
            fi
        fi
        if [[ "$qo_found" == "false" ]]; then
            log_warn "Quantum Origin not detected (no service or package found)"
        fi
    fi
    
    log_info "Pre-flight checks complete: ${checks_passed} passed, ${checks_failed} failed"
    
    if [[ ${checks_failed} -gt 0 ]]; then
        log_error "Pre-flight checks failed. Some tests may not run correctly."
        return 1
    fi
    return 0
}

#-------------------------------------------------------------------------------
# Run Test Sections
#-------------------------------------------------------------------------------
run_section() {
    local section_name="$1"
    local section_script="$2"
    local section_num="$3"
    
    header "Section ${section_num}: ${section_name}"
    
    if [[ -x "${SCRIPT_DIR}/${section_script}" ]]; then
        local start_time=$(date +%s)
        
        if "${SCRIPT_DIR}/${section_script}" "${RESULTS_DIR}" 2>&1 | tee -a "${LOG_FILE}"; then
            local end_time=$(date +%s)
            local duration=$((end_time - start_time))
            log_pass "Section ${section_num} completed in ${duration}s"
            return 0
        else
            local end_time=$(date +%s)
            local duration=$((end_time - start_time))
            log_fail "Section ${section_num} failed after ${duration}s"
            return 1
        fi
    else
        log_warn "Section script not found or not executable: ${section_script}"
        return 1
    fi
}

#-------------------------------------------------------------------------------
# Main Test Execution
#-------------------------------------------------------------------------------
run_all_tests() {
    local total_sections=5
    local passed_sections=0
    local failed_sections=0
    
    # Section 4.1: System Entropy Source
    if run_section "System Entropy Source" "4.1_entropy.sh" "4.1"; then
        passed_sections=$((passed_sections + 1))
    else
        failed_sections=$((failed_sections + 1))
    fi

    # Section 4.2: Cryptographic Key Generation
    if run_section "Cryptographic Key Generation" "4.2_keygen.sh" "4.2"; then
        passed_sections=$((passed_sections + 1))
    else
        failed_sections=$((failed_sections + 1))
    fi

    # Section 4.3: Storage Encryption
    if run_section "Storage Encryption" "4.3_storage.sh" "4.3"; then
        passed_sections=$((passed_sections + 1))
    else
        failed_sections=$((failed_sections + 1))
    fi

    # Section 4.4: Network Security (TLS/VPN)
    if run_section "Network Security" "4.4_network.sh" "4.4"; then
        passed_sections=$((passed_sections + 1))
    else
        failed_sections=$((failed_sections + 1))
    fi

    # Section 4.5: Virtual Machine Operations
    if run_section "VM Operations" "4.5_vm.sh" "4.5"; then
        passed_sections=$((passed_sections + 1))
    else
        failed_sections=$((failed_sections + 1))
    fi
    
    return ${failed_sections}
}

#-------------------------------------------------------------------------------
# Generate Final Report
#-------------------------------------------------------------------------------
generate_report() {
    header "Generating Final Report"
    
    local report_file="${RESULTS_DIR}/final_report.md"
    
    cat > "${report_file}" << EOF
# Quantum Origin + Metalvisor Integration Test Report

**Test Run:** $(date)
**Mode:** ${TEST_MODE}
**Quantum Origin Enabled:** ${QO_ENABLED}
**Host:** $(hostname)
**Kernel:** $(uname -r)

## Executive Summary

This report documents the results of the Quantum Origin integration testing
with the Mainsail Metalvisor platform.

## Test Sections

EOF

    # Append section results
    for section_result in "${RESULTS_DIR}"/*/results.json; do
        if [[ -f "${section_result}" ]]; then
            local section_name=$(dirname "${section_result}" | xargs basename)
            echo "### ${section_name}" >> "${report_file}"
            echo "" >> "${report_file}"
            echo '```json' >> "${report_file}"
            cat "${section_result}" >> "${report_file}"
            echo '```' >> "${report_file}"
            echo "" >> "${report_file}"
        fi
    done
    
    log_info "Report generated: ${report_file}"
}

#-------------------------------------------------------------------------------
# Cleanup
#-------------------------------------------------------------------------------
cleanup() {
    header "Cleanup"
    log_info "Test run complete"
    log_info "Results available in: ${RESULTS_DIR}"
}

#-------------------------------------------------------------------------------
# Main Entry Point
#-------------------------------------------------------------------------------
main() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║      QUANTUM ORIGIN + METALVISOR INTEGRATION TEST SUITE                      ║"
    echo "║      STTR Phase Testing - Based on Test Plan v1.0                            ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    
    setup_environment
    
    if ! preflight_checks; then
        log_warn "Pre-flight checks had failures, continuing anyway..."
    fi
    
    local exit_code=0
    if ! run_all_tests; then
        log_error "Some test sections failed"
        exit_code=1
    fi
    
    generate_report
    cleanup
    
    echo ""
    echo "=============================================================================="
    echo "TEST RUN COMPLETE"
    echo "Results: ${RESULTS_DIR}"
    echo "=============================================================================="
    
    exit ${exit_code}
}

# Handle arguments
case "${1:-run}" in
    run)
        main
        ;;
    baseline)
        export TEST_MODE="baseline"
        export QO_ENABLED="false"
        main
        ;;
    qo)
        export TEST_MODE="qo_enabled"
        export QO_ENABLED="true"
        main
        ;;
    help|--help|-h)
        echo "Usage: $0 [run|baseline|qo|help]"
        echo ""
        echo "Commands:"
        echo "  run       Run tests with current environment settings"
        echo "  baseline  Run tests in baseline mode (no QO)"
        echo "  qo        Run tests with Quantum Origin enabled"
        echo "  help      Show this help message"
        echo ""
        echo "Environment Variables:"
        echo "  TEST_MODE    baseline or qo_enabled"
        echo "  QO_ENABLED   true or false"
        echo "  VERBOSE      true or false"
        ;;
    *)
        echo "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac
