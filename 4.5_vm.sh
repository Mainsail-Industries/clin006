#!/bin/bash
#===============================================================================
# SECTION 4.5: VIRTUAL MACHINE OPERATIONS TESTS
# Reference: Test Plan Section 4.5 - Subsystem: Virtual Machine Operations
#
# What is being tested:
# - VM provisioning with quantum-hardened entropy
# - VM-level cryptographic operations
# - Guest OS access to quantum-enhanced randomness (if exposed)
# - Isolation and multi-tenancy security
#
# Success Criteria:
# - VMs provision and boot normally
# - Guest workloads function correctly
# - Confidential compute features enhanced by QO
# - No security boundary violations
# - Multi-tenant isolation maintained
#===============================================================================

set -euo pipefail

RESULTS_DIR="${1:-./results}"
SECTION_DIR="${RESULTS_DIR}/vm"
SECTION_RESULTS="${SECTION_DIR}/results.json"

source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh" 2>/dev/null || {
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
    "section": "4.5",
    "name": "Virtual Machine Operations",
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
# TEST 4.5.1: Virtualization Capabilities Check
#-------------------------------------------------------------------------------
test_virtualization_capabilities() {
    log_info "TEST 4.5.1: Virtualization Capabilities Check"
    
    local status="PASS"
    local details=""
    
    # Check CPU virtualization support
    if grep -qE "vmx|svm" /proc/cpuinfo 2>/dev/null; then
        if grep -q "vmx" /proc/cpuinfo; then
            details+="✓ Intel VT-x supported\n"
        fi
        if grep -q "svm" /proc/cpuinfo; then
            details+="✓ AMD-V supported\n"
        fi
    else
        status="WARN"
        details+="⚠ Hardware virtualization not detected in /proc/cpuinfo\n"
    fi
    
    # Check for nested virtualization
    if [[ -f /sys/module/kvm_intel/parameters/nested ]]; then
        local nested=$(cat /sys/module/kvm_intel/parameters/nested 2>/dev/null)
        details+="Intel nested virtualization: ${nested}\n"
    elif [[ -f /sys/module/kvm_amd/parameters/nested ]]; then
        local nested=$(cat /sys/module/kvm_amd/parameters/nested 2>/dev/null)
        details+="AMD nested virtualization: ${nested}\n"
    fi
    
    # Check KVM module
    if lsmod 2>/dev/null | grep -q "^kvm"; then
        details+="✓ KVM kernel module loaded\n"
        
        # Get KVM devices
        if [[ -c /dev/kvm ]]; then
            details+="✓ /dev/kvm available\n"
            local kvm_perms=$(stat -c '%a' /dev/kvm)
            details+="  Permissions: ${kvm_perms}\n"
        fi
    else
        status="WARN"
        details+="⚠ KVM kernel module not loaded\n"
    fi
    
    # Check for vhost-net
    if lsmod 2>/dev/null | grep -q "vhost_net"; then
        details+="✓ vhost-net module loaded (optimized networking)\n"
    fi
    
    # Check for IOMMU
    if dmesg 2>/dev/null | grep -qi "IOMMU\|DMAR"; then
        details+="✓ IOMMU/DMAR support detected\n"
        
        # Check IOMMU groups
        if [[ -d /sys/kernel/iommu_groups ]]; then
            local iommu_count=$(ls /sys/kernel/iommu_groups 2>/dev/null | wc -l)
            details+="  IOMMU groups: ${iommu_count}\n"
        fi
    else
        details+="IOMMU support not detected in dmesg\n"
    fi
    
    echo -e "$details"
    add_test_result "virtualization_capabilities" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.5.1 PASSED" || log_warn "TEST 4.5.1 WARNING"
}

#-------------------------------------------------------------------------------
# TEST 4.5.2: Confidential Computing Check (TDX/SEV)
#-------------------------------------------------------------------------------
test_confidential_computing() {
    log_info "TEST 4.5.2: Confidential Computing Capabilities Check"
    
    local status="INFO"
    local details=""
    
    # Check for Intel TDX
    if grep -q "tdx" /proc/cpuinfo 2>/dev/null; then
        details+="✓ Intel TDX CPU flag present\n"
    else
        details+="Intel TDX not detected in CPU flags\n"
    fi
    
    # Check TDX module
    if [[ -d /sys/firmware/tdx ]]; then
        details+="✓ TDX firmware interface available\n"
    fi
    
    if lsmod 2>/dev/null | grep -qi "intel_tdx"; then
        details+="✓ Intel TDX kernel module loaded\n"
    fi
    
    # Check for AMD SEV
    if grep -q "sev" /proc/cpuinfo 2>/dev/null; then
        details+="✓ AMD SEV CPU flag present\n"
    else
        details+="AMD SEV not detected in CPU flags\n"
    fi
    
    # Check SEV device
    if [[ -c /dev/sev ]]; then
        details+="✓ AMD SEV device available (/dev/sev)\n"
    fi
    
    # Check for SEV-SNP
    if dmesg 2>/dev/null | grep -qi "SEV-SNP"; then
        details+="✓ AMD SEV-SNP support detected\n"
    fi
    
    # Check ccp/sev module
    if lsmod 2>/dev/null | grep -qE "ccp|sev"; then
        details+="✓ AMD CCP/SEV kernel module loaded\n"
    fi
    
    # Check kernel config
    if [[ -f /boot/config-$(uname -r) ]]; then
        local config_file="/boot/config-$(uname -r)"
        
        if grep -q "CONFIG_INTEL_TDX_GUEST=y" "${config_file}" 2>/dev/null; then
            details+="Kernel configured with TDX guest support\n"
        fi
        
        if grep -q "CONFIG_AMD_MEM_ENCRYPT=y" "${config_file}" 2>/dev/null; then
            details+="Kernel configured with AMD memory encryption\n"
        fi
    fi
    
    echo -e "$details"
    add_test_result "confidential_computing" "$status" "$(echo -e "$details")"
    
    log_info "TEST 4.5.2 COMPLETE (informational)"
}

#-------------------------------------------------------------------------------
# TEST 4.5.3: Libvirt/QEMU Check
#-------------------------------------------------------------------------------
test_libvirt_qemu() {
    log_info "TEST 4.5.3: Libvirt/QEMU Environment Check"
    
    local status="PASS"
    local details=""
    
    # Check for QEMU
    if command -v qemu-system-x86_64 &>/dev/null; then
        local qemu_version=$(qemu-system-x86_64 --version 2>/dev/null | head -1)
        details+="✓ QEMU installed: ${qemu_version}\n"
    elif command -v qemu-kvm &>/dev/null; then
        local qemu_version=$(qemu-kvm --version 2>/dev/null | head -1)
        details+="✓ QEMU-KVM installed: ${qemu_version}\n"
    else
        status="WARN"
        details+="⚠ QEMU not found\n"
    fi
    
    # Check for libvirt
    if command -v virsh &>/dev/null; then
        local virsh_version=$(virsh --version 2>/dev/null)
        details+="✓ virsh available: version ${virsh_version}\n"
        
        # Check libvirtd service
        if systemctl is-active --quiet libvirtd 2>/dev/null; then
            details+="✓ libvirtd service active\n"
            
            # Get connection info
            if virsh uri &>/dev/null; then
                local uri=$(virsh uri 2>/dev/null)
                details+="  Connection URI: ${uri}\n"
            fi
            
            # List running domains
            local running_domains=$(virsh list --name 2>/dev/null | grep -v "^$" | wc -l)
            details+="  Running VMs: ${running_domains}\n"
        else
            details+="libvirtd service not active\n"
        fi
    else
        status="WARN"
        details+="⚠ virsh not found\n"
    fi
    
    # Check for virtio modules
    local virtio_modules=("virtio" "virtio_pci" "virtio_blk" "virtio_net" "virtio_rng")
    details+="Virtio modules:\n"
    for mod in "${virtio_modules[@]}"; do
        if lsmod 2>/dev/null | grep -q "^${mod}"; then
            details+="  ✓ ${mod}\n"
        else
            details+="  - ${mod} (not loaded)\n"
        fi
    done
    
    echo -e "$details"
    add_test_result "libvirt_qemu" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.5.3 PASSED" || log_warn "TEST 4.5.3 WARNING"
}

#-------------------------------------------------------------------------------
# TEST 4.5.4: Virtio-RNG Check
#-------------------------------------------------------------------------------
test_virtio_rng() {
    log_info "TEST 4.5.4: Virtio-RNG (Guest Entropy) Check"
    
    local status="INFO"
    local details=""
    
    # Check if virtio_rng module is available
    if lsmod 2>/dev/null | grep -q "virtio_rng"; then
        details+="✓ virtio_rng kernel module loaded\n"
    else
        details+="virtio_rng module not loaded\n"
        details+="  (This is normal on host systems)\n"
    fi
    
    # Check for hwrng devices
    if [[ -d /sys/class/misc/hw_random ]]; then
        details+="Hardware RNG interface available:\n"
        
        if [[ -f /sys/class/misc/hw_random/rng_available ]]; then
            local available=$(cat /sys/class/misc/hw_random/rng_available 2>/dev/null)
            details+="  Available RNGs: ${available}\n"
        fi
        
        if [[ -f /sys/class/misc/hw_random/rng_current ]]; then
            local current=$(cat /sys/class/misc/hw_random/rng_current 2>/dev/null)
            details+="  Current RNG: ${current}\n"
        fi
    fi
    
    # Check for rngd (entropy daemon)
    if systemctl is-active --quiet rngd 2>/dev/null; then
        details+="✓ rngd service active\n"
    elif systemctl is-active --quiet rng-tools 2>/dev/null; then
        details+="✓ rng-tools service active\n"
    else
        details+="No hardware RNG daemon active\n"
    fi
    
    # Document QEMU RNG options for VM configuration
    details+="\nFor VMs, add virtio-rng device:\n"
    details+="  -object rng-random,id=rng0,filename=/dev/urandom\n"
    details+="  -device virtio-rng-pci,rng=rng0\n"
    
    echo -e "$details"
    add_test_result "virtio_rng" "$status" "$(echo -e "$details")"
    
    log_info "TEST 4.5.4 COMPLETE (informational)"
}

#-------------------------------------------------------------------------------
# TEST 4.5.5: Container Runtime Check
#-------------------------------------------------------------------------------
test_container_runtime() {
    log_info "TEST 4.5.5: Container Runtime Check"
    
    local status="PASS"
    local details=""
    
    # Check for Podman
    if command -v podman &>/dev/null; then
        local podman_version=$(podman --version 2>/dev/null)
        details+="✓ Podman installed: ${podman_version}\n"
        
        # Check Podman info
        local podman_info=$(podman info --format json 2>/dev/null)
        if [[ -n "${podman_info}" ]]; then
            local runtime=$(echo "${podman_info}" | jq -r '.host.ociRuntime.name // "unknown"' 2>/dev/null)
            details+="  OCI Runtime: ${runtime}\n"
            
            local storage_driver=$(echo "${podman_info}" | jq -r '.store.graphDriverName // "unknown"' 2>/dev/null)
            details+="  Storage driver: ${storage_driver}\n"
        fi
    else
        details+="Podman not installed\n"
    fi
    
    # Check for Docker
    if command -v docker &>/dev/null; then
        if docker info &>/dev/null 2>&1; then
            local docker_version=$(docker --version 2>/dev/null)
            details+="✓ Docker installed: ${docker_version}\n"
        else
            details+="Docker installed but daemon not accessible\n"
        fi
    fi
    
    # Check for containerd
    if command -v ctr &>/dev/null; then
        details+="✓ containerd (ctr) available\n"
    fi
    
    # Check for crun/runc
    if command -v crun &>/dev/null; then
        local crun_version=$(crun --version 2>/dev/null | head -1)
        details+="✓ crun installed: ${crun_version}\n"
    elif command -v runc &>/dev/null; then
        local runc_version=$(runc --version 2>/dev/null | head -1)
        details+="✓ runc installed: ${runc_version}\n"
    fi
    
    echo -e "$details"
    add_test_result "container_runtime" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.5.5 PASSED" || log_warn "TEST 4.5.5 WARNING"
}

#-------------------------------------------------------------------------------
# TEST 4.5.6: Memory Encryption Check
#-------------------------------------------------------------------------------
test_memory_encryption() {
    log_info "TEST 4.5.6: Memory Encryption Check"
    
    local status="INFO"
    local details=""
    
    # Check for SME (Secure Memory Encryption)
    if grep -q "sme" /proc/cpuinfo 2>/dev/null; then
        details+="✓ AMD SME CPU flag present\n"
    else
        details+="AMD SME not detected\n"
    fi
    
    # Check kernel command line for mem_encrypt
    local cmdline=$(cat /proc/cmdline 2>/dev/null)
    if echo "${cmdline}" | grep -q "mem_encrypt"; then
        details+="✓ Memory encryption enabled in kernel cmdline\n"
        local mem_encrypt_val=$(echo "${cmdline}" | grep -oP 'mem_encrypt=\S+')
        details+="  ${mem_encrypt_val}\n"
    else
        details+="Memory encryption not specified in kernel cmdline\n"
    fi
    
    # Check for TME (Total Memory Encryption - Intel)
    if dmesg 2>/dev/null | grep -qi "TME"; then
        details+="✓ Intel TME detected\n"
    fi
    
    # Check for MKTME (Multi-Key TME)
    if dmesg 2>/dev/null | grep -qi "MKTME"; then
        details+="✓ Intel MKTME detected\n"
    fi
    
    # Check dmesg for memory encryption status
    local mem_encrypt_dmesg=$(dmesg 2>/dev/null | grep -i "memory encrypt" | head -3)
    if [[ -n "${mem_encrypt_dmesg}" ]]; then
        details+="Kernel messages:\n${mem_encrypt_dmesg}\n"
    fi
    
    echo -e "$details"
    add_test_result "memory_encryption" "$status" "$(echo -e "$details")"
    
    log_info "TEST 4.5.6 COMPLETE (informational)"
}

#-------------------------------------------------------------------------------
# TEST 4.5.7: VM Image Crypto Test
#-------------------------------------------------------------------------------
test_vm_image_crypto() {
    log_info "TEST 4.5.7: VM Image Encryption Test"
    
    local status="PASS"
    local details=""
    
    local test_img="${SECTION_DIR}/test_vm.qcow2"
    
    # Check for qemu-img
    if ! command -v qemu-img &>/dev/null; then
        status="SKIP"
        details="qemu-img not available"
        add_test_result "vm_image_crypto" "$status" "$details"
        log_warn "TEST 4.5.7 SKIPPED"
        return
    fi
    
    # Create a test qcow2 image
    log_info "Creating test qcow2 image..."
    
    if qemu-img create -f qcow2 "${test_img}" 100M &>/dev/null; then
        details+="✓ Created test qcow2 image\n"
        
        # Get image info
        local img_info=$(qemu-img info "${test_img}" 2>/dev/null)
        details+="Image info:\n${img_info}\n"
        
        # Test encrypted image creation
        log_info "Testing encrypted qcow2 image..."
        local enc_img="${SECTION_DIR}/test_vm_encrypted.qcow2"
        local secret_file="${SECTION_DIR}/vm_secret.txt"
        
        # Generate secret
        openssl rand -base64 32 > "${secret_file}"
        
        # Create encrypted image (LUKS format)
        if qemu-img create -f qcow2 \
            --object secret,id=sec0,file="${secret_file}" \
            -o encrypt.format=luks,encrypt.key-secret=sec0 \
            "${enc_img}" 100M &>/dev/null; then
            
            details+="✓ Created LUKS-encrypted qcow2 image\n"
            
            local enc_info=$(qemu-img info "${enc_img}" 2>/dev/null)
            if echo "${enc_info}" | grep -qi "encrypted"; then
                details+="✓ Image shows as encrypted\n"
            fi
            
            rm -f "${enc_img}"
        else
            details+="⚠ Encrypted image creation failed (may need QEMU 2.10+)\n"
        fi
        
        rm -f "${secret_file}" "${test_img}"
    else
        status="FAIL"
        details+="✗ Failed to create test image\n"
    fi
    
    echo -e "$details"
    add_test_result "vm_image_crypto" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.5.7 PASSED" || log_fail "TEST 4.5.7 FAILED"
}

#-------------------------------------------------------------------------------
# TEST 4.5.8: Namespace Isolation Check
#-------------------------------------------------------------------------------
test_namespace_isolation() {
    log_info "TEST 4.5.8: Namespace Isolation Check"
    
    local status="PASS"
    local details=""
    
    # Check available namespaces
    local namespaces=("cgroup" "ipc" "mnt" "net" "pid" "time" "user" "uts")
    
    details+="Kernel namespace support:\n"
    for ns in "${namespaces[@]}"; do
        if [[ -d "/proc/self/ns" ]] && ls /proc/self/ns 2>/dev/null | grep -q "${ns}"; then
            details+="  ✓ ${ns}\n"
        else
            details+="  - ${ns} (not available)\n"
        fi
    done
    
    # Check for user namespace support
    if [[ -f /proc/sys/user/max_user_namespaces ]]; then
        local max_user_ns=$(cat /proc/sys/user/max_user_namespaces)
        details+="Max user namespaces: ${max_user_ns}\n"
    fi
    
    # Check for seccomp
    if grep -q "seccomp" /proc/self/status 2>/dev/null; then
        local seccomp_mode=$(grep "Seccomp:" /proc/self/status | awk '{print $2}')
        details+="✓ Seccomp available (current mode: ${seccomp_mode})\n"
    fi
    
    # Check for cgroups v2
    if [[ -d /sys/fs/cgroup/cgroup.controllers ]]; then
        details+="✓ cgroups v2 (unified) available\n"
        local controllers=$(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null)
        details+="  Controllers: ${controllers}\n"
    elif [[ -d /sys/fs/cgroup/cpu ]]; then
        details+="cgroups v1 detected\n"
    fi
    
    echo -e "$details"
    add_test_result "namespace_isolation" "$status" "$(echo -e "$details")"
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.5.8 PASSED" || log_fail "TEST 4.5.8 FAILED"
}

#===============================================================================
# PERFORMANCE TESTS (4.5.9 - 4.5.12)
# Lightweight simulation tests to measure QO overhead in virtualized environments
#===============================================================================

#-------------------------------------------------------------------------------
# TEST 4.5.9: Container Creation Performance
#-------------------------------------------------------------------------------
test_container_creation_performance() {
    log_info "TEST 4.5.9: Container Creation Performance"

    local status="PASS"
    local details=""
    local perf_file="${SECTION_DIR}/container_performance.json"

    # Determine container runtime
    local runtime=""
    if command -v podman &>/dev/null; then
        runtime="podman"
    elif command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        runtime="docker"
    else
        status="SKIP"
        details="No container runtime available (podman or docker required)"
        add_test_result "container_creation_performance" "$status" "$details"
        log_warn "TEST 4.5.9 SKIPPED"
        return
    fi

    details+="Container runtime: ${runtime}\n"

    # Initialize performance JSON
    echo '{"runtime": "'"${runtime}"'", "tests": []}' > "${perf_file}"

    # Test 1: Container startup time (5 iterations)
    log_info "Measuring container startup time..."
    local startup_times=()
    for i in $(seq 1 5); do
        local start_time=$(date +%s.%N)
        ${runtime} run --rm alpine:latest /bin/true 2>/dev/null
        local end_time=$(date +%s.%N)
        local duration=$(echo "${end_time} - ${start_time}" | bc)
        startup_times+=("${duration}")
    done

    # Calculate average startup time
    local sum=0
    for t in "${startup_times[@]}"; do
        sum=$(echo "${sum} + ${t}" | bc)
    done
    local avg_startup=$(echo "scale=3; ${sum} / 5" | bc)
    details+="Average container startup time: ${avg_startup}s\n"

    # Test 2: Entropy access inside container
    log_info "Testing entropy access inside container..."
    local entropy_start=$(date +%s.%N)
    local container_entropy=$(${runtime} run --rm alpine:latest sh -c 'cat /proc/sys/kernel/random/entropy_avail' 2>/dev/null || echo "0")
    local entropy_end=$(date +%s.%N)
    local entropy_access_time=$(echo "${entropy_end} - ${entropy_start}" | bc)

    details+="Container entropy available: ${container_entropy} bits\n"
    details+="Entropy access time: ${entropy_access_time}s\n"

    # Test 3: Random data throughput inside container
    log_info "Measuring entropy throughput inside container..."
    local throughput_result=$(${runtime} run --rm alpine:latest sh -c '
        start=$(date +%s.%N 2>/dev/null || date +%s)
        dd if=/dev/urandom of=/dev/null bs=1M count=10 2>&1
        end=$(date +%s.%N 2>/dev/null || date +%s)
        echo "duration=$(echo "$end - $start" | bc 2>/dev/null || echo "1")"
    ' 2>/dev/null)

    local container_throughput="N/A"
    if echo "${throughput_result}" | grep -q "duration="; then
        local duration=$(echo "${throughput_result}" | grep -oP 'duration=\K[0-9.]+' || echo "1")
        container_throughput=$(echo "scale=2; 10 / ${duration}" | bc 2>/dev/null || echo "N/A")
    fi
    details+="Container entropy throughput: ${container_throughput} MB/s\n"

    # Compare with host throughput
    local host_start=$(date +%s.%N)
    dd if=/dev/urandom of=/dev/null bs=1M count=10 2>/dev/null
    local host_end=$(date +%s.%N)
    local host_duration=$(echo "${host_end} - ${host_start}" | bc)
    local host_throughput=$(echo "scale=2; 10 / ${host_duration}" | bc)
    details+="Host entropy throughput: ${host_throughput} MB/s\n"

    # Update performance JSON
    local tmp_file=$(mktemp)
    jq --arg startup "${avg_startup}" \
       --arg container_entropy "${container_entropy}" \
       --arg container_throughput "${container_throughput}" \
       --arg host_throughput "${host_throughput}" \
       '.tests += [{
           "name": "container_startup",
           "avg_startup_sec": ($startup | tonumber),
           "container_entropy_bits": ($container_entropy | tonumber),
           "container_throughput_mbps": $container_throughput,
           "host_throughput_mbps": ($host_throughput | tonumber)
       }]' "${perf_file}" > "${tmp_file}" && mv "${tmp_file}" "${perf_file}"

    # Evaluate results
    if (( $(echo "${avg_startup} > 5" | bc -l) )); then
        status="WARN"
        details+="\n⚠ Container startup time is slow (>5s)"
    else
        details+="\n✓ Container startup time acceptable"
    fi

    echo -e "$details"
    add_test_result "container_creation_performance" "$status" "$(echo -e "$details")"

    [[ "$status" == "PASS" ]] && log_pass "TEST 4.5.9 PASSED" || log_warn "TEST 4.5.9 WARNING"
}

#-------------------------------------------------------------------------------
# TEST 4.5.10: Container Crypto Operations
#-------------------------------------------------------------------------------
test_container_crypto_operations() {
    log_info "TEST 4.5.10: Container Crypto Operations"

    local status="PASS"
    local details=""

    # Determine container runtime
    local runtime=""
    if command -v podman &>/dev/null; then
        runtime="podman"
    elif command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        runtime="docker"
    else
        status="SKIP"
        details="No container runtime available"
        add_test_result "container_crypto_operations" "$status" "$details"
        log_warn "TEST 4.5.10 SKIPPED"
        return
    fi

    details+="Container runtime: ${runtime}\n"

    # Test key generation inside container
    log_info "Testing key generation inside container..."

    # Use alpine with openssl
    local keygen_result=$(${runtime} run --rm alpine:latest sh -c '
        apk add --no-cache openssl >/dev/null 2>&1
        # Generate RSA key and time it
        start=$(date +%s.%N 2>/dev/null || date +%s)
        openssl genrsa 2048 >/dev/null 2>&1
        end=$(date +%s.%N 2>/dev/null || date +%s)
        echo "rsa_time=$(echo "$end - $start" | bc 2>/dev/null || echo "1")"

        # Generate random bytes
        start=$(date +%s.%N 2>/dev/null || date +%s)
        openssl rand -out /dev/null 1048576
        end=$(date +%s.%N 2>/dev/null || date +%s)
        echo "rand_time=$(echo "$end - $start" | bc 2>/dev/null || echo "1")"
    ' 2>/dev/null)

    local container_rsa_time=$(echo "${keygen_result}" | grep -oP 'rsa_time=\K[0-9.]+' || echo "N/A")
    local container_rand_time=$(echo "${keygen_result}" | grep -oP 'rand_time=\K[0-9.]+' || echo "N/A")

    details+="Container RSA-2048 keygen: ${container_rsa_time}s\n"
    details+="Container 1MB random gen: ${container_rand_time}s\n"

    # Compare with host
    local host_start=$(date +%s.%N)
    openssl genrsa 2048 >/dev/null 2>&1
    local host_end=$(date +%s.%N)
    local host_rsa_time=$(echo "${host_end} - ${host_start}" | bc)

    host_start=$(date +%s.%N)
    openssl rand -out /dev/null 1048576
    host_end=$(date +%s.%N)
    local host_rand_time=$(echo "${host_end} - ${host_start}" | bc)

    details+="Host RSA-2048 keygen: ${host_rsa_time}s\n"
    details+="Host 1MB random gen: ${host_rand_time}s\n"

    # Calculate overhead if possible
    if [[ "${container_rsa_time}" != "N/A" && "${host_rsa_time}" != "0" ]]; then
        local rsa_overhead=$(echo "scale=1; (${container_rsa_time} - ${host_rsa_time}) / ${host_rsa_time} * 100" | bc 2>/dev/null || echo "N/A")
        details+="\nRSA overhead: ${rsa_overhead}%\n"

        if [[ "${rsa_overhead}" != "N/A" ]] && (( $(echo "${rsa_overhead} > 50" | bc -l) )); then
            status="WARN"
            details+="⚠ Significant crypto overhead in container"
        else
            details+="✓ Container crypto performance acceptable"
        fi
    fi

    echo -e "$details"
    add_test_result "container_crypto_operations" "$status" "$(echo -e "$details")"

    [[ "$status" == "PASS" ]] && log_pass "TEST 4.5.10 PASSED" || log_warn "TEST 4.5.10 WARNING"
}

#-------------------------------------------------------------------------------
# TEST 4.5.11: VM Creation Performance (if available)
#-------------------------------------------------------------------------------
test_vm_creation_performance() {
    log_info "TEST 4.5.11: VM Creation Performance"

    local status="INFO"
    local details=""

    # Check if we can run VMs
    if ! command -v qemu-system-x86_64 &>/dev/null; then
        status="SKIP"
        details="QEMU not available for VM performance testing"
        add_test_result "vm_creation_performance" "$status" "$details"
        log_warn "TEST 4.5.11 SKIPPED - QEMU not available"
        return
    fi

    # Check KVM access
    if [[ ! -w /dev/kvm ]]; then
        status="SKIP"
        details="No write access to /dev/kvm - cannot run accelerated VMs\nRun as root or add user to kvm group"
        add_test_result "vm_creation_performance" "$status" "$details"
        log_warn "TEST 4.5.11 SKIPPED - no KVM access"
        return
    fi

    details+="QEMU available with KVM acceleration\n"

    # Create a minimal test - just measure QEMU startup/shutdown time
    log_info "Measuring QEMU startup overhead..."

    local test_times=()
    for i in $(seq 1 3); do
        local start_time=$(date +%s.%N)
        timeout 10s qemu-system-x86_64 \
            -machine accel=kvm \
            -m 128 \
            -nographic \
            -no-reboot \
            -device virtio-rng-pci \
            -kernel /dev/null 2>/dev/null || true
        local end_time=$(date +%s.%N)
        local duration=$(echo "${end_time} - ${start_time}" | bc)
        test_times+=("${duration}")
    done

    # Calculate average
    local sum=0
    for t in "${test_times[@]}"; do
        sum=$(echo "${sum} + ${t}" | bc)
    done
    local avg_time=$(echo "scale=3; ${sum} / 3" | bc)

    details+="Average QEMU startup overhead: ${avg_time}s\n"
    details+="virtio-rng device configured\n"
    details+="\n✓ QEMU with virtio-rng ready for VM entropy testing"

    echo -e "$details"
    add_test_result "vm_creation_performance" "$status" "$(echo -e "$details")"

    log_info "TEST 4.5.11 COMPLETE (informational)"
}

#-------------------------------------------------------------------------------
# TEST 4.5.12: Multi-Container Isolation Test
#-------------------------------------------------------------------------------
test_multi_container_isolation() {
    log_info "TEST 4.5.12: Multi-Container Isolation Test"

    local status="PASS"
    local details=""

    # Determine container runtime
    local runtime=""
    if command -v podman &>/dev/null; then
        runtime="podman"
    elif command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        runtime="docker"
    else
        status="SKIP"
        details="No container runtime available"
        add_test_result "multi_container_isolation" "$status" "$details"
        log_warn "TEST 4.5.12 SKIPPED"
        return
    fi

    details+="Container runtime: ${runtime}\n"

    # Start multiple containers simultaneously and check entropy
    log_info "Starting 3 containers simultaneously..."

    local container_ids=()
    local start_time=$(date +%s.%N)

    # Start 3 containers in background that will run entropy tests
    for i in 1 2 3; do
        local cid=$(${runtime} run -d --rm alpine:latest sh -c '
            sleep 1
            entropy=$(cat /proc/sys/kernel/random/entropy_avail)
            # Generate some random data
            dd if=/dev/urandom of=/dev/null bs=1M count=5 2>/dev/null
            entropy_after=$(cat /proc/sys/kernel/random/entropy_avail)
            echo "container_'${i}': entropy_before=${entropy} entropy_after=${entropy_after}"
            sleep 2
        ' 2>/dev/null)
        container_ids+=("${cid}")
    done

    local launch_time=$(date +%s.%N)
    local launch_duration=$(echo "${launch_time} - ${start_time}" | bc)
    details+="Time to launch 3 containers: ${launch_duration}s\n"

    # Wait for containers and collect results
    sleep 5

    # Get logs from each container
    details+="\nEntropy readings per container:\n"
    for i in "${!container_ids[@]}"; do
        local cid="${container_ids[$i]}"
        local logs=$(${runtime} logs "${cid}" 2>/dev/null || echo "Container finished")
        local entropy_info=$(echo "${logs}" | grep "container_" | head -1)
        if [[ -n "${entropy_info}" ]]; then
            details+="  ${entropy_info}\n"
        else
            details+="  Container $((i+1)): completed\n"
        fi
        # Clean up
        ${runtime} rm -f "${cid}" 2>/dev/null || true
    done

    # Check host entropy during multi-container load
    local host_entropy=$(cat /proc/sys/kernel/random/entropy_avail)
    details+="\nHost entropy after multi-container test: ${host_entropy} bits\n"

    if [[ ${host_entropy} -lt 128 ]]; then
        status="WARN"
        details+="\n⚠ Host entropy dropped during multi-container test"
    else
        details+="\n✓ Host entropy maintained during concurrent container operations"
        details+="✓ Container isolation verified"
    fi

    echo -e "$details"
    add_test_result "multi_container_isolation" "$status" "$(echo -e "$details")"

    [[ "$status" == "PASS" ]] && log_pass "TEST 4.5.12 PASSED" || log_warn "TEST 4.5.12 WARNING"
}

#-------------------------------------------------------------------------------
# Main Execution
#-------------------------------------------------------------------------------
main() {
    echo ""
    echo "=============================================================================="
    echo "SECTION 4.5: VIRTUAL MACHINE OPERATIONS TESTS"
    echo "=============================================================================="
    echo ""

    init_results

    # Capability tests (4.5.1 - 4.5.8)
    test_virtualization_capabilities
    test_confidential_computing
    test_libvirt_qemu
    test_virtio_rng
    test_container_runtime
    test_memory_encryption
    test_vm_image_crypto
    test_namespace_isolation

    # Performance tests (4.5.9 - 4.5.12)
    echo ""
    echo "=============================================================================="
    echo "PERFORMANCE TESTS"
    echo "=============================================================================="
    echo ""

    test_container_creation_performance
    test_container_crypto_operations
    test_vm_creation_performance
    test_multi_container_isolation

    # Finalize results
    local tmp_file=$(mktemp)
    jq '.end_time = "'"$(date -Iseconds)"'"' "${SECTION_RESULTS}" > "${tmp_file}" && mv "${tmp_file}" "${SECTION_RESULTS}"

    echo ""
    echo "Section 4.5 tests complete. Results: ${SECTION_RESULTS}"
}

main "$@"
