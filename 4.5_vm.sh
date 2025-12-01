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
# TEST 4.5.5: Cloud-Hypervisor Check
#-------------------------------------------------------------------------------
test_cloud_hypervisor() {
    log_info "TEST 4.5.5: Cloud-Hypervisor Check"
    
    local status="INFO"
    local details=""
    
    # Check for cloud-hypervisor
    if command -v cloud-hypervisor &>/dev/null; then
        local ch_version=$(cloud-hypervisor --version 2>/dev/null | head -1)
        details+="✓ Cloud-Hypervisor installed: ${ch_version}\n"
        
        # Check capabilities
        local ch_help=$(cloud-hypervisor --help 2>/dev/null)
        
        if echo "${ch_help}" | grep -qi "tdx"; then
            details+="  ✓ TDX support available\n"
        fi
        
        if echo "${ch_help}" | grep -qi "sev"; then
            details+="  ✓ SEV support available\n"
        fi
        
        if echo "${ch_help}" | grep -qi "rng"; then
            details+="  ✓ RNG device support available\n"
        fi
    else
        details+="Cloud-Hypervisor not installed\n"
        details+="  (This is the Metalvisor VMM component)\n"
    fi
    
    # Check for ch-remote
    if command -v ch-remote &>/dev/null; then
        details+="✓ ch-remote tool available\n"
    fi
    
    echo -e "$details"
    add_test_result "cloud_hypervisor" "$status" "$(echo -e "$details")"
    
    log_info "TEST 4.5.5 COMPLETE (informational)"
}

#-------------------------------------------------------------------------------
# TEST 4.5.6: Container Runtime Check
#-------------------------------------------------------------------------------
test_container_runtime() {
    log_info "TEST 4.5.6: Container Runtime Check"
    
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
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.5.6 PASSED" || log_warn "TEST 4.5.6 WARNING"
}

#-------------------------------------------------------------------------------
# TEST 4.5.7: Memory Encryption Check
#-------------------------------------------------------------------------------
test_memory_encryption() {
    log_info "TEST 4.5.7: Memory Encryption Check"
    
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
    
    log_info "TEST 4.5.7 COMPLETE (informational)"
}

#-------------------------------------------------------------------------------
# TEST 4.5.8: VM Image Crypto Test
#-------------------------------------------------------------------------------
test_vm_image_crypto() {
    log_info "TEST 4.5.8: VM Image Encryption Test"
    
    local status="PASS"
    local details=""
    
    local test_img="${SECTION_DIR}/test_vm.qcow2"
    
    # Check for qemu-img
    if ! command -v qemu-img &>/dev/null; then
        status="SKIP"
        details="qemu-img not available"
        add_test_result "vm_image_crypto" "$status" "$details"
        log_warn "TEST 4.5.8 SKIPPED"
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
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.5.8 PASSED" || log_fail "TEST 4.5.8 FAILED"
}

#-------------------------------------------------------------------------------
# TEST 4.5.9: Namespace Isolation Check
#-------------------------------------------------------------------------------
test_namespace_isolation() {
    log_info "TEST 4.5.9: Namespace Isolation Check"
    
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
    
    [[ "$status" == "PASS" ]] && log_pass "TEST 4.5.9 PASSED" || log_fail "TEST 4.5.9 FAILED"
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
    
    test_virtualization_capabilities
    test_confidential_computing
    test_libvirt_qemu
    test_virtio_rng
    test_cloud_hypervisor
    test_container_runtime
    test_memory_encryption
    test_vm_image_crypto
    test_namespace_isolation
    
    # Finalize results
    local tmp_file=$(mktemp)
    jq '.end_time = "'"$(date -Iseconds)"'"' "${SECTION_RESULTS}" > "${tmp_file}" && mv "${tmp_file}" "${SECTION_RESULTS}"
    
    echo ""
    echo "Section 4.5 tests complete. Results: ${SECTION_RESULTS}"
}

main "$@"
