#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║  HardHat — Red Hat Enterprise Linux Hardening Tool                  ║
# ║  Version: 2.0.0                                                     ║
# ║  Author:  Ali AlEnezi (@SiteQ8)                                     ║
# ║  License: MIT                                                       ║
# ║  Standards: CIS Benchmark RHEL 8/9, NIST 800-53, DISA STIG         ║
# ║                                                                     ║
# ║  The only tool you need to harden your Red Hat environment.         ║
# ╚══════════════════════════════════════════════════════════════════════╝
set -euo pipefail

# ─── Colors & Formatting ─────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ─── Globals ──────────────────────────────────────────────────────────
VERSION="2.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/hardhat"
LOG_FILE="${LOG_DIR}/hardhat-$(date +%Y%m%d-%H%M%S).log"
REPORT_FILE="${LOG_DIR}/hardhat-report-$(date +%Y%m%d-%H%M%S).html"
BACKUP_DIR="/var/backups/hardhat/$(date +%Y%m%d-%H%M%S)"
PASS_COUNT=0; FAIL_COUNT=0; WARN_COUNT=0; SKIP_COUNT=0; TOTAL_COUNT=0
DRY_RUN=false
AUDIT_ONLY=false
INTERACTIVE=false
PROFILE="level1"  # level1, level2, stig
MODULES=()
RHEL_VERSION=""

# ─── Banner ───────────────────────────────────────────────────────────
banner() {
    echo -e "${RED}"
    cat << 'BANNER'
    ██╗  ██╗ █████╗ ██████╗ ██████╗ ██╗  ██╗ █████╗ ████████╗
    ██║  ██║██╔══██╗██╔══██╗██╔══██╗██║  ██║██╔══██╗╚══██╔══╝
    ███████║███████║██████╔╝██║  ██║███████║███████║   ██║
    ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══██║██╔══██║   ██║
    ██║  ██║██║  ██║██║  ██║██████╔╝██║  ██║██║  ██║   ██║
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
BANNER
    echo -e "${NC}"
    echo -e "  ${BOLD}Red Hat Enterprise Linux Hardening Tool${NC} ${DIM}v${VERSION}${NC}"
    echo -e "  ${DIM}CIS Benchmark | NIST 800-53 | DISA STIG${NC}"
    echo -e "  ${DIM}Author: Ali AlEnezi (@SiteQ8)${NC}"
    echo ""
}

# ─── Logging ──────────────────────────────────────────────────────────
log() { echo -e "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_FILE" 2>/dev/null; }
log_pass() { ((PASS_COUNT++)); ((TOTAL_COUNT++)); echo -e "  ${GREEN}[PASS]${NC} $*" | tee -a "$LOG_FILE" 2>/dev/null; }
log_fail() { ((FAIL_COUNT++)); ((TOTAL_COUNT++)); echo -e "  ${RED}[FAIL]${NC} $*" | tee -a "$LOG_FILE" 2>/dev/null; }
log_warn() { ((WARN_COUNT++)); ((TOTAL_COUNT++)); echo -e "  ${YELLOW}[WARN]${NC} $*" | tee -a "$LOG_FILE" 2>/dev/null; }
log_skip() { ((SKIP_COUNT++)); ((TOTAL_COUNT++)); echo -e "  ${DIM}[SKIP]${NC} $*" | tee -a "$LOG_FILE" 2>/dev/null; }
log_info() { echo -e "  ${CYAN}[INFO]${NC} $*" | tee -a "$LOG_FILE" 2>/dev/null; }
log_section() { echo ""; echo -e "${BLUE}${BOLD}━━━ $* ━━━${NC}" | tee -a "$LOG_FILE" 2>/dev/null; }

# ─── Helpers ──────────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[ERROR] HardHat must be run as root.${NC}"
        exit 1
    fi
}

detect_rhel() {
    if [[ -f /etc/redhat-release ]]; then
        RHEL_VERSION=$(rpm -E %{rhel} 2>/dev/null || echo "unknown")
        log_info "Detected RHEL/CentOS version: ${RHEL_VERSION}"
    else
        echo -e "${RED}[ERROR] This tool is designed for Red Hat / CentOS / Rocky / Alma Linux.${NC}"
        exit 1
    fi
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        mkdir -p "$BACKUP_DIR"
        cp -a "$file" "${BACKUP_DIR}/$(echo "$file" | tr '/' '_')" 2>/dev/null
    fi
}

apply_fix() {
    if $DRY_RUN || $AUDIT_ONLY; then
        return 1
    fi
    return 0
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 1: FILESYSTEM CONFIGURATION
# CIS 1.1 — Filesystem configuration
# ═══════════════════════════════════════════════════════════════════════
mod_filesystem() {
    log_section "1. FILESYSTEM CONFIGURATION (CIS 1.1)"

    # 1.1.1 — Disable unused filesystems
    local unused_fs=("cramfs" "freevxfs" "jffs2" "hfs" "hfsplus" "squashfs" "udf" "vfat" "usb-storage")
    for fs in "${unused_fs[@]}"; do
        if lsmod | grep -q "^${fs} " 2>/dev/null; then
            log_fail "CIS 1.1.1 — Filesystem '${fs}' is loaded"
            if apply_fix; then
                backup_file "/etc/modprobe.d/hardhat.conf"
                echo "install ${fs} /bin/true" >> /etc/modprobe.d/hardhat.conf
                echo "blacklist ${fs}" >> /etc/modprobe.d/hardhat.conf
                rmmod "$fs" 2>/dev/null || true
                log_info "Disabled and blacklisted ${fs}"
            fi
        else
            log_pass "CIS 1.1.1 — Filesystem '${fs}' is not loaded"
        fi
    done

    # 1.1.2 — /tmp partition
    if findmnt -n /tmp &>/dev/null; then
        log_pass "CIS 1.1.2 — /tmp is a separate partition"
    else
        log_fail "CIS 1.1.2 — /tmp is NOT a separate partition"
    fi

    # 1.1.3-5 — /tmp mount options
    if findmnt -n /tmp 2>/dev/null | grep -q "nodev"; then
        log_pass "CIS 1.1.3 — /tmp has nodev option"
    else
        log_fail "CIS 1.1.3 — /tmp missing nodev option"
    fi
    if findmnt -n /tmp 2>/dev/null | grep -q "nosuid"; then
        log_pass "CIS 1.1.4 — /tmp has nosuid option"
    else
        log_fail "CIS 1.1.4 — /tmp missing nosuid option"
    fi
    if findmnt -n /tmp 2>/dev/null | grep -q "noexec"; then
        log_pass "CIS 1.1.5 — /tmp has noexec option"
    else
        log_fail "CIS 1.1.5 — /tmp missing noexec option"
    fi

    # 1.1.6-8 — /var, /var/tmp, /var/log partitions
    for part in /var /var/tmp /var/log /var/log/audit /home; do
        if findmnt -n "$part" &>/dev/null; then
            log_pass "CIS 1.1.x — ${part} is a separate partition"
        else
            log_warn "CIS 1.1.x — ${part} is NOT a separate partition (recommended)"
        fi
    done

    # 1.1.21 — Sticky bit on world-writable directories
    local sticky_issues
    sticky_issues=$(df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | xargs -I{} find {} -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | head -5)
    if [[ -z "$sticky_issues" ]]; then
        log_pass "CIS 1.1.21 — Sticky bit set on all world-writable dirs"
    else
        log_fail "CIS 1.1.21 — World-writable dirs without sticky bit found"
        if apply_fix; then
            df --local -P | awk '{if (NR!=1) print $6}' | xargs -I{} find {} -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t 2>/dev/null
            log_info "Applied sticky bit to world-writable directories"
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 2: SOFTWARE UPDATES & PACKAGE INTEGRITY
# CIS 1.2-1.3 — Package manager configuration
# ═══════════════════════════════════════════════════════════════════════
mod_packages() {
    log_section "2. SOFTWARE UPDATES & INTEGRITY (CIS 1.2-1.3)"

    # 1.2.1 — GPG keys configured
    if rpm -q gpg-pubkey &>/dev/null; then
        log_pass "CIS 1.2.1 — GPG keys are configured for package manager"
    else
        log_fail "CIS 1.2.1 — No GPG keys configured"
    fi

    # 1.2.2 — gpgcheck enabled
    if grep -q "^gpgcheck=1" /etc/yum.conf 2>/dev/null || grep -q "^gpgcheck=1" /etc/dnf/dnf.conf 2>/dev/null; then
        log_pass "CIS 1.2.2 — gpgcheck is globally enabled"
    else
        log_fail "CIS 1.2.2 — gpgcheck is NOT globally enabled"
        if apply_fix; then
            if [[ -f /etc/dnf/dnf.conf ]]; then
                backup_file /etc/dnf/dnf.conf
                sed -i 's/^gpgcheck=.*/gpgcheck=1/' /etc/dnf/dnf.conf
                grep -q "^gpgcheck" /etc/dnf/dnf.conf || echo "gpgcheck=1" >> /etc/dnf/dnf.conf
            fi
            log_info "Enabled gpgcheck in package manager"
        fi
    fi

    # 1.2.3 — Check for available updates
    local updates_count
    updates_count=$(dnf check-update --quiet 2>/dev/null | grep -c "^[a-zA-Z]" || true)
    if [[ "$updates_count" -eq 0 ]]; then
        log_pass "CIS 1.2.3 — System is up to date (no pending updates)"
    else
        log_warn "CIS 1.2.3 — ${updates_count} package updates available"
    fi

    # 1.3.1 — AIDE installed
    if rpm -q aide &>/dev/null; then
        log_pass "CIS 1.3.1 — AIDE (file integrity) is installed"
    else
        log_fail "CIS 1.3.1 — AIDE is not installed"
        if apply_fix; then
            dnf install -y aide &>/dev/null && aide --init &>/dev/null
            log_info "Installed and initialized AIDE"
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 3: BOOT SETTINGS & SECURE BOOT
# CIS 1.4-1.5 — Boot loader, process hardening
# ═══════════════════════════════════════════════════════════════════════
mod_boot() {
    log_section "3. BOOT & PROCESS HARDENING (CIS 1.4-1.5)"

    # 1.4.1 — Bootloader password
    if grep -q "^GRUB2_PASSWORD" /boot/grub2/user.cfg 2>/dev/null || grep -q "^set superusers" /boot/grub2/grub.cfg 2>/dev/null; then
        log_pass "CIS 1.4.1 — GRUB2 bootloader password is set"
    else
        log_fail "CIS 1.4.1 — GRUB2 bootloader password is NOT set"
    fi

    # 1.4.2 — Boot loader config permissions
    local grub_cfg="/boot/grub2/grub.cfg"
    if [[ -f "$grub_cfg" ]]; then
        local perms
        perms=$(stat -c "%a" "$grub_cfg" 2>/dev/null)
        if [[ "$perms" == "600" ]] || [[ "$perms" == "400" ]]; then
            log_pass "CIS 1.4.2 — GRUB config permissions: ${perms}"
        else
            log_fail "CIS 1.4.2 — GRUB config permissions too open: ${perms}"
            if apply_fix; then
                chmod 600 "$grub_cfg"
                chown root:root "$grub_cfg"
                log_info "Set GRUB config to 600 root:root"
            fi
        fi
    fi

    # 1.5.1 — core dumps restricted
    if grep -q "hard core 0" /etc/security/limits.conf 2>/dev/null || grep -rq "hard core 0" /etc/security/limits.d/ 2>/dev/null; then
        log_pass "CIS 1.5.1 — Core dumps are restricted"
    else
        log_fail "CIS 1.5.1 — Core dumps are NOT restricted"
        if apply_fix; then
            backup_file /etc/security/limits.conf
            echo "* hard core 0" >> /etc/security/limits.conf
            log_info "Restricted core dumps in limits.conf"
        fi
    fi

    # 1.5.3 — ASLR enabled
    local aslr
    aslr=$(sysctl -n kernel.randomize_va_space 2>/dev/null)
    if [[ "$aslr" == "2" ]]; then
        log_pass "CIS 1.5.3 — ASLR is fully enabled (${aslr})"
    else
        log_fail "CIS 1.5.3 — ASLR is not fully enabled (${aslr})"
        if apply_fix; then
            sysctl -w kernel.randomize_va_space=2 &>/dev/null
            echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/99-hardhat.conf
            log_info "Enabled ASLR"
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 4: MANDATORY ACCESS CONTROL (SELinux)
# CIS 1.6 — SELinux
# ═══════════════════════════════════════════════════════════════════════
mod_selinux() {
    log_section "4. MANDATORY ACCESS CONTROL — SELinux (CIS 1.6)"

    # 1.6.1.1 — SELinux installed
    if rpm -q libselinux &>/dev/null; then
        log_pass "CIS 1.6.1.1 — SELinux is installed"
    else
        log_fail "CIS 1.6.1.1 — SELinux is NOT installed"
    fi

    # 1.6.1.2 — SELinux not disabled in bootloader
    if ! grep -q "selinux=0" /proc/cmdline 2>/dev/null && ! grep -q "enforcing=0" /proc/cmdline 2>/dev/null; then
        log_pass "CIS 1.6.1.2 — SELinux not disabled in bootloader"
    else
        log_fail "CIS 1.6.1.2 — SELinux is disabled via bootloader"
    fi

    # 1.6.1.3 — SELinux policy
    local policy
    policy=$(sestatus 2>/dev/null | grep "Loaded policy" | awk '{print $NF}')
    if [[ "$policy" == "targeted" ]] || [[ "$policy" == "mls" ]]; then
        log_pass "CIS 1.6.1.3 — SELinux policy: ${policy}"
    else
        log_fail "CIS 1.6.1.3 — SELinux policy not set to targeted/mls"
    fi

    # 1.6.1.4 — SELinux mode
    local mode
    mode=$(getenforce 2>/dev/null)
    if [[ "$mode" == "Enforcing" ]]; then
        log_pass "CIS 1.6.1.4 — SELinux mode: Enforcing"
    elif [[ "$mode" == "Permissive" ]]; then
        log_warn "CIS 1.6.1.4 — SELinux mode: Permissive (should be Enforcing)"
        if apply_fix; then
            setenforce 1 2>/dev/null
            backup_file /etc/selinux/config
            sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
            log_info "Set SELinux to Enforcing"
        fi
    else
        log_fail "CIS 1.6.1.4 — SELinux mode: ${mode} (Disabled)"
    fi

    # Unconfined services
    local unconfined
    unconfined=$(ps -eZ 2>/dev/null | grep -c "unconfined_service_t" || true)
    if [[ "$unconfined" -eq 0 ]]; then
        log_pass "CIS 1.6.1.6 — No unconfined services running"
    else
        log_warn "CIS 1.6.1.6 — ${unconfined} unconfined service(s) detected"
    fi
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 5: NETWORK CONFIGURATION
# CIS 3.1-3.5 — Network parameters, firewall, IP tables
# ═══════════════════════════════════════════════════════════════════════
mod_network() {
    log_section "5. NETWORK CONFIGURATION (CIS 3.1-3.5)"

    # Kernel network parameters
    local -A net_params=(
        ["net.ipv4.ip_forward"]="0"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["net.ipv4.conf.default.send_redirects"]="0"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.conf.default.accept_source_route"]="0"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.conf.default.accept_redirects"]="0"
        ["net.ipv4.conf.all.secure_redirects"]="0"
        ["net.ipv4.conf.default.secure_redirects"]="0"
        ["net.ipv4.conf.all.log_martians"]="1"
        ["net.ipv4.conf.default.log_martians"]="1"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
        ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
        ["net.ipv4.conf.all.rp_filter"]="1"
        ["net.ipv4.conf.default.rp_filter"]="1"
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv6.conf.all.accept_ra"]="0"
        ["net.ipv6.conf.default.accept_ra"]="0"
        ["net.ipv6.conf.all.accept_redirects"]="0"
        ["net.ipv6.conf.default.accept_redirects"]="0"
    )

    for param in "${!net_params[@]}"; do
        local expected="${net_params[$param]}"
        local actual
        actual=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
        if [[ "$actual" == "$expected" ]]; then
            log_pass "CIS 3.x — ${param} = ${actual}"
        else
            log_fail "CIS 3.x — ${param} = ${actual} (expected: ${expected})"
            if apply_fix; then
                sysctl -w "${param}=${expected}" &>/dev/null
                echo "${param} = ${expected}" >> /etc/sysctl.d/99-hardhat.conf
            fi
        fi
    done

    # 3.4 — Firewall
    if systemctl is-active firewalld &>/dev/null; then
        log_pass "CIS 3.4.1 — firewalld is active"
    elif systemctl is-active nftables &>/dev/null; then
        log_pass "CIS 3.4.1 — nftables is active"
    elif systemctl is-active iptables &>/dev/null; then
        log_pass "CIS 3.4.1 — iptables is active"
    else
        log_fail "CIS 3.4.1 — No firewall service is active"
        if apply_fix; then
            systemctl enable --now firewalld &>/dev/null
            log_info "Enabled and started firewalld"
        fi
    fi

    # Wireless
    if nmcli radio wifi 2>/dev/null | grep -q "disabled"; then
        log_pass "CIS 3.1.2 — Wireless interfaces are disabled"
    else
        log_warn "CIS 3.1.2 — Wireless interfaces may be enabled"
    fi

    # Uncommon network protocols
    local uncommon_protos=("dccp" "sctp" "rds" "tipc")
    for proto in "${uncommon_protos[@]}"; do
        if lsmod | grep -q "^${proto} " 2>/dev/null; then
            log_fail "CIS 3.5.x — Uncommon protocol '${proto}' is loaded"
            if apply_fix; then
                echo "install ${proto} /bin/true" >> /etc/modprobe.d/hardhat.conf
                echo "blacklist ${proto}" >> /etc/modprobe.d/hardhat.conf
            fi
        else
            log_pass "CIS 3.5.x — Protocol '${proto}' is not loaded"
        fi
    done
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 6: SSH SERVER HARDENING
# CIS 5.2 — SSH server configuration
# ═══════════════════════════════════════════════════════════════════════
mod_ssh() {
    log_section "6. SSH SERVER HARDENING (CIS 5.2)"

    local sshd_cfg="/etc/ssh/sshd_config"
    [[ -f "$sshd_cfg" ]] || { log_skip "sshd_config not found"; return; }

    backup_file "$sshd_cfg"

    # SSH checks
    local -A ssh_params=(
        ["Protocol"]="2"
        ["LogLevel"]="INFO"
        ["MaxAuthTries"]="4"
        ["IgnoreRhosts"]="yes"
        ["HostbasedAuthentication"]="no"
        ["PermitRootLogin"]="no"
        ["PermitEmptyPasswords"]="no"
        ["PermitUserEnvironment"]="no"
        ["ClientAliveInterval"]="300"
        ["ClientAliveCountMax"]="3"
        ["LoginGraceTime"]="60"
        ["MaxStartups"]="10:30:60"
        ["MaxSessions"]="10"
        ["Banner"]="/etc/issue.net"
        ["X11Forwarding"]="no"
        ["AllowTcpForwarding"]="no"
        ["UsePAM"]="yes"
    )

    for param in "${!ssh_params[@]}"; do
        local expected="${ssh_params[$param]}"
        local actual
        actual=$(grep -i "^${param}" "$sshd_cfg" 2>/dev/null | awk '{print $2}' | head -1)
        if [[ "${actual,,}" == "${expected,,}" ]]; then
            log_pass "CIS 5.2.x — SSH ${param} = ${actual}"
        else
            log_fail "CIS 5.2.x — SSH ${param} = '${actual:-not set}' (expected: ${expected})"
            if apply_fix; then
                if grep -qi "^${param}" "$sshd_cfg"; then
                    sed -i "s/^${param}.*/${param} ${expected}/i" "$sshd_cfg"
                else
                    echo "${param} ${expected}" >> "$sshd_cfg"
                fi
            fi
        fi
    done

    # SSH key permissions
    if [[ -f "$sshd_cfg" ]]; then
        local sshd_perms
        sshd_perms=$(stat -c "%a" "$sshd_cfg" 2>/dev/null)
        if [[ "$sshd_perms" == "600" ]]; then
            log_pass "CIS 5.2.1 — sshd_config permissions: ${sshd_perms}"
        else
            log_fail "CIS 5.2.1 — sshd_config permissions: ${sshd_perms} (expected 600)"
            if apply_fix; then chmod 600 "$sshd_cfg"; fi
        fi
    fi

    # Approved ciphers (CIS 5.2.13)
    local strong_ciphers="aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
    if grep -qi "^Ciphers" "$sshd_cfg" 2>/dev/null; then
        log_pass "CIS 5.2.13 — SSH Ciphers are configured"
    else
        log_warn "CIS 5.2.13 — SSH Ciphers not explicitly configured"
        if apply_fix; then
            echo "Ciphers ${strong_ciphers}" >> "$sshd_cfg"
            log_info "Set strong SSH ciphers"
        fi
    fi

    # Approved MACs (CIS 5.2.14)
    local strong_macs="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
    if grep -qi "^MACs" "$sshd_cfg" 2>/dev/null; then
        log_pass "CIS 5.2.14 — SSH MACs are configured"
    else
        log_warn "CIS 5.2.14 — SSH MACs not explicitly configured"
        if apply_fix; then
            echo "MACs ${strong_macs}" >> "$sshd_cfg"
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 7: USER ACCOUNTS & AUTHENTICATION
# CIS 5.3-5.6 — PAM, password policy, user settings
# ═══════════════════════════════════════════════════════════════════════
mod_accounts() {
    log_section "7. USER ACCOUNTS & AUTHENTICATION (CIS 5.3-5.6)"

    # 5.4.1 — Password expiration
    local max_days min_days warn_days
    max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    min_days=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    warn_days=$(grep "^PASS_WARN_AGE" /etc/login.defs 2>/dev/null | awk '{print $2}')

    if [[ "${max_days:-99999}" -le 365 ]]; then
        log_pass "CIS 5.4.1.1 — PASS_MAX_DAYS: ${max_days}"
    else
        log_fail "CIS 5.4.1.1 — PASS_MAX_DAYS: ${max_days:-not set} (should be ≤365)"
        if apply_fix; then
            backup_file /etc/login.defs
            sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t365/' /etc/login.defs
        fi
    fi

    if [[ "${min_days:-0}" -ge 1 ]]; then
        log_pass "CIS 5.4.1.2 — PASS_MIN_DAYS: ${min_days}"
    else
        log_fail "CIS 5.4.1.2 — PASS_MIN_DAYS: ${min_days:-0} (should be ≥1)"
        if apply_fix; then
            sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/' /etc/login.defs
        fi
    fi

    if [[ "${warn_days:-0}" -ge 7 ]]; then
        log_pass "CIS 5.4.1.3 — PASS_WARN_AGE: ${warn_days}"
    else
        log_fail "CIS 5.4.1.3 — PASS_WARN_AGE: ${warn_days:-0} (should be ≥7)"
        if apply_fix; then
            sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t7/' /etc/login.defs
        fi
    fi

    # 5.4.2 — System accounts secured
    local sys_accounts
    sys_accounts=$(awk -F: '($3 < 1000 && $1 != "root" && $7 != "/sbin/nologin" && $7 != "/bin/false" && $7 != "/usr/sbin/nologin") {print $1}' /etc/passwd 2>/dev/null)
    if [[ -z "$sys_accounts" ]]; then
        log_pass "CIS 5.4.2 — All system accounts have nologin shell"
    else
        log_fail "CIS 5.4.2 — System accounts with login shell: ${sys_accounts}"
    fi

    # 5.4.3 — Default group for root
    if [[ "$(grep "^root:" /etc/passwd | cut -d: -f4)" == "0" ]]; then
        log_pass "CIS 5.4.3 — Default group for root is GID 0"
    else
        log_fail "CIS 5.4.3 — Root default group is not GID 0"
    fi

    # 5.4.4 — Default user umask
    local umask_val
    umask_val=$(grep -E "^\s*umask\s+[0-9]+" /etc/bashrc /etc/profile 2>/dev/null | awk '{print $2}' | head -1)
    if [[ "$umask_val" == "027" ]] || [[ "$umask_val" == "077" ]]; then
        log_pass "CIS 5.4.4 — Default umask: ${umask_val}"
    else
        log_fail "CIS 5.4.4 — Default umask: ${umask_val:-not set} (should be 027 or 077)"
    fi

    # 5.5.2 — Root login restricted to console
    if [[ -f /etc/securetty ]]; then
        log_pass "CIS 5.5.2 — /etc/securetty exists (root console restricted)"
    else
        log_warn "CIS 5.5.2 — /etc/securetty not found"
    fi

    # 5.6 — su restricted
    if grep -q "pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
        log_pass "CIS 5.6 — Access to su is restricted via pam_wheel"
    else
        log_warn "CIS 5.6 — su access not restricted to wheel group"
    fi

    # UID 0 accounts
    local uid0
    uid0=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
    if [[ -z "$uid0" ]]; then
        log_pass "NIST — Only root has UID 0"
    else
        log_fail "NIST — Non-root accounts with UID 0: ${uid0}"
    fi

    # Empty passwords
    local empty_pw
    empty_pw=$(awk -F: '($2 == "" ) {print $1}' /etc/shadow 2>/dev/null)
    if [[ -z "$empty_pw" ]]; then
        log_pass "NIST — No accounts with empty passwords"
    else
        log_fail "NIST — Accounts with empty passwords: ${empty_pw}"
    fi
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 8: AUDIT & LOGGING
# CIS 4.1-4.2 — auditd, rsyslog
# ═══════════════════════════════════════════════════════════════════════
mod_logging() {
    log_section "8. AUDIT & LOGGING (CIS 4.1-4.2)"

    # 4.1.1.1 — auditd installed
    if rpm -q audit &>/dev/null; then
        log_pass "CIS 4.1.1.1 — auditd is installed"
    else
        log_fail "CIS 4.1.1.1 — auditd is NOT installed"
        if apply_fix; then
            dnf install -y audit audit-libs &>/dev/null
        fi
    fi

    # 4.1.1.2 — auditd enabled
    if systemctl is-enabled auditd &>/dev/null; then
        log_pass "CIS 4.1.1.2 — auditd is enabled"
    else
        log_fail "CIS 4.1.1.2 — auditd is NOT enabled"
        if apply_fix; then
            systemctl enable --now auditd &>/dev/null
        fi
    fi

    # 4.1.3 — Audit rules for key events
    local audit_rules=(
        "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change"
        "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale"
        "-w /etc/group -p wa -k identity"
        "-w /etc/passwd -p wa -k identity"
        "-w /etc/shadow -p wa -k identity"
        "-w /etc/sudoers -p wa -k scope"
        "-w /var/log/lastlog -p wa -k logins"
        "-w /var/run/faillock -p wa -k logins"
        "-w /etc/selinux/ -p wa -k MAC-policy"
        "-w /var/log/audit/ -p wa -k audit-logs"
    )

    if [[ -f /etc/audit/rules.d/hardhat.rules ]]; then
        log_pass "CIS 4.1.3+ — HardHat audit rules file exists"
    else
        log_warn "CIS 4.1.3+ — HardHat audit rules not yet deployed"
        if apply_fix; then
            printf '%s\n' "${audit_rules[@]}" > /etc/audit/rules.d/hardhat.rules
            augenrules --load &>/dev/null 2>&1
            log_info "Deployed HardHat audit rules"
        fi
    fi

    # 4.2.1 — rsyslog installed and running
    if rpm -q rsyslog &>/dev/null && systemctl is-active rsyslog &>/dev/null; then
        log_pass "CIS 4.2.1 — rsyslog is installed and active"
    else
        log_fail "CIS 4.2.1 — rsyslog is not active"
    fi

    # 4.2.1.4 — Log file permissions
    local bad_perms
    bad_perms=$(find /var/log -type f -perm /037 2>/dev/null | head -5 | wc -l)
    if [[ "$bad_perms" -eq 0 ]]; then
        log_pass "CIS 4.2.1.4 — Log file permissions are appropriate"
    else
        log_warn "CIS 4.2.1.4 — ${bad_perms} log files with loose permissions"
    fi
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 9: SERVICES
# CIS 2.1-2.2 — Unnecessary services
# ═══════════════════════════════════════════════════════════════════════
mod_services() {
    log_section "9. SERVICES (CIS 2.1-2.2)"

    local unnecessary_services=(
        "autofs" "avahi-daemon" "cups" "dhcpd" "dovecot" "httpd"
        "named" "nfs-server" "rpcbind" "slapd" "smb" "squid"
        "snmpd" "vsftpd" "xinetd" "ypserv" "telnet.socket"
        "rsh.socket" "rlogin.socket" "rexec.socket" "tftp.socket"
    )

    for svc in "${unnecessary_services[@]}"; do
        if systemctl is-active "$svc" &>/dev/null; then
            log_fail "CIS 2.x — Service '${svc}' is running (should be disabled)"
            if apply_fix; then
                systemctl stop "$svc" &>/dev/null
                systemctl disable "$svc" &>/dev/null
                systemctl mask "$svc" &>/dev/null
                log_info "Stopped, disabled, and masked ${svc}"
            fi
        else
            log_pass "CIS 2.x — Service '${svc}' is not running"
        fi
    done

    # NTP
    if systemctl is-active chronyd &>/dev/null || systemctl is-active ntpd &>/dev/null; then
        log_pass "CIS 2.2.1.1 — Time synchronization is active"
    else
        log_fail "CIS 2.2.1.1 — No time synchronization service active"
    fi
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 10: FILE PERMISSIONS & INTEGRITY
# CIS 6.1-6.2 — System file permissions, user/group
# ═══════════════════════════════════════════════════════════════════════
mod_permissions() {
    log_section "10. FILE PERMISSIONS & INTEGRITY (CIS 6.1-6.2)"

    local -A critical_files=(
        ["/etc/passwd"]="644"
        ["/etc/shadow"]="000"
        ["/etc/group"]="644"
        ["/etc/gshadow"]="000"
        ["/etc/passwd-"]="644"
        ["/etc/shadow-"]="000"
        ["/etc/group-"]="644"
        ["/etc/gshadow-"]="000"
    )

    for file in "${!critical_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            log_skip "File ${file} not found"
            continue
        fi
        local expected="${critical_files[$file]}"
        local actual
        actual=$(stat -c "%a" "$file" 2>/dev/null)
        if [[ "$actual" == "$expected" ]] || [[ "$actual" -le "$expected" ]]; then
            log_pass "CIS 6.1.x — ${file} permissions: ${actual}"
        else
            log_fail "CIS 6.1.x — ${file} permissions: ${actual} (expected: ${expected})"
            if apply_fix; then
                chmod "$expected" "$file"
                chown root:root "$file" 2>/dev/null
            fi
        fi
    done

    # World-writable files
    local ww_count
    ww_count=$(df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | xargs -I{} find {} -xdev -type f -perm -0002 2>/dev/null | wc -l)
    if [[ "$ww_count" -eq 0 ]]; then
        log_pass "CIS 6.1.10 — No world-writable files found"
    else
        log_warn "CIS 6.1.10 — ${ww_count} world-writable file(s) found"
    fi

    # Unowned files
    local unowned
    unowned=$(df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | xargs -I{} find {} -xdev -nouser 2>/dev/null | wc -l)
    if [[ "$unowned" -eq 0 ]]; then
        log_pass "CIS 6.1.11 — No unowned files found"
    else
        log_warn "CIS 6.1.11 — ${unowned} unowned file(s) found"
    fi

    # SUID/SGID audit
    local suid_count
    suid_count=$(df --local -P 2>/dev/null | awk '{if (NR!=1) print $6}' | xargs -I{} find {} -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l)
    log_info "SUID/SGID binaries found: ${suid_count} (review for unauthorized additions)"
}

# ═══════════════════════════════════════════════════════════════════════
# MODULE 11: LOGIN WARNING BANNERS
# CIS 1.7 — Warning banners
# ═══════════════════════════════════════════════════════════════════════
mod_banners() {
    log_section "11. LOGIN WARNING BANNERS (CIS 1.7)"

    local banner_text="Authorized users only. All activity may be monitored and reported."

    for file in /etc/motd /etc/issue /etc/issue.net; do
        if [[ -f "$file" ]] && [[ -s "$file" ]]; then
            log_pass "CIS 1.7.x — ${file} exists and is not empty"
        else
            log_fail "CIS 1.7.x — ${file} is missing or empty"
            if apply_fix; then
                echo "$banner_text" > "$file"
                chmod 644 "$file"
                chown root:root "$file"
                log_info "Created warning banner in ${file}"
            fi
        fi

        # Check for OS info leakage
        if grep -qEi "(\\\\v|\\\\r|\\\\m|\\\\s|centos|red.hat|rocky|alma)" "$file" 2>/dev/null; then
            log_warn "CIS 1.7.x — ${file} contains OS information (should be removed)"
        fi
    done
}

# ═══════════════════════════════════════════════════════════════════════
# REPORT GENERATION
# ═══════════════════════════════════════════════════════════════════════
generate_report() {
    log_section "GENERATING REPORT"
    local score=0
    [[ $TOTAL_COUNT -gt 0 ]] && score=$(( PASS_COUNT * 100 / TOTAL_COUNT ))

    cat > "$REPORT_FILE" << HTMLEOF
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>HardHat Report</title>
<style>body{font-family:monospace;background:#0a0e14;color:#c8d6e5;padding:20px;max-width:900px;margin:0 auto}
h1{color:#ee0000}h2{color:#00d4ff;border-bottom:1px solid #1e2d3e;padding-bottom:8px}
.pass{color:#2ed573}.fail{color:#ff4757}.warn{color:#ee0000}
.stat{display:inline-block;padding:8px 16px;margin:4px;border:1px solid #1e2d3e;border-radius:6px}
pre{background:#111922;padding:16px;border-radius:6px;overflow-x:auto;border:1px solid #1e2d3e}</style></head>
<body><h1>🔨 HardHat Hardening Report</h1>
<p>Generated: $(date)</p><p>Hostname: $(hostname)</p><p>RHEL Version: ${RHEL_VERSION}</p><p>Profile: ${PROFILE}</p>
<h2>Summary</h2>
<div class="stat pass">PASS: ${PASS_COUNT}</div>
<div class="stat fail">FAIL: ${FAIL_COUNT}</div>
<div class="stat warn">WARN: ${WARN_COUNT}</div>
<div class="stat">SKIP: ${SKIP_COUNT}</div>
<div class="stat">TOTAL: ${TOTAL_COUNT}</div>
<div class="stat" style="color:#ee0000;font-size:1.5em">SCORE: ${score}%</div>
<h2>Full Log</h2><pre>$(cat "$LOG_FILE" 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g')</pre>
</body></html>
HTMLEOF
    log_info "HTML report: ${REPORT_FILE}"
}

# ═══════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════
print_summary() {
    local score=0
    [[ $TOTAL_COUNT -gt 0 ]] && score=$(( PASS_COUNT * 100 / TOTAL_COUNT ))

    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  HardHat Hardening Summary${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}PASS:${NC}  ${PASS_COUNT}"
    echo -e "  ${RED}FAIL:${NC}  ${FAIL_COUNT}"
    echo -e "  ${YELLOW}WARN:${NC}  ${WARN_COUNT}"
    echo -e "  ${DIM}SKIP:${NC}  ${SKIP_COUNT}"
    echo -e "  TOTAL: ${TOTAL_COUNT}"
    echo ""
    if [[ $score -ge 80 ]]; then
        echo -e "  Score: ${GREEN}${BOLD}${score}%${NC} — Well hardened"
    elif [[ $score -ge 60 ]]; then
        echo -e "  Score: ${YELLOW}${BOLD}${score}%${NC} — Needs improvement"
    else
        echo -e "  Score: ${RED}${BOLD}${score}%${NC} — Critical gaps found"
    fi
    echo ""
    echo -e "  ${DIM}Log:    ${LOG_FILE}${NC}"
    echo -e "  ${DIM}Report: ${REPORT_FILE}${NC}"
    echo -e "  ${DIM}Backup: ${BACKUP_DIR}${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
}

# ═══════════════════════════════════════════════════════════════════════
# USAGE & CLI
# ═══════════════════════════════════════════════════════════════════════
usage() {
    echo "Usage: hardhat.sh [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --audit          Audit only (no changes, just report)"
    echo "  --fix            Audit + apply fixes (default)"
    echo "  --dry-run        Show what would be changed"
    echo "  --profile LEVEL  CIS profile: level1, level2, stig (default: level1)"
    echo "  --module MOD     Run specific module(s): filesystem, packages, boot,"
    echo "                   selinux, network, ssh, accounts, logging, services,"
    echo "                   permissions, banners"
    echo "  --report         Generate HTML report"
    echo "  --version        Show version"
    echo "  --help           Show this help"
    echo ""
    echo "Examples:"
    echo "  hardhat.sh --audit                    # Audit only"
    echo "  hardhat.sh --fix --profile level2     # Fix with CIS Level 2"
    echo "  hardhat.sh --module ssh,network       # Only harden SSH and network"
    echo "  hardhat.sh --dry-run --report         # Dry run with HTML report"
}

# ─── Parse Arguments ──────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --audit) AUDIT_ONLY=true; shift ;;
            --fix) AUDIT_ONLY=false; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            --profile) PROFILE="$2"; shift 2 ;;
            --module) IFS=',' read -ra MODULES <<< "$2"; shift 2 ;;
            --report) shift ;;
            --version) echo "HardHat v${VERSION}"; exit 0 ;;
            --help|-h) usage; exit 0 ;;
            *) echo "Unknown option: $1"; usage; exit 1 ;;
        esac
    done
}

# ─── Main ─────────────────────────────────────────────────────────────
main() {
    parse_args "$@"
    banner
    check_root
    mkdir -p "$LOG_DIR" "$BACKUP_DIR"
    detect_rhel

    log_info "Mode: $( $AUDIT_ONLY && echo 'AUDIT ONLY' || ($DRY_RUN && echo 'DRY RUN' || echo 'AUDIT + FIX'))"
    log_info "Profile: ${PROFILE}"
    log_info "Log: ${LOG_FILE}"

    # Run modules
    local all_modules=("filesystem" "packages" "boot" "selinux" "network" "ssh" "accounts" "logging" "services" "permissions" "banners")

    if [[ ${#MODULES[@]} -gt 0 ]]; then
        for mod in "${MODULES[@]}"; do
            case "$mod" in
                filesystem)  mod_filesystem ;;
                packages)    mod_packages ;;
                boot)        mod_boot ;;
                selinux)     mod_selinux ;;
                network)     mod_network ;;
                ssh)         mod_ssh ;;
                accounts)    mod_accounts ;;
                logging)     mod_logging ;;
                services)    mod_services ;;
                permissions) mod_permissions ;;
                banners)     mod_banners ;;
                *) log_warn "Unknown module: ${mod}" ;;
            esac
        done
    else
        for mod in "${all_modules[@]}"; do
            "mod_${mod}"
        done
    fi

    generate_report
    print_summary
}

main "$@"
