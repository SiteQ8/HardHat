# Changelog

## [2.0.0] - 2026-03-09

### Added
- 11 hardening modules (938 lines)
- 100+ security checks aligned to CIS Benchmark RHEL 8/9
- NIST 800-53 and DISA STIG alignment
- Auto-backup system (/var/backups/hardhat/)
- HTML report generation
- CLI with --audit, --fix, --dry-run, --module, --profile
- Color-coded terminal output (PASS/FAIL/WARN/SKIP)
- Compliance scoring (percentage)
- Module: Filesystem (CIS 1.1) — 15+ checks
- Module: Packages (CIS 1.2-1.3) — GPG, AIDE
- Module: Boot (CIS 1.4-1.5) — GRUB2, ASLR, core dumps
- Module: SELinux (CIS 1.6) — enforcing, policy, unconfined
- Module: Network (CIS 3.1-3.5) — 20 sysctl params, firewall
- Module: SSH (CIS 5.2) — 17 sshd parameters, ciphers, MACs
- Module: Accounts (CIS 5.3-5.6) — password policy, UID 0, umask
- Module: Logging (CIS 4.1-4.2) — auditd, 10 audit rules, rsyslog
- Module: Services (CIS 2.1-2.2) — 21 unnecessary services
- Module: Permissions (CIS 6.1-6.2) — critical files, SUID/SGID
- Module: Banners (CIS 1.7) — login warning banners
- GUI documentation page (docs/index.html)
- SVG banner screenshot
- Comprehensive README with module table
- Community files (LICENSE, SECURITY, CONTRIBUTING, CHANGELOG)
- GitHub issue templates, CI workflow
