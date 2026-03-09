# Security Policy

## Reporting Vulnerabilities

If you discover a security issue in HardHat:

1. **DO NOT** open a public GitHub issue
2. Email: **Site@hotmail.com**
3. Subject: `[HardHat Security] Brief description`

## Response Timeline
- Acknowledgment: 48 hours
- Status update: 7 days
- Resolution: 30 days

## Scope

**In scope:**
- Script injection vulnerabilities
- Privilege escalation via HardHat
- Incorrect hardening that weakens security
- Backup file exposure

**Out of scope:**
- Issues in the OS itself (report to Red Hat)
- CIS Benchmark content accuracy (report to CIS)
- Intentional misuse of the tool

## Important

HardHat modifies system configuration. Always test in a non-production environment first.
Running `--audit` mode makes no system changes and is always safe.
