# Contributing to HardHat

## Adding Checks

1. Identify the CIS/NIST/STIG control ID
2. Add the check to the appropriate module function in `hardhat.sh`
3. Use the logging functions: `log_pass`, `log_fail`, `log_warn`, `log_skip`
4. Include remediation in the `if apply_fix` block
5. Always `backup_file` before modifying any config

## Code Style

- Pure Bash (no Python, no external tools beyond coreutils)
- Use `shellcheck` for linting
- Include CIS/NIST control ID in every check
- Always wrap fixes in `if apply_fix; then ... fi`
- Test on both RHEL 8 and RHEL 9

## Testing

```bash
# Lint
shellcheck hardhat.sh

# Audit mode (safe, no changes)
sudo ./hardhat.sh --audit

# Dry run
sudo ./hardhat.sh --dry-run
```

## Commit Messages

Use conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`
