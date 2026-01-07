# Security Policy

## Reporting a Vulnerability

Please report sensitive security issues via email to specific security contact (TBD), or open a draft security advisory in GitHub if available.

**Do not open public issues for security vulnerabilities.**

## Design Principles

- **Privacy First**: We assume logs contain sensitive PII. No data leaves the machine unless the user explicitly enables an "External AI" feature (which defaults to OFF).
- **Fail-Safe**: If the agent crashes or encounters error, it defaults to "do nothing" rather than "block everything".
- **Privilege Separation**: Ideally, the agent runs as a dedicated user, though it needs read access to logs (often root or `adm` group).
- **No Auto-Remediation**: The agent is an advisor. It does not modify firewall rules or kill processes automatically.

## Updates

Security updates will be prioritised.
