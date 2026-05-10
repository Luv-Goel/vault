# Vault — Code Secret Scanner

<div align="center">

**Find hardcoded credentials, API keys, tokens, and secrets before they reach production.**

[![CI](https://github.com/Luv-Goel/vault/actions/workflows/ci.yml/badge.svg)](https://github.com/Luv-Goel/vault/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.8%20|%203.9%20|%203.10%20|%203.11%20|%203.12-blue?logo=python)](https://github.com/Luv-Goel/vault)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/Luv-Goel/vault?style=social)](https://github.com/Luv-Goel/vault/stargazers)

**Zero API keys. Zero dependencies. Pure Python.**

</div>

---

## Why Vault?

Hardcoded secrets are the #1 cause of credential leaks. But existing tools are:

- **Heavy** — trufflehog, gitleaks are Go binaries, slow to install
- **Cloud-dependent** — some require API keys to run
- **Over-engineered** — you just need to scan a directory

Vault is a single-file scanner: `pip install vault-secret-scanner && vault scan .`. No setup, no config, no cloud.

## Quick Start

```bash
pip install vault-secret-scanner

# Scan current directory
vault scan .

# Scan with minimum severity
vault scan ./src --severity high

# Generate HTML report
vault scan . --format html -o report.html

# JSON output for CI pipelines
vault scan . --format json -o results.json

# SARIF for GitHub Code Scanning
vault scan . --format sarif -o results.sarif

# List all detection patterns
vault list-patterns
```

## What It Finds

### Critical
- AWS Access Keys & Secret Keys
- GitHub tokens (personal, fine-grained, OAuth)
- GitLab personal tokens
- Stripe API Keys (live & test)
- Database URLs with credentials (postgres://, mysql://, mongodb://, redis://)
- RSA/DSA/EC/SSH Private Keys
- JWT tokens

### High
- Google API Keys
- Slack tokens (bot, app, user)
- Discord bot tokens
- npm and PyPI tokens
- Bearer tokens in code
- Twilio API Keys
- Heroku API Keys

### Medium
- Password/hardcoded credential assignments
- High-entropy strings (Shannon entropy > 4.5)

## Smart Filtering

Vault automatically filters out common false positives:

- **UUIDs** — `550e8400-e29b-41d4-a716-446655440000`
- **Git commit hashes** — `a1b2c3d4e5f6...`
- **Version strings** — `v1.2.3`, `1.0.0-alpha`
- **SHA hashes** — cryptographic hashes in code
- **Test files** — `test_*.py`, `*_test.go`, specs, fixtures
- **Example code** — lines containing "example", "placeholder", "changeme"
- **Dependency files** — `package-lock.json`, `yarn.lock`, `Gemfile.lock`

## Output Formats

| Format | Description | Use Case |
|--------|-------------|----------|
| Text | Color-coded severity with context | Terminal scanning |
| JSON | Structured findings with metadata | CI/CD pipelines |
| HTML | Dashboard with severity breakdown, searchable | Team reviews |
| SARIF | GitHub Code Scanning compatible | GitHub Actions |

## Project Structure

```
vault/
├── vault/
│   ├── cli.py       # Scan + list-patterns commands
│   ├── patterns.py  # 20+ regex detection patterns
│   ├── entropy.py   # Shannon entropy with FP filtering
│   ├── scanner.py   # File/directory scanning with threading
│   └── report.py    # Text, JSON, HTML, SARIF formatters
├── pyproject.toml
└── README.md
```

**Pure Python, zero external dependencies.** Works on Python 3.8+.

---

*Built by [ClawWorks Engineering Inc.](https://github.com/Luv-Goel) — 6 projects/day, no excuses.*
