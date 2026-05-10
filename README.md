# Vault ðŸ”’

<div align="center">

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)]()
[![Python](https://img.shields.io/badge/python-3.8%2B-brightgreen)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-lightgrey)]()

**Code secret scanner â€” find hardcoded credentials, tokens, API keys, and secrets. Zero dependencies.**

</div>

---

## Features

- **20+ regex patterns** â€” AWS keys, GitHub tokens, GitLab tokens, Stripe API keys, Discord tokens, SSH private keys, database URLs, generic secrets
- **Entropy detection** â€” Shannon entropy scoring to find high-entropy strings that look like secrets
- **Smart false-positive filtering** â€” Skips test files, example code, known safe patterns
- **Multi-threaded scanning** â€” Parallel file processing for speed
- **Multiple output formats** â€” SARIF, JSON, HTML, plain text
- **CI/CD ready** â€” Exit code on findings for pipeline integration
- **Zero dependencies** â€” Pure Python 3.8+, stdlib only

## Quick Start

```bash
pip install vault-scanner

# Scan current directory
vault scan

# Scan specific path
vault scan /path/to/project

# JSON output (for pipeline integration)
vault scan . --format json

# SARIF output (for GitHub Code Scanning)
vault scan . --format sarif

# Full HTML report
vault report . --output vault-report.html
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `vault scan [path]` | Scan for hardcoded secrets |
| `vault report [path]` | Generate HTML scan report |

### Options

| Flag | Description |
|------|-------------|
| `--format TYPE` | Output format: text, json, sarif, html (default: text) |
| `--output FILE` | Write results to file |
| `--include-tests` | Include test files in scan (excluded by default) |
| `--entropy-threshold` | Entropy score threshold (default: 4.5) |
| `--threads N` | Parallel scan threads (default: CPU count) |

## Detection Patterns

| Category | Patterns |
|----------|----------|
| Cloud | AWS Access Key, AWS Secret Key, GCP Service Account |
| SCM | GitHub Token, GitLab Token, GitHub SSH Key |
| Payment | Stripe Live/Test Key, Stripe Webhook Secret |
| Communication | Discord Token, Slack Token, Telegram Bot Token |
| Crypto | Private Key (RSA, ECDSA, Ed25519), PGP Private Key |
| Database | PostgreSQL/MySQL/MongoDB URLs, Redis URI |
| Generic | Password= in configs, secret= in URLs, API keys, Bearer tokens |

## How It Works

1. **Pattern matching** â€” Regex scan against 20+ known secret patterns
2. **Entropy analysis** â€” Shannon entropy on high-risk strings (API keys, tokens)
3. **False-positive filter** â€” Excludes test fixtures, examples, known safe patterns
4. **Priority scoring** â€” Ranks findings by risk level (critical, high, medium, low)
5. **Report generation** â€” Formats findings with file, line, context, and severity

## Architecture

```
vault/
â”œâ”€â”€ vault/
â”‚   â”œâ”€â”€ __init__.py
â”‚   â”œâ”€â”€ cli.py       # CLI entry point
â”‚   â”œâ”€â”€ patterns.py  # Secret detection regex patterns
â”‚   â”œâ”€â”€ scanner.py   # File scanning engine
â”‚   â”œâ”€â”€ entropy.py   # Shannon entropy calculation
â”‚   â””â”€â”€ report.py    # Output formatters
â”œâ”€â”€ pyproject.toml
â””â”€â”€ README.md
```

## License

MIT â€” see [LICENSE](LICENSE).
