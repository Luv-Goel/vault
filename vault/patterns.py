"""Secret detection patterns for Vault."""

import re

# High-value secret patterns
PATTERNS = [
    # AWS
    {
        "id": "aws-access-key",
        "name": "AWS Access Key ID",
        "pattern": re.compile(r'(AKIA|ASIA)[0-9A-Z]{16}'),
        "severity": "critical",
        "group": "aws",
    },
    {
        "id": "aws-secret-key",
        "name": "AWS Secret Access Key",
        "pattern": re.compile(r'(?i)aws.{0,20}(?:secret.?access.?key|secret.?key).{0,20}([0-9a-zA-Z\/+]{40})'),
        "severity": "critical",
        "group": "aws",
    },
    # GitHub
    {
        "id": "github-token",
        "name": "GitHub Token",
        "pattern": re.compile(r'(ghp|gho|ghu|ghs|ghf)_[0-9a-zA-Z]{36,}'),
        "severity": "critical",
        "group": "github",
    },
    {
        "id": "github-pat",
        "name": "GitHub Fine-Grained PAT",
        "pattern": re.compile(r'github_pat_[0-9a-zA-Z]{22,}'),
        "severity": "critical",
        "group": "github",
    },
    # GitLab
    {
        "id": "gitlab-token",
        "name": "GitLab Personal Token",
        "pattern": re.compile(r'glpat-[0-9a-zA-Z\-_]{20,}'),
        "severity": "critical",
        "group": "gitlab",
    },
    # Google
    {
        "id": "google-api-key",
        "name": "Google API Key",
        "pattern": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        "severity": "high",
        "group": "google",
    },
    # Slack
    {
        "id": "slack-token",
        "name": "Slack Bot Token",
        "pattern": re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}'),
        "severity": "high",
        "group": "slack",
    },
    # Discord
    {
        "id": "discord-token",
        "name": "Discord Bot Token",
        "pattern": re.compile(r'(?:discord|bot).{0,20}([MN][0-9a-z_-]{23,25}\.[0-9a-z_-]{6,7}\.[0-9a-z_-]{27,})', re.I),
        "severity": "high",
        "group": "discord",
    },
    # Generic tokens
    {
        "id": "bearer-token",
        "name": "Bearer Token in Code",
        "pattern": re.compile(r'(?i)(?:authorization|bearer|token|apikey|api_key)\s*[:=]\s*["\']?[0-9a-zA-Z\-_.]{20,}["\']?'),
        "severity": "high",
        "group": "generic",
    },
    {
        "id": "jwt-token",
        "name": "JWT Token",
        "pattern": re.compile(r'eyJ[0-9a-zA-Z\-_]+\.eyJ[0-9a-zA-Z\-_]+\.[0-9a-zA-Z\-_]+'),
        "severity": "high",
        "group": "generic",
    },
    # Private keys
    {
        "id": "rsa-private-key",
        "name": "RSA Private Key",
        "pattern": re.compile(r'-----BEGIN\s*(?:RSA|DSA|EC|OPENSSH|PGP)\s*PRIVATE\s*KEY-----'),
        "severity": "critical",
        "group": "crypto",
    },
    {
        "id": "ssh-private-key",
        "name": "SSH Private Key",
        "pattern": re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
        "severity": "critical",
        "group": "crypto",
    },
    # npm / PyPI tokens
    {
        "id": "npm-token",
        "name": "npm Token",
        "pattern": re.compile(r'npm_[0-9a-zA-Z]{36}'),
        "severity": "high",
        "group": "package",
    },
    {
        "id": "pypi-token",
        "name": "PyPI Token",
        "pattern": re.compile(r'pypi-[A-Za-z0-9\-_]{20,}'),
        "severity": "high",
        "group": "package",
    },
    # Payment
    {
        "id": "stripe-key",
        "name": "Stripe API Key",
        "pattern": re.compile(r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}'),
        "severity": "critical",
        "group": "payment",
    },
    # Database connection strings with credentials
    {
        "id": "db-connection-url",
        "name": "Database URL with Credentials",
        "pattern": re.compile(r'(?i)(?:postgres|mysql|mongodb|redis|redshift)://\w+:\w+@'),
        "severity": "critical",
        "group": "database",
    },
    # Password assignments (high FP risk - marked medium)
    {
        "id": "password-assignment",
        "name": "Password/Hardcoded Credential",
        "pattern": re.compile(r'(?i)(?:password|passwd|pwd|secret)\s*[:=]\s*["\'][^"\']{6,}["\']'),
        "severity": "medium",
        "group": "generic",
    },
    # Twilio
    {
        "id": "twilio-key",
        "name": "Twilio API Key",
        "pattern": re.compile(r'SK[0-9a-fA-F]{32}'),
        "severity": "high",
        "group": "twilio",
    },
    # Heroku
    {
        "id": "heroku-key",
        "name": "Heroku API Key",
        "pattern": re.compile(r'(?i)heroku.{0,20}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}'),
        "severity": "high",
        "group": "heroku",
    },
]
