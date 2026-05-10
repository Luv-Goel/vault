"""Entropy-based secret detection for Vault."""

import re
import math
from typing import List, Dict, Any
from collections import Counter


def shannon_entropy(data: str) -> float:
    """Compute Shannon entropy of a string."""
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def find_high_entropy_strings(line: str, min_length: int = 20, threshold: float = 4.5) -> List[Dict]:
    """Find high-entropy strings in a line of text."""
    results = []

    # Find potential secret-like tokens (alphanumeric + special chars)
    # Match strings that look like tokens/keys
    patterns = [
        r'[0-9a-zA-Z\/+]{40,}',        # Base64-like (40+ chars)
        r'[0-9a-fA-F]{32,}',            # Hex strings (32+ chars)
        r'[0-9a-zA-Z\-_]{30,}',          # Alphanumeric with dashes/underscores
    ]

    for pat in patterns:
        for m in re.finditer(pat, line):
            token = m.group()
            if len(token) >= min_length:
                ent = shannon_entropy(token)
                if ent >= threshold:
                    # Filter out common false positives
                    if _is_false_positive(token, line):
                        continue
                    results.append({
                        "value": token,
                        "entropy": round(ent, 2),
                        "start": m.start(),
                        "end": m.end(),
                        "length": len(token),
                    })

    return results


_FP_PATTERNS = [
    re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I),  # UUID
    re.compile(r'^v[0-9]+\.[0-9]+\.[0-9]+'),  # Version strings
    re.compile(r'^[0-9a-f]{40}$', re.I),  # Git commit hashes
    re.compile(r'^[0-9a-f]{64}$', re.I),  # SHA-256 hashes
    re.compile(r'^[0-9a-f]{128}$', re.I),  # SHA-512 hashes
    re.compile(r'^\d{4}-\d{2}-\d{2}T'),  # ISO timestamps
    re.compile(r'^[a-z]+\.[a-z]+\.[a-z]+$'),  # Package names
]


def _is_false_positive(token: str, line: str) -> bool:
    """Check if a high-entropy string is likely not a secret."""
    # Check known FP patterns
    for fp in _FP_PATTERNS:
        if fp.match(token):
            return True

    # Check if it's in a test/mock file context
    lower_line = line.lower()
    fp_keywords = ["example", "test", "mock", "fake", "placeholder", "changeme",
                   "your-", "your_", "xxxx", "sample", "demo"]
    for kw in fp_keywords:
        if kw in lower_line:
            return True

    # Check if it looks like a URL path
    if token.startswith("/") or token.startswith("./"):
        return True

    # Check if it's a file path
    if token.count("/") >= 2 and not token.startswith("http"):
        return True

    return False
