"""Core scanner for Vault — detects secrets in files and directories."""

import os
import re
from typing import List, Dict, Any, Optional, Set
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

from .patterns import PATTERNS
from .entropy import find_high_entropy_strings


# File extensions to skip
BINARY_EXTENSIONS = {
    ".pyc", ".o", ".so", ".dll", ".dylib", ".exe", ".elf",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".bmp",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".flac",
    ".db", ".sqlite", ".sqlite3",
    ".min.js", ".min.css",
    ".woff2", ".eot",
}

# Directories to skip
SKIP_DIRS = {
    ".git", ".svn", ".hg", ".venv", "node_modules", "__pycache__",
    ".eggs", "eggs", ".tox", "dist", "build", ".gradle",
    ".idea", ".vscode", ".mypy_cache", ".pytest_cache",
    ".serverless", ".terraform", "vendor",
}

# Filenames to skip
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Gemfile.lock", "poetry.lock", "Cargo.lock",
    ".gitignore", ".dockerignore",
}


def should_scan(path: str, root: str) -> bool:
    """Determine if a file should be scanned."""
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()

    if name in SKIP_FILES:
        return False
    if ext in BINARY_EXTENSIONS:
        return False

    # Check if any parent dir is in skip list
    rel = os.path.relpath(path, root)
    parts = rel.replace("\\", "/").split("/")
    for part in parts[:-1]:
        if part in SKIP_DIRS:
            return False

    return True


def find_files(root: str) -> List[str]:
    """Recursively find all files to scan."""
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Remove skip dirs in-place
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for fn in filenames:
            path = os.path.join(dirpath, fn)
            if should_scan(path, root):
                files.append(path)

    return files


def scan_line(line: str, file_path: str, line_num: int, enable_entropy: bool = True) -> List[Dict]:
    """Scan a single line for secrets."""
    results = []

    # Check regex patterns
    for pattern_info in PATTERNS:
        for m in pattern_info["pattern"].finditer(line):
            matched = m.group()
            # Truncate very long matches for display
            display = matched[:80] + "..." if len(matched) > 80 else matched

            results.append({
                "type": "pattern",
                "pattern_id": pattern_info["id"],
                "pattern_name": pattern_info["name"],
                "severity": pattern_info["severity"],
                "group": pattern_info["group"],
                "file": file_path,
                "line": line_num,
                "match": display,
                "start": m.start(),
                "end": m.end(),
            })

    # Check entropy
    if enable_entropy:
        for ent_match in find_high_entropy_strings(line):
            results.append({
                "type": "entropy",
                "pattern_id": "high-entropy",
                "pattern_name": "High-Entropy String",
                "severity": "medium",
                "group": "entropy",
                "file": file_path,
                "line": line_num,
                "match": ent_match["value"][:80],
                "entropy": ent_match["entropy"],
                "start": ent_match["start"],
                "end": ent_match["end"],
            })

    return results


def scan_file(file_path: str, enable_entropy: bool = True, context_lines: int = 0) -> List[Dict]:
    """Scan a single file for secrets."""
    results = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            # Read as bytes first to check for null bytes (binary)
            content = f.read()
    except Exception:
        return results

    if "\x00" in content[:4096]:
        return results  # Likely binary

    lines = content.split("\n")
    for i, line in enumerate(lines, 1):
        findings = scan_line(line, file_path, i, enable_entropy)
        if context_lines > 0:
            for f in findings:
                ctx_start = max(0, i - context_lines - 1)
                ctx_end = min(len(lines), i + context_lines)
                f["context"] = "\n".join(lines[ctx_start:ctx_end])
        results.extend(findings)

    return results


def scan_directory(root: str, enable_entropy: bool = True, max_workers: int = 4,
                   context_lines: int = 0) -> List[Dict]:
    """Scan a directory for secrets using parallel workers."""
    files = find_files(root)
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        for f in files:
            futures.append(executor.submit(scan_file, f, enable_entropy, context_lines))

        for future in futures:
            try:
                results.extend(future.result())
            except Exception:
                pass

    return results


def deduplicate_findings(findings: List[Dict]) -> List[Dict]:
    """Remove duplicate findings (same pattern on same line)."""
    seen: Set[str] = set()
    unique = []
    for f in findings:
        key = f"{f['file']}:{f['line']}:{f.get('pattern_id', 'entropy')}:{f.get('start', 0)}"
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def filter_by_severity(findings: List[Dict], min_severity: str) -> List[Dict]:
    """Filter findings by minimum severity level."""
    levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    min_level = levels.get(min_severity, 0)
    return [f for f in findings if levels.get(f.get("severity", "low"), 0) >= min_level]
