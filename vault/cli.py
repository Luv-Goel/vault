"""Vault CLI — Code secret scanner."""

import argparse
import sys
import os

from . import __version__
from .scanner import scan_directory, scan_file, deduplicate_findings, filter_by_severity, find_files
from .report import format_text, write_json, write_html, write_sarif


def main():
    parser = argparse.ArgumentParser(
        prog="vault",
        description="Code secret scanner — find hardcoded credentials, tokens, and keys",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    p = sub.add_parser("scan", help="Scan a file or directory for secrets")
    p.add_argument("target", help="File or directory to scan")
    p.add_argument("--no-entropy", action="store_true", help="Disable entropy detection")
    p.add_argument("--severity", choices=["low", "medium", "high", "critical"], default=None,
                   help="Minimum severity to report")
    p.add_argument("--context", type=int, default=0, help="Lines of context around each finding")
    p.add_argument("--format", choices=["text", "json", "html", "sarif"], default="text",
                   help="Output format")
    p.add_argument("-o", "--output", default=None, help="Output file (default: stdout for text)")

    # list-patterns
    p = sub.add_parser("list-patterns", help="List all detection patterns")
    p.add_argument("--json", action="store_true", help="JSON output")

    args = parser.parse_args()

    if args.command == "list-patterns":
        _list_patterns(args)
        return

    if not os.path.exists(args.target):
        print(f"[ERR] Path not found: {args.target}", file=sys.stderr)
        sys.exit(1)

    if args.command == "scan":
        _scan(args)


def _scan(args):
    enable_entropy = not args.no_entropy

    print(f"  Scanning {args.target}...", file=sys.stderr)

    if os.path.isfile(args.target):
        findings = scan_file(args.target, enable_entropy, args.context)
    else:
        findings = scan_directory(args.target, enable_entropy, context_lines=args.context)

    findings = deduplicate_findings(findings)

    if args.severity:
        findings = filter_by_severity(findings, args.severity)

    # Output
    if args.format == "json":
        if args.output:
            path = write_json(findings, args.output)
            print(f"[OK] Results written to {path}", file=sys.stderr)
        else:
            import json
            json.dump({"findings": findings, "total": len(findings)}, sys.stdout, indent=2, default=str)
    elif args.format == "html":
        path = write_html(findings, args.output or "vault_report.html")
        print(f"[OK] Report written to {path}", file=sys.stderr)
    elif args.format == "sarif":
        path = write_sarif(findings, args.output or "vault_results.sarif")
        print(f"[OK] SARIF results written to {path}", file=sys.stderr)
    else:
        text = format_text(findings)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text)
                f.write("\n")
            print(f"[OK] Results written to {args.output}", file=sys.stderr)
        else:
            print(text)

    # Exit with code if findings exist
    if findings:
        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        if critical > 0 or high > 0:
            sys.exit(2)  # Critical/high findings
        sys.exit(1)  # Medium/low findings


def _list_patterns(args):
    from .patterns import PATTERNS
    if args.json:
        import json
        print(json.dumps([
            {"id": p["id"], "name": p["name"], "severity": p["severity"], "group": p["group"]}
            for p in PATTERNS
        ], indent=2))
    else:
        print("=" * 56)
        print("  Vault Detection Patterns")
        print("=" * 56)
        for p in PATTERNS:
            print(f"  [{p['severity'].upper():>8}] {p['name']:40s} ({p['group']})")
        print(f"\n  Total: {len(PATTERNS)} patterns")


if __name__ == "__main__":
    main()
