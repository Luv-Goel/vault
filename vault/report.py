"""Output formatting and report generation for Vault."""

import json
import os
from typing import List, Dict, Any
from datetime import datetime


def format_text(findings: List[Dict]) -> str:
    """Format findings as human-readable text."""
    if not findings:
        return "  [OK] No secrets found."

    # Group by severity
    by_severity: Dict[str, List] = {}
    for f in findings:
        sev = f.get("severity", "low")
        if sev not in by_severity:
            by_severity[sev] = []
        by_severity[sev].append(f)

    lines = ["=" * 56, "  Vault Scan Results", "=" * 56]
    lines.append(f"  Total findings: {len(findings)}")
    lines.append("")

    severity_order = ["critical", "high", "medium", "low"]
    sev_labels = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}

    for sev in severity_order:
        if sev not in by_severity:
            continue
        items = by_severity[sev]
        lines.append(f"  [{sev_labels[sev]}] {len(items)} findings:")
        for f in items:
            relpath = os.path.relpath(f["file"])
            if f["type"] == "entropy":
                lines.append(f"    {relpath}:{f['line']}")
                lines.append(f"      High-entropy string ({f.get('entropy', '?')} bits)")
                lines.append(f"      {f['match']}")
            else:
                lines.append(f"    {relpath}:{f['line']}")
                lines.append(f"      {f['pattern_name']} ({f['group']})")
                lines.append(f"      {f['match']}")
            if "context" in f:
                ctx_lines = f["context"].split("\n")
                lines.append(f"      Context:")
                for cl in ctx_lines:
                    lines.append(f"        | {cl}")
        lines.append("")

    return "\n".join(lines)


def write_json(findings: List[Dict], output_path: str) -> str:
    """Write findings as JSON."""
    report = {
        "tool": "vault",
        "version": "0.1.0",
        "generated_at": datetime.now().isoformat(),
        "total_findings": len(findings),
        "findings": findings,
        "summary": {
            "critical": sum(1 for f in findings if f.get("severity") == "critical"),
            "high": sum(1 for f in findings if f.get("severity") == "high"),
            "medium": sum(1 for f in findings if f.get("severity") == "medium"),
            "low": sum(1 for f in findings if f.get("severity") == "low"),
        },
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    return output_path


def write_html(findings: List[Dict], output_path: str, title: str = "Vault Security Scan") -> str:
    """Generate HTML report."""
    summary = {
        "critical": sum(1 for f in findings if f.get("severity") == "critical"),
        "high": sum(1 for f in findings if f.get("severity") == "high"),
        "medium": sum(1 for f in findings if f.get("severity") == "medium"),
        "low": sum(1 for f in findings if f.get("severity") == "low"),
    }

    rows = ""
    for f in findings:
        sev_color = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#94a3b8"}
        sev = f.get("severity", "low")
        color = sev_color.get(sev, "#94a3b8")
        relpath = os.path.relpath(f.get("file", ""))
        rows += f"""
        <tr>
            <td><span class="sev-dot" style="background:{color}"></span>{sev.upper()}</td>
            <td>{f.get('pattern_name', '')}</td>
            <td>{relpath}:{f.get('line', 0)}</td>
            <td style="font-size:0.8rem;max-width:400px;overflow:hidden;text-overflow:ellipsis"><code>{f.get('match', '')}</code></td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }}
h1 {{ font-size: 1.8rem; margin-bottom: 0.5rem; }}
.meta {{ color: #94a3b8; margin-bottom: 1.5rem; }}
.grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 2rem; }}
.stat {{ padding: 1rem; border-radius: 0.75rem; }}
.stat.critical {{ background: #450a0a; border-left: 4px solid #ef4444; }}
.stat.high {{ background: #431407; border-left: 4px solid #f97316; }}
.stat.medium {{ background: #422006; border-left: 4px solid #eab308; }}
.stat.low {{ background: #1e293b; border-left: 4px solid #64748b; }}
.stat-value {{ font-size: 1.5rem; font-weight: 700; }}
.stat-label {{ font-size: 0.8rem; opacity: 0.8; }}
table {{ width: 100%; border-collapse: collapse; }}
th {{ text-align: left; padding: 0.5rem; background: #1e293b; border-bottom: 2px solid #334155; font-size: 0.8rem; }}
td {{ padding: 0.5rem; border-bottom: 1px solid #1e293b; font-size: 0.85rem; }}
tr:hover {{ background: #1e293b; }}
.sev-dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 4px; }}
code {{ color: #f87171; background: #1e293b; padding: 0.1rem 0.3rem; border-radius: 2px; }}
.total {{ margin: 1rem 0; font-size: 1.1rem; }}
</style>
</head>
<body>
<h1>{title}</h1>
<p class="meta">Generated by Vault 0.1.0</p>

<div class="grid">
    <div class="stat critical"><div class="stat-value">{summary['critical']}</div><div class="stat-label">Critical</div></div>
    <div class="stat high"><div class="stat-value">{summary['high']}</div><div class="stat-label">High</div></div>
    <div class="stat medium"><div class="stat-value">{summary['medium']}</div><div class="stat-label">Medium</div></div>
    <div class="stat low"><div class="stat-value">{summary['low']}</div><div class="stat-label">Low</div></div>
</div>

<div class="total">Total findings: {len(findings)}</div>

<table>
<thead><tr><th>Severity</th><th>Type</th><th>Location</th><th>Match</th></tr></thead>
<tbody>
{rows if rows else '<tr><td colspan="4" style="text-align:center;padding:2rem;color:#64748b">No findings</td></tr>'}
</tbody>
</table>
<p style="margin-top:2rem;color:#64748b;font-size:0.8rem;">Generated by Vault — Code Secret Scanner</p>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path


def write_sarif(findings: List[Dict], output_path: str) -> str:
    """Write findings in SARIF format (for GitHub Code Scanning)."""
    results = []
    for i, f in enumerate(findings):
        sev_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
        results.append({
            "ruleId": f.get("pattern_id", "unknown"),
            "level": sev_map.get(f.get("severity", "low"), "note"),
            "message": {"text": f"{f.get('pattern_name', 'Unknown')}: {f.get('match', '')}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": os.path.abspath(f.get("file", ""))},
                    "region": {
                        "startLine": f.get("line", 0),
                        "startColumn": f.get("start", 0) + 1,
                        "endColumn": f.get("end", 0) + 1,
                    },
                }
            }],
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Vault",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/Luv-Goel/vault",
                }
            },
            "results": results,
        }],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)

    return output_path
