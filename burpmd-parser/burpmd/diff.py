"""
burpmd.diff
===========
Diffing engine to compare two BurpExport corpuses and highlight API changes,
new endpoints, and missing authorization headers.
"""

from pathlib import Path
from collections import defaultdict
import json
from urllib.parse import urlparse, parse_qsl

from .parser import BurpExport

def generate_diff_report(export1: BurpExport, export2: BurpExport, output_dir: Path, verbose: bool = False):
    """
    Compare export1 (baseline) and export2 (new) and generate DIFF_REPORT.md.
    """
    if verbose:
        print("[*] Generating differential analysis report...")

    ep1 = _extract_endpoints(export1)
    ep2 = _extract_endpoints(export2)

    # 1. Endpoint Diff
    set1 = set(ep1.keys())
    set2 = set(ep2.keys())

    new_endpoints = set2 - set1
    removed_endpoints = set1 - set2
    common_endpoints = set1 & set2

    # 2. Parameter Diff for common endpoints
    param_changes = {}
    for ep in common_endpoints:
        params1 = _extract_params(ep1[ep])
        params2 = _extract_params(ep2[ep])

        new_params = params2 - params1
        removed_params = params1 - params2
        if new_params or removed_params:
            param_changes[ep] = {
                "new": new_params,
                "removed": removed_params
            }

    # 3. Auth Diff (Did an endpoint lose its auth headers?)
    auth_downgrades = []
    auth_headers = {"authorization", "cookie", "x-api-key", "x-auth-token"}
    for ep in common_endpoints:
        has_auth_1 = any(bool(set(k.lower() for k in (item.request_headers or {}).keys()) & auth_headers) for item in ep1[ep])
        has_auth_2 = any(bool(set(k.lower() for k in (item.request_headers or {}).keys()) & auth_headers) for item in ep2[ep])

        if has_auth_1 and not has_auth_2 and any(i.status.startswith("2") for i in ep2[ep]):
            auth_downgrades.append(ep)

    _write_diff_report(
        output_dir / "DIFF_REPORT.md",
        export1.source_file,
        export2.source_file,
        new_endpoints,
        removed_endpoints,
        param_changes,
        auth_downgrades
    )

    if verbose:
        print(f"[+] Differential analysis complete -> {output_dir / 'DIFF_REPORT.md'}")

def _extract_endpoints(export: BurpExport):
    # returns dict mapping 'METHOD /path' to list of BurpItems
    endpoints = defaultdict(list)
    for item in export.items:
        key = f"{item.method} {item.protocol}://{item.host}:{item.port}{item.path.split(chr(63))[0]}"
        endpoints[key].append(item)
    return endpoints

def _extract_params(items):
    # Extract unique parameter names from a list of items for the same endpoint
    params = set()
    for item in items:
        try:
            parsed = urlparse(item.url or "")
            for k, _ in parse_qsl(parsed.query, keep_blank_values=True):
                params.add(f"query:{k}")
        except Exception:
            pass

        body = item.request_body or ""
        if body.strip().startswith("{"):
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    for k in data.keys():
                        params.add(f"json:{k}")
            except (json.JSONDecodeError, ValueError):
                pass
    return params

def _write_diff_report(path: Path, src1: str, src2: str, new_eps, rem_eps, param_changes, auth_downgrades):
    lines = [
        "# BurpMD Differential Analysis Report\n",
        f"**Baseline:** `{Path(src1).name}`",
        f"**Comparison:** `{Path(src2).name}`\n",
        "---\n"
    ]

    lines.append(f"## 1. New Endpoints ({len(new_eps)})\n")
    if new_eps:
        for ep in sorted(new_eps):
            lines.append(f"- `{ep}`")
    else:
        lines.append("*No new endpoints discovered.*")
    lines.append("\n")

    lines.append(f"## 2. Removed Endpoints ({len(rem_eps)})\n")
    if rem_eps:
        for ep in sorted(rem_eps):
            lines.append(f"- `{ep}`")
    else:
        lines.append("*No endpoints were removed.*")
    lines.append("\n")

    lines.append(f"## 3. Parameter Changes ({len(param_changes)})\n")
    if param_changes:
        for ep, changes in sorted(param_changes.items()):
            lines.append(f"### `{ep}`")
            if changes["new"]:
                lines.append(f"- **New Parameters:** {', '.join(sorted(changes['new']))}")
            if changes["removed"]:
                lines.append(f"- **Removed Parameters:** {', '.join(sorted(changes['removed']))}")
            lines.append("")
    else:
        lines.append("*No parameter changes on common endpoints.*")
    lines.append("\n")

    lines.append(f"## 4. Authorization Downgrades ({len(auth_downgrades)})\n")
    lines.append("> Endpoints that had Auth headers in Baseline but are missing them in Comparison. This may indicate an Unauthenticated Access vulnerability if the comparison file was an unauthenticated export.\n")
    if auth_downgrades:
        for ep in sorted(auth_downgrades):
            lines.append(f"- **[REVIEW]** `{ep}` - Missing Auth headers in Comparison export!")
    else:
        lines.append("*No authorization downgrades detected.*")

    lines.append("\n---\n*Generated by **BurpMD Parser Pro** - Differential Engine*\n")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
