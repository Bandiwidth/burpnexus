"""
burpmd.analyzer
===============
Automated security analysis of parsed Burp traffic.

Produces:
  - SECURITY_FINDINGS.md   (--auto-findings)
  - param-index.json       (--param-index)
  - AI_ANALYSIS_PROMPTS.md (--ai-prompts)
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import List, Optional
from urllib.parse import parse_qsl, urlparse, unquote_plus

from .parser import BurpExport, BurpItem


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_SECURITY_HEADERS = {
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
}

_SENSITIVE_PATTERNS = [
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), "email address"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN-like number"),
    (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"), "credit card number"),
    (re.compile(r"(?i)(?:password|passwd|secret|private.?key)\s*[:=]\s*[\"']?[^\s\"',}{]{4,}"), "hardcoded secret"),
    (re.compile(r"(?i)(?:aws_?access_?key|AKIA)[A-Z0-9]{12,}"), "AWS key"),
    (re.compile(r"(?i)(?:sk-|pk_live_|pk_test_|sk_live_|sk_test_)[A-Za-z0-9]{20,}"), "API secret key"),
]

_ERROR_SIGNATURES = [
    (re.compile(r"(?i)SQL\s*syntax.*?(?:MySQL|MariaDB|PostgreSQL|ORA-|MSSQL)"), "SQL error disclosure"),
    (re.compile(r"(?i)(?:Traceback \(most recent call last\)|stack ?trace|at [\w$.]+\([\w.]+:\d+\))"), "Stack trace"),
    (re.compile(r"(?i)(?:Internal Server Error|Unhandled Exception|System\.Exception)"), "Unhandled exception"),
    (re.compile(r"(?i)(?:phpinfo\(\)|<title>phpinfo\(\))"), "phpinfo() exposure"),
    (re.compile(r'(?i)(?:root:|/etc/passwd|/etc/shadow|C:\\Windows\\system32)'), "Path/file disclosure"),
    (re.compile(r"(?i)(?:debug\s*=\s*True|DEBUG_MODE|DJANGO_SETTINGS_MODULE)"), "Debug mode enabled"),
]

_IDOR_PARAM_NAMES = {
    "id", "uid", "user_id", "userid", "account_id", "accountid",
    "order_id", "orderid", "doc_id", "docid", "file_id", "fileid",
    "project_id", "projectid", "customer_id", "customerid",
    "invoice_id", "record_id", "item_id", "profile_id",
}


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# 1. Security Findings
# ---------------------------------------------------------------------------

def generate_security_findings(
    export: BurpExport,
    output_dir: Path,
    verbose: bool = False,
) -> None:
    """Analyze traffic and write SECURITY_FINDINGS.md."""
    findings: list[dict] = []

    _check_missing_security_headers(export, findings)
    _check_idor_candidates(export, findings)
    _check_reflected_input(export, findings)
    _check_error_disclosure(export, findings)
    _check_sensitive_data_in_responses(export, findings)
    _check_unauthenticated_endpoints(export, findings)
    _check_cors_misconfig(export, findings)
    _check_http_methods(export, findings)
    _check_cookie_security(export, findings)
    _check_open_redirects(export, findings)

    md = _render_findings_md(export, findings)
    _write_text(output_dir / "SECURITY_FINDINGS.md", md)

    findings_json = output_dir / "security-findings.json"
    _write_text(findings_json, json.dumps(findings, indent=2, ensure_ascii=False) + "\n")

    if verbose:
        print(f"[+] Security findings: {len(findings)} potential issues -> SECURITY_FINDINGS.md")


def _check_missing_security_headers(export: BurpExport, findings: list) -> None:
    host_missing: dict[str, set[str]] = defaultdict(set)
    host_seen: dict[str, set[str]] = defaultdict(set)

    for item in export.items:
        if not item.response_headers:
            continue
        resp_lower = {k.lower(): v for k, v in item.response_headers.items()}
        host = item.host or "unknown"
        for hdr in _SECURITY_HEADERS:
            if hdr in resp_lower:
                host_seen[host].add(hdr)
            else:
                host_missing[host].add(hdr)

    for host, missing in sorted(host_missing.items()):
        actually_missing = missing - host_seen.get(host, set())
        if actually_missing:
            findings.append({
                "category": "Security Headers",
                "severity": "Medium",
                "title": f"Missing security headers on {host}",
                "detail": f"Headers never observed: {', '.join(sorted(actually_missing))}",
                "host": host,
                "items": [],
            })


def _check_idor_candidates(export: BurpExport, findings: list) -> None:
    numeric_id_pat = re.compile(r"/(\d{1,10})(?:/|$|\?)")

    for item in export.items:
        url = item.url or ""
        path = item.path or ""

        suspects = []
        for match in numeric_id_pat.finditer(path):
            suspects.append(("path", match.group(1)))

        try:
            parsed = urlparse(url)
            for k, v in parse_qsl(parsed.query):
                if k.lower() in _IDOR_PARAM_NAMES:
                    suspects.append((f"param:{k}", v))
        except Exception:
            pass

        if item.request_body:
            try:
                body_json = json.loads(item.request_body)
                if isinstance(body_json, dict):
                    for k, v in body_json.items():
                        if k.lower() in _IDOR_PARAM_NAMES and isinstance(v, (int, str)):
                            suspects.append((f"json:{k}", str(v)))
            except (json.JSONDecodeError, ValueError):
                for k, v in parse_qsl(item.request_body):
                    if k.lower() in _IDOR_PARAM_NAMES:
                        suspects.append((f"body:{k}", v))

        if suspects:
            detail_parts = [f"{loc}={val}" for loc, val in suspects]
            findings.append({
                "category": "IDOR",
                "severity": "High",
                "title": f"Potential IDOR: {item.method} {item.path}",
                "detail": f"Numeric/predictable identifiers: {', '.join(detail_parts)}",
                "host": item.host,
                "items": [item.slug],
            })


def _check_reflected_input(export: BurpExport, findings: list) -> None:
    for item in export.items:
        if not item.response_body:
            continue
        resp_lower = item.response_body.lower()

        try:
            parsed = urlparse(item.url or "")
            for k, v in parse_qsl(parsed.query):
                if len(v) >= 4 and v.lower() in resp_lower:
                    findings.append({
                        "category": "Reflected Input (XSS candidate)",
                        "severity": "High",
                        "title": f"Reflected param '{k}' in response: {item.method} {item.path}",
                        "detail": f"Value '{v[:60]}' from query param '{k}' appears in response body.",
                        "host": item.host,
                        "items": [item.slug],
                    })
                    break
        except Exception:
            pass


def _check_error_disclosure(export: BurpExport, findings: list) -> None:
    for item in export.items:
        body = item.response_body or item.response_raw or ""
        if not body:
            continue
        for pat, label in _ERROR_SIGNATURES:
            if pat.search(body):
                findings.append({
                    "category": "Information Disclosure",
                    "severity": "Medium",
                    "title": f"{label}: {item.method} {item.path} [{item.status}]",
                    "detail": f"Response contains {label.lower()} pattern.",
                    "host": item.host,
                    "items": [item.slug],
                })
                break


def _check_sensitive_data_in_responses(export: BurpExport, findings: list) -> None:
    for item in export.items:
        body = item.response_body or ""
        if not body:
            continue
        for pat, label in _SENSITIVE_PATTERNS:
            match = pat.search(body)
            if match:
                snippet = match.group(0)[:40]
                findings.append({
                    "category": "Sensitive Data Exposure",
                    "severity": "High",
                    "title": f"{label} in response: {item.method} {item.path}",
                    "detail": f"Matched pattern: '{snippet}...'",
                    "host": item.host,
                    "items": [item.slug],
                })
                break


def _check_unauthenticated_endpoints(export: BurpExport, findings: list) -> None:
    auth_headers = {"authorization", "cookie", "x-api-key", "x-auth-token"}

    for item in export.items:
        if not item.request_headers:
            continue
        req_lower = {k.lower() for k in item.request_headers.keys()}
        has_auth = bool(req_lower & auth_headers)

        status = item.status or ""
        if not has_auth and status.startswith("2"):
            if item.path and item.path not in {"/", "/favicon.ico", "/robots.txt"}:
                findings.append({
                    "category": "Authentication",
                    "severity": "Medium",
                    "title": f"Unauthenticated 2xx: {item.method} {item.path}",
                    "detail": "Endpoint returned success without any auth headers in request.",
                    "host": item.host,
                    "items": [item.slug],
                })


def _check_cors_misconfig(export: BurpExport, findings: list) -> None:
    for item in export.items:
        resp = item.response_headers or {}
        acao = ""
        for k, v in resp.items():
            if k.lower() == "access-control-allow-origin":
                acao = v.strip()
                break
        if acao == "*":
            findings.append({
                "category": "CORS Misconfiguration",
                "severity": "Medium",
                "title": f"Wildcard CORS: {item.method} {item.path}",
                "detail": "Access-Control-Allow-Origin: * allows any origin.",
                "host": item.host,
                "items": [item.slug],
            })
        elif acao and acao != item.host:
            acac = ""
            for k, v in resp.items():
                if k.lower() == "access-control-allow-credentials":
                    acac = v.strip().lower()
            if acac == "true":
                findings.append({
                    "category": "CORS Misconfiguration",
                    "severity": "High",
                    "title": f"CORS with credentials: {item.method} {item.path}",
                    "detail": f"Origin '{acao}' with Allow-Credentials: true.",
                    "host": item.host,
                    "items": [item.slug],
                })


def _check_http_methods(export: BurpExport, findings: list) -> None:
    dangerous = {"PUT", "DELETE", "PATCH", "TRACE", "OPTIONS"}
    endpoint_methods: dict[str, set[str]] = defaultdict(set)

    for item in export.items:
        method = (item.method or "").upper()
        key = f"{item.host}:{item.path}"
        endpoint_methods[key].add(method)

    for endpoint, methods in endpoint_methods.items():
        risky = methods & dangerous
        if risky:
            host, _, path = endpoint.partition(":")
            findings.append({
                "category": "HTTP Methods",
                "severity": "Low",
                "title": f"State-changing methods on {path}",
                "detail": f"Methods observed: {', '.join(sorted(risky))}. Verify authorization checks.",
                "host": host,
                "items": [],
            })


def _check_cookie_security(export: BurpExport, findings: list) -> None:
    seen_cookies: dict[str, dict] = {}

    for item in export.items:
        resp = item.response_headers or {}
        for k, v in resp.items():
            if k.lower() != "set-cookie":
                continue
            cookie_str = v
            name_part = cookie_str.split("=")[0].strip() if "=" in cookie_str else "unknown"
            flags_lower = cookie_str.lower()

            issues = []
            if "httponly" not in flags_lower:
                issues.append("missing HttpOnly")
            if "secure" not in flags_lower:
                issues.append("missing Secure")
            if "samesite" not in flags_lower:
                issues.append("missing SameSite")

            if issues and name_part not in seen_cookies:
                seen_cookies[name_part] = True
                findings.append({
                    "category": "Cookie Security",
                    "severity": "Medium",
                    "title": f"Insecure cookie '{name_part}' on {item.host}",
                    "detail": f"Cookie flags: {', '.join(issues)}.",
                    "host": item.host,
                    "items": [item.slug],
                })


def _check_open_redirects(export: BurpExport, findings: list) -> None:
    redirect_params = {"url", "redirect", "redirect_uri", "redirect_url",
                       "return", "returnto", "return_url", "next", "goto",
                       "dest", "destination", "continue", "target", "rurl"}

    for item in export.items:
        try:
            parsed = urlparse(item.url or "")
            for k, v in parse_qsl(parsed.query):
                if k.lower() in redirect_params:
                    if v.startswith("http") or v.startswith("//"):
                        findings.append({
                            "category": "Open Redirect",
                            "severity": "Medium",
                            "title": f"Open redirect candidate: {item.method} {item.path}",
                            "detail": f"Param '{k}' = '{v[:80]}' contains external URL.",
                            "host": item.host,
                            "items": [item.slug],
                        })
                        break
        except Exception:
            pass


def _render_findings_md(export: BurpExport, findings: list[dict]) -> str:
    lines = [
        "# BurpMD Security Findings Report\n",
        "> Auto-generated security analysis of captured HTTP traffic.",
        "> Feed this file alongside the JSON corpus to VS Code Copilot for deeper analysis.\n",
        "---\n",
    ]

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.get("severity", "Info"), 4))

    by_category: dict[str, list] = defaultdict(list)
    for f in sorted_findings:
        by_category[f["category"]].append(f)

    lines.append("## Summary\n")
    lines.append(f"| Metric | Value |")
    lines.append(f"| ------ | ----- |")
    lines.append(f"| Total items analyzed | `{len(export.items)}` |")
    lines.append(f"| Total findings | `{len(findings)}` |")
    lines.append(f"| Categories | `{len(by_category)}` |")

    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f.get("severity", "Info")] += 1
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        if sev_counts[sev]:
            lines.append(f"| {sev} severity | `{sev_counts[sev]}` |")
    lines.append("")

    if not findings:
        lines.append("**No automated findings detected.** This does not mean the application is secure.\n")
        lines.append("Manual review with Copilot is still recommended.\n")
    else:
        lines.append("---\n")
        for category, cat_findings in by_category.items():
            lines.append(f"## {category}\n")
            for i, f in enumerate(cat_findings, 1):
                sev = f.get("severity", "?")
                title = f.get("title", "")
                detail = f.get("detail", "")
                items = f.get("items", [])

                lines.append(f"### {i}. [{sev}] {title}\n")
                lines.append(f"{detail}\n")
                if items:
                    lines.append(f"**Related files:** {', '.join(f'`{s}.json`' for s in items)}\n")
                lines.append("")

    lines.append("---\n")
    lines.append("## Recommended Copilot Prompts for These Findings\n")
    lines.append("```")
    if sev_counts.get("High", 0) or sev_counts.get("Critical", 0):
        lines.append("@workspace Review all High/Critical findings in SECURITY_FINDINGS.md and cross-reference with the source code for exploitability.")
    if by_category.get("IDOR"):
        lines.append("@workspace Analyze all IDOR candidates and check if authorization is enforced server-side for these endpoints.")
    if by_category.get("Reflected Input (XSS candidate)"):
        lines.append("@workspace Check all reflected input findings for proper output encoding in the source code.")
    if by_category.get("Information Disclosure"):
        lines.append("@workspace Review error handling in the source code to ensure stack traces and SQL errors are not exposed in production.")
    if by_category.get("Authentication"):
        lines.append("@workspace Verify that all sensitive endpoints require authentication middleware.")
    lines.append("@workspace Based on SECURITY_FINDINGS.md and the JSON corpus, generate a prioritized list of vulnerabilities with PoC scripts.")
    lines.append("```\n")

    lines.append("---")
    lines.append("*Generated by **BurpMD Parser Pro** - Automated Security Analysis*\n")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# 2. Parameter Index
# ---------------------------------------------------------------------------

def generate_param_index(
    export: BurpExport,
    output_dir: Path,
    verbose: bool = False,
) -> None:
    """Extract all input parameters into param-index.json."""
    params: dict[str, dict] = {}

    for item in export.items:
        _extract_query_params(item, params)
        _extract_body_params(item, params)
        _extract_json_fields(item, params)
        _extract_cookie_names(item, params)
        _extract_custom_headers(item, params)

    param_list = []
    for p in sorted(params.values(), key=lambda p: (-p["occurrences"], p["name"])):
        param_list.append({
            "name": p["name"],
            "source": p["source"],
            "occurrences": p["occurrences"],
            "example_values": p["example_values"],
            "endpoints": sorted(p["_endpoints"]),
            "hosts": sorted(p["_hosts"]),
            "is_sensitive": p["is_sensitive"],
        })

    payload = {
        "summary": {
            "total_unique_parameters": len(param_list),
            "total_items_analyzed": len(export.items),
            "parameter_sources": sorted(set(p["source"] for p in param_list)),
        },
        "parameters": param_list,
    }

    _write_text(output_dir / "param-index.json",
                json.dumps(payload, indent=2, ensure_ascii=False) + "\n")

    if verbose:
        print(f"[+] Parameter index: {len(param_list)} unique params -> param-index.json")


def _param_key(name: str, source: str) -> str:
    return f"{source}:{name.lower()}"


def _register_param(params: dict, name: str, source: str,
                     example_value: str, endpoint: str, host: str) -> None:
    key = _param_key(name, source)
    if key not in params:
        params[key] = {
            "name": name,
            "source": source,
            "occurrences": 0,
            "example_values": [],
            "_endpoints": set(),
            "_hosts": set(),
            "is_sensitive": _is_sensitive_param(name),
        }
    entry = params[key]
    entry["occurrences"] += 1
    entry["_endpoints"].add(endpoint)
    entry["_hosts"].add(host)
    if example_value and len(entry["example_values"]) < 3:
        truncated = example_value[:100]
        if truncated not in entry["example_values"]:
            entry["example_values"].append(truncated)


def _is_sensitive_param(name: str) -> bool:
    n = name.lower()
    sensitive = {"password", "passwd", "token", "secret", "api_key", "apikey",
                 "access_token", "refresh_token", "session", "sessionid",
                 "csrf", "xsrf", "ssn", "credit_card", "cc", "cvv",
                 "authorization", "auth", "private_key"}
    return n in sensitive or any(s in n for s in ["password", "token", "secret", "key", "auth"])


def _extract_query_params(item: BurpItem, params: dict) -> None:
    try:
        parsed = urlparse(item.url or "")
        for k, v in parse_qsl(parsed.query, keep_blank_values=True):
            _register_param(params, k, "query", v,
                            f"{item.method} {item.path}", item.host or "")
    except Exception:
        pass


def _extract_body_params(item: BurpItem, params: dict) -> None:
    body = item.request_body or ""
    if not body:
        return
    ct = ""
    for k, v in (item.request_headers or {}).items():
        if k.lower() == "content-type":
            ct = v.lower()
            break
    if "form" in ct or ("=" in body and not body.strip().startswith("{")):
        try:
            for k, v in parse_qsl(body, keep_blank_values=True):
                _register_param(params, k, "body_form", v,
                                f"{item.method} {item.path}", item.host or "")
        except Exception:
            pass


def _extract_json_fields(item: BurpItem, params: dict) -> None:
    body = item.request_body or ""
    if not body.strip().startswith("{") and not body.strip().startswith("["):
        return
    try:
        data = json.loads(body)
        _walk_json(data, params, item, prefix="")
    except (json.JSONDecodeError, ValueError):
        pass


def _walk_json(obj, params: dict, item: BurpItem, prefix: str) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, (dict, list)):
                _walk_json(v, params, item, full_key)
            else:
                _register_param(params, full_key, "json_body", str(v)[:100],
                                f"{item.method} {item.path}", item.host or "")
    elif isinstance(obj, list):
        for i, elem in enumerate(obj[:5]):
            _walk_json(elem, params, item, f"{prefix}[{i}]")


def _extract_cookie_names(item: BurpItem, params: dict) -> None:
    for k, v in (item.request_headers or {}).items():
        if k.lower() != "cookie":
            continue
        for part in v.split(";"):
            if "=" in part:
                name = part.split("=")[0].strip()
                _register_param(params, name, "cookie", "(value)",
                                f"{item.method} {item.path}", item.host or "")


def _extract_custom_headers(item: BurpItem, params: dict) -> None:
    standard = {"host", "user-agent", "accept", "accept-language",
                "accept-encoding", "connection", "content-type",
                "content-length", "cache-control", "pragma",
                "upgrade-insecure-requests", "referer", "origin",
                "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
                "sec-fetch-user", "sec-ch-ua", "sec-ch-ua-mobile",
                "sec-ch-ua-platform", "dnt", "te", "if-none-match",
                "if-modified-since"}
    for k, v in (item.request_headers or {}).items():
        if k.lower() not in standard:
            _register_param(params, k, "header", v[:60],
                            f"{item.method} {item.path}", item.host or "")


# ---------------------------------------------------------------------------
# 3. AI Analysis Prompts
# ---------------------------------------------------------------------------

def generate_ai_prompts(
    export: BurpExport,
    output_dir: Path,
    findings: Optional[list] = None,
    verbose: bool = False,
) -> None:
    """Generate tailored Copilot prompts based on the actual exported data."""
    hosts = sorted(export.hosts)
    tools = sorted(export.tools)
    endpoints = set()
    methods = set()
    statuses = set()
    auth_endpoints = []
    noauth_endpoints = []
    error_endpoints = []

    auth_headers = {"authorization", "cookie", "x-api-key", "x-auth-token"}

    for item in export.items:
        ep = f"{item.method} {item.path}"
        endpoints.add(ep)
        methods.add(item.method or "?")
        statuses.add(item.status or "?")

        req_lower = {k.lower() for k in (item.request_headers or {}).keys()}
        has_auth = bool(req_lower & auth_headers)
        if has_auth:
            auth_endpoints.append(ep)
        else:
            noauth_endpoints.append(ep)

        s = item.status or ""
        if s.startswith("4") or s.startswith("5"):
            error_endpoints.append(f"{ep} [{s}]")

    lines = [
        "# AI Analysis Prompts for This Export\n",
        "> Copy-paste these prompts into VS Code Copilot Chat to analyze this traffic",
        "> alongside the application source code.\n",
        "---\n",
        "## Export Context\n",
        f"- **Hosts:** {', '.join(hosts)}",
        f"- **Unique endpoints:** {len(endpoints)}",
        f"- **Items:** {len(export.items)}",
        f"- **Tools:** {', '.join(tools)}",
        f"- **Status codes:** {', '.join(sorted(statuses))}",
        "",
        "---\n",
    ]

    lines.append("## Phase 1: Reconnaissance Prompts\n")
    lines.append("```")
    lines.append(f"@workspace Summarize all API endpoints discovered in this Burp export for hosts: {', '.join(hosts[:5])}. Group by resource and list HTTP methods available for each.")
    lines.append("```\n")
    lines.append("```")
    lines.append("@workspace Map out the authentication flow: find login/logout/token-refresh endpoints, identify what auth mechanisms are used (JWT, session cookies, API keys), and note any weaknesses.")
    lines.append("```\n")
    lines.append("```")
    lines.append("@workspace List all user input vectors: query parameters, POST body fields, JSON fields, custom headers, and cookies. Flag any that look injectable or sensitive.")
    lines.append("```\n")

    lines.append("## Phase 2: Vulnerability Analysis Prompts\n")

    if auth_endpoints:
        lines.append("### Access Control / IDOR\n")
        lines.append("```")
        sample = list(set(auth_endpoints))[:5]
        lines.append(f"@workspace Check these authenticated endpoints for IDOR vulnerabilities: {'; '.join(sample)}. For each endpoint, verify if the server validates that the authenticated user owns the requested resource. Generate PoC scripts for any findings.")
        lines.append("```\n")

    if noauth_endpoints:
        lines.append("### Unauthenticated Access\n")
        lines.append("```")
        sample = list(set(noauth_endpoints))[:5]
        lines.append(f"@workspace These endpoints were accessed without authentication: {'; '.join(sample)}. Check the source code to determine if they should require auth and if any expose sensitive data.")
        lines.append("```\n")

    lines.append("### Injection Flaws\n")
    lines.append("```")
    lines.append("@workspace Analyze all request parameters across the JSON corpus for SQL injection, command injection, and XSS vulnerabilities. Focus on parameters that are reflected in responses or used in database queries. Generate PoC payloads.")
    lines.append("```\n")

    lines.append("### SSRF\n")
    lines.append("```")
    lines.append("@workspace Find any request parameters that accept URLs, hostnames, file paths, or IP addresses. Check if the application makes server-side requests based on this input. Test for SSRF using internal URLs like http://169.254.169.254/.")
    lines.append("```\n")

    if error_endpoints:
        lines.append("### Error Analysis\n")
        lines.append("```")
        sample = error_endpoints[:5]
        lines.append(f"@workspace Analyze these error responses: {'; '.join(sample)}. Check if they leak server internals (stack traces, SQL errors, file paths, framework versions). Suggest how to reproduce and exploit.")
        lines.append("```\n")

    lines.append("## Phase 3: Business Logic\n")
    lines.append("```")
    lines.append("@workspace Analyze the request sequences to identify business logic flaws: race conditions, price manipulation, quantity bypasses, workflow skipping, state tampering. Look at multi-step operations across the JSON corpus.")
    lines.append("```\n")

    lines.append("## Phase 4: Comprehensive Report\n")
    lines.append("```")
    lines.append("@workspace Based on the complete analysis of the Burp export JSON corpus and SECURITY_FINDINGS.md, generate a penetration test report with: Executive Summary, Findings (severity, description, PoC, remediation), and Risk Matrix. Use the OWASP Top 10 framework.")
    lines.append("```\n")

    if hosts:
        lines.append("## Phase 5: Source Code Cross-Reference\n")
        lines.append("```")
        lines.append(f"@workspace Cross-reference the API endpoints from the Burp export with the application source code. For each endpoint, identify the handler function, trace user input through the code, and flag any missing input validation, authorization checks, or output encoding.")
        lines.append("```\n")

    lines.append("---")
    lines.append("*Generated by **BurpMD Parser Pro** - Tailored for this export*\n")

    _write_text(output_dir / "AI_ANALYSIS_PROMPTS.md", "\n".join(lines) + "\n")

    if verbose:
        print("[+] AI prompts generated -> AI_ANALYSIS_PROMPTS.md")
