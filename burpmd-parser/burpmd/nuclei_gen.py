"""Generate reviewable Nuclei candidates as JSON (a valid YAML subset)."""
import json
import re
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl, urlencode
from .fuzzer import _detect_injection_points, _mutate_request

def _template(finding, item, idx):
    category = finding.get("category", "")
    if not item or item.method.upper() != "GET":
        return None  # Do not silently turn body-bearing requests into unrelated GETs.
    parsed = urlsplit(item.url)
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    request = {"method": "GET", "path": ["{{BaseURL}}" + target], "redirects": False}
    info = {"name": finding.get("title", category) + " (review candidate)", "author": "BurpNexus",
            "severity": "info", "description": "Passive candidate; manually verify authorization and impact.",
            "tags": "burpnexus,review", "metadata": {"source-item": item.slug, "source-host": item.host}}
    if category == "IDOR":
        points = _detect_injection_points(item, finding)
        points = [p for p in points if p["type"] in {"path_segment", "query_param"}]
        if not points:
            return None
        point = points[0]
        value = point["original_value"]
        if not value.isdigit():
            return None
        changed = urlsplit(_mutate_request(item, point, str(int(value) + 1))["url"])
        other = changed.path + ("?" + changed.query if changed.query else "")
        request = {"raw": [f"GET {p} HTTP/1.1\nHost: {{{{Hostname}}}}\n\n" for p in (target, other)],
                   "req-condition": True, "redirects": False,
                   "matchers": [{"type": "dsl", "dsl": ["status_code_1 == 200 && status_code_2 == 200 && body_1 != body_2"]}]}
    elif category == "Reflected Input (XSS candidate)":
        points = _detect_injection_points(item, finding)
        if not points:
            return None
        canary = "burpnexus-reflection-probe"
        changed = urlsplit(_mutate_request(item, points[0], canary)["url"])
        request["path"] = ["{{BaseURL}}" + changed.path + "?" + changed.query]
        request["matchers"] = [{"type": "word", "part": "body", "words": [canary]}]
        info["description"] = "Reflection only. Does not establish JavaScript execution or XSS."
    elif category == "Security Headers":
        headers = finding.get("detail", "").partition(":")[2].strip().split(", ")
        headers = [h for h in headers if re.fullmatch(r"[a-z-]+", h)]
        if not headers:
            return None
        request["matchers"] = [{"type": "word", "part": "header", "words": [h + ":"], "negative": True,
                                 "case-insensitive": True} for h in headers]
        request["matchers-condition"] = "or"
    elif category == "Information Disclosure":
        request["matchers"] = [{"type": "regex", "part": "body", "regex": [r"(?i)(SQL syntax|Traceback \(most recent call last\)|stack\s*trace|Unhandled Exception)"]}]
    elif category == "Sensitive Data Exposure":
        request["matchers"] = [{"type": "regex", "part": "body", "regex": [r"gh[pousr]_[a-zA-Z0-9]{36}|AKIA[A-Z0-9]{16}"]}]
    elif category == "Open Redirect":
        points = _detect_injection_points(item, finding)
        if not points:
            return None
        changed = urlsplit(_mutate_request(item, points[0], "https://example.invalid/")["url"])
        request["path"] = ["{{BaseURL}}" + changed.path + "?" + changed.query]
        request["matchers"] = [{"type": "regex", "part": "header", "regex": [r"(?im)^location:\s*https://example\.invalid/"]}]
    elif category == "CORS Misconfiguration":
        request["headers"] = {"Origin": "https://example.invalid"}
        request["matchers-condition"] = "and"
        request["matchers"] = [{"type": "regex", "part": "header", "regex": [pattern]} for pattern in
                              [r"(?im)^access-control-allow-origin:\s*https://example\.invalid\s*$",
                               r"(?im)^access-control-allow-credentials:\s*true\s*$"]]
    elif category == "Cookie Security":
        request["matchers"] = [{"type": "dsl", "dsl": ["contains(tolower(all_headers), 'set-cookie:') && (!contains(tolower(all_headers), 'httponly') || !contains(tolower(all_headers), 'secure'))"]}]
    else:
        return None
    return {"id": f"burpnexus-review-{idx:04d}", "info": info, "http": [request]}

def generate_nuclei_templates(export, output_dir: Path, findings=None, verbose=False):
    if findings is None:
        findings = json.loads((output_dir / "security-findings.json").read_text(encoding="utf-8"))
    directory = output_dir / "nuclei-templates"
    directory.mkdir(parents=True, exist_ok=True)
    # Only replace our generated files; leave user-authored templates alone.
    for old in directory.glob("burpnexus-review-*.yaml"):
        old.unlink()
    index = {i.slug: i for i in export.items}
    generated = []
    for idx, finding in enumerate(findings):
        sources = finding.get("items", [])
        item = index.get(sources[0]) if sources else next((i for i in export.items if i.host == finding.get("host") and i.method == "GET"), None)
        template = _template(finding, item, idx)
        if template:
            filename = template["id"] + ".yaml"
            (directory / filename).write_text(json.dumps(template, indent=2), encoding="utf-8")
            generated.append(filename)
    (output_dir / "NUCLEI_TEMPLATES.md").write_text(
        "# Nuclei review templates\n\nThese offline templates are candidates, not confirmed vulnerabilities. "
        "They contain GET probes only and do not copy captured authentication headers. Review the source item, "
        "supply appropriate test identities, and run only against authorized targets. IDOR requires "
        "ownership checks; reflection alone is not XSS. Cookie matching is a coarse candidate check.\n\n"
        + f"Generated: {len(generated)}. Unsupported methods/categories are omitted.\n\n"
        + "\n".join("- " + f for f in generated)
        + "\n\nValidate: `nuclei -validate -t nuclei-templates/`\n", encoding="utf-8")
