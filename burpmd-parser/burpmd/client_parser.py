"""
burpmd.client_parser
====================
Extracts and analyzes client-side assets (JavaScript, WebAssembly)
from the HTTP responses in the proxy traffic.
"""

from pathlib import Path
import re
from urllib.parse import urlparse

from .parser import BurpExport

def extract_client_assets(export: BurpExport, output_dir: Path, verbose: bool = False):
    """
    Extracts all .js and .wasm files from the responses and saves them
    into a dedicated 'client_assets' folder. It also scans JS for hardcoded endpoints.
    """
    assets_dir = output_dir / "client_assets"

    js_count = 0
    wasm_count = 0

    endpoint_pat = re.compile(r"(?:[\"'])(/api/[a-zA-Z0-9_\-\./]+)(?:[\"'])")

    findings = []

    for item in export.items:
        if not item.response_body:
            continue

        url = item.url or ""
        mime = (item.mime_type or "").lower()

        is_js = mime == "script" or urlparse(url).path.endswith(".js") or "javascript" in mime
        is_wasm = mime == "wasm" or urlparse(url).path.endswith(".wasm") or "wasm" in mime

        if is_js or is_wasm:
            assets_dir.mkdir(parents=True, exist_ok=True)

            filename = Path(urlparse(url).path).name if url else f"asset_{item.index}"
            if not filename or filename == "/":
                filename = f"asset_{item.index}"

            if is_js and not filename.endswith(".js"): filename += ".js"
            if is_wasm and not filename.endswith(".wasm"): filename += ".wasm"

            from .writer import _sanitise_path_segment
            filename = _sanitise_path_segment(filename)

            # Avoid overwriting
            filepath = assets_dir / filename
            counter = 1
            while filepath.exists():
                name_part = filename.rsplit('.', 1)[0]
                ext_part = filename.rsplit('.', 1)[-1]
                filepath = assets_dir / f"{name_part}_{counter}.{ext_part}"
                counter += 1

            if is_js:
                filepath.write_text(item.response_body, encoding="utf-8", errors="ignore")
                js_count += 1

                # Basic AST-like regex scanning for hidden API routes
                for match in endpoint_pat.finditer(item.response_body):
                    findings.append(f"- Found potential API route `{match.group(1)}` in `{filepath.name}`")

            elif is_wasm:
                if not item.response_bytes:
                    continue
                raw = item.response_bytes
                body = raw.split(b"\r\n\r\n", 1)[-1]
                if not body.startswith(b"\0asm"):
                    continue
                filepath.write_bytes(body)
                wasm_count += 1

    if verbose and (js_count > 0 or wasm_count > 0):
        print(f"[+] Client-side extraction complete: {js_count} JS files, {wasm_count} WASM files -> {assets_dir}")

    if findings:
        report_path = assets_dir / "JS_ANALYSIS.md"
        lines = ["# JavaScript Static Analysis\n", "The following hardcoded API routes were discovered inside the client-side JavaScript bundles:\n"]
        lines.extend(sorted(list(set(findings))))
        report_path.write_text("\n".join(lines), encoding="utf-8")
        if verbose:
            print(f"[+] JavaScript analysis report generated -> {report_path}")
