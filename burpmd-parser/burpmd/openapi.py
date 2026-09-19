"""
burpmd.openapi
==============
Generates OpenAPI v3 specification (JSON format) from a BurpExport corpus.
"""

from collections import defaultdict
from pathlib import Path
import json
from urllib.parse import urlparse, parse_qsl

from .parser import BurpExport

def generate_openapi_spec(export: BurpExport, output_dir: Path, verbose: bool = False):
    if verbose:
        print("[*] Generating OpenAPI v3 specification...")

    paths = defaultdict(lambda: defaultdict(dict))

    # Servers
    servers = set()

    for item in export.items:
        if not item.url:
            continue

        try:
            parsed = urlparse(item.url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                continue
            host_url = f"{parsed.scheme}://{parsed.netloc}"
            servers.add(host_url)

            path = parsed.path or "/"
            method = (item.method or "get").lower()

            if method not in {"get", "put", "post", "delete", "options", "head", "patch", "trace"}:
                continue
            if method not in paths[path]:
                paths[path][method] = {
                    "summary": f"{method.upper()} {path}",
                    "parameters": [],
                    "responses": {
                        item.status if item.status.isdigit() and len(item.status) == 3 else "default": {"description": "Observed response"}
                    }
                }
            else:
                # Add status if not already there
                status = item.status if item.status.isdigit() and len(item.status) == 3 else "default"
                if status not in paths[path][method]["responses"]:
                    paths[path][method]["responses"][status] = {"description": "Observed response"}

            # Extract query params
            for k, _ in parse_qsl(parsed.query, keep_blank_values=True):
                # check if param already exists
                exists = any(p["name"] == k and p["in"] == "query" for p in paths[path][method].get("parameters", []))
                if not exists:
                    paths[path][method]["parameters"].append({
                        "name": k,
                        "in": "query",
                        "schema": {"type": "string"}
                    })

            # Extract JSON body
            body = item.request_body or ""
            if body.strip().startswith("{") and method in ("post", "put", "patch", "delete"):
                if "requestBody" not in paths[path][method]:
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict):
                            properties = {}
                            for k, v in data.items():
                                properties[k] = _schema(v)

                            paths[path][method]["requestBody"] = {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": properties
                                        }
                                    }
                                }
                            }
                    except (json.JSONDecodeError, ValueError):
                        pass
        except Exception:
            pass

    # Build OpenAPI dict
    openapi = {
        "openapi": "3.0.0",
        "info": {
            "title": "BurpNexus Exported API",
            "version": "1.0.0",
            "description": "Auto-generated OpenAPI v3 specification from Burp Suite XML exports."
        },
        "servers": [{"url": s} for s in sorted(servers)],
        "paths": dict(paths)
    }

    out_path = output_dir / "openapi.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(openapi, f, indent=2)

    if verbose:
        print(f"[+] OpenAPI specification generated -> {out_path}")


def _schema(value):
    if value is None: return {"nullable": True}
    if isinstance(value, bool): return {"type": "boolean"}
    if isinstance(value, int): return {"type": "integer"}
    if isinstance(value, float): return {"type": "number"}
    if isinstance(value, list): return {"type": "array", "items": _schema(value[0]) if value else {}}
    if isinstance(value, dict): return {"type": "object", "properties": {k: _schema(v) for k, v in value.items()}}
    return {"type": "string"}
