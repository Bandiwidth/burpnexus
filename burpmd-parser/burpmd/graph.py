"""
burpmd.graph
============
Semantic Graph engine to trace parameter flow across requests/responses.
Useful for BOLA hunting and understanding business logic dependencies.
"""

from pathlib import Path
import json
import re
from urllib.parse import urlparse, parse_qsl

from .parser import BurpExport

def diagram_label(value: str) -> str:
    """Keep captured text inside a Mermaid quoted label and Markdown fence."""
    return ''.join(f'#{ord(c)};' if c in '"`<>\\&' else c if c.isprintable() else ' ' for c in value[:200])

def build_semantic_graph(export: BurpExport, output_dir: Path, verbose: bool = False):
    """
    Analyzes the chronological flow of items to find where an ID in a response
    is later used in a request.
    """
    if verbose:
        print("[*] Building Semantic Graph for BOLA hunting...")

    response_values = {}

    uuid_pat = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
    json_id_pat = re.compile(r"\"[a-zA-Z0-9_]*id\"\s*:\s*(?:\"([^\"]+)\"|(\d+))", re.I)

    graph_edges = []
    items = sorted(export.items, key=lambda x: x.index)

    values_by_origin = {}
    for item in items:
        response_values = values_by_origin.setdefault((item.host, item.session_tag), {})
        req_targets = []
        path = item.path or ""
        body = item.request_body or ""

        parts = path.split('/')
        for p in parts:
            if p in response_values:
                req_targets.append(("path_param", p))

        try:
            parsed = urlparse(item.url or "")
            for k, v in parse_qsl(parsed.query):
                if v in response_values:
                    req_targets.append((f"query:{k}", v))
        except Exception:
            pass

        for match in json_id_pat.finditer(body):
            val = match.group(1) or match.group(2)
            if val in response_values:
                req_targets.append(("body_json", val))

        for context, val in req_targets:
            source = response_values[val]
            edge = {
                "value": val,
                "source_item": source['index'],
                "source_endpoint": source['endpoint'],
                "target_item": item.index,
                "target_endpoint": f"{item.method} {item.path}",
                "target_context": context
            }
            if edge["source_item"] != edge["target_item"]:
                graph_edges.append(edge)

        resp_body = item.response_body or ""
        new_vals = set()

        for match in uuid_pat.finditer(resp_body):
            new_vals.add(match.group(0))

        for match in json_id_pat.finditer(resp_body):
            new_vals.add(match.group(1) or match.group(2))

        for val in new_vals:
            if val not in response_values:
                response_values[val] = {
                    "index": item.index,
                    "endpoint": f"{item.method} {item.path}"
                }

    graph_path = output_dir / "semantic-graph.json"
    graph_path.parent.mkdir(parents=True, exist_ok=True)
    with open(graph_path, 'w', encoding='utf-8') as f:
        json.dump(graph_edges, f, indent=2)

    mermaid_path = output_dir / "SEMANTIC_GRAPH.md"
    lines = ["# Semantic Graph (Business Logic Flow)\n"]
    lines.append("This graph traces how identifiers (like UUIDs or numeric IDs) flow from server responses into subsequent client requests. This is extremely useful for understanding business logic and hunting for Broken Object Level Authorization (BOLA) vulnerabilities.\n")

    if not graph_edges:
        lines.append("*No semantic linkages detected in the traffic.*")
    else:
        lines.append("```mermaid")
        lines.append("graph TD")

        endpoint_edges = set()
        for e in graph_edges:
            src = e["source_endpoint"]
            dst = e["target_endpoint"]
            src_gen = re.sub(r'/[0-9a-fA-F\-]{36}', '/{id}', src)
            src_gen = re.sub(r'/[0-9]+', '/{id}', src_gen)
            dst_gen = re.sub(r'/[0-9a-fA-F\-]{36}', '/{id}', dst)
            dst_gen = re.sub(r'/[0-9]+', '/{id}', dst_gen)

            if src_gen != dst_gen:
                endpoint_edges.add((src_gen, dst_gen))

        for idx, (src, dst) in enumerate(sorted(endpoint_edges)):
            lines.append(f'  node{idx}a["{diagram_label(src)}"] -->|passes ID| node{idx}b["{diagram_label(dst)}"]')

        lines.append("```")

    mermaid_path.write_text("\n".join(lines), encoding="utf-8")

    if verbose:
        print(f"[+] Semantic graph generated: {len(graph_edges)} linkages -> {graph_path}")
