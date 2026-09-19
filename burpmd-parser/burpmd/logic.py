"""
burpmd.logic
============
Infers state machines and business logic workflows from chronological
traffic analysis. Grouping by session allows discovering standard
user journeys.
"""

from pathlib import Path
import json
from collections import defaultdict
import re

from .parser import BurpExport
from .graph import diagram_label

def infer_state_machine(export: BurpExport, output_dir: Path, verbose: bool = False):
    """
    Groups traffic by session and generates a Mermaid state diagram
    representing the inferred user journey.
    """
    if verbose:
        print("[*] Inferring State Machine from user journeys...")

    sessions = defaultdict(list)
    for item in export.items:
        session_id = _derive_session(item)
        sessions[session_id].append(item)

    transitions = defaultdict(int)

    for session_id, items in sessions.items():
        sorted_items = sorted(items, key=lambda x: x.index)

        for i in range(len(sorted_items) - 1):
            src = sorted_items[i]
            dst = sorted_items[i+1]

            src_ep = _generalize_endpoint(src)
            dst_ep = _generalize_endpoint(dst)

            if src_ep != dst_ep:
                transitions[(src_ep, dst_ep)] += 1

    # Filter noise
    threshold = 2 if len(export.items) > 50 else 1
    filtered_transitions = {k: v for k, v in transitions.items() if v >= threshold}

    output_dir.mkdir(parents=True, exist_ok=True)
    mermaid_path = output_dir / "STATE_MACHINE.md"
    lines = ["# State Machine Inference\n"]
    lines.append("The following state diagram maps out the common chronological sequences of API calls made within individual user sessions. This helps visualize the expected 'happy path' business logic workflows, making it easier to identify multi-step processes and potential logic bypasses.\n")

    if not filtered_transitions:
        lines.append("*Not enough session data to confidently infer state transitions.*")
    else:
        lines.append("```mermaid")
        lines.append("stateDiagram-v2")

        selected = sorted(filtered_transitions.items(), key=lambda x: (-x[1], x[0]))[:50]
        endpoints = sorted({endpoint for pair, _ in selected for endpoint in pair})
        aliases = {endpoint: f'state{idx}' for idx, endpoint in enumerate(endpoints)}
        for endpoint, alias in aliases.items():
            lines.append(f'    state "{diagram_label(endpoint)}" as {alias}')
        for (src, dst), count in selected:
            lines.append(f"    {aliases[src]} --> {aliases[dst]} : {count} times")

        lines.append("```")

    mermaid_path.write_text("\n".join(lines), encoding="utf-8")

    if verbose:
        print(f"[+] State machine inferred: {len(filtered_transitions)} transitions -> {mermaid_path}")

def _derive_session(item) -> str:
    if item.session_tag:
        return (item.host, item.session_tag)
    if item.request_headers:
        for k, v in item.request_headers.items():
            kl = k.lower()
            if kl == "authorization":
                return (item.host, v.strip())
            if kl == "cookie":
                return (item.host, v.strip())
    return (item.host, "unauthenticated")

def _generalize_endpoint(item) -> str:
    ep = f"{item.method} {item.path}"
    ep = re.sub(r'/[0-9a-fA-F\-]{36}', '/{id}', ep)
    ep = re.sub(r'/[0-9]+', '/{id}', ep)
    return ep
