"""
burpmd.writer
=============
Writes parsed Burp items to disk in organized folder hierarchies.

Supports three output modes:

1. **Flat Mode** (default):
       {output_dir}/{tool}/0001_GET_login.json

2. **By-Host Mode** (--by-host):
       {output_dir}/{tool}/{host}/0001_GET_login.json

3. **Site Map Mode** (--sitemap):
   Mirrors Burp Suite's Site Map tree — the URL path hierarchy
   becomes the folder structure on disk:
       {output_dir}/{host}/api/v1/users/0001_GET_users.json
       {output_dir}/{host}/api/v1/products/0002_POST_products.json
       {output_dir}/{host}/login/0003_POST_login.json

4. **Host-First Mode** (--host-first):
       {output_dir}/{host}/{tool}/0001_GET_login.json

Each request/response pair produces:
  - {slug}.json — structured JSON data (always, default)
  - {slug}.md   — rich Markdown with embedded JSON block (optional, --md)
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import List, Optional
from urllib.parse import parse_qsl, urlparse, unquote

from .formatter import MarkdownFormatter
from .parser import BurpExport, BurpItem, TOOL_UNKNOWN


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _portable_segment(value):
    if value.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
        value = "_" + value
    if len(value) > 64:
        import hashlib
        value = value[:48] + "_" + hashlib.sha256(value.encode()).hexdigest()[:12]
    return value


def _sanitise_dirname(name: str) -> str:
    """Convert a hostname or tool name into a safe directory name."""
    name = name.strip().lower()
    name = re.sub(r"[^\w\-.]", "_", name)
    name = re.sub(r"_+", "_", name).strip("_.")
    return _portable_segment(name or "unknown")


def _sanitise_path_segment(segment: str) -> str:
    """Convert a single URL path segment into a safe directory name."""
    segment = unquote(segment).strip()
    # Remove query strings and fragments
    segment = segment.split("?")[0].split("#")[0]
    # Replace unsafe chars
    segment = re.sub(r"[^\w\-.]", "_", segment)
    segment = re.sub(r"_+", "_", segment).strip("_.")
    return _portable_segment(segment or "_")


def _url_to_dir_path(url: str, path_field: str) -> List[str]:
    """
    Convert a URL path into a list of directory segments,
    mirroring the Burp Suite Site Map tree structure.

    Example:
        /api/v1/users/123?name=test  →  ["api", "v1", "users", "123"]
        /login                        →  ["login"]
        /                             →  ["root"]
    """
    # Prefer the path field, fall back to parsing the URL
    raw_path = path_field or ""
    if not raw_path and url:
        try:
            parsed = urlparse(url)
            raw_path = parsed.path or "/"
        except Exception:
            raw_path = "/"

    # Remove query string and fragment
    raw_path = raw_path.split("?")[0].split("#")[0]

    # Split into segments and sanitise each one
    segments = [s for s in raw_path.split("/") if s.strip()]
    if not segments:
        return ["root"]

    # The last segment might be a file (e.g., index.html, api endpoint)
    # We treat it as a directory to group requests to the same endpoint
    sanitised = [_sanitise_path_segment(s) for s in segments]
    return sanitised


def _write_text(path: Path, content: str) -> None:
    """Write text to a file, creating parent directories as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

class BurpMDWriter:
    """
    Writes a BurpExport to disk as JSON + (optional) Markdown files.

    Parameters
    ----------
    output_dir : str | Path
        Root directory for all output files.
    by_host : bool
        If True, create subdirectories per hostname inside each tool folder.
    sitemap : bool
        If True, mirror Burp Suite's Site Map tree structure
        (host → directory → subdirectory → files).
    host_first : bool
        If True, group by host first, then by tool.
    split_by_session : bool
        If True, group by session bucket first, then by tool.
    include_md : bool
        If True, write a companion .md file alongside each .json file.
    include_json : bool
        If True (default), write .json files for each item.
    formatter : MarkdownFormatter | None
        Custom formatter instance; defaults to MarkdownFormatter().
    verbose : bool
        Print progress to stdout.
    """

    def __init__(
        self,
        output_dir:   str | Path,
        by_host:      bool = False,
        sitemap:      bool = False,
        host_first:   bool = False,
        split_by_session: bool = False,
        include_md:   bool = False,
        include_json: bool = True,
        formatter:    Optional[MarkdownFormatter] = None,
        verbose:      bool = False,
    ):
        self.output_dir   = Path(output_dir)
        self.by_host      = by_host
        self.sitemap      = sitemap
        self.host_first   = host_first
        self.split_by_session = split_by_session
        self.include_md   = include_md
        self.include_json = include_json
        self.formatter    = formatter or MarkdownFormatter()
        self.verbose      = verbose

        # Stats
        self._written_md   = 0
        self._written_json = 0
        self._skipped      = 0

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def write(self, export: BurpExport) -> None:
        """Write all items in a BurpExport to the output directory."""
        self.output_dir.mkdir(parents=True, exist_ok=True)

        mode_label = (
            "SITEMAP" if self.sitemap else
            ("SESSION-SPLIT" if self.split_by_session else ("HOST-FIRST" if self.host_first else ("BY-HOST" if self.by_host else "FLAT")))
        )
        if self.verbose:
            print(f"\n[*] Writing to: {self.output_dir}")
            print(f"[*] Output mode: {mode_label}")
            print(f"[*] Total items : {len(export.items)}")
            print(f"[*] Tools found : {', '.join(export.tools) or 'none'}")
            print(f"[*] Hosts found : {len(export.hosts)}")
            print(f"[*] JSON output : {'ON' if self.include_json else 'OFF'}")
            print(f"[*] MD output   : {'ON' if self.include_md else 'OFF'}\n")

        # Write individual item files
        for item in export.items:
            self._write_item(item)

        # Write per-tool README indexes (only in non-sitemap mode)
        if not self.sitemap:
            for tool in export.tools:
                tool_items = export.items_by_tool(tool)
                self._write_tool_index(tool, tool_items)

        # Write root README
        self._write_root_index(export)
        self._write_attack_surface_index(export)

        if self.verbose:
            print(f"\n[+] Done!")
            print(f"    JSON files     : {self._written_json}")
            print(f"    Markdown files : {self._written_md}")
            print(f"    Skipped        : {self._skipped}")

    # ------------------------------------------------------------------
    # Internal — Directory resolution
    # ------------------------------------------------------------------

    def _item_dir(self, item: BurpItem) -> Path:
        """Compute the target directory for a single item."""

        # --- SITEMAP MODE ---
        # Mirrors Burp Suite's Site Map tree:
        #   {output_dir}/{host}/api/v1/users/
        if self.sitemap:
            host_dir = self.output_dir / _sanitise_dirname(item.host or "unknown")
            path_segments = _url_to_dir_path(item.url, item.path)
            target = host_dir
            for seg in path_segments:
                target = target / seg
            return target

        # --- BY-HOST MODE ---
        # {output_dir}/{tool}/{host}/
        if self.by_host:
            tool_dir = self.output_dir / _sanitise_dirname(item.tool)
            if item.host:
                return tool_dir / _sanitise_dirname(item.host)
            return tool_dir

        # --- HOST-FIRST MODE ---
        # {output_dir}/{host}/{tool}/
        if self.host_first:
            host_dir = self.output_dir / _sanitise_dirname(item.host or "unknown")
            return host_dir / _sanitise_dirname(item.tool)

        # --- SESSION SPLIT MODE ---
        # {output_dir}/{session_tag}/{tool}/
        if self.split_by_session:
            session_dir = self.output_dir / _sanitise_dirname(item.session_tag or "session_anon")
            return session_dir / _sanitise_dirname(item.tool)

        # --- FLAT MODE ---
        # {output_dir}/{tool}/
        return self.output_dir / _sanitise_dirname(item.tool)

    # ------------------------------------------------------------------
    # Internal — File writing
    # ------------------------------------------------------------------

    def _write_item(self, item: BurpItem) -> None:
        """Write the .json and (optionally) .md files for one item."""
        target_dir = self._item_dir(item)
        slug = item.slug or f"{item.index:04d}_item"
        if Path(slug).name != slug or "/" in slug or "\\" in slug:
            raise ValueError("Unsafe item slug")
        (target_dir / (slug + ".json")).resolve().relative_to(self.output_dir.resolve())

        # --- JSON (default) ---
        if self.include_json:
            json_path = target_dir / f"{slug}.json"
            try:
                json_content = json.dumps(item.to_dict(), indent=2, ensure_ascii=False)
                _write_text(json_path, json_content)
                self._written_json += 1
                if self.verbose:
                    status = item.status or "?"
                    print(f"  [JSON] {json_path.relative_to(self.output_dir)}  [{status}]")
            except Exception as exc:
                self._skipped += 1
                if self.verbose:
                    print(f"  [!]  Failed to write JSON for item {item.index}: {exc}", file=sys.stderr)
                raise

        # --- Markdown (optional) ---
        if self.include_md:
            md_path = target_dir / f"{slug}.md"
            try:
                md_content = self.formatter.render(item)
                _write_text(md_path, md_content)
                self._written_md += 1
                if self.verbose:
                    status = item.status or "?"
                    print(f"  [MD]   {md_path.relative_to(self.output_dir)}  [{status}]")
            except Exception as exc:
                self._skipped += 1
                if self.verbose:
                    print(f"  [!]  Failed to write MD for item {item.index}: {exc}", file=sys.stderr)
                raise

    # ------------------------------------------------------------------
    # Internal — Index files
    # ------------------------------------------------------------------

    def _write_tool_index(self, tool: str, items: List[BurpItem]) -> None:
        """Write a README.md index for a tool folder."""
        tool_dir = self.output_dir / _sanitise_dirname(tool)
        readme_path = tool_dir / "README.md"

        if self.by_host:
            content = self._render_tool_index_by_host(tool, items)
        elif self.split_by_session:
            content = self._render_tool_index_by_session(tool, items)
        elif self.host_first:
            content = self._render_tool_index_host_first(tool, items)
        else:
            content = self._render_tool_index_flat(tool, items)

        _write_text(readme_path, content)

    def _render_tool_index_flat(self, tool: str, items: List[BurpItem]) -> str:
        """Render a flat tool-level index table."""
        lines = [
            f"# {tool.upper()} — Request/Response Index\n",
            f"> **{len(items)}** items captured from the **{tool}** tool.\n",
            "",
            "| # | Method | Path | Status | MIME | Host | File |",
            "| - | ------ | ---- | ------ | ---- | ---- | ---- |",
        ]
        for item in items:
            slug = item.slug or f"{item.index:04d}_item"
            ext = "json" if self.include_json else "md"
            link = f"[{slug}.{ext}](./{slug}.{ext})"
            lines.append(
                f"| {item.index} "
                f"| `{item.method or '?'}` "
                f"| `{(item.path or '/')[:60]}` "
                f"| `{item.status or '?'}` "
                f"| `{item.mime_type or '?'}` "
                f"| `{item.host or '?'}` "
                f"| {link} |"
            )
        lines.append("")
        lines.append("---")
        lines.append("*Generated by **BurpMD Parser Pro***")
        return "\n".join(lines) + "\n"

    def _render_tool_index_by_host(self, tool: str, items: List[BurpItem]) -> str:
        """Render a host-grouped tool-level index."""
        host_map: dict[str, list[BurpItem]] = {}
        for item in items:
            host_map.setdefault(item.host or "unknown", []).append(item)

        lines = [
            f"# {tool.upper()} — Request/Response Index (by Host)\n",
            f"> **{len(items)}** items across **{len(host_map)}** hosts.\n",
        ]

        for host in sorted(host_map.keys()):
            host_items = host_map[host]
            host_slug  = _sanitise_dirname(host)
            lines.append(f"\n## {host}\n")
            lines.append(f"| # | Method | Path | Status | MIME | File |")
            lines.append(f"| - | ------ | ---- | ------ | ---- | ---- |")
            for item in host_items:
                slug = item.slug or f"{item.index:04d}_item"
                ext = "json" if self.include_json else "md"
                link = f"[{slug}.{ext}](./{host_slug}/{slug}.{ext})"
                lines.append(
                    f"| {item.index} "
                    f"| `{item.method or '?'}` "
                    f"| `{(item.path or '/')[:60]}` "
                    f"| `{item.status or '?'}` "
                    f"| `{item.mime_type or '?'}` "
                    f"| {link} |"
                )

        lines.append("\n---")
        lines.append("*Generated by **BurpMD Parser Pro***")
        return "\n".join(lines) + "\n"

    def _render_tool_index_host_first(self, tool: str, items: List[BurpItem]) -> str:
        """Render a tool index when files are stored under host/tool folders."""
        host_map: dict[str, list[BurpItem]] = {}
        for item in items:
            host_map.setdefault(item.host or "unknown", []).append(item)

        tool_slug = _sanitise_dirname(tool)
        lines = [
            f"# {tool.upper()} — Request/Response Index (host-first)\n",
            f"> **{len(items)}** items across **{len(host_map)}** hosts.\n",
        ]

        for host in sorted(host_map.keys()):
            host_items = host_map[host]
            host_slug = _sanitise_dirname(host)
            lines.append(f"\n## {host}\n")
            lines.append("| # | Method | Path | Status | MIME | File |")
            lines.append("| - | ------ | ---- | ------ | ---- | ---- |")
            for item in host_items:
                slug = item.slug or f"{item.index:04d}_item"
                ext = "json" if self.include_json else "md"
                link = f"[{slug}.{ext}](../{host_slug}/{tool_slug}/{slug}.{ext})"
                lines.append(
                    f"| {item.index} "
                    f"| `{item.method or '?'}` "
                    f"| `{(item.path or '/')[:60]}` "
                    f"| `{item.status or '?'}` "
                    f"| `{item.mime_type or '?'}` "
                    f"| {link} |"
                )

        lines.append("\n---")
        lines.append("*Generated by **BurpMD Parser Pro***")
        return "\n".join(lines) + "\n"

    def _render_tool_index_by_session(self, tool: str, items: List[BurpItem]) -> str:
        """Render a tool index when files are grouped by session/tool."""
        sess_map: dict[str, list[BurpItem]] = {}
        for item in items:
            sess_map.setdefault(item.session_tag or "session_anon", []).append(item)

        tool_slug = _sanitise_dirname(tool)
        lines = [
            f"# {tool.upper()} — Request/Response Index (by Session)\n",
            f"> **{len(items)}** items across **{len(sess_map)}** session buckets.\n",
        ]

        for sess in sorted(sess_map.keys()):
            sess_items = sess_map[sess]
            sess_slug = _sanitise_dirname(sess)
            lines.append(f"\n## {sess}\n")
            lines.append("| # | Method | Path | Status | MIME | Host | File |")
            lines.append("| - | ------ | ---- | ------ | ---- | ---- | ---- |")
            for item in sess_items:
                slug = item.slug or f"{item.index:04d}_item"
                ext = "json" if self.include_json else "md"
                link = f"[{slug}.{ext}](../{sess_slug}/{tool_slug}/{slug}.{ext})"
                lines.append(
                    f"| {item.index} "
                    f"| `{item.method or '?'}` "
                    f"| `{(item.path or '/')[:60]}` "
                    f"| `{item.status or '?'}` "
                    f"| `{item.mime_type or '?'}` "
                    f"| `{item.host or '?'}` "
                    f"| {link} |"
                )

        lines.append("\n---")
        lines.append("*Generated by **BurpMD Parser Pro***")
        return "\n".join(lines) + "\n"

    def _write_root_index(self, export: BurpExport) -> None:
        """Write the top-level README.md summarising the entire export."""
        readme_path = self.output_dir / "README.md"

        # Build summary stats
        tool_stats: dict[str, dict] = {}
        for item in export.items:
            t = item.tool
            if t not in tool_stats:
                tool_stats[t] = {"count": 0, "hosts": set(), "methods": set()}
            tool_stats[t]["count"]   += 1
            tool_stats[t]["hosts"].add(item.host or "unknown")
            tool_stats[t]["methods"].add(item.method or "?")

        lines = [
            "# BurpMD Parser Pro — Export Analysis\n",
            "> This repository was generated by **BurpMD Parser Pro** from a Burp Suite XML export.",
            "> Feed this data to **VS Code Copilot** or any AI assistant for security analysis.\n",
            "---\n",
            "## Export Information\n",
            "| Field | Value |",
            "| ----- | ----- |",
            f"| Source File    | `{Path(export.source_file).name}` |",
            f"| Burp Version   | `{export.burp_version or 'unknown'}` |",
            f"| Export Time    | `{export.export_time or 'unknown'}` |",
            f"| Total Items    | `{len(export.items)}` |",
            f"| Unique Hosts   | `{len(export.hosts)}` |",
            f"| Tools Present  | `{', '.join(export.tools) or 'none'}` |",
            "",
            "---\n",
        ]

        # --- SITEMAP MODE: Show tree structure ---
        if self.sitemap:
            lines.append("## Site Map Tree Structure\n")
            lines.append("The output mirrors Burp Suite's Site Map hierarchy:\n")
            lines.append("```")
            lines.append(f"{self.output_dir.name}/")

            # Build a tree from all items
            tree: dict = {}
            for item in export.items:
                host = _sanitise_dirname(item.host or "unknown")
                path_segments = _url_to_dir_path(item.url, item.path)
                node = tree.setdefault(host, {})
                for seg in path_segments:
                    node = node.setdefault(seg, {})

            # Render the tree
            for host in sorted(tree.keys()):
                lines.append(f"├── {host}/")
                self._render_tree(tree[host], lines, prefix="│   ")

            lines.append("```\n")

        # --- NON-SITEMAP: Show tool breakdown ---
        else:
            lines.append("## Tool Breakdown\n")
            lines.append("| Tool | Items | Unique Hosts | Methods |")
            lines.append("| ---- | ----- | ------------ | ------- |")

            for tool, stats in sorted(tool_stats.items()):
                methods = ", ".join(sorted(stats["methods"]))
                tool_link = f"[{tool}](./{_sanitise_dirname(tool)}/README.md)"
                lines.append(
                    f"| {tool_link} "
                    f"| `{stats['count']}` "
                    f"| `{len(stats['hosts'])}` "
                    f"| `{methods}` |"
                )
            lines.append("")

        lines.append("---\n")
        lines.append("## Host Summary\n")
        lines.append("| Host | Items | Tools |")
        lines.append("| ---- | ----- | ----- |")

        host_tool_map: dict[str, set] = {}
        host_count_map: dict[str, int] = {}
        for item in export.items:
            h = item.host or "unknown"
            host_tool_map.setdefault(h, set()).add(item.tool)
            host_count_map[h] = host_count_map.get(h, 0) + 1

        for host in sorted(host_count_map.keys()):
            tools_str = ", ".join(sorted(host_tool_map[host]))
            lines.append(f"| `{host}` | `{host_count_map[host]}` | `{tools_str}` |")

        lines.append("")
        lines.append("---\n")
        lines.append("## AI Analysis Tips\n")
        lines.append(
            "Use the following VS Code Copilot prompts to analyse this export:\n"
        )
        lines.append("```")
        lines.append("@workspace Analyse all HTTP requests in the proxy folder for SQL injection vulnerabilities.")
        lines.append("@workspace Find all endpoints that accept user input and check for XSS vectors.")
        lines.append("@workspace Summarise all unique API endpoints discovered in this Burp export.")
        lines.append("@workspace Identify authentication mechanisms used across all captured requests.")
        lines.append("@workspace List all cookies and security headers present in the responses.")
        lines.append("@workspace Find requests with sensitive data like passwords, tokens, or PII.")
        lines.append("```")
        lines.append("")
        lines.append("---")
        lines.append("*Generated by **BurpMD Parser Pro** v1.0.0*")

        _write_text(readme_path, "\n".join(lines) + "\n")

    def _write_attack_surface_index(self, export: BurpExport) -> None:
        """Write machine-friendly attack-surface summary for automation and AI."""
        output_path = self.output_dir / "attack-surface-index.json"

        endpoints = {}
        auth_headers = set()
        security_headers = set()
        methods = {}
        statuses = {}
        session_counts = {}
        sensitive_params = set()

        for item in export.items:
            method = (item.method or "UNKNOWN").upper()
            path = item.path or "/"
            key = "{0} {1}://{2}:{3}{4}".format(method, item.protocol, item.host, item.port, path)
            endpoints[key] = endpoints.get(key, 0) + 1
            methods[method] = methods.get(method, 0) + 1
            status = item.status or "unknown"
            statuses[status] = statuses.get(status, 0) + 1
            session = item.session_tag or "session_anon"
            session_counts[session] = session_counts.get(session, 0) + 1

            for hk, hv in (item.request_headers or {}).items():
                hk_low = (hk or "").lower()
                if hk_low in {"authorization", "cookie", "x-api-key", "x-auth-token"}:
                    auth_headers.add(hk)
                for p, _v in parse_qsl(str(hv), keep_blank_values=True):
                    if (p or "").lower() in {"token", "auth", "session", "password", "api_key", "apikey"}:
                        sensitive_params.add(p)

            for hk in (item.response_headers or {}).keys():
                hk_low = (hk or "").lower()
                if hk_low.startswith("x-") or hk_low in {"content-security-policy", "strict-transport-security"}:
                    security_headers.add(hk)

            try:
                parsed = urlparse(item.url or "")
                for p, _v in parse_qsl(parsed.query, keep_blank_values=True):
                    if p and p.lower() in {"token", "auth", "session", "password", "api_key", "apikey"}:
                        sensitive_params.add(p)
            except Exception:
                pass

        payload = {
            "summary": {
                "total_items": len(export.items),
                "unique_hosts": len(export.hosts),
                "unique_tools": len(export.tools),
                "unique_endpoints": len(endpoints),
                "unique_sessions": len(session_counts),
            },
            "top_endpoints": [
                {"endpoint": k, "count": v}
                for k, v in sorted(endpoints.items(), key=lambda x: x[1], reverse=True)[:200]
            ],
            "methods": methods,
            "statuses": statuses,
            "auth_headers_observed": sorted(auth_headers),
            "security_headers_observed": sorted(security_headers),
            "sensitive_query_params_observed": sorted(sensitive_params),
            "session_buckets": session_counts,
        }
        _write_text(output_path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")

    def _render_tree(self, node: dict, lines: list, prefix: str = "") -> None:
        """Recursively render a tree structure for the README."""
        keys = sorted(node.keys())
        for i, key in enumerate(keys):
            is_last = (i == len(keys) - 1)
            connector = "└── " if is_last else "├── "
            lines.append(f"{prefix}{connector}{key}/")
            child_prefix = prefix + ("    " if is_last else "│   ")
            if node[key]:
                self._render_tree(node[key], lines, child_prefix)
