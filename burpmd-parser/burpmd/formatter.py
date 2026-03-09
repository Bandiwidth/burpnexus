"""
burpmd.formatter
================
Converts BurpItem objects into rich Markdown documents with embedded JSON
data blocks, optimised for VS Code Copilot AI analysis.

Each Markdown file follows a consistent structure:

    # {METHOD} {PATH} — {STATUS}

    ## Metadata
    | Field | Value |
    ...

    ## Request
    ### Headers
    | Name | Value |
    ...

    ### Body
    ```http
    {raw request}
    ```

    ## Response
    ### Status
    ...

    ### Headers
    | Name | Value |
    ...

    ### Body
    ```
    {response body}
    ```

    ## JSON Data
    ```json
    { ... full item dict ... }
    ```
"""

from __future__ import annotations

import json
from typing import Optional

from .parser import BurpItem


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _escape_md(text: str) -> str:
    """Escape pipe characters so they don't break Markdown tables."""
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", "")


def _truncate(text: str, max_chars: int = 2000) -> tuple[str, bool]:
    """Return (possibly truncated text, was_truncated)."""
    if len(text) <= max_chars:
        return text, False
    return text[:max_chars], True


def _table_row(key: str, value: str) -> str:
    return f"| `{_escape_md(key)}` | {_escape_md(value)} |"


def _headers_table(headers: dict) -> str:
    if not headers:
        return "_No headers captured._\n"
    lines = [
        "| Header | Value |",
        "| ------ | ----- |",
    ]
    for k, v in headers.items():
        lines.append(_table_row(k, v))
    return "\n".join(lines) + "\n"


def _code_block(content: str, lang: str = "", max_chars: int = 8000) -> str:
    content, truncated = _truncate(content, max_chars)
    note = "\n> **[Truncated]** Content exceeds display limit. See JSON block for full data.\n" if truncated else ""
    return f"```{lang}\n{content}\n```\n{note}"


# ---------------------------------------------------------------------------
# Main formatter
# ---------------------------------------------------------------------------

class MarkdownFormatter:
    """
    Renders a BurpItem as a Markdown document.

    Parameters
    ----------
    include_raw_request : bool
        Include the full raw HTTP request in a code block.
    include_raw_response : bool
        Include the full raw HTTP response in a code block.
    max_body_chars : int
        Maximum characters to render for request/response bodies inline.
        Larger bodies are truncated with a note; full data is in the JSON block.
    """

    def __init__(
        self,
        include_raw_request:  bool = True,
        include_raw_response: bool = True,
        max_body_chars:       int  = 8000,
    ):
        self.include_raw_request  = include_raw_request
        self.include_raw_response = include_raw_response
        self.max_body_chars       = max_body_chars

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def render(self, item: BurpItem) -> str:
        """Return the full Markdown string for a single BurpItem."""
        parts: list[str] = []

        parts.append(self._header(item))
        parts.append(self._metadata_section(item))
        parts.append(self._request_section(item))
        parts.append(self._response_section(item))
        parts.append(self._json_section(item))
        parts.append(self._footer(item))

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    def _header(self, item: BurpItem) -> str:
        method   = item.method   or "?"
        path     = item.path     or "/"
        status   = item.status   or "—"
        tool_tag = item.tool.upper()
        return (
            f"# [{tool_tag}] {method} {path}\n\n"
            f"> **Status:** `{status}`  |  "
            f"**Host:** `{item.host}`  |  "
            f"**Protocol:** `{item.protocol.upper()}`  |  "
            f"**Port:** `{item.port}`\n\n"
            f"---\n"
        )

    def _metadata_section(self, item: BurpItem) -> str:
        rows = [
            ("Index",           str(item.index)),
            ("Tool",            item.tool),
            ("Time",            item.time),
            ("URL",             item.url),
            ("Host",            item.host),
            ("Host IP",         item.host_ip),
            ("Port",            item.port),
            ("Protocol",        item.protocol),
            ("Method",          item.method),
            ("Path",            item.path),
            ("Extension",       item.extension),
            ("HTTP Status",     item.status),
            ("Response Length", item.response_length),
            ("MIME Type",       item.mime_type),
            ("Comment",         item.comment),
            ("SHA-256",         item.sha256),
        ]
        lines = [
            "## Metadata\n",
            "| Field | Value |",
            "| ----- | ----- |",
        ]
        for key, val in rows:
            lines.append(_table_row(key, val or "—"))
        return "\n".join(lines) + "\n"

    def _request_section(self, item: BurpItem) -> str:
        parts = ["## Request\n"]

        # Headers table
        parts.append("### Headers\n")
        parts.append(_headers_table(item.request_headers))

        # Body
        if item.request_body:
            parts.append("\n### Body\n")
            body, truncated = _truncate(item.request_body, self.max_body_chars)
            parts.append(_code_block(body, ""))
            if truncated:
                parts.append("> Full body available in the JSON data block below.\n")

        # Full raw request
        if self.include_raw_request and item.request_raw:
            parts.append("\n### Raw HTTP Request\n")
            raw, truncated = _truncate(item.request_raw, self.max_body_chars)
            parts.append(_code_block(raw, "http"))
            if truncated:
                parts.append("> Full raw request available in the JSON data block below.\n")

        return "\n".join(parts) + "\n"

    def _response_section(self, item: BurpItem) -> str:
        parts = ["## Response\n"]

        # Status line
        if item.response_status_line:
            parts.append(f"**Status Line:** `{item.response_status_line}`\n")

        # Headers table
        parts.append("\n### Headers\n")
        parts.append(_headers_table(item.response_headers))

        # Body
        if item.response_body:
            parts.append("\n### Body\n")
            # Detect likely language for syntax highlighting
            lang = self._detect_response_lang(item)
            body, truncated = _truncate(item.response_body, self.max_body_chars)
            parts.append(_code_block(body, lang))
            if truncated:
                parts.append("> Full body available in the JSON data block below.\n")

        # Full raw response
        if self.include_raw_response and item.response_raw:
            parts.append("\n### Raw HTTP Response\n")
            raw, truncated = _truncate(item.response_raw, self.max_body_chars)
            parts.append(_code_block(raw, "http"))
            if truncated:
                parts.append("> Full raw response available in the JSON data block below.\n")

        return "\n".join(parts) + "\n"

    def _json_section(self, item: BurpItem) -> str:
        data = item.to_dict()
        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        return (
            "## JSON Data\n\n"
            "> This block contains the complete structured data for this request/response pair.\n"
            "> Feed directly to VS Code Copilot or any AI assistant for analysis.\n\n"
            + _code_block(json_str, "json", max_chars=200_000)
            + "\n"
        )

    def _footer(self, item: BurpItem) -> str:
        return (
            "---\n\n"
            f"*Generated by **BurpMD Parser Pro** · "
            f"Item `{item.index}` · Tool `{item.tool}` · "
            f"[{item.url}]({item.url})*\n"
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_response_lang(item: BurpItem) -> str:
        """Guess a Markdown code-fence language from MIME type or response body."""
        mime = (item.mime_type or "").lower()
        body = (item.response_body or "")[:200].strip()

        if "json" in mime or body.startswith("{") or body.startswith("["):
            return "json"
        if "html" in mime or body.lower().startswith("<!doctype") or body.lower().startswith("<html"):
            return "html"
        if "xml" in mime or body.startswith("<?xml") or body.startswith("<"):
            return "xml"
        if "javascript" in mime or "js" in mime:
            return "javascript"
        if "css" in mime:
            return "css"
        return ""
