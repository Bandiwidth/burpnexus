"""
burpmd.parser
=============
Core parsing engine for Burp Suite XML export files.

Burp Suite exports HTTP history, Repeater tabs, Intruder results, and Scanner
findings via "Save Items" → XML.  The XML schema (as defined in the internal
DTD) looks like:

    <!ELEMENT items (item*)>
    <!ATTLIST items burpVersion CDATA "">
    <!ATTLIST items exportTime  CDATA "">

    <!ELEMENT item (time, url, host, port, protocol, method, path, extension,
                    request, status, responselength, mimetype, response, comment)>
    <!ATTLIST item tool CDATA "">

    <!ELEMENT request  (#PCDATA)>
    <!ATTLIST request  base64 (true|false) "false">

    <!ELEMENT response (#PCDATA)>
    <!ATTLIST response base64 (true|false) "false">

This module handles:
  - XML parsing with graceful error recovery for malformed / large files
  - Base64 decoding of request / response bodies
  - Binary-safe UTF-8 decoding with latin-1 fallback
  - Normalisation of all metadata fields into a consistent BurpItem dataclass
  - Detection of the originating Burp tool from the <tool> attribute or
    heuristic analysis of the item metadata
"""

from __future__ import annotations

import base64
import hashlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Tool name constants  (Burp uses numeric codes in some versions; we normalise
# to human-readable strings that become folder names)
# ---------------------------------------------------------------------------

TOOL_PROXY    = "proxy"
TOOL_REPEATER = "repeater"
TOOL_INTRUDER = "intruder"
TOOL_SCANNER  = "scanner"
TOOL_SEQUENCER = "sequencer"
TOOL_DECODER  = "decoder"
TOOL_COMPARER = "comparer"
TOOL_EXTENDER = "extender"
TOOL_TARGET   = "target"
TOOL_LOGGER   = "logger"
TOOL_UNKNOWN  = "unknown"

# Burp Suite numeric tool identifiers (used in older XML exports)
_NUMERIC_TOOL_MAP: dict[str, str] = {
    "1":   TOOL_TARGET,
    "2":   TOOL_PROXY,
    "4":   TOOL_SCANNER,
    "8":   TOOL_INTRUDER,
    "16":  TOOL_REPEATER,
    "32":  TOOL_SEQUENCER,
    "64":  TOOL_DECODER,
    "128": TOOL_COMPARER,
    "256": TOOL_EXTENDER,
    "512": TOOL_LOGGER,
}

# String tool name aliases that Burp may embed
_STRING_TOOL_MAP: dict[str, str] = {
    "proxy":      TOOL_PROXY,
    "repeater":   TOOL_REPEATER,
    "intruder":   TOOL_INTRUDER,
    "scanner":    TOOL_SCANNER,
    "sequencer":  TOOL_SEQUENCER,
    "decoder":    TOOL_DECODER,
    "comparer":   TOOL_COMPARER,
    "extender":   TOOL_EXTENDER,
    "target":     TOOL_TARGET,
    "logger":     TOOL_LOGGER,
    "sitemap":    TOOL_TARGET,
    "site map":   TOOL_TARGET,
    "http history": TOOL_PROXY,
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class BurpItem:
    """Represents a single HTTP request/response pair from a Burp export."""

    # Metadata
    index:          int             = 0
    tool:           str             = TOOL_UNKNOWN
    time:           str             = ""
    url:            str             = ""
    host:           str             = ""
    host_ip:        str             = ""
    port:           str             = ""
    protocol:       str             = ""
    method:         str             = ""
    path:           str             = ""
    extension:      str             = ""
    status:         str             = ""
    response_length: str            = ""
    mime_type:      str             = ""
    comment:        str             = ""

    # Raw decoded bytes (stored as str for JSON serialisation)
    request_raw:    str             = ""
    response_raw:   str             = ""

    # Parsed HTTP components
    request_headers:  dict          = field(default_factory=dict)
    request_body:     str           = ""
    response_headers: dict          = field(default_factory=dict)
    response_body:    str           = ""
    response_status_line: str       = ""

    # Derived helpers
    slug:           str             = ""   # filesystem-safe identifier
    sha256:         str             = ""   # hash of request raw for dedup
    session_tag:    str             = ""   # derived session bucket label

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dictionary of all fields."""
        return {
            "metadata": {
                "index":           self.index,
                "tool":            self.tool,
                "time":            self.time,
                "url":             self.url,
                "host":            self.host,
                "host_ip":         self.host_ip,
                "port":            self.port,
                "protocol":        self.protocol,
                "method":          self.method,
                "path":            self.path,
                "extension":       self.extension,
                "status":          self.status,
                "response_length": self.response_length,
                "mime_type":       self.mime_type,
                "comment":         self.comment,
                "sha256":          self.sha256,
                "session_tag":     self.session_tag,
            },
            "request": {
                "raw":     self.request_raw,
                "headers": self.request_headers,
                "body":    self.request_body,
            },
            "response": {
                "status_line": self.response_status_line,
                "raw":         self.response_raw,
                "headers":     self.response_headers,
                "body":        self.response_body,
            },
        }


@dataclass
class BurpExport:
    """Container for a parsed Burp XML export file."""

    source_file:   str        = ""
    burp_version:  str        = ""
    export_time:   str        = ""
    items:         List[BurpItem] = field(default_factory=list)

    @property
    def tools(self) -> List[str]:
        """Return sorted list of unique tool names present in this export."""
        return sorted({item.tool for item in self.items})

    @property
    def hosts(self) -> List[str]:
        """Return sorted list of unique host values present in this export."""
        return sorted({item.host for item in self.items if item.host})

    def items_by_tool(self, tool: str) -> List[BurpItem]:
        return [i for i in self.items if i.tool == tool]

    def items_by_host(self, host: str) -> List[BurpItem]:
        return [i for i in self.items if i.host == host]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _safe_text(element: Optional[ET.Element]) -> str:
    """Return stripped text content of an XML element, or empty string."""
    if element is None:
        return ""
    return (element.text or "").strip()


def _decode_field(element: Optional[ET.Element]) -> str:
    """
    Decode a request or response XML element.

    The element may carry  base64="true"  in which case the text is
    base64-encoded.  We decode to bytes then attempt UTF-8; if that fails
    we fall back to latin-1 which is lossless for arbitrary byte values.
    """
    if element is None:
        return ""
    raw_text = (element.text or "").strip()
    if not raw_text:
        return ""

    is_b64 = element.get("base64", "false").lower() == "true"
    if is_b64:
        try:
            data = base64.b64decode(raw_text)
        except Exception:
            return raw_text   # return as-is if decode fails
    else:
        data = raw_text.encode("latin-1", errors="replace")

    # Try UTF-8 first, fall back to latin-1
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


def _normalise_tool(raw: str) -> str:
    """Convert a raw tool string (numeric or textual) to a canonical name."""
    if not raw:
        return TOOL_UNKNOWN
    stripped = raw.strip()
    if stripped in _NUMERIC_TOOL_MAP:
        return _NUMERIC_TOOL_MAP[stripped]
    lower = stripped.lower()
    for key, val in _STRING_TOOL_MAP.items():
        if key in lower:
            return val
    return lower or TOOL_UNKNOWN


def _make_slug(item: BurpItem) -> str:
    """
    Create a filesystem-safe slug for an item.

    Format: {index:04d}_{METHOD}_{sanitised_path}
    """
    method = (item.method or "REQ").upper()[:10]
    path_part = re.sub(r"[^\w\-.]", "_", item.path or "root")
    path_part = re.sub(r"_+", "_", path_part).strip("_")[:60]
    return f"{item.index:04d}_{method}_{path_part}"


def _parse_http_headers(raw: str) -> tuple[dict, str]:
    """
    Parse raw HTTP headers from the first block of an HTTP message.

    Returns (headers_dict, body_string).
    """
    headers: dict[str, str] = {}
    if not raw:
        return headers, ""

    # Split on the first blank line separating headers from body
    if "\r\n\r\n" in raw:
        header_block, body = raw.split("\r\n\r\n", 1)
        sep = "\r\n"
    elif "\n\n" in raw:
        header_block, body = raw.split("\n\n", 1)
        sep = "\n"
    else:
        return headers, raw

    lines = header_block.split(sep)
    for line in lines[1:]:   # skip the request/status line
        if ":" in line:
            name, _, value = line.partition(":")
            headers[name.strip()] = value.strip()

    return headers, body


def _parse_request(raw: str) -> tuple[dict, str]:
    return _parse_http_headers(raw)


def _parse_response(raw: str) -> tuple[str, dict, str]:
    """
    Parse a raw HTTP response.

    Returns (status_line, headers_dict, body_string).
    """
    if not raw:
        return "", {}, ""

    # Determine line separator
    sep = "\r\n" if "\r\n" in raw else "\n"
    first_line_end = raw.find(sep)
    status_line = raw[:first_line_end].strip() if first_line_end != -1 else raw.strip()

    headers, body = _parse_http_headers(raw)
    return status_line, headers, body


# ---------------------------------------------------------------------------
# Public parser
# ---------------------------------------------------------------------------

class BurpXMLParser:
    """
    Parse one or more Burp Suite XML export files into BurpExport objects.

    Usage::

        parser = BurpXMLParser()
        export = parser.parse_file("/path/to/export.xml")
        for item in export.items:
            print(item.tool, item.url, item.status)
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def parse_file(self, path: str | Path) -> BurpExport:
        """Parse a single Burp XML export file and return a BurpExport."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        export = BurpExport(source_file=str(path))

        try:
            tree = ET.parse(str(path))
            root = tree.getroot()
        except ET.ParseError as exc:
            # Attempt recovery: strip invalid XML characters and retry
            if self.verbose:
                print(f"  [!] XML parse error ({exc}), attempting recovery …")
            root = self._recover_parse(path)
            if root is None:
                raise ValueError(f"Cannot parse XML file: {path}") from exc

        export.burp_version = root.get("burpVersion", "")
        export.export_time  = root.get("exportTime", "")

        items_elements = root.findall("item")
        total = len(items_elements)
        if self.verbose:
            print(f"  [*] Found {total} items in {path.name}")

        for idx, elem in enumerate(items_elements, start=1):
            try:
                item = self._parse_item(elem, idx)
                export.items.append(item)
            except Exception as exc:
                if self.verbose:
                    print(f"  [!] Skipping item {idx}: {exc}")

        return export

    def parse_files(self, paths: List[str | Path]) -> List[BurpExport]:
        """Parse multiple XML files and return a list of BurpExport objects."""
        exports = []
        for p in paths:
            try:
                exports.append(self.parse_file(p))
            except Exception as exc:
                if self.verbose:
                    print(f"  [!] Failed to parse {p}: {exc}")
        return exports

    def merge_exports(self, exports: List[BurpExport]) -> BurpExport:
        """
        Merge multiple BurpExport objects into a single combined export.
        Item indices are re-assigned sequentially across all exports.
        """
        merged = BurpExport(source_file="<merged>")
        counter = 1
        for exp in exports:
            merged.burp_version = merged.burp_version or exp.burp_version
            merged.export_time  = merged.export_time  or exp.export_time
            for item in exp.items:
                item.index = counter
                item.slug  = _make_slug(item)
                merged.items.append(item)
                counter += 1
        return merged

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _recover_parse(self, path: Path) -> Optional[ET.Element]:
        """
        Attempt to parse a malformed XML file by stripping control characters
        and re-trying the parse.
        """
        try:
            raw = path.read_bytes()
            # Remove null bytes and other control chars that break ET
            cleaned = re.sub(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", b"", raw)
            return ET.fromstring(cleaned)
        except Exception:
            return None

    def _parse_item(self, elem: ET.Element, idx: int) -> BurpItem:
        """Convert a single <item> XML element into a BurpItem dataclass."""
        item = BurpItem()
        item.index = idx

        # --- Tool detection ---
        raw_tool = elem.get("tool", "")
        item.tool = _normalise_tool(raw_tool)

        # --- Metadata fields ---
        item.time            = _safe_text(elem.find("time"))
        item.url             = _safe_text(elem.find("url"))
        item.port            = _safe_text(elem.find("port"))
        item.protocol        = _safe_text(elem.find("protocol"))
        item.method          = _safe_text(elem.find("method"))
        item.path            = _safe_text(elem.find("path"))
        item.extension       = _safe_text(elem.find("extension"))
        item.status          = _safe_text(elem.find("status"))
        item.response_length = _safe_text(elem.find("responselength"))
        item.mime_type       = _safe_text(elem.find("mimetype"))
        item.comment         = _safe_text(elem.find("comment"))

        # Host element may carry an "ip" attribute
        host_elem = elem.find("host")
        if host_elem is not None:
            item.host    = (host_elem.text or "").strip()
            item.host_ip = host_elem.get("ip", "")

        # Fallback: derive host from URL if not present
        if not item.host and item.url:
            try:
                parsed = urlparse(item.url)
                item.host     = parsed.hostname or ""
                item.protocol = item.protocol or parsed.scheme or ""
                item.port     = item.port or str(parsed.port or "")
            except Exception:
                pass

        # --- Request / Response ---
        item.request_raw  = _decode_field(elem.find("request"))
        item.response_raw = _decode_field(elem.find("response"))

        # Parse HTTP components
        item.request_headers, item.request_body = _parse_request(item.request_raw)
        (item.response_status_line,
         item.response_headers,
         item.response_body) = _parse_response(item.response_raw)

        # --- Derived fields ---
        item.sha256 = hashlib.sha256(item.request_raw.encode("utf-8", errors="replace")).hexdigest()
        item.slug   = _make_slug(item)

        # If tool is still unknown, try to infer from request headers or URL
        if item.tool == TOOL_UNKNOWN:
            item.tool = self._infer_tool(item)

        return item

    @staticmethod
    def _infer_tool(item: BurpItem) -> str:
        """
        Heuristic tool inference when the <item tool=""> attribute is absent.

        When Burp exports from Proxy history the tool attribute is often
        empty.  We default to PROXY as the most common source.
        """
        # If there is a comment that looks like a Repeater tab name, use that
        comment_lower = (item.comment or "").lower()
        if "repeater" in comment_lower:
            return TOOL_REPEATER
        if "intruder" in comment_lower:
            return TOOL_INTRUDER
        if "scanner" in comment_lower or "scan" in comment_lower:
            return TOOL_SCANNER
        # Default to proxy for items without tool info
        return TOOL_PROXY
