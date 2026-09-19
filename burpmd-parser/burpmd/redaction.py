"""Shared best-effort redaction for exports and external AI context."""
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

MASK = "[REDACTED]"
SECRET = re.compile(r"password|passwd|token|secret|api[-_]?key|authorization|cookie|session|csrf|xsrf|private[-_]?key|credential|ssn|credit[-_]?card", re.I)
ASSIGN = re.compile(r'''(?i)((?:password|passwd|[\w-]*token|[\w-]*secret|api[_-]?key|session(?:_?id)?|csrf|xsrf|credential|ssn|credit_card)\s*[=:]\s*)([^&\s;<>]+)''')
HEADER = re.compile(r"^([^:\r\n]+):[^\S\r\n]*(.*)$", re.M)
TOKEN = re.compile(r"(?i)\bBearer\s+[^\s\"'<>]+|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*|\b(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]+|sk-[A-Za-z0-9_-]{16,})")

def redact_value(value):
    if isinstance(value, dict):
        return {k: MASK if SECRET.search(str(k)) else redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value

def redact_url(url):
    try:
        parts = urlsplit(url)
        netloc = parts.netloc.rsplit("@", 1)[-1]
        query = urlencode([(k, MASK if SECRET.search(k) or k.lower() in {"key", "auth"} else redact_text(v))
                           for k, v in parse_qsl(parts.query, keep_blank_values=True)])
        return urlunsplit((parts.scheme, netloc, redact_text(parts.path), query, ""))
    except ValueError:
        return redact_text(url)

def redact_text(text):
    if not text:
        return text
    try:
        data = json.loads(text)
        if isinstance(data, (dict, list)):
            return json.dumps(redact_value(data), ensure_ascii=False)
    except (ValueError, TypeError):
        pass
    # Raw HTTP: process the first line, every header, then the body separately.
    for sep in ("\r\n\r\n", "\n\n"):
        if sep in text and re.match(r"(?:[A-Z]+ \S+ HTTP/|HTTP/)", text):
            head, body = text.split(sep, 1)
            lines = head.splitlines()
            bits = lines[0].split(" ")
            if len(bits) >= 3 and not bits[0].startswith("HTTP/"):
                bits[1] = redact_url(bits[1])
                lines[0] = " ".join(bits)
            for i in range(1, len(lines)):
                name, colon, value = lines[i].partition(":")
                lines[i] = name + colon + (" " + MASK if SECRET.search(name) else redact_text(value))
            return "\r\n".join(lines) + "\r\n\r\n" + redact_text(body)
    text = HEADER.sub(lambda m: m[1] + ": " + MASK if SECRET.search(m[1]) else m[0], text)
    text = ASSIGN.sub(lambda m: m[1] + MASK, text)
    return TOKEN.sub(MASK, text)

def redact_item(item):
    item.url = redact_url(item.url)
    item.path = redact_url(item.path)
    for attr in ("request_headers", "response_headers"):
        setattr(item, attr, redact_value(getattr(item, attr)))
    for attr in ("request_body", "response_body", "request_raw", "response_raw", "comment", "response_status_line"):
        setattr(item, attr, redact_text(getattr(item, attr)))
    # Binary source is deliberately removed after redaction.
    item.response_bytes = b""
