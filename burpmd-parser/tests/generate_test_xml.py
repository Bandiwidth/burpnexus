"""
Generate a realistic Burp Suite XML export test fixture.

This script creates a sample XML file that closely mirrors what Burp Suite
actually produces when you use "Save Items" from Proxy, Repeater, or Intruder.
"""

import base64
import os
from datetime import datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Sample HTTP messages
# ---------------------------------------------------------------------------

PROXY_REQUESTS = [
    {
        "tool": "2",  # Proxy (numeric)
        "time": "Wed Feb 19 10:00:01 EST 2026",
        "url": "https://example.com/login",
        "host": "example.com",
        "host_ip": "93.184.216.34",
        "port": "443",
        "protocol": "https",
        "method": "POST",
        "path": "/login",
        "extension": "",
        "status": "200",
        "responselength": "1842",
        "mimetype": "HTML",
        "comment": "Login form submission",
        "request": (
            "POST /login HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 38\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "Cookie: session=abc123; csrftoken=xyz789\r\n"
            "\r\n"
            "username=admin&password=password123"
        ),
        "response": (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Set-Cookie: auth_token=eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123; HttpOnly; Secure\r\n"
            "X-Frame-Options: DENY\r\n"
            "Content-Security-Policy: default-src 'self'\r\n"
            "\r\n"
            "<!DOCTYPE html><html><head><title>Dashboard</title></head>"
            "<body><h1>Welcome, admin!</h1></body></html>"
        ),
    },
    {
        "tool": "2",  # Proxy
        "time": "Wed Feb 19 10:00:05 EST 2026",
        "url": "https://example.com/api/users",
        "host": "example.com",
        "host_ip": "93.184.216.34",
        "port": "443",
        "protocol": "https",
        "method": "GET",
        "path": "/api/users",
        "extension": "",
        "status": "200",
        "responselength": "512",
        "mimetype": "JSON",
        "comment": "",
        "request": (
            "GET /api/users HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123\r\n"
            "Accept: application/json\r\n"
            "\r\n"
        ),
        "response": (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "X-Content-Type-Options: nosniff\r\n"
            "\r\n"
            '{"users": [{"id": 1, "username": "admin", "role": "administrator"}, '
            '{"id": 2, "username": "testuser", "role": "user"}]}'
        ),
    },
    {
        "tool": "2",  # Proxy
        "time": "Wed Feb 19 10:00:10 EST 2026",
        "url": "https://api.target.com/v2/products?id=1",
        "host": "api.target.com",
        "host_ip": "10.0.0.5",
        "port": "443",
        "protocol": "https",
        "method": "GET",
        "path": "/v2/products",
        "extension": "",
        "status": "200",
        "responselength": "1024",
        "mimetype": "JSON",
        "comment": "Possible IDOR - check product ID",
        "request": (
            "GET /v2/products?id=1 HTTP/1.1\r\n"
            "Host: api.target.com\r\n"
            "Authorization: Bearer user_token_here\r\n"
            "Accept: application/json\r\n"
            "\r\n"
        ),
        "response": (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"id": 1, "name": "Product A", "price": 99.99, "owner_id": 42}'
        ),
    },
    {
        "tool": "2",  # Proxy
        "time": "Wed Feb 19 10:00:15 EST 2026",
        "url": "https://api.target.com/v2/admin/config",
        "host": "api.target.com",
        "host_ip": "10.0.0.5",
        "port": "443",
        "protocol": "https",
        "method": "GET",
        "path": "/v2/admin/config",
        "extension": "",
        "status": "403",
        "responselength": "89",
        "mimetype": "JSON",
        "comment": "Admin endpoint - access denied",
        "request": (
            "GET /v2/admin/config HTTP/1.1\r\n"
            "Host: api.target.com\r\n"
            "Authorization: Bearer user_token_here\r\n"
            "\r\n"
        ),
        "response": (
            "HTTP/1.1 403 Forbidden\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"error": "Access denied", "code": 403}'
        ),
    },
]

REPEATER_REQUESTS = [
    {
        "tool": "16",  # Repeater (numeric)
        "time": "Wed Feb 19 11:30:00 EST 2026",
        "url": "https://example.com/api/users/1",
        "host": "example.com",
        "host_ip": "93.184.216.34",
        "port": "443",
        "protocol": "https",
        "method": "PUT",
        "path": "/api/users/1",
        "extension": "",
        "status": "200",
        "responselength": "256",
        "mimetype": "JSON",
        "comment": "Testing IDOR on user update endpoint",
        "request": (
            "PUT /api/users/1 HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123\r\n"
            "\r\n"
            '{"username": "admin_modified", "role": "superadmin"}'
        ),
        "response": (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"id": 1, "username": "admin_modified", "role": "superadmin", "updated": true}'
        ),
    },
    {
        "tool": "16",  # Repeater
        "time": "Wed Feb 19 11:35:00 EST 2026",
        "url": "https://example.com/search?q=test",
        "host": "example.com",
        "host_ip": "93.184.216.34",
        "port": "443",
        "protocol": "https",
        "method": "GET",
        "path": "/search",
        "extension": "",
        "status": "200",
        "responselength": "4096",
        "mimetype": "HTML",
        "comment": "XSS probe - reflected input",
        "request": (
            "GET /search?q=<script>alert(1)</script> HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "\r\n"
        ),
        "response": (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<!DOCTYPE html><html><body>"
            "<h1>Search Results for: <script>alert(1)</script></h1>"
            "<p>No results found.</p></body></html>"
        ),
    },
]

INTRUDER_REQUESTS = [
    {
        "tool": "8",  # Intruder (numeric)
        "time": "Wed Feb 19 14:00:00 EST 2026",
        "url": "https://example.com/login",
        "host": "example.com",
        "host_ip": "93.184.216.34",
        "port": "443",
        "protocol": "https",
        "method": "POST",
        "path": "/login",
        "extension": "",
        "status": "401",
        "responselength": "128",
        "mimetype": "JSON",
        "comment": "Brute force attempt #1",
        "request": (
            "POST /login HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"username": "admin", "password": "password"}'
        ),
        "response": (
            "HTTP/1.1 401 Unauthorized\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"error": "Invalid credentials", "attempts_remaining": 4}'
        ),
    },
    {
        "tool": "8",  # Intruder
        "time": "Wed Feb 19 14:00:01 EST 2026",
        "url": "https://example.com/login",
        "host": "example.com",
        "host_ip": "93.184.216.34",
        "port": "443",
        "protocol": "https",
        "method": "POST",
        "path": "/login",
        "extension": "",
        "status": "200",
        "responselength": "512",
        "mimetype": "JSON",
        "comment": "Brute force attempt #2 - SUCCESS",
        "request": (
            "POST /login HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            '{"username": "admin", "password": "admin123"}'
        ),
        "response": (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Set-Cookie: session=new_session_token; HttpOnly\r\n"
            "\r\n"
            '{"success": true, "token": "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123"}'
        ),
    },
]

SCANNER_REQUESTS = [
    {
        "tool": "4",  # Scanner (numeric)
        "time": "Wed Feb 19 09:00:00 EST 2026",
        "url": "https://api.target.com/v2/products?id=1",
        "host": "api.target.com",
        "host_ip": "10.0.0.5",
        "port": "443",
        "protocol": "https",
        "method": "GET",
        "path": "/v2/products",
        "extension": "",
        "status": "500",
        "responselength": "2048",
        "mimetype": "HTML",
        "comment": "SQL injection probe - error based",
        "request": (
            "GET /v2/products?id=1' HTTP/1.1\r\n"
            "Host: api.target.com\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "\r\n"
        ),
        "response": (
            "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<!DOCTYPE html><html><body>"
            "<h1>500 Internal Server Error</h1>"
            "<pre>You have an error in your SQL syntax; check the manual that corresponds "
            "to your MySQL server version for the right syntax to use near '''' at line 1</pre>"
            "</body></html>"
        ),
    },
]


# ---------------------------------------------------------------------------
# XML generator
# ---------------------------------------------------------------------------

def encode_b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def build_item_xml(item: dict) -> str:
    req_b64  = encode_b64(item["request"])
    resp_b64 = encode_b64(item["response"])
    return f"""  <item tool="{item['tool']}">
    <time>{item['time']}</time>
    <url><![CDATA[{item['url']}]]></url>
    <host ip="{item['host_ip']}">{item['host']}</host>
    <port>{item['port']}</port>
    <protocol>{item['protocol']}</protocol>
    <method>{item['method']}</method>
    <path><![CDATA[{item['path']}]]></path>
    <extension>{item['extension']}</extension>
    <request base64="true"><![CDATA[{req_b64}]]></request>
    <status>{item['status']}</status>
    <responselength>{item['responselength']}</responselength>
    <mimetype>{item['mimetype']}</mimetype>
    <response base64="true"><![CDATA[{resp_b64}]]></response>
    <comment><![CDATA[{item['comment']}]]></comment>
  </item>"""


def generate_xml(output_path: str) -> None:
    all_items = PROXY_REQUESTS + REPEATER_REQUESTS + INTRUDER_REQUESTS + SCANNER_REQUESTS
    item_xmls = "\n".join(build_item_xml(i) for i in all_items)

    xml = f"""<?xml version="1.0"?>
<!DOCTYPE items [
<!ELEMENT items (item*)>
<!ATTLIST items burpVersion CDATA "">
<!ATTLIST items exportTime CDATA "">
<!ELEMENT item (time, url, host, port, protocol, method, path, extension, request, status, responselength, mimetype, response, comment)>
<!ATTLIST item tool CDATA "">
<!ELEMENT time (#PCDATA)>
<!ELEMENT url (#PCDATA)>
<!ELEMENT host (#PCDATA)>
<!ATTLIST host ip CDATA "">
<!ELEMENT port (#PCDATA)>
<!ELEMENT protocol (#PCDATA)>
<!ELEMENT method (#PCDATA)>
<!ELEMENT path (#PCDATA)>
<!ELEMENT extension (#PCDATA)>
<!ELEMENT request (#PCDATA)>
<!ATTLIST request base64 (true|false) "false">
<!ELEMENT status (#PCDATA)>
<!ELEMENT responselength (#PCDATA)>
<!ELEMENT mimetype (#PCDATA)>
<!ELEMENT response (#PCDATA)>
<!ATTLIST response base64 (true|false) "false">
<!ELEMENT comment (#PCDATA)>
]>
<items burpVersion="2023.10.3.7" exportTime="Wed Feb 19 08:00:00 EST 2026">
{item_xmls}
</items>
"""

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(xml)
    print(f"[+] Test XML generated: {output_path}")
    print(f"    Items: {len(all_items)}")


if __name__ == "__main__":
    output = str(Path(__file__).resolve().parent / "sample_burp_export.xml")
    generate_xml(output)
