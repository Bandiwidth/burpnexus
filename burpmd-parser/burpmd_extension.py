# -*- coding: utf-8 -*-
"""
BurpMD Auto-Exporter - Burp Suite Extension (Jython / Legacy API)
=================================================================
Right-click in Proxy History or Site Map to export traffic as XML
and automatically invoke burpmd to produce an AI-ready corpus.
"""

from burp import IBurpExtender, IContextMenuFactory, ITab
from javax.swing import (JMenuItem, JMenu, JPanel, JButton, JLabel,
                         BoxLayout, JSeparator)
from java.awt.event import ActionListener
from java.util import ArrayList
import base64
import hashlib
import os
import subprocess
import time
import uuid
import threading


# -----------------------------------------------------------------------
# Every export profile the CLI supports, as a (label, [flags]) tuple.
# -----------------------------------------------------------------------

PROFILES = [
    # --- RECOMMENDED: Full AI Analysis ---
    ("FULL AI ANALYSIS  (JSON + findings + prompts)",
     ["--sitemap", "--dedupe", "--full-analysis"]),
    ("FULL AI ANALYSIS  (JSON + MD + findings + prompts)",
     ["--sitemap", "--md", "--dedupe", "--full-analysis"]),

    None,  # separator

    # --- Output format ---
    ("JSON only  (sitemap layout)",
     ["--sitemap", "--dedupe"]),
    ("Markdown only  (sitemap layout)",
     ["--sitemap", "--md-only", "--dedupe"]),
    ("JSON + Markdown  (sitemap layout)",
     ["--sitemap", "--md", "--dedupe"]),

    None,  # separator

    # --- Layout modes (JSON) ---
    ("JSON  (flat / by tool)",
     ["--dedupe"]),
    ("JSON  (by-host)",
     ["--by-host", "--dedupe"]),
    ("JSON  (host-first)",
     ["--host-first", "--dedupe"]),
    ("JSON  (split-by-session)",
     ["--split-by-session", "--dedupe"]),

    None,  # separator

    # --- Triage / filtered ---
    ("Triage: errors + auth only  (401,403,5xx)",
     ["--sitemap", "--only-status", "401,403,5xx", "--dedupe"]),
    ("Triage: errors + auth  (JSON + MD)",
     ["--sitemap", "--md", "--only-status", "401,403,5xx", "--dedupe"]),

    None,  # separator

    # --- Redaction ---
    ("Redacted JSON  (secrets masked, sitemap)",
     ["--sitemap", "--redact-secrets", "--dedupe"]),
    ("Redacted JSON + MD  (secrets masked)",
     ["--sitemap", "--md", "--redact-secrets", "--dedupe"]),
    ("Redacted + Session Split",
     ["--split-by-session", "--redact-secrets", "--dedupe"]),

    None,  # separator

    # --- Scope-only exports ---
    ("In-Scope only  (JSON + full analysis)",
     ["--sitemap", "--dedupe", "--full-analysis", "__SCOPE_ONLY__"]),
]

TAB_PROFILES = [
    ("Export Project  -  FULL AI ANALYSIS (recommended)",
     ["--sitemap", "--dedupe", "--full-analysis"]),
    ("Export Project  -  JSON only (sitemap)",
     ["--sitemap", "--dedupe"]),
    ("Export Project  -  Markdown only (sitemap)",
     ["--sitemap", "--md-only", "--dedupe"]),
    ("Export Project  -  JSON + MD (sitemap)",
     ["--sitemap", "--md", "--dedupe"]),
    ("Export Project  -  Triage (401,403,5xx)",
     ["--sitemap", "--only-status", "401,403,5xx", "--dedupe"]),
    ("Export Project  -  Redacted (secrets masked)",
     ["--sitemap", "--redact-secrets", "--dedupe"]),
    ("Export Project  -  Redacted + Session Split",
     ["--split-by-session", "--redact-secrets", "--dedupe"]),
    ("Export Project  -  In-Scope only + AI analysis",
     ["--sitemap", "--dedupe", "--full-analysis", "__SCOPE_ONLY__"]),
]


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName("BurpMD Auto-Exporter")
        callbacks.registerContextMenuFactory(self)

        self._panel = self._build_tab_ui()
        callbacks.addSuiteTab(self)

        self._println("[+] BurpMD Auto-Exporter loaded.")
        self._println("[*] Right-click in Proxy/Site Map for all export options.")

    # ------------------------------------------------------------------
    # ITab
    # ------------------------------------------------------------------

    def getTabCaption(self):
        return "BurpMD"

    def getUiComponent(self):
        return self._panel

    def _build_tab_ui(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.add(JLabel(" "))
        panel.add(JLabel("  BurpMD Auto-Exporter"))
        panel.add(JLabel("  Export entire Burp project to AI-ready corpus."))
        panel.add(JLabel(" "))

        for label, flags in TAB_PROFILES:
            f = list(flags)
            btn = JButton(label)
            btn.addActionListener(_Listener(lambda fl=f: self._export_all(fl)))
            panel.add(btn)

        panel.add(JLabel(" "))
        panel.add(JLabel("  Output: ~/burpmd_exports/<timestamp>/"))
        return panel

    # ------------------------------------------------------------------
    # IContextMenuFactory
    # ------------------------------------------------------------------

    def createMenuItems(self, invocation):
        menu = ArrayList()
        try:
            selected = self._items_from_invocation(invocation)

            if selected:
                hosts = self._extract_hosts(selected)
                all_items = self._collect_items_for_hosts(hosts)
                count = len(all_items)

                submenu = JMenu("BurpMD: Export %d items (%s)" % (
                    count, ", ".join(hosts[:3])))

                for entry in PROFILES:
                    if entry is None:
                        submenu.addSeparator()
                        continue
                    label, flags = entry
                    f = list(flags)
                    items_copy = list(all_items)
                    submenu.add(self._menu_item(
                        label,
                        lambda fl=f, it=items_copy: self._run_export(it, fl)))

                menu.add(submenu)
            else:
                submenu = JMenu("BurpMD: Export Entire Project")
                for entry in PROFILES:
                    if entry is None:
                        submenu.addSeparator()
                        continue
                    label, flags = entry
                    f = list(flags)
                    submenu.add(self._menu_item(
                        label,
                        lambda fl=f: self._export_all(fl)))
                menu.add(submenu)

        except Exception as ex:
            self._printerr("[!] createMenuItems error: " + str(ex))
            menu.add(self._menu_item(
                "BurpMD: Export Entire Project (fallback)",
                lambda: self._export_all(["--sitemap", "--md", "--dedupe"])))
        return menu

    # ------------------------------------------------------------------
    # Item collection - deep crawl by host
    # ------------------------------------------------------------------

    def _items_from_invocation(self, invocation):
        if invocation is None:
            return []
        try:
            msgs = invocation.getSelectedMessages()
            if msgs and len(msgs) > 0:
                return list(msgs)
        except Exception:
            pass
        return []

    def _extract_hosts(self, items):
        hosts = set()
        for item in items:
            try:
                svc = item.getHttpService()
                if svc:
                    hosts.add(svc.getHost())
            except Exception:
                pass
        return sorted(hosts)

    def _collect_items_for_hosts(self, hosts):
        """
        Deep-crawl: for each selected host, pull ALL matching
        request/response pairs from Proxy History AND Site Map.
        Each item is stored as (IHttpRequestResponse, tool_name).
        """
        if not hosts:
            return []

        host_set = set(h.lower() for h in hosts)
        seen = {}
        merged = []

        # Proxy History items are tagged as "proxy"
        try:
            for item in self._callbacks.getProxyHistory() or []:
                try:
                    svc = item.getHttpService()
                    if svc is None:
                        continue
                    if svc.getHost().lower() not in host_set:
                        continue
                    req = item.getRequest()
                    if req is None:
                        continue
                    key = hashlib.sha256(
                        bytes(bytearray(req))).hexdigest()
                    if key not in seen:
                        seen[key] = True
                        merged.append((item, "proxy"))
                except Exception:
                    continue
        except Exception:
            pass

        # Site Map items are tagged as "target"
        for host in hosts:
            for prefix in ["https://" + host, "http://" + host]:
                try:
                    result = self._callbacks.getSiteMap(prefix)
                    if not result:
                        continue
                    for item in result:
                        try:
                            req = item.getRequest()
                            if req is None:
                                continue
                            key = hashlib.sha256(
                                bytes(bytearray(req))).hexdigest()
                            if key not in seen:
                                seen[key] = True
                                merged.append((item, "target"))
                        except Exception:
                            continue
                except Exception:
                    pass

        self._println("[*] Deep-crawl: %d unique items for hosts: %s" % (
            len(merged), ", ".join(hosts)))
        return merged

    def _collect_all_items(self, scope_only=False):
        """Collect everything from Proxy + Site Map (full project)."""
        seen = {}
        merged = []

        try:
            for item in self._callbacks.getProxyHistory() or []:
                req = item.getRequest()
                if req is None:
                    continue
                if scope_only and not self._is_in_scope(item):
                    continue
                key = hashlib.sha256(
                    bytes(bytearray(req))).hexdigest()
                if key not in seen:
                    seen[key] = True
                    merged.append((item, "proxy"))
        except Exception:
            pass

        try:
            for item in self._callbacks.getSiteMap("") or []:
                req = item.getRequest()
                if req is None:
                    continue
                if scope_only and not self._is_in_scope(item):
                    continue
                key = hashlib.sha256(
                    bytes(bytearray(req))).hexdigest()
                if key not in seen:
                    seen[key] = True
                    merged.append((item, "target"))
        except Exception:
            pass

        return merged

    def _is_in_scope(self, item):
        """Check if an item is within Burp's defined target scope."""
        try:
            svc = item.getHttpService()
            if svc is None:
                return False
            req = item.getRequest()
            if req is None:
                return False
            info = self._helpers.analyzeRequest(svc, req)
            url = info.getUrl()
            return self._callbacks.isInScope(url)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def _export_all(self, flags=None):
        if flags is None:
            flags = ["--sitemap", "--md", "--dedupe"]
        scope_only = "__SCOPE_ONLY__" in flags
        clean_flags = [f for f in flags if f != "__SCOPE_ONLY__"]
        items = self._collect_all_items(scope_only=scope_only)
        self._run_export(items, clean_flags)

    def _run_export(self, items, flags=None):
        if flags is None:
            flags = ["--sitemap", "--md", "--dedupe"]
        clean_flags = [f for f in flags if f != "__SCOPE_ONLY__"]
        if "__SCOPE_ONLY__" in flags:
            items = [item for item in items if self._is_in_scope(item)]
        if not items:
            self._printerr("[-] No items to export.")
            return
        threading.Thread(
            target=self._export_thread,
            args=(items, clean_flags)).start()

    def _export_thread(self, items, flags):
        try:
            ts = time.strftime("%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:8]
            base = os.path.join(
                os.path.expanduser("~"), "burpmd_exports", ts)
            xml_path = os.path.join(base, "burpmd_export_" + ts + ".xml")
            ai_repo = os.path.join(base, "ai_repo_" + ts)

            if not os.path.exists(base):
                os.makedirs(base)

            xml = self._build_xml(items)
            with open(xml_path, "w") as f:
                f.write(xml)

            self._println("[+] XML saved (%d items): %s" % (
                len(items), xml_path))

            ok = self._invoke_burpmd(xml_path, ai_repo, flags)
            if ok:
                self._println("[+] AI corpus: " + ai_repo)
                self._println(
                    "[!] Open in VS Code for Copilot analysis.")
            else:
                self._printerr(
                    "[-] burpmd auto-invoke failed. Run manually:")
                self._println(
                    '    burpmd "%s" -o "%s" %s -v' % (
                        xml_path, ai_repo, " ".join(flags)))
        except Exception as ex:
            self._printerr("[-] Export error: " + str(ex))

    def _invoke_burpmd(self, xml_path, output_dir, flags):
        for cmd in [
            ["burpmd", xml_path, "-o", output_dir] + flags + ["-v"],
            ["python3", "-m", "burpmd", xml_path,
             "-o", output_dir] + flags + ["-v"],
            ["python", "-m", "burpmd", xml_path,
             "-o", output_dir] + flags + ["-v"],
        ]:
            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = proc.communicate()
                if proc.returncode == 0:
                    return True
            except Exception:
                continue
        return False

    # ------------------------------------------------------------------
    # XML generation (legacy API objects)
    # ------------------------------------------------------------------

    # Burp numeric tool codes for XML
    _TOOL_CODES = {
        "proxy": "2", "target": "1", "scanner": "4",
        "intruder": "8", "repeater": "16", "sequencer": "32",
        "decoder": "64", "comparer": "128", "extender": "256",
        "logger": "512",
    }

    def _build_xml(self, items):
        """
        Build Burp-compatible XML from collected items.
        items is a list of (IHttpRequestResponse, tool_name) tuples.
        """
        now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
        out = ['<?xml version="1.0" encoding="UTF-8"?>']
        out.append(
            '<items burpVersion="extension" exportTime="%s">'
            % self._esc(now))

        for entry in items:
            try:
                if isinstance(entry, tuple):
                    item, tool_name = entry
                else:
                    item = entry
                    tool_name = "proxy"

                req = item.getRequest()
                resp = item.getResponse()
                svc = item.getHttpService()
                if req is None or svc is None:
                    continue

                info = self._helpers.analyzeRequest(svc, req)
                url = info.getUrl().toString()
                host = svc.getHost()
                port = str(svc.getPort())
                proto = svc.getProtocol() or "http"
                method = info.getMethod()
                path = info.getUrl().getPath() or "/"

                tool_code = self._TOOL_CODES.get(
                    tool_name, self._TOOL_CODES["proxy"])

                status = "0"
                resp_len = "0"
                resp_b64 = ""
                if resp:
                    ri = self._helpers.analyzeResponse(resp)
                    status = str(ri.getStatusCode())
                    resp_len = str(len(resp))
                    resp_b64 = base64.b64encode(
                        bytes(bytearray(resp))).decode("ascii")

                req_b64 = base64.b64encode(
                    bytes(bytearray(req))).decode("ascii")

                out.append('  <item tool="%s">' % tool_code)
                out.append('    <time>%s</time>' % self._esc(now))
                out.append(
                    '    <url><![CDATA[%s]]></url>' % url)
                out.append(
                    '    <host ip="">%s</host>' % self._esc(host))
                out.append('    <port>%s</port>' % port)
                out.append('    <protocol>%s</protocol>' % proto)
                out.append(
                    '    <method><![CDATA[%s]]></method>' % method)
                out.append(
                    '    <path><![CDATA[%s]]></path>' % path)
                out.append('    <extension></extension>')
                out.append(
                    '    <request base64="true">'
                    '<![CDATA[%s]]></request>' % req_b64)
                out.append('    <status>%s</status>' % status)
                out.append(
                    '    <responselength>%s</responselength>'
                    % resp_len)
                out.append('    <mimetype></mimetype>')
                out.append(
                    '    <response base64="true">'
                    '<![CDATA[%s]]></response>' % resp_b64)
                out.append('    <comment><![CDATA[]]></comment>')
                out.append('  </item>')
            except Exception:
                continue

        out.append("</items>")
        return "\n".join(out)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _menu_item(self, label, callback):
        item = JMenuItem(label)
        item.addActionListener(_Listener(callback))
        return item

    def _esc(self, t):
        return (str(t).replace("&", "&amp;")
                .replace("<", "&lt;").replace(">", "&gt;"))

    def _println(self, msg):
        try:
            self._callbacks.printOutput(msg)
        except Exception:
            pass

    def _printerr(self, msg):
        try:
            self._callbacks.printError(msg)
        except Exception:
            pass


class _Listener(ActionListener):
    """Swing ActionListener wrapper for a zero-arg Python callable."""
    def __init__(self, fn):
        self._fn = fn

    def actionPerformed(self, event):
        try:
            self._fn()
        except Exception:
            pass
