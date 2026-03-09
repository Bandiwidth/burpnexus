# BurpNexus

Self-contained Burp Suite exporter and BurpMD CLI. The extension runs entirely inside Burp and writes to your local disk; the CLI parses Burp XML exports into the same sitemap-style corpus from the command line.

---

## Extension (BurpNexus)

**What it does:** Exports Burp Proxy History and Site Map traffic into a sitemap-style directory:

- **Per-request JSON** (and optional Markdown) — one file per request/response pair
- **attack-surface-index.json** — endpoint summary, methods, status codes, auth headers
- **param-index.json** — all parameters (query, body, JSON, cookies, headers)
- **SECURITY_FINDINGS.md** + **security-findings.json** — automated pattern-based findings
- **AI_ANALYSIS_PROMPTS.md** — prompts tailored to the export
- **README.md** — export summary and stats

**Requirements:** Burp Suite Professional or Community (Montoya extensions). No Python or CLI needed for the extension.

**Install:** Load `Nexus_extension/burpnexus-1.0.0.jar` in Burp: **Extensions** → **Add** → **Extension type: Java** → **Select file**. The **BurpNexus** tab and right-click menu appear.

**Output location:** Timestamped subfolders under your user home:

| OS      | Base folder |
|--------|-------------|
| Windows | `C:\Users\<YourUsername>\burpnexus_exports\` |
| macOS   | `/Users/<YourUsername>/burpnexus_exports/` |
| Linux   | `/home/<YourUsername>/burpnexus_exports/` |

**Features:**

- **Main EXPORT:** Set output mode (Sitemap), scope (All traffic / In-scope only), options (Deduplicate, Include Markdown, Redact secrets, Full analysis), optional time range (From/To) and filters (Tools, Status). Click **EXPORT**; runs in background.
- **Export presets:** One-click presets (e.g. Full AI Analysis, JSON Only, Triage 401/403/5xx).
- **Parameter search:** Name/value, Contains/Exact, JSON or MD → **Search & Export** (only matching items).
- **Regex content search:** Pattern (Java regex), Request/Response/Both → **Search & Export**.
- **Right-click:** With items selected — export those hosts only (all traffic for those hosts). With nothing selected — export entire project. Submenus for presets (AI Analysis, JSON only, Triage, Redacted, etc.).

**Privacy:** No network calls; no telemetry; output only to `~/burpnexus_exports/`. Safe for air-gapped environments.



---

## CLI (BurpMD parser)

**What it does:** Python CLI that parses Burp Suite XML exports into the same sitemap-style corpus (per-request JSON/Markdown, attack-surface index, param index, security findings, AI prompts). Use when you already have XML exports and prefer the command line.

**Install:** From the `burpmd-parser/` folder:

```bash
cd burpmd-parser
pip install .
# or on Windows: .\install.ps1 or install.bat
```

Requires Python 3.8+. No external dependencies beyond the standard library.

**Basic usage:**

```bash
# Full analysis, sitemap layout (recommended)
burpmd export.xml -o output_dir --sitemap --full-analysis --dedupe -v

# JSON only
burpmd export.xml -o output_dir --sitemap --dedupe

# JSON + Markdown with findings
burpmd export.xml -o output_dir --sitemap --md --auto-findings --dedupe
```

**Features:**

- **Output modes:** `--sitemap` (recommended), `--by-host`, `--host-first`, `--split-by-session`, or flat (default).
- **Format:** JSON (default), `--md` (add Markdown), `--md-only`.
- **Filters:** `--only-tools` (e.g. proxy,repeater,scanner), `--only-status` (e.g. 401,403,5xx), `--dedupe`, `--redact-secrets`.
- **Analysis:** `--auto-findings`, `--param-index`, `--ai-prompts`; or `--full-analysis` to enable all three.

For full CLI options and output structure, see the `burpmd-parser/` folder (install scripts, run scripts, and package source).

---

## Summary

| Item | Extension | CLI |
|------|-----------|-----|
| **What** | Export Burp traffic to sitemap + indexes + findings + prompts. | Parse Burp XML to same corpus. |
| **Install** | Load `Nexus_extension/burpnexus-1.0.0.jar` in Burp. | `pip install .` from `burpmd-parser/`. |
| **Output** | `~/burpnexus_exports/<timestamp>/`. | `-o` directory (default `burp_export`). |
| **Platform** | Windows, macOS, Linux (wherever Burp runs). | Python 3.8+ on Windows, macOS, Linux. |
