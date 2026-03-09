# BurpNexus

**Self-contained security corpus exporter for AI-assisted analysis.**  
No Python, no CLI, no network calls. Runs entirely inside Burp Suite and writes to your local disk.

---

## What it does

BurpNexus exports your Burp Proxy History and Site Map traffic into a **sitemap-style directory** with:

- **Per-request JSON** (and optional Markdown) — one file per request/response pair
- **attack-surface-index.json** — endpoint summary, methods, status codes, auth headers
- **param-index.json** — all parameters (query, body, JSON, cookies, headers)
- **SECURITY_FINDINGS.md** + **security-findings.json** — automated pattern-based findings
- **AI_ANALYSIS_PROMPTS.md** — ready-to-paste prompts for VS Code Copilot or any AI assistant
- **README.md** — export summary and stats

This output can be used as the **Burp corpus** in a security audit pipeline (e.g. source code + Burp export + AI analysis in VS Code/Copilot). Use your internal documentation for end-to-end workflow steps.

---

## Requirements

- **Burp Suite** Professional or Community (any recent version that supports Montoya extensions)
- **No Python** — no CLI or external tools
- **No network** — extension never makes outbound calls; safe for air-gapped / locked-down environments
- **No Burp AI** — works with Burp AI disabled

---

## Installation

1. Build the JAR (see [Build](#build-for-developers) below), or obtain `burpnexus-1.0.0.jar`.
2. In Burp: **Extensions** → **Add** → **Extension type: Java** → **Select file** → choose the JAR.
3. Click **Next**. The **BurpNexus** tab and right-click menu appear.

Only the single JAR is required; no need to copy the whole project folder.

---

## Where output is saved

Each export is written to a **timestamped subfolder** under your user home:

| OS      | Base folder |
|--------|-------------|
| Windows | `C:\Users\<YourUsername>\burpnexus_exports\` |
| macOS   | `/Users/<YourUsername>/burpnexus_exports/` |
| Linux   | `/home/<YourUsername>/burpnexus_exports/` |

Example:

```
burpnexus_exports/
├── export_20260303_142301/          ← full project export
│   ├── README.md
│   ├── attack-surface-index.json
│   ├── param-index.json
│   ├── SECURITY_FINDINGS.md
│   ├── security-findings.json
│   ├── AI_ANALYSIS_PROMPTS.md
│   └── example.com/
│       └── api/
│           └── 0001_GET_users.json
├── param_search_token_any_20260303_143000/   ← parameter search export
└── regex_search_eyJ_20260303_144500/         ← regex content search export
```

---

## Using the extension

### Main EXPORT button

1. Set **Output mode** (e.g. Sitemap), **Scope** (All traffic / In-scope only), **Options** (Deduplicate, Include Markdown, Redact secrets, Full analysis, etc.).
2. Optionally set **Time range** (From / To) and **Filters** (Tools, Status).
3. Click the green **EXPORT** button at the bottom.  
   Export runs in the background; status appears in the status bar.  
   Only one export runs at a time (button is disabled until it finishes).

### Time range (From / To)

- **Format:**  
  - `yyyy-MM-dd HH:mm` or `yyyy-MM-dd HH:mm:ss` (e.g. `2026-03-02 10:00`)  
  - `yyyy-MM-dd` (whole day in local timezone)  
  - Full ISO-8601 (e.g. `2026-03-03T12:30:00Z` or `2026-03-03T12:30:00+05:30`)
- Leave **From** or **To** empty for no lower or upper limit.
- Uses the request time from Proxy History (Site Map–only items without a time are still included when a range is set).

### Quick export presets

Use the preset buttons (e.g. **Export: Full AI Analysis**, **Export: JSON Only**, **Export: Triage (401,403,5xx)**) for one-click exports with fixed settings. Scope (All traffic / In-scope only) still comes from the radio buttons.

### Parameter search & regex search

- **Parameter search:** Fill **Name** and/or **Value**, choose Contains/Exact and JSON or MD, then **Search & Export**. Exports only items that match the parameter (query, body, JSON, cookies, headers, path).
- **Regex content search:** Enter a **Pattern** (Java regex), choose Request / Response / Both and format, then **Search & Export**. Exports only items whose request or response body/headers match the pattern.

### Right-click (context menu)

- **With items selected:** Menu shows “BurpNexus: Export (host1, host2, …)”. Submenus run exports for **those hosts only** (all traffic for those hosts from Proxy + Site Map), with different presets (AI Analysis, JSON only, Triage, Redacted, etc.).
- **With nothing selected:** “BurpNexus: Export Entire Project” and submenus export the full project with the chosen preset.

---

## Use case: audit pipeline

Use BurpNexus export as the **Burp corpus** in your audit workflow:

1. **Export** — In Burp, capture traffic, open the BurpNexus tab, choose Sitemap + Full analysis, click **EXPORT**.
2. **Copy** — Copy the timestamped folder from `~/burpnexus_exports/` into your workspace (e.g. `burpexplore/`).
3. **Sanitize** — If you didn’t use **Redact secrets**, run Scrubber (or your preferred tool) on source code and replace secrets in the export with placeholders before AI or sharing.
4. **Analyze** — Use the export with your preferred pipeline (e.g. VS Code + Copilot, or internal how-to). The structure (sitemap tree, `attack-surface-index.json`, `param-index.json`, `SECURITY_FINDINGS`, `AI_ANALYSIS_PROMPTS`) is suitable for automated or AI-assisted analysis.

---

## Privacy and connectivity

- **No network calls** — the extension does not open sockets, HTTP connections, or any outbound traffic.
- **No telemetry** — nothing is sent to any server.
- **Static and local** — all processing is in-process; output is only written to `~/burpnexus_exports/` on the machine where Burp runs.
- **Air-gapped / locked-down** — safe to use in environments where Burp AI or internet is disabled; only the JAR and Burp Suite are required.

---

## Build (for developers)

```bash
./gradlew jar
```

JAR output: `build/libs/burpnexus-1.0.0.jar`

Requires **Java 17+**. The Montoya API is a compile-only dependency (provided by Burp at runtime).

---

## Optional: CLI

If you use a **CLI** (e.g. Python parser) to generate the same sitemap-style corpus from Burp XML exports, BurpNexus output is compatible. Schema differences between extension and CLI output are documented in your audit pipeline or toolkit docs. Use BurpNexus when you want no Python and no external tools.

---

## Summary

| Item | Detail |
|------|--------|
| **What** | Export Burp traffic to sitemap + index + findings + AI prompts. |
| **Install** | Load `burpnexus-1.0.0.jar` in Burp Extensions. |
| **Output** | `~/burpnexus_exports/<export_YYYYMMDD_HHMMSS>/` (or param/regex subfolders). |
| **Use case** | Use export as Burp corpus in your audit pipeline (source code + burpexplore + AI/tooling). |
| **Network** | None. |
| **Platform** | Windows, macOS, Linux (wherever Burp runs). |
