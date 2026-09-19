# BurpNexus Source Review 1.1.0

Connect a BurpNexus JSON export to the target application's local source repository. Inspect candidate routes and bounded evidence, then review with a model exposed through VS Code's Language Model API or save the same context for another assistant. Desktop VS Code 1.95+ and workspace trust are required. No model is needed for mapping or manual plans.

## Start

1. Install `burpnexus-1.1.0.vsix` using **Extensions: Install from VSIX**.
2. Open the application repository and run **BurpNexus: Connect Export to Source Repository**.
3. Select the export root containing `attack-surface-index.json`, then the application source folder.
4. Select a captured endpoint and inspect candidate file/line links.
5. Choose a Review focus, add business policy/context, and prepare the exact evidence preview.
6. Choose **Choose model & send preview**, **Save pack for another assistant**, or **Save manual test plan**.

Commands available from **Ctrl+Shift+P**:

| Command | Purpose |
| --- | --- |
| `BurpNexus: Connect Export to Source Repository` | Select a BurpNexus JSON export and application source root |
| `BurpNexus: Open AI Analysis` | Open the source-review panel; offline mapping and plans work without AI |
| `BurpNexus: Refresh Traffic to Source Map` | Reindex the current export and source connection |
| `BurpNexus: Import Burp XML` | Run the separately installed Python CLI, then connect the generated export |

Use the BurpNexus **1.1.0 JAR** to export traffic; its Nuclei templates, fuzz manifests, passive findings, and JSON/Markdown outputs remain available. Burp contains no LLM client. Native JSON exports do not require Python. The optional **Import Burp XML** command needs the separately installed Python parser.

## Included public disclosure skill

Select **Public bug bounty lessons**. Eight checks cover incomplete authorization, webhook credential leakage, redirect-based SSRF, approval races, unverified identity fields, stored XSS, frontend path traversal, and cache-key mismatches. Each has prerequisites, inspection questions, a manual test procedure, expected behavior, regression guidance, and false-positive cautions.

The skill instructions (`skills/public-bounty-review/SKILL.md`) and source catalog (`skills/public-bounty-review/references/catalog.json`) are packaged and loaded locally. Seven historical HackerOne reports were reviewed through public GitLab mirrors and one primary PortSwigger research article; the source review date is 2026-09-18. This is a curated, GitLab-heavy selection, not an exhaustive or automatically refreshed corpus. Expand **Built-in skill** to inspect the lessons and open their attributed sources. No separate skill installation is needed.

The selected skill and catalog are included in the exact AI preview, external review pack, and offline manual plan. Saved model reviews retain source provenance and skill version. Historical reports cannot substitute for your application's evidence. The original five profiles and ten checks remain available separately.

## Limits

Mapping recognizes bounded static route patterns in Express, Flask, FastAPI, Spring MVC, and Next.js App Router. It is not complete program analysis. Review includes a limited number of traffic samples and source excerpts; add relevant policy/service excerpts where needed. Refresh after changing source or exports; choose a new connection for a different export directory.

No active tests or AI patches run automatically. Manual plans start `not-run`; AI findings remain `needs-validation`. Citation IDs are checked for existence, not correctness of the model's interpretation. Inspect redaction and business-sensitive content before sending a preview to a model. The skill does not train a model or establish detection accuracy.

## Development

Run `npm ci`, `npm test`, `npm audit --audit-level=high`, and `npm run package` with Node.js 24. The VSIX has no runtime npm dependencies. The `skills/` directory must be included in the package; activation loads its resources. Repository-wide installation, testing, data-handling, and release instructions are linked from the project README.
