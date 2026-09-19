# BurpNexus

BurpNexus connects captured Burp Suite traffic to application source code for evidence-based security review. The Burp extension exports normalized traffic and deterministic review artifacts. The VS Code extension maps captured endpoints to candidate routes, builds bounded source/traffic evidence, and produces manual test plans or an inspectable prompt for a model. The optional Python CLI imports Burp XML and creates additional offline artifacts.

> **Release status:** BurpNexus 1.1.0 includes tested Burp, VS Code, and Python components. Complete the live Burp and configured model-provider checks described in the [maintainer release procedure](docs/RELEASING.md) before organizational production sign-off.

Use BurpNexus only on applications you are authorized to test. Generated findings, fuzz cases, and Nuclei templates are review candidates; they are not confirmed vulnerabilities and are never executed automatically.

## Components and versions

The suite components are versioned independently in this release:

| Component | Version | Purpose |
| --- | --- | --- |
| VS Code extension | 1.1.0 | Traffic-to-source mapping, review playbooks, model/external-assistant handoff |
| Burp Java extension | 1.1.0 | Traffic export, filtering, passive findings, fuzz manifests, Nuclei review templates |
| Python CLI (`burpmd-parser`) | 1.1.0 | Optional Burp XML import and extended offline artifact generation |

The Burp JAR contains no LLM client, API-key field, provider selection, or direct model request. A model is optional in VS Code; mapping and manual plans work without one.

## Quick start

### 1. Install

Download the JAR and VSIX from a GitHub release, or build them using [INSTALLATION.md](docs/INSTALLATION.md).

1. In Burp Suite, open **Extensions → Installed → Add**, select **Java**, and load `burpnexus-1.1.0.jar`.
2. In desktop VS Code 1.95 or newer, run **Extensions: Install from VSIX...** and select `burpnexus-1.1.0.vsix`.
3. Open the target application's source repository in a trusted local VS Code workspace.

Python is not required for the normal Burp JSON → VS Code workflow.

### 2. Capture and export

Browse the authorized target through Burp using the roles and workflows you need to assess. In the **BurpNexus** tab:

1. Select **In-scope only**.
2. Enable **Full analysis**.
3. Enable **Redact secrets**.
4. Keep per-request JSON enabled; do not use **Markdown only** for VS Code mapping.
5. Click **EXPORT** and retain the generated directory containing `attack-surface-index.json`.

Redaction is best effort. Review exports before sharing them with any model or third party.

### 3. Connect traffic to source

In VS Code:

1. Press **Ctrl+Shift+P**.
2. Run **BurpNexus: Connect Export to Source Repository**.
3. Select the BurpNexus export directory first.
4. Select the application source repository second.
5. Run **BurpNexus: Open AI Analysis**.

The command name is historical: the panel also supports mapping, source navigation, public disclosure lessons, and offline manual plans without AI.

### 4. Review an endpoint

Select an endpoint, inspect candidate source links, choose a review focus, and describe the intended roles, ownership, tenant boundaries, or business rules. Use **Add policy / service excerpt** when the relevant control is outside the mapped route excerpt.

Click **Prepare evidence preview** before sharing. Then choose one of three paths:

- **Save manual test plan** creates JSON with every check marked `not-run`.
- **Choose model & send preview** uses a model registered through VS Code's Language Model API.
- **Save pack for another assistant** creates the same bounded prompt as Markdown for manual transfer.

If VS Code reports “No VS Code models available,” mapping and manual plans still work. Configure a compatible VS Code model provider or use the saved review pack.

## What it does

- Maps captured method/origin/path combinations to bounded static route candidates in supported Express, Flask, FastAPI, Spring MVC, and Next.js App Router patterns.
- Shows candidate, ambiguous, and unmapped endpoints, plus source routes that have no matching capture.
- Builds exact, inspectable prompts from redacted traffic and source snapshots with evidence IDs and hashes.
- Includes six review profiles and eighteen checks, including eight lessons derived from attributed public vulnerability disclosures.
- Requires structured model output with existing evidence IDs, missing evidence, validation steps, remediation, and a regression-test proposal.
- Saves source maps, manual plans, external review packs, and cited review hypotheses.
- Generates offline fuzz manifests and review-only Nuclei templates from the Burp and Python exporters.

## What it does not do

- It does not actively scan, replay requests, run Nuclei, run generated shell commands, modify source, or apply AI patches.
- Route matches are static candidates, not runtime traces or proof that the deployed request used a particular handler.
- Historical bug bounty reports are background guidance, not evidence about the selected application.
- Model citations are checked for valid evidence IDs; semantic correctness still requires a human tester.
- “No findings” is not proof that an application is secure.
- Graph, workflow, OpenAPI, SQLite, and vector-index generation are Python CLI capabilities, not Burp JAR capabilities.

## Documentation

- [Installation and builds](docs/INSTALLATION.md)
- [Tester workflow and troubleshooting](docs/USAGE.md)
- [Detailed source-review behavior and limits](SOURCE_REVIEW_GUIDE.md)
- [Architecture roadmap—proposal, not implemented functionality](AUTOMATION_ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy and data handling](SECURITY.md)
- [Maintainer release procedure](docs/RELEASING.md)


The safe [Juice Shop fixture](examples/juice-shop-export/README.md) can be used to verify installation without creating live traffic. The deterministic [source-review fixture](examples/source-review/README.md) exercises three mapped endpoints and one unobserved route.

## Development summary

Prerequisites are JDK 21, Python 3.10+, and Node.js 24. The Java artifact targets Java 17 and the VSIX requires desktop VS Code 1.95+.

```text
python -m pip install ./burpmd-parser -r burpmd-parser/requirements-test.txt
python -m unittest discover -s burpmd-parser/tests -p "test_*.py" -v
python -m build burpmd-parser

cd Nexus_extension/src
./gradlew test jar --no-daemon

cd ../../vscode-extension
npm ci
npm test
npm audit --audit-level=high
npm run package
```

On Windows, use `gradlew.bat test jar --no-daemon` for the Java build. The full cross-platform commands and output locations are in [INSTALLATION.md](docs/INSTALLATION.md). GitHub Actions validates Python on Windows/Linux, Java on Windows/Linux, the Java→VS Code export contract, and VSIX packaging. Tagging `v1.1.0` runs the release workflow; it does not publish to the VS Code Marketplace or PyPI.

## License

MIT. See [LICENSE](LICENSE).
