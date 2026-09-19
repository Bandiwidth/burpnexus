# BurpNexus 1.1.0 validation report

Date: 2026-09-18. This is the GitHub release candidate that follows the public 1.0.0 baseline. The Burp JAR, VS Code extension, and Python CLI are aligned at 1.1.0. Status: locally tested release candidate; live Burp and real model-provider checks remain deployment gates.

## Delivered

- Burp extension 1.1.0 with deterministic traffic export, passive review artifacts, fuzz manifests, and review-only Nuclei templates. Direct LLM/provider/API-key functionality is absent from the Burp extension.
- VS Code extension 1.1.0 with traffic-to-source mapping, bounded evidence previews, offline plans, external-assistant packs, optional VS Code Language Model API integration, and six review profiles.
- Packaged **Public bug bounty lessons** profile with eight attributed checks. Historical references are background guidance and cannot be accepted as application evidence.
- Python CLI 1.1.0 for optional Burp XML import and extended offline artifact generation.
- GitHub-ready repository metadata: MIT license, contribution and security policies, issue and pull-request templates, Dependabot, cross-platform CI, and a tag-controlled release workflow.

## Public disclosure provenance

The packaged catalog references seven public HackerOne reports through readable public GitLab mirrors and one primary PortSwigger research article. The catalog stores original paraphrases, applicability requirements, manual validation procedures, expected secure behavior, regression guidance, and false-positive cautions. It does not bundle exploit payload collections, fetch reports during review, train a model, or assert a vulnerability in the selected application.

## Validation

| Check | Result |
| --- | --- |
| Java 21 regression suite | 25 passed, no failures or skips |
| Python 3.12 regression suite | 34 passed; installed environment has no broken requirements |
| Python distributions | Wheel and source distribution built for 1.1.0 |
| Node 24 regression suite | 51 passed, no failures or skips |
| npm clean install and audit | Exact lockfile installed in an isolated nonsynchronized directory; 0 vulnerabilities at the high threshold |
| Java→VS Code export contract | Passed: 3 captures, 3 candidate mappings, 0 ambiguous/unmapped, 1 unobserved source route |
| GitHub metadata audit | Workflow YAML, relative documentation links, versions, artifact names, and tag guard verified |
| VSIX packaging | Packaged resources inspected; no runtime npm dependencies or build cache included |
| Isolated VSIX installation | Passed; 14 installed extension files match the package after removing VS Code's added manifest metadata |
| Real VS Code extension host | The same extension runtime previously activated and registered all four commands. The final 1.1.0 repeat was blocked before extension startup because the installed VS Code updater held its global `vscode-updating` mutex for the full launcher wait. |
| Live Burp load/export/unload | Not performed in this environment |
| Real model provider | Not performed; model lifecycle tests use a controlled fake provider |

The 1.1.0 VSIX installed successfully, contains 16 archive entries, and includes no npm cache or runtime dependencies. The updater-mutex failure occurred before the extension host started and is recorded as an environment-blocked repeat rather than an extension failure or a new host pass. Local validation uses isolated caches under `.validation`; these are excluded from source archives and Git.

## Limits

Route matches are static candidates rather than runtime traces. Redaction is best effort. Generated Nuclei templates, fuzz cases, manual plans, and model findings are never automatically executed and do not establish vulnerabilities. Model evidence IDs are checked for existence, but semantic correctness and business policy still require a human tester. “No findings” is not proof that an application is secure.

Before production sign-off, load the exact JAR in the intended Burp version, exercise an in-scope redacted export, unload/reload it, install the exact VSIX, and assess the organization's intended model-provider workflow.

## Artifact verification

```text
d0ee19db4d54840c4b72e531bdce408b4470312c39ec4e5fbac9538b34a497fa  Nexus_extension/burpnexus-1.1.0.jar
6ebd000606366495e2113155cac197cb8a7d9baeb032e398365a207df03978f5  vscode-extension/burpnexus-1.1.0.vsix
```

The source archive contains 124 files and includes the GitHub metadata, JAR, and VSIX. Its integrity check passes, and it excludes Git metadata, validation environments, dependency caches, and build directories. The archive checksum is retained in `.validation/archive.json` outside the distributable source archive so recording it cannot change the archive's own hash.
