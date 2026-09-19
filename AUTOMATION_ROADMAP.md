> Historical proposal. The current source-review implementation and its actual limits are documented in SOURCE_REVIEW_GUIDE.md. Remaining roadmap items are not implied to be implemented.

# BurpNexus: proposed automation design

Status: architecture proposal, not implemented functionality. Based on the reviewed 1.1.0 source. This document does not change the current release or its production-readiness assessment.

## Desired tester experience

Create an engagement once: name the application, choose scope, label test identities/tenants, record important ownership rules, and choose an AI provider and operating mode. Browse the application. BurpNexus records evidence, updates the endpoint inventory, runs local checks, and prepares a prioritized test queue. The tester can inspect a candidate, send it to Repeater, run a configured test plan, and generate a report with supporting evidence.

Use three clear operating modes:

- Observe: collect in-scope traffic and run local analysis. BurpNexus sends no additional application requests.
- AI review: analyze redacted evidence using the selected provider under a saved data/cost policy. The model can request additional evidence through constrained read-only selectors.
- Validate: execute a selected, reviewable test plan through Burp under its configured scope, identities, endpoint restrictions, rate, request-count and runtime limits.

A saved authorization applies to the selected job and its defined boundaries; it should not prompt on every request. Changing targets, identities, test categories or limits creates a new plan revision. Read-only collection can remain automatic. An HTTP method such as GET is not sufficient to classify an operation as harmless.

## Current gaps that drive the design

| Current behavior | Practical consequence | Proposed change |
|---|---|---|
| Timestamped export folders are the main unit of work | Repeated setup, manual folder selection, disconnected results | Persistent engagement and stable evidence IDs; exports become optional views |
| Collector reads Proxy History and Site Map snapshots | Repeated whole-history work; Repeater experiments are not a complete input source | Historical import plus event-driven capture with source attribution and an explicit results path |
| Main export, quick presets and search actions construct different configurations | Redaction/filter expectations can vary by entry point | One project policy applied to every action; presets control presentation, not privacy/scope |
| VS Code samples up to 50 traffic items; CLI uses a bounded initial sample | Later endpoints, roles and response variants may never receive AI review | Coverage-aware queue, grouped batches and targeted context retrieval |
| Session tags are derived from credentials | Token rotation and multiple accounts do not reliably establish identity/tenant/ownership | Named identity profiles linked to locally held credentials and confirmed test objects |
| Graph/state modules infer links from capture order and values | Sequence and shared values can be mistaken for causal business rules | Recorded journeys and explicit invariants, with inference marked as tentative |
| Findings and generated mutations are files | No durable disposition, evidence linkage, validation state or retest history | Structured finding/test lifecycle and report generation |
| Java and Python contain parallel analysis logic | Fixes and semantics can diverge | Versioned contracts, common fixtures and gradual consolidation of rule ownership |
| Corpus is retained in memory | Large captures can exhaust memory even with SQLite-only output | Bounded ingestion queue, disk-backed evidence and incremental analysis |

## Project model and ownership

Persist the following concepts with versioned schemas:

- Engagement: scope, exclusions, provider/data policy, test limits, retention and schema version.
- Identity: account label, role, tenant, session state and a reference to credential storage; no raw credentials in shared manifests.
- Evidence: immutable capture ID, origin, timestamp/source, exact captured bytes where available, content hash and links to decoded/redacted representations.
- Endpoint: origin + method + route/operation signature, parameter locations/types, observed identities and distinct response variants. Preserve original URLs; inferred route grouping must be reversible.
- Journey: explicitly recorded steps, actor, inputs/outputs and expected business invariants. Concurrent browsing tabs must not silently become one causal sequence.
- Analysis job: selected evidence IDs, detector/model version, limits, progress, retries, cancellation and checkpoint.
- Candidate/test: evidence references, hypothesis, required identities/objects, expected outcome, planned mutations and execution limits.
- Finding: observation, severity, confidence, disposition, validation evidence, remediation and retest history.

The evidence store has one writer per engagement. Burp owns live capture writes; an offline importer owns its import session. Other components read or submit work through a defined interface. Publish committed manifests atomically and version all contracts. Analysis metadata must be independently reproducible from preserved evidence.

Keep the native Burp JAR usable without Python. Python remains an optional offline import and advanced-analysis adapter. The VS Code extension is a review surface and provider adapter. Both Burp and VS Code should reference the same engagement and evidence IDs.

## Proposed implementation slices

### A. Consistent policy and one-click review

Add a single engagement form and a prominent Analyze action. Persist nonsecret preferences. Apply the same scope/redaction policy to the main export, quick presets, searches and AI context generation.

After a successful export, open the exact VS Code workspace and select its analysis context. The handoff should carry a validated project identifier/path, not a shell command. Workspace trust remains required. Opening a folder alone must not execute tests or send traffic to an AI provider. A saved opt-in policy can allow subsequent AI jobs within its stated bounds.

Expose a findings view with source links and saved AI results. Move output formats and optional artifacts into advanced/export controls. Generate fuzz/Nuclei artifacts on demand for selected candidates instead of making every analysis produce every possible file.

Acceptance: a newly captured fixture reaches a redacted VS Code preview in one action; all entry points honor project policy; failed exports do not open partial results; no provider request occurs before the configured send policy is satisfied; paths containing spaces and shell characters work correctly.

Likely touchpoints: `NexusTab.java`, `NexusProfiles.java`, `NexusContextMenu.java`, `ExportConfig.java`, `NexusEngine.java`, `WorkspaceExport.java`, `vscode-extension/src/extension.js`.

### B. Durable evidence and incremental capture

Import existing history once, then add in-scope exchanges through a lightweight capture adapter. The callback enqueues work; parsing, persistence and analysis run off the UI/capture thread. Source attribution must identify ordinary browser traffic, Repeater experiments and BurpNexus-generated validation traffic so it does not trigger recursive test generation.

Use a bounded queue with visible overload behavior. Store large bodies separately, retain capture timestamps, and record truncation/omission explicitly. Decode content under compressed/decompressed size limits while preserving originals. Keep separate records for repeated observations even when payload bytes share storage.

Only process new or changed endpoint/identity/response variants. Resume interrupted jobs, support pause/cancel and avoid reanalyzing unchanged data. Keep human Markdown/JSON exports available for portability.

Acceptance: restart recovers committed evidence and pending jobs; duplicate event delivery does not create duplicate work; repeated observations remain distinguishable; overload and oversized bodies are visible; measured latency/memory stay within declared benchmark budgets.

Likely touchpoints: `NexusCollector.java`, `NexusEngine.java`, `NexusItem.java`, `parser.py`, `writer.py`, `sqlite_exporter.py`; new project/schema/queue modules.

### C. Identity and ownership-aware testing

Let the tester label Alice, Bob, administrator and unauthenticated contexts, including their tenants. Link rotating tokens to stable identities only through confirmed mappings. Provide a session-health baseline; expired logins pause affected jobs instead of creating false authorization findings.

Record known ownership examples: Alice owns order 1001; Bob owns order 1002. Infer candidate links from traffic, but ask for confirmation where policy is unknown. Store credentials locally in an appropriate secret store or Burp session context and reference them by identity ID.

Generate object, property, function and tenant authorization test matrices using observed requests. Include legitimate baselines as well as forbidden combinations. Do not mark a difference in response size/status as proof. Compare meaningful fields and effects against explicit expected access, accounting for login redirects and dynamic response values.

Acceptance: controlled fixtures correctly distinguish own-object access, cross-user disclosure, cross-tenant disclosure, forbidden function access, session expiry and a 200-status login page. Each conclusion links the baseline and variant evidence.

This priority aligns with OWASP's treatment of [object, property and function authorization](https://api-security.owasp.org/editions/2023/en/0x11-t10/). Business rules still need application-specific input.

### D. Coverage-aware AI orchestration

Replace initial-item sampling with a work queue. Group by origin, endpoint/operation, identity/tenant, journey and response variant. Run deterministic checks locally first. Select representative evidence, retain failure/authorization transitions, and request more context only when needed.

Use structured model results: observation, category, confidence, evidence IDs, missing evidence and proposed validation. Validate the shape and reject nonexistent citations. Models cannot directly execute shell commands or expand scope. Read-only context selectors must validate project IDs and evidence IDs before retrieval.

Record model/prompt version, token usage, latency and job result. Cache by evidence and analysis version. Apply budgets, bounded retries/backoff and cancellation. Report coverage as separate counts for captured, indexed, rule-checked, AI-reviewed and actively validated evidence; none imply complete application coverage.

Start with structured database/text retrieval. Semantic embeddings are optional; the current ChromaDB advisory decision must be resolved independently before making them a production default.

Acceptance: a significant fixture placed after item 500 is selected and cited; absent/oversized/omitted evidence is disclosed; bogus citations cannot become validated findings; provider failure resumes without losing completed work; repeated unchanged runs reuse results.

Likely touchpoints: `vscode-extension/src/corpus.js`, `vscode-extension/src/extension.js`, `LLMClient.java`, `llm_agent.py`, `vectordb.py`; new scheduler/coverage/result-schema modules.

### E. Controlled validation and finding lifecycle

The first useful action is Send baseline and variant to Repeater. A later execution engine runs selected test plans through Burp APIs with coherent identity handling and preserved evidence. Avoid using generated shell commands as the internal execution format.

Each job specifies target origins, endpoints, identity IDs, permitted mutation classes, request and time budgets, concurrency, redirects and stop conditions. Scope is checked at dispatch and on redirects. Session failure, rate limiting or unexpected state transitions can pause the job. A global stop must cancel queued work and stop new dispatches.

Use distinct dispositions: observed, candidate, needs validation, validated, rejected, inconclusive, fixed and regressed. A validated finding requires the relevant assertion to pass against captured execution evidence; AI wording cannot promote it.

Record why a candidate was rejected or left inconclusive. Repeated scans should preserve those decisions when the underlying evidence and detector version have not changed. Retests update history instead of overwriting the original finding.

Acceptance: no off-scope or out-of-plan request is sent; cancellation prevents new dispatches; expired sessions and failed baselines prevent confirmation; replay preserves target/method/body semantics; fixture findings can be reproduced and retested.

Likely touchpoints: `ActiveArtifacts.java`, `fuzzer.py`, `nuclei_gen.py`, new Montoya replay adapter and finding/test store. Nuclei stays an optional external adapter.

### F. Journeys, modern protocols and reporting

Add recorded journeys and tester-defined invariants: an unpaid order cannot become fulfilled; a revoked session cannot access protected resources; a customer cannot modify a protected account property. Use observed dependencies to populate test inputs. Sequence alone is insufficient to establish a valid workflow.

Add protocol adapters incrementally: GraphQL operation/variable awareness, multipart/file uploads and WebSocket evidence. Each adapter needs capture and comparison tests; do not list an entire protocol as supported because its handshake or raw text can be exported.

Generate a report from the evidence/finding store: scope, tested identities, coverage limitations, confirmed findings, unresolved hypotheses, baseline/variant evidence, remediation and retest results. Map applicable tests to a pinned [OWASP WSTG](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/02-Test_Ability_to_Forge_Requests/) version; a mapping is not a claim of complete coverage.

Support recorded browser journeys later to repeat already-understood application flows. Scope, session refresh and sensitive operations must be explicit; exploratory browsing and business-policy discovery remain separate from replaying an established test.

## Redaction that preserves analysis value

Maintain raw evidence locally under project access controls, a normalized analysis representation, and a separately redacted AI/export representation. Preserve identifier relationships with stable engagement-specific aliases where appropriate. Do not replace every actor/object with the same placeholder.

Ensure local detectors that require token/secret information can run before redaction without putting the secret itself into a finding. Only redacted evidence may cross the AI boundary. Keep keys and aliasing secrets out of shared manifests and logs. Provider context previews and audit records should identify what was sent.

Treat captured responses and model output as untrusted content. Keep VS Code [Workspace Trust](https://code.visualstudio.com/api/extension-guides/workspace-trust), constrained filesystem access and [webview CSP/text rendering](https://code.visualstudio.com/api/extension-guides/webview). A local command bridge, if later needed, requires authenticated pairing and validated operations; loopback binding alone does not authenticate callers.

## Release order and success criteria

1. Consistent project policy, one-click handoff, persistent review results and honest coverage display.
2. Durable incremental evidence, checkpointed analysis, batching and named identities.
3. Ownership-aware matrices, Repeater handoff and controlled validation.
4. Journey assertions, protocol adapters, optional recorded browser replay and deeper reporting.

Each release needs real Burp and VS Code host checks in addition to unit tests. Use a controlled test app with both vulnerable and correctly protected variants to measure false positives/negatives. Include session rotation, 200-status login pages, redirects, missing capture bodies, mixed tenants, dynamic content, prompt injection, interrupted jobs and large captures.

Track time from capture to an actionable candidate, tester actions per review, evidence citation validity, false-confirmation rate, identity/endpoint coverage, token cost per reviewed group, incremental reanalysis cost, capture overhead and cancellation behavior. Publish measured results; do not promise a universal automation percentage.
