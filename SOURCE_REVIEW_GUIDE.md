# BurpNexus Source Review 1.1.0: traffic-to-source security review

Burp captures and exports local evidence. VS Code correlates that evidence with your application repository and prepares security review context. The Java extension has no LLM client, provider selection, model configuration, API-key input or model requests. Its existing deterministic findings, exports, parameter searches and generated test artifacts remain available. The separate Python CLI retains its optional AI commands; those are not part of the Burp JAR.

## Installation and first project

1. In Burp, unload any previous BurpNexus JAR and load `Nexus_extension/burpnexus-1.1.0.jar` through **Extensions → Add → Java**. Confirm that the BurpNexus suite tab appears and review the extension output for load errors.
2. In VS Code, use **Extensions → Install from VSIX** to install `vscode-extension/burpnexus-1.1.0.vsix`. Reload VS Code if prompted. Open your application's source repository. Workspace trust is required; desktop/local workspaces are supported. This release keeps Nuclei and fuzz artifact generation in the Burp JAR.
3. Browse your authorized test application through Burp. Capture relevant authenticated roles, tenant boundaries and multi-step flows. Select the intended traffic in Burp and choose **Export for VS Code**, or select **Full analysis** and **Redact secrets** in the BurpNexus tab. Keep per-request JSON enabled; Markdown-only exports cannot be mapped.
4. Run **BurpNexus: Connect Export to Source Repository** in VS Code. Select the generated export folder, then the application source folder. The two folders may be different. The connection is remembered in VS Code workspace state; credentials and model output are not persisted there.
5. The panel indexes locally. Filter by origin, endpoint text or mapping status. Select an endpoint, inspect its candidate handlers and open the file/line links. Routes without matching captures identify gaps in testing coverage, not necessarily public endpoints.
6. Choose a review focus: authorization/tenant isolation, injection/SSRF/file handling, authentication/session/browser trust, business logic, or comprehensive review. Add intended roles and business rules where useful. Click **Prepare evidence preview**. If global authorization or service logic is missing, use **Add policy / service excerpt** to select an indexed file and relevant line. Up to five additional excerpts can be attached per endpoint; refresh resets them.
7. Inspect the exact prompt, redacted request/response samples, route excerpts, router mounts and related declarations. Excerpts show file names, line numbers, evidence IDs and snapshot hashes. Review personal data and business-sensitive content because redaction cannot recognize every secret.
8. Choose either **Choose model & send preview** or **Save pack for another assistant**. The first uses models exposed by your installed VS Code Language Model API provider; sign-in and availability depend on that provider. The second writes the same prompt to Markdown for your preferred assistant or manual review. Mapping and pack generation require no model account or network access.
9. Read the structured hypotheses. Every accepted finding has known evidence IDs, uncertainty, missing evidence, manual validation steps, remediation and a regression-test proposal. All findings remain **needs-validation**. Existence of a citation does not prove its conclusion. Review suspicious behavior in Burp with controlled accounts and inspect the full source before reporting a confirmed issue.
10. Save the source map or cited review as JSON. Use **Refresh map** after changing source files or adding captures. Source or traffic changes to previewed evidence block sending until refreshed. The extension never executes generated tests, runs repository scripts or applies AI patches.

## Are analysis/testing skills included?

Yes. The VSIX bundles versioned security review playbooks. No separate skill files, Codex skills, prompt marketplace package or knowledge-base installation is required. The six selectable profiles are comprehensive, authorization, input boundaries, authentication/session/browser trust, business logic, and public bug bounty lessons. The original profiles organize ten built-in checks:

| Check | Review area |
| --- | --- |
| AUTHZ-01 | Object ownership and tenant isolation |
| AUTHZ-02 | Function, role and property authorization |
| INPUT-01 | Input to query, template or process boundaries |
| INPUT-02 | Outbound requests and redirects |
| INPUT-03 | File paths, uploads and deserialization |
| SESSION-01 | Authentication and session/token lifecycle |
| SESSION-02 | CSRF, CORS, cookies and browser trust |
| LOGIC-01 | State transitions and server-controlled values |
| LOGIC-02 | Replay, idempotency and concurrency |
| DATA-01 | Sensitive responses, errors and exposure |

Expand **Built-in skill** under Review focus to see the checks. Each contains evidence requirements, source-inspection questions, manual test procedures, expected secure behavior, a regression-test recommendation and common reasons a suspicious pattern may be a false positive. The selected playbook is included in the exact model preview and recorded by ID/version in saved reviews.

**Save manual test plan** creates an endpoint-scoped JSON plan without a model or network access. Checks start as `not-run`, with empty observed results and evidence references for the analyst to fill. Saving or viewing a plan does not execute its procedures. The extension neither loads arbitrary SKILL.md files nor installs/executes external tools. These playbooks guide a general model; they are not a separately trained model or a complete security testing standard.

You supply the application source, Burp capture, intended roles/tenant boundaries and business rules. Test execution also needs controlled accounts, disposable data and an appropriate test environment. AI review requires a model provider exposed in VS Code, or an assistant to which you give the saved pack. Custom team policy can be described in the question and relevant source can be attached using **Add policy / service excerpt**.

The access-control and business-invariant checks are consistent with the review areas in OWASP's [authorization regression guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Regression_Testing_Cheat_Sheet.html) and [business-logic security guidance](https://cheatsheetseries.owasp.org/cheatsheets/Business_Logic_Security_Cheat_Sheet.html). This is a scoped built-in guide, not a claim of full WSTG/ASVS coverage or certification.

## Public bug bounty lessons

Select **Public bug bounty lessons** in Review focus, then expand **Built-in skill**. This profile adds eight separate checks covering sibling endpoint authorization, credential/destination binding, SSRF redirects, duplicate approvals, verified identity fields, rendering after sanitization, frontend path interpolation, and cache-key mismatches. The original five profiles retain their existing scopes.

The packaged [SKILL.md](vscode-extension/skills/public-bounty-review/SKILL.md) is loaded into the selected model context. Its [catalog](vscode-extension/skills/public-bounty-review/references/catalog.json) contains applicability, required evidence, source inspections, manual procedures, expected behavior, regression guidance, false-positive cautions, authors, and source URLs. Seven sources are public GitLab mirrors of HackerOne reports; the eighth is a primary PortSwigger research article. Direct HackerOne pages required JavaScript during research, so their full content was not independently read; the readable vendor mirrors are the cited sources. No private reports or attachments were used. Summaries and generalized guidance are original paraphrases, not copied report bodies or payload collections.

The source review date is **2026-09-18**, and the skill version is **1.0.0**. This is a small, GitLab-heavy historical selection, not an exhaustive dataset, current-vulnerability feed, trained model, or claim of improved detection accuracy. Local packaged guidance is loaded without network access. Clicking a disclosure source opens its known HTTPS page in your browser; the extension does not read the page or send project evidence to it.

Use **Prepare evidence preview** to inspect the included instructions, lessons, provenance, and application evidence. Both **Choose model & send preview** and **Save pack for another assistant** receive that same context. **Save manual test plan** works offline and preserves the skill and source catalog; checks start as `not-run`. Saved in-panel reviews preserve the skill version and attribution in `scope.backgroundSkill`. Historical IDs such as `H1-582349` cannot be used as application evidence citations. Findings still need captured traffic citations and remain `needs-validation`.

Choose a lesson only when its prerequisites match the application. Attach missing service, policy, browser, or deployment context when available; otherwise record a gap. A report about GitLab does not prove the same weakness in your application. Browser restrictions, legitimate sharing, global policies, and deployment differences can invalidate an apparent match. No test, browser payload, scanner, or repository command executes automatically.

## Example: `GET /api/users/12`

An Express application mounts `users` with `app.use('/api', authenticate, users)`. That router registers `router.get('/users/:id', getUser)`. The mapper combines the mount prefix, HTTP method and route template to produce a candidate link from the capture to the handler. The preview includes the request/response, the router declaration, the application mount and any bounded same-name declarations it finds for `authenticate` and `getUser`.

An authorization review should ask whether the caller can access that user's object and tenant. A 200 response and a handler calling `findById` are insufficient proof of BOLA: a global policy may enforce ownership, and the captured request may be legitimate. The assistant must describe those gaps and a two-account controlled test. The suite helps collect and cite the evidence; you validate the security conclusion.

## Mapping support and honest limits

| Source pattern | Supported static forms |
| --- | --- |
| Express | `app = express()`, `router = express.Router()` or `Router()`, literal `get/post/put/patch/delete/head/options/all`, chained `route('/path').get(...)`, local default/named imports and basic CommonJS exports, literal `use('/prefix', middleware, router)` mounts |
| Flask | `Flask`, `Blueprint`, literal decorator paths, method lists, literal `url_prefix` registration |
| FastAPI | `FastAPI`, `APIRouter`, literal decorator paths, `prefix`, basic local `from ... import ...` aliases and `include_router` mounts |
| Spring MVC | Literal class/method `RequestMapping` and HTTP-specific annotations, path arrays, explicit method arrays; declarations in separate controller classes |
| Next.js | App Router `app/**/route.ts` or `.js`, route groups, exported HTTP method functions/constants, dynamic and catch-all segments |

This is a bounded static route index, not a compiler, complete call graph, taint engine, runtime tracer or autonomous penetration tester. Computed routes, custom frameworks, Java mapping inheritance, composed Spring annotations, Express path arrays, complex module re-exports, Next.js Pages Router and framework/deployment rewrites are not resolved. Related declarations are selected by symbol name and may be unrelated. Unknown router mounts are excluded rather than silently assigned a root prefix. Multiple matching declarations remain ambiguous. Trailing slashes are normalized and route case is matched literally, so framework-specific strict/case settings may need manual review.

The repository is linked to captured origins by your folder selection, not by verified deployment identity. Filter to the intended origin; do not assume all hosts in a Burp export run the selected code. One connection selects one source root; a monorepo can contain several services and create ambiguous matches. Connect a narrower service folder when needed. No automatic test or vulnerability confirmation occurs.

## Reverse-proxy prefixes and source exclusions

For a captured path `/gateway/users/12` routed internally to `/users/12`, configure the exact origin and prefix in VS Code settings:

```json
{
  "burpnexus.pathRewrites": [
    { "origin": "https://app.example.test", "from": "/gateway", "to": "/" }
  ],
  "burpnexus.sourceExcludes": ["private", "legacy/generated", "src/internal-only.js"]
}
```

Rewrites require explicit configuration, apply by longest matching prefix, and appear in the review scope. Exclusion paths are repository-relative literal files/directories, not globs. Default exclusions cover dotfiles, symlinks, dependencies, common build/test/generated directories, secret/credential file names, binary files and unsupported extensions. Git ignore rules are not automatically evaluated; add project-specific exclusions before indexing.

## Resource and privacy boundaries

- Source: at most 4,000 files, 300 KB per file, 20 MB total; only JS/TS/Python/Java source; depth 20; 30,000 directory entries; route patterns/prefixes limited to 1,024 characters; at most 5,000 route declarations, 40,000 lexical tokens per file and 500,000 overall. Token limits can make route coverage partial before the byte/file limits are reached.
- Traffic: at most 5,000 item files, 1 MB per JSON file, 8,192 characters per URL, 50 MB total, 2,000 distinct method/origin/path endpoints; depth 20 and 30,000 entries. Counts and omissions appear in the panel.
- Review: one selected endpoint, up to three distinct status/session sample variants, six route candidates, up to five analyst-selected excerpts and eight same-name related declarations; each excerpt is bounded. Request/response bodies are limited to 2,400 characters and headers to 4,000 per side. An evidence budget of 55,000 characters is enforced before the model's token check. These samples are not an exhaustive comparison of sessions or bodies.
- Requests: explicit preview and model selection, 120-second cancellation deadline, bounded response size. No model request is made while indexing. No telemetry is added. The model provider controls transport, billing and retention.
- Files and model text display as text under a nonce-based CSP. File opening accepts indexed evidence IDs, not arbitrary paths supplied by a model. Saved packs/reports contain the previewed source/traffic and should be handled as project evidence.

## Build and validate

From `Nexus_extension/src`, run `gradlew.bat test jar --no-daemon` (JDK 21; output targets Java 17). On systems with locked build folders, pass `-PoutputDir=<fresh-directory>`.

From `vscode-extension`, run `npm ci`, `npm test`, then `npm run package` (Node 24 used for packaging). The VSIX has no runtime npm dependencies. The Java tests also write `build/release/contract-export`; test it with `node scripts/validate-contract.js ../Nexus_extension/src/build/release/contract-export` from `vscode-extension`.

Provider guidance: [VS Code Language Model API](https://code.visualstudio.com/api/extension-guides/ai/language-model). Static route patterns were checked against the official [Express routing](https://expressjs.com/en/guide/routing/), [FastAPI router](https://fastapi.tiangolo.com/tutorial/bigger-applications/) and [Spring mapping](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-requestmapping.html) documentation. Supported patterns above are narrower than those frameworks' complete capabilities.
