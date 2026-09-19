# Tester workflow

This guide covers the normal source-assisted workflow. The target must be an application you are authorized to test.

## Prepare the engagement

Use a source revision that corresponds to the deployed application as closely as possible. BurpNexus does not verify deployment identity or Git revision. Prepare controlled test accounts for the roles, owners, and tenants you intend to compare. Document the expected access policy; the extension cannot infer ownership or business authorization reliably from traffic alone.

Recommended working inputs:

- application source repository;
- in-scope Burp traffic containing representative successful and denied workflows;
- controlled accounts and disposable data;
- intended role, ownership, tenant, and state-transition rules;
- optional source locations for central middleware, policy, service, or query controls.

## Capture and export in Burp

1. Configure Burp Proxy for the authorized target and define Burp scope.
2. Exercise relevant workflows with the required test accounts.
3. Keep original authenticated requests in Burp for later Repeater validation.
4. Open the **BurpNexus** tab.
5. Select **In-scope only**, **Full analysis**, and **Redact secrets**.
6. Keep per-request JSON enabled. **Markdown only** cannot be mapped in VS Code.
7. Click **EXPORT**.

The quick VS Code presets do not force redaction, so use the explicit tab settings when the export may contain sensitive data. Context-menu exports select traffic by the selected hosts; they are not guaranteed to contain only individually highlighted messages.

Full analysis creates offline artifacts including passive findings, parameter indexes, fuzz manifests, Nuclei review templates, prompts, and a VS Code workspace. It does not run the generated probes.

## Connect the export to source

1. Open the application source repository in desktop VS Code.
2. Run **BurpNexus: Connect Export to Source Repository**.
3. Choose the export root containing `attack-surface-index.json`.
4. Choose the source repository root.
5. Wait for local indexing to finish.
6. Run **BurpNexus: Open AI Analysis** to reopen the panel later.

The folders may be separate. Connection paths are stored in VS Code workspace state. Mapping does not send data to a model.

## Interpret the map

| State | Meaning |
| --- | --- |
| Candidate | One plausible method/path route match was found |
| Ambiguous | Multiple route declarations may match |
| Unmapped | No supported static route pattern matched |
| Route without captured traffic | Source route was indexed but no capture matched it |

A candidate is not a runtime trace. Dynamic routes, complex imports, custom frameworks, middleware outside the excerpt, reverse-proxy rewrites, and source/deployment drift may change the conclusion.

Use `burpnexus.pathRewrites` for known reverse-proxy prefixes. Example VS Code workspace setting:

```json
{
  "burpnexus.pathRewrites": [
    {
      "origin": "https://staging.example.test",
      "from": "/gateway",
      "to": "/"
    }
  ]
}
```

The origin match includes scheme, host, and port. The longest matching prefix is applied. Source exclusions use repository-relative literal paths, not glob syntax:

```json
{
  "burpnexus.sourceExcludes": ["generated", "legacy/private"]
}
```

## Review an endpoint

1. Filter by captured origin or endpoint text.
2. Select an endpoint and open candidate source links.
3. Choose a review focus.
4. Enter the intended policy and your concrete question.
5. Add missing policy/service excerpts when needed.
6. Click **Prepare evidence preview**.
7. Inspect every traffic sample and source excerpt before sharing.

Available profiles:

- Full security review
- Authorization / BOLA / tenant isolation
- Injection / SSRF / file handling
- Authentication / sessions / browser trust
- Business logic / replay / state transitions
- Public bug bounty lessons

The public-disclosure profile is a curated historical reference set. It does not fetch reports during review and does not assert that the selected application shares a disclosed vulnerability.

## Choose an analysis path

### Offline manual plan

Click **Save manual test plan**. The JSON includes evidence prerequisites, source questions, manual steps, expected secure behavior, regression guidance, and cautions. Every check begins with:

```json
"status": "not-run"
```

Saving a plan does not execute it.

### VS Code model

Click **Choose model & send preview**. The panel lists only models exposed to third-party extensions through VS Code's Language Model API. A general chat extension can work in VS Code without exposing models through that API.

If the panel reports no available model:

1. Confirm that the intended provider is installed, signed in, and usable in its own chat UI.
2. Reload VS Code with **Developer: Reload Window**.
3. Prepare a new preview.
4. If no model is exposed, use the external-assistant pack.

BurpNexus has no direct provider/API-key field.

### External assistant

Click **Save pack for another assistant**. Review the generated Markdown, then attach or paste it into the approved assistant. The assistant's response is not automatically imported or citation-validated by BurpNexus.

## Validate in Burp

Model output is a hypothesis and remains `needs-validation`. Use original captured requests in Repeater with controlled accounts; redacted export values may no longer authenticate.

For an object-authorization hypothesis:

1. Establish account A's permitted request to an object A owns.
2. Establish account B's permitted request to an object B owns.
3. Keep B's valid authentication and change only the target object to A's controlled object.
4. Inspect response content and resulting state, not only status code or response length.
5. Repeat cross-tenant or role comparisons required by policy.
6. Record the exact baseline, variant, expected policy, observed result, and side effects.

Do not report a confirmed vulnerability solely because a source excerpt lacks a visible check or two responses differ.

## Nuclei and fuzz artifacts

The Burp exporter and Python full-analysis mode can create:

```text
FUZZ_MANIFEST.json
FUZZ_COMMANDS.md
nuclei-templates/
NUCLEI_TEMPLATES.md
```

These are offline candidates. Current Nuclei templates use eligible GET findings, omit captured credentials, and cover only supported categories. Validate syntax and review scope, authentication, matchers, and impact before running them. BurpNexus does not invoke Nuclei.

## Retest

After a code change, repeat both the failing security case and legitimate baseline cases. Capture updated traffic and export it. Use **Change connection** when the new export has a different directory; use **Refresh map** when the connected export/source changed in place. There is no background filesystem watcher.

## Safe fixtures

Use [the Juice Shop fixture](../examples/juice-shop-export/README.md) for a safe UI/import check. It contains three synthetic localhost records and no real credentials. Mapping results depend on the Juice Shop revision. Use [the deterministic source-review fixture](../examples/source-review/README.md) when you need known results: three mapped captures and one unobserved source route.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Commands are missing | Ensure the VSIX is enabled, reload VS Code, and use a trusted local workspace |
| “Choose a BurpNexus export directory” | Select the directory containing `attack-surface-index.json`, not a child endpoint directory |
| No endpoints | Keep per-request JSON enabled and inspect indexing warnings |
| Many unmapped endpoints | Check source root, deployed revision, proxy prefixes, framework support, and dynamic routing |
| No VS Code models | Configure a compatible provider or save an external-assistant pack |
| XML import cannot run | Install `burpmd-parser` and set `burpnexus.pythonPath` to that environment's Python executable |
| Preview became stale | Refresh after source/export changes, then prepare a new preview |
| Important policy file is absent | Check source exclusions and supported JS/TS/Python/Java file limits |

Precise resource limits and supported route syntax are documented in [SOURCE_REVIEW_GUIDE.md](../SOURCE_REVIEW_GUIDE.md).
