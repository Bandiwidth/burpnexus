---
name: public-bounty-review
description: Review captured web application requests and related source using lessons from public vulnerability disclosures. Use for source-assisted pentesting, hypothesis development, and manual validation plans; it does not execute tests or establish findings from historical similarity.
---

# Public bug bounty review

Use the supplied application's HTTP evidence, source excerpts, and intended policy to investigate relevant patterns in [the curated catalog](references/catalog.json). The catalog contains original paraphrases of seven HackerOne reports available through GitLab's public issue tracker and one researcher-authored PortSwigger case study. Report URLs are provenance, not authorization to test those services. This is a small, GitLab-heavy historical selection, not a representative benchmark or a continuously updated feed.

## Apply a lesson

Select checks by the observed behavior and trust boundary, not by a product name or an isolated keyword. The catalog's applicability, required evidence, and cautions determine whether a check is relevant. A URL parameter alone is insufficient for SSRF; an object identifier alone is insufficient for broken authorization.

For each relevant check, connect the application's controllable input, principal, transformation, security decision, and observable result. Distinguish the historical report's observation from the catalog's generalized testing advice and from facts observed in this application. Report sources and lesson IDs must never substitute for the application's traffic/source evidence IDs.

Look for the control that would disprove the hypothesis: global policies, tenant filters, verified identity records, redirect checks, database constraints, output encoding, browser isolation, and cache configuration. Missing excerpts are evidence gaps; request the specific service, middleware, rendering, or deployment context instead of assuming the control is absent.

Follow transformations after the apparent check. Examples include a URL after a redirect, HTML after post-processing, an identifier after browser URL normalization, and identity fields after another field changes. For multi-step chains, state and validate each dependency separately. Do not transfer a report's severity or account-takeover claim to another deployment.

## Plan validation

Provide a legitimate baseline, the smallest relevant change, the expected policy, and the observable response or state needed to distinguish a weakness from normal behavior. Use controlled accounts and disposable test objects. Use dummy secrets and controlled destinations for outbound requests. Cache or concurrency checks need an isolated test setup with bounded requests; inability to establish isolation is a gap, not a reason to run broader probes. Do not replay historical payloads against their original hosts.

Record untested procedures as not run. Reflection is not browser execution; response differences are not ownership violations; a successful request is not proof of a persisted state change. A negative result only covers the tested context. Do not claim a target is secure or a vulnerability is confirmed from these snapshots.

## Extension use and output

The VS Code extension packages this file and catalog locally. Selecting **Public bug bounty lessons** loads the instructions, checks, and source attributions into the exact evidence preview, external-assistant pack, and manual plan. No website is fetched during review. The bundled model-review schema still applies: cite supplied application evidence, explain missing evidence, and provide validation, remediation, and regression steps. Findings remain needs-validation. In a standalone assistant, read only relevant catalog entries and follow the user's requested output format.
