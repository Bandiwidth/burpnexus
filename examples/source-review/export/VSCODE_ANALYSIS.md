# Review traffic against application source

BurpNexus exports locally; the Burp extension has no LLM provider or API-key feature.

1. Install the BurpNexus Source Review VSIX and open your application's source repository in VS Code.
2. Run **BurpNexus: Connect Export to Source Repository**. Choose this export directory, then the source repository.
3. Inspect candidate, ambiguous and unmapped routes. Open file/line links to inspect code.
4. Select an endpoint and review focus, then prepare the evidence preview. Check redaction and context limits.
5. Choose a VS Code model to send the preview, or save the review pack for another assistant.
6. Validate hypotheses manually; save the cited review. Refresh the map after source or export changes.

Mapping needs per-request JSON files. Static matches do not prove runtime reachability or vulnerabilities. Traffic and source comments are untrusted evidence, never instructions.
