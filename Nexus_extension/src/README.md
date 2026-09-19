# BurpNexus native extension

Build with JDK 21 using `gradlew.bat test jar --no-daemon` on Windows or `./gradlew test jar --no-daemon` elsewhere. The JAR targets Java 17 and bundles Gson; Burp supplies the Montoya API. Output: `build/release/libs/burpnexus-1.1.0.jar`. For an isolated build, pass `-PoutputDir=/path/to/build`.

Load the JAR through Burp **Extensions → Add → Java**. Exports go to unique folders under `~/burpnexus_exports/`. Only one export runs at a time. Unloading the extension interrupts pending export work.

The suite tab supports layout choices, scope, deduplication, Markdown, secret redaction, time/tool/status filters, nested parameter search and regex content search. Context-menu selection exports captured traffic for the selected hosts. Full analysis includes passive findings, parameter indexes, prompts, offline fuzz manifests, Nuclei templates and a VS Code workspace.

Time filters accept ISO timestamps or local `yyyy-MM-dd HH:mm[:ss]`; a date-only upper bound includes that entire day. Unknown capture times stay unknown rather than becoming export time. Check the resulting selection when filtering Site Map-only traffic.

The 1.1.0 Burp extension contains no LLM provider client, API-key UI or direct AI request path. Full analysis remains deterministic local analysis and artifact generation.

Install the companion VSIX and run **BurpNexus: Connect Export to Source Repository** in your application's VS Code workspace. Select the export and source folders, inspect candidate mappings, and prepare a cited review preview. Use a VS Code model or save the pack for another assistant. See the [source-review guide](../../SOURCE_REVIEW_GUIDE.md).

The Java extension does not implement the Python-only graph, workflow, asset, OpenAPI, SQLite or vector-index modules. It does not automatically execute generated curl commands or Nuclei probes. Exported traffic is normalized; it is not an exact binary replay archive. Passive findings and templates require manual assessment.

JUnit regression tests are under `src/test/java/nexus/`. Live Burp load/export/unload checks still need to run in the intended deployment version before production sign-off.
