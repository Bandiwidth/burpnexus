# BurpMD parser

Requires Python 3.10+. Install with `python -m pip install .`.

```sh
burpmd capture.xml -o export --sitemap --full-analysis --redact-secrets --vscode
```

Open `export/BurpNexus.code-workspace` in VS Code. Install the companion
extension in `vscode-extension/` for a dedicated analysis panel using a model
available through VS Code's Language Model API.

Export, static analysis, fuzz manifests and Nuclei templates are local and passive.
Generated tests require review; a candidate is not a confirmed vulnerability.
Direct cloud analysis is explicit: `--ask-llm "question" --llm-provider openai
--llm-model MODEL_ID`. Keys come from the selected provider's environment variable.
AI context is redacted and bounded. Review it for business-specific sensitive data.

`--sqlite-only` avoids per-request files. Parsing uses incremental XML reads, but
the normalized corpus and analysis remain in memory; this is not a constant-memory
pipeline. Split very large captures. `--import-format` currently supports Burp XML
only; incomplete ZAP/Caido importers were not reliable enough to expose.

Optional RAG: install `.[rag]`, then use `--build-vector-db` and `--rag-query`.
Embeddings run locally (the embedding model may download on first use); RAG sends
the selected, redacted context to the chosen provider only when requested. ChromaDB 1.5.9 has published security advisories; the adapter forces embedded execution and a concrete ONNX embedding function. Use only indexes created locally by this tool. Optional RAG requires a separate dependency risk review before production approval.

Use a new or empty output directory for each export. Existing indexes can be queried without supplying XML: `burpmd -o indexed-export --rag-query "review" --llm-model MODEL_ID`.

Tests: install `requirements-test.txt`, then run `python -m unittest discover -s tests -p "test_*.py" -v`. The optional real-embedding check is `tests/integration_rag.py --work-dir PATH` (requires the RAG extra).

See the repository review report for the release validation boundary. The legacy `burpmd_extension.py` Jython bridge is retained for compatibility investigation but is not a supported release path.
