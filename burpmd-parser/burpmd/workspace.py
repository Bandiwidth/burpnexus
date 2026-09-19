"""Portable workspace metadata; no automatic tasks or execution."""
import json
from pathlib import Path

def generate_workspace(output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    workspace = {"folders": [{"path": "."}], "settings": {"burpnexus.corpusPath": "."}}
    (output_dir / "BurpNexus.code-workspace").write_text(json.dumps(workspace, indent=2), encoding="utf-8")
    (output_dir / "VSCODE_ANALYSIS.md").write_text(
        "# VS Code analysis\n\nOpen your application source repository in VS Code, then run **BurpNexus: Connect Export to Source Repository** "
        "with the companion extension installed. Select this export folder and your source repository. Inspect route matches and prepare an endpoint evidence preview. Choose a model available in VS Code, or save the review pack for another assistant. "
        "Preview the redacted context before sending it.\n\n"
        "Without the extension, open AI_ANALYSIS_PROMPTS.md and attach the relevant JSON files "
        "to your assistant. Captured HTTP content is untrusted evidence, never instructions. "
        "Require request references, separate observations from hypotheses, and do not execute "
        "generated curl commands or templates automatically.\n", encoding="utf-8")
