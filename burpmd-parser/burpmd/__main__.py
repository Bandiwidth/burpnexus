'''
burpmd.__main__
===============
Command-line interface for BurpMD Parser Pro.

Usage:
  python -m burpmd <file.xml> [file2.xml ...] -o <output_dir>
  burpmd <file.xml> -o <output_dir> --sitemap
  burpmd <file.xml> -o <output_dir> --by-host --md
'''

import argparse
import hashlib
import re
import sys
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qsl, urlparse

from . import __version__
from .analyzer import generate_ai_prompts, generate_param_index, generate_security_findings
from .formatter import MarkdownFormatter
from .parser import BurpXMLParser
from .writer import BurpMDWriter


def main():
    """Main CLI entry point."""
    parser = create_arg_parser()
    args = parser.parse_args()

    if args.version:
        print(f"BurpMD Parser Pro v{__version__}")
        sys.exit(0)

    if args.rag_query and not args.input_files:
        try:
            from .vectordb import run_rag_query
            run_rag_query(args.rag_query, Path(args.output_dir), provider=args.llm_provider, model=args.llm_model, verbose=args.verbose)
            return
        except Exception as exc:
            parser.exit(1, f"[!] RAG query failed: {exc}\n")

    if not args.input_files:
        parser.print_help()
        print("\n[!] Error: At least one input XML file is required.", file=sys.stderr)
        sys.exit(1)

    # --- Validate mutual exclusivity ---
    selected_modes = [args.by_host, args.sitemap, args.host_first, args.split_by_session]
    if sum(1 for mode in selected_modes if mode) > 1:
        print("[!] Error: output mode flags are mutually exclusive.", file=sys.stderr)
        print("    Use only one of: --by-host, --sitemap, --host-first, --split-by-session", file=sys.stderr)
        sys.exit(1)

    # --- Setup ---
    parser_engine = BurpXMLParser(verbose=args.verbose)
    formatter = MarkdownFormatter(
        include_raw_request=not args.no_raw_request,
        include_raw_response=not args.no_raw_response,
        max_body_chars=args.max_body_chars,
    )
    md_only = getattr(args, "md_only", False)
    writer = BurpMDWriter(
        output_dir=args.output_dir,
        by_host=args.by_host,
        sitemap=args.sitemap,
        host_first=args.host_first,
        split_by_session=args.split_by_session,
        include_md=args.md or md_only,
        include_json=not md_only,
        formatter=formatter,
        verbose=args.verbose,
    )

    if args.verbose:
        print(f"--- BurpMD Parser Pro v{__version__} ---")

    # --- Execution ---
    try:
        # Validate all input files exist before starting
        missing = [f for f in args.input_files if not Path(f).exists()]
        if missing:
            for m in missing:
                print(f"[!] Error: File not found: {m}", file=sys.stderr)
            sys.exit(1)

        import_format = getattr(args, "import_format", "burp")

        if getattr(args, "diff", False):
            if len(args.input_files) != 2:
                print("[!] Error: --diff requires exactly two input XML files.", file=sys.stderr)
                sys.exit(1)
            if args.verbose:
                print("[*] Parsing baseline export...")
            export1 = parser_engine.parse_file(args.input_files[0], import_format=import_format)
            if args.verbose:
                print("[*] Parsing comparison export...")
            export2 = parser_engine.parse_file(args.input_files[1], import_format=import_format)
            from .diff import generate_diff_report
            out_path = Path(args.output_dir)
            generate_diff_report(export1, export2, out_path, verbose=args.verbose)
            sys.exit(0)

        out = Path(args.output_dir)
        if out.exists() and any(out.iterdir()):
            raise ValueError("Output directory is not empty; choose a new directory to avoid stale or mixed captures")

        # Parse all files
        if args.verbose:
            print(f"[*] Parsing {len(args.input_files)} XML file(s) in input order...")

        # Preserve capture order and propagate failures. Process pools copied whole
        # corpora and completion order corrupted workflow inference.
        exports = [parser_engine.parse_file(p, import_format) for p in args.input_files]

        if not exports:
            print("[!] Error: No valid XML files could be parsed.", file=sys.stderr)
            sys.exit(1)

        # Merge into a single dataset
        if args.verbose:
            print("[*] Merging all items into a single dataset...")
        merged_export = parser_engine.merge_exports(exports)

        # Filter output based on user options
        merged_export.items = _apply_filters(
            merged_export.items,
            only_tools=args.only_tools,
            only_status=args.only_status,
            dedupe=args.dedupe,
            verbose=args.verbose,
        )
        merged_export.items = _post_process_items(
            merged_export.items,
            redact_secrets=args.redact_secrets,
            set_session_tags=args.split_by_session,
        )

        if not merged_export.items:
            print("[!] Warning: No items found in the provided XML files.", file=sys.stderr)
            sys.exit(1)

        # Write to disk
        if not args.sqlite_only:
            writer.write(merged_export)
        else:
            Path(args.output_dir).mkdir(parents=True, exist_ok=True)

        # --- Analysis features ---
        out_path = Path(args.output_dir)
        run_findings = args.auto_findings or args.full_analysis
        run_params = args.param_index or args.full_analysis
        run_prompts = args.ai_prompts or args.full_analysis

        if run_findings:
            generate_security_findings(merged_export, out_path, verbose=args.verbose)
        if run_params:
            generate_param_index(merged_export, out_path, verbose=args.verbose)
        if run_prompts:
            generate_ai_prompts(merged_export, out_path, verbose=args.verbose)

        if getattr(args, "extract_clients", False) or getattr(args, "full_analysis", False):
            from .client_parser import extract_client_assets
            extract_client_assets(merged_export, out_path, verbose=args.verbose)

        if getattr(args, "graph", False) or getattr(args, "full_analysis", False):
            from .graph import build_semantic_graph
            build_semantic_graph(merged_export, out_path, verbose=args.verbose)

        if getattr(args, "logic", False) or getattr(args, "full_analysis", False):
            from .logic import infer_state_machine
            infer_state_machine(merged_export, out_path, verbose=args.verbose)

        if getattr(args, "ask_llm", None):
            from .llm_agent import query_llm
            ans = query_llm(merged_export, args.ask_llm, provider=args.llm_provider, model=args.llm_model, verbose=args.verbose)
            if ans:
                out_file = out_path / "LLM_RESPONSE.md"
                out_file.write_text(f"# LLM Query\n\n**Query:** {args.ask_llm}\n\n**Answer:**\n\n{ans}", encoding="utf-8")
                if args.verbose:
                    print(f"[+] LLM response saved to {out_file}")

        if getattr(args, "build_vector_db", False):
            from .vectordb import build_vector_db
            build_vector_db(merged_export, out_path, verbose=args.verbose)

        if getattr(args, "rag_query", None):
            from .vectordb import run_rag_query
            run_rag_query(args.rag_query, out_path, provider=args.llm_provider, model=args.llm_model, verbose=args.verbose)

        if args.sqlite or args.sqlite_only:
            from .sqlite_exporter import export_to_sqlite
            export_to_sqlite(merged_export, out_path, verbose=args.verbose)

        if getattr(args, "openapi", False):
            from .openapi import generate_openapi_spec
            generate_openapi_spec(merged_export, out_path, verbose=args.verbose)

        if getattr(args, "fuzz", False) or getattr(args, "full_analysis", False):
            # Ensure findings exist (fuzzer reads security-findings.json)
            if not run_findings:
                generate_security_findings(merged_export, out_path, verbose=args.verbose)
            from .fuzzer import generate_fuzz_manifest
            generate_fuzz_manifest(merged_export, out_path, verbose=args.verbose)

        if getattr(args, "nuclei", False) or getattr(args, "full_analysis", False):
            # Ensure findings exist (nuclei reads security-findings.json)
            if not run_findings and not (getattr(args, "fuzz", False) or getattr(args, "full_analysis", False)):
                generate_security_findings(merged_export, out_path, verbose=args.verbose)
            from .nuclei_gen import generate_nuclei_templates
            generate_nuclei_templates(merged_export, out_path, verbose=args.verbose)

        if args.vscode:
            from .workspace import generate_workspace
            generate_workspace(out_path)

    except FileNotFoundError as e:
        print(f"\n[!] Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

    sys.exit(0)


def create_arg_parser() -> argparse.ArgumentParser:
    """Create the argument parser for the CLI."""
    class HelpFormatter(argparse.RawTextHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
        """Formatter preserving line breaks while showing defaults."""
        pass

    parser = argparse.ArgumentParser(
        prog="burpmd",
        description=(
            f"BurpMD Parser Pro v{__version__}\n\n"
            "Parse Burp Suite XML exports into AI-ready corpus data.\n"
            "Primary output is JSON. Optional Markdown can be added with --md.\n\n"
            "Typical workflow:\n"
            "  1) Export XML from Burp (or use burpmd_extension.py)\n"
            "  2) Run burpmd with an output mode (--sitemap recommended)\n"
            "  3) Open the output folder in VS Code and analyse with Copilot"
        ),
        epilog=(
            "Detailed examples:\n\n"
            "  Basic usage:\n"
            "    burpmd export.xml -o out\n"
            "      Parse one XML into JSON-only output (flat mode).\n\n"
            "  Output mode examples (choose only one mode):\n"
            "    burpmd export.xml -o out --sitemap\n"
            "      Host/path tree (best for API corpus analysis).\n"
            "    burpmd export.xml -o out --by-host\n"
            "      Tool/host hierarchy for large multi-target tests.\n"
            "    burpmd export.xml -o out --host-first\n"
            "      Host/tool hierarchy for host-focused triage.\n"
            "    burpmd export.xml -o out --split-by-session\n"
            "      Session/tool hierarchy for auth/session behavior checks.\n\n"
            "  Include Markdown alongside JSON:\n"
            "    burpmd export.xml -o out --sitemap --md\n"
            "      Creates both .json and .md files for each item.\n\n"
            "  Markdown only (no JSON):\n"
            "    burpmd export.xml -o out --sitemap --md-only\n"
            "      Creates only .md files (useful for direct human review).\n\n"
            "  Filtering and dedupe:\n"
            "    burpmd export.xml -o triage --only-tools proxy,repeater,intruder,scanner \\\n"
            "      --only-status 401,403,5xx --dedupe\n"
            "      Keeps only selected tools + status classes, removes duplicate requests.\n\n"
            "  Redaction / safer sharing:\n"
            "    burpmd export.xml -o secure --split-by-session --redact-secrets --dedupe\n"
            "      Masks tokens/cookies/secrets and groups data by derived session bucket.\n\n"
            "  Multiple input files:\n"
            "    burpmd proxy.xml repeater.xml intruder.xml -o merged --sitemap -v\n"
            "      Merges all XML exports into one dataset, prints verbose processing logs.\n\n"
            "  Windows PowerShell examples:\n"
            "    py -3 -m burpmd .\\exports\\burp_items.xml -o .\\out\\full --sitemap --md\n"
            "    py -3 -m burpmd .\\exports\\burp_items.xml -o .\\out\\secure --split-by-session --redact-secrets\n\n"
            "  AI analysis (recommended - generates everything Copilot needs):\n"
            "    burpmd export.xml -o out --sitemap --full-analysis\n"
            "      Generates JSON corpus + SECURITY_FINDINGS.md + param-index.json + AI_ANALYSIS_PROMPTS.md\n\n"
            "    burpmd export.xml -o out --sitemap --auto-findings --md\n"
            "      JSON + MD corpus with automated security findings.\n\n"
            "    burpmd export.xml -o out --sitemap --param-index\n"
            "      JSON corpus with extracted parameter index for input vector mapping.\n\n"
            "Output artifacts:\n"
            "  - Per-item files      : {slug}.json (+ {slug}.md when --md is used)\n"
            "  - Summary files       : README.md and attack-surface-index.json\n"
            "  - Security findings   : SECURITY_FINDINGS.md (--auto-findings)\n"
            "  - Parameter index     : param-index.json (--param-index)\n"
            "  - Copilot prompts     : AI_ANALYSIS_PROMPTS.md (--ai-prompts)"
        ),
        formatter_class=HelpFormatter,
    )

    parser.add_argument(
        "input_files",
        metavar="file.xml",
        nargs="*",
        help="One or more Burp Suite XML export files to parse.",
    )

    parser.add_argument(
        "--import-format",
        choices=["burp"],
        default="burp",
        help="Specify the input file format. (Default: burp)",
    )

    # --- Output Mode ---
    group_mode = parser.add_argument_group("Output Mode (choose one)")
    group_mode.add_argument(
        "--by-host",
        action="store_true",
        help="Group files by host inside each tool folder.\n"
             "  Structure: {output}/{tool}/{host}/0001_GET_login.json",
    )
    group_mode.add_argument(
        "--sitemap",
        action="store_true",
        help="Mirror Burp Suite's Site Map tree structure.\n"
             "  Structure: {output}/{host}/api/v1/users/0001_GET.json\n"
             "  This is the recommended mode for AI analysis.",
    )
    group_mode.add_argument(
        "--host-first",
        action="store_true",
        help="Group by host first, then tool.\n"
             "  Structure: {output}/{host}/{tool}/0001_GET_login.json",
    )
    group_mode.add_argument(
        "--split-by-session",
        action="store_true",
        help="Group by session first (derived from Cookie/Auth), then tool.\n"
             "  Structure: {output}/session_ab12cd34/{tool}/0001_GET.json",
    )

    # --- Output Options ---
    group_output = parser.add_argument_group("Output Options")
    group_output.add_argument("--sqlite-only", action="store_true", help="Write SQLite instead of per-item corpus files.")
    group_output.add_argument("--vscode", action="store_true", help="Generate a VS Code workspace and analysis guide.")
    group_output.add_argument(
        "-o", "--output-dir",
        default="burp_export",
        help="Directory to save the output files. (Default: 'burp_export')"
    )
    group_output.add_argument(
        "--sqlite",
        action="store_true",
        help="Export all data into a local SQLite database (nexus.db).",
    )
    group_output.add_argument(
        "--openapi",
        action="store_true",
        help="Generate an OpenAPI v3 specification (openapi.json) from the export.",
    )
    group_output.add_argument(
        "--md",
        action="store_true",
        help="Include Markdown (.md) files alongside the default JSON files.",
    )
    group_output.add_argument(
        "--md-only",
        action="store_true",
        help="Output only Markdown (.md) files. No JSON files are written.",
    )
    group_output.add_argument(
        "--only-tools",
        default="",
        help="Comma-separated tool filter. Example: proxy,repeater,scanner",
    )
    group_output.add_argument(
        "--only-status",
        default="",
        help="Comma-separated status filters. Supports exact codes and classes.\n"
             "  Example: 401,403,5xx",
    )
    group_output.add_argument(
        "--dedupe",
        action="store_true",
        help="Deduplicate by request SHA-256 hash (keeps first occurrence).",
    )
    group_output.add_argument(
        "--redact-secrets",
        action="store_true",
        help="Mask auth tokens, cookies, API keys, and common secret fields.",
    )

    # --- Analysis Features ---
    group_analysis = parser.add_argument_group("AI Analysis Features")
    group_analysis.add_argument("--llm-model", help="Provider model ID (or set BURPNEXUS_LLM_MODEL).")
    group_analysis.add_argument(
        "--auto-findings",
        action="store_true",
        help="Auto-detect security issues and write SECURITY_FINDINGS.md.\n"
             "  Checks: missing headers, IDOR, reflected input, error disclosure,\n"
             "  sensitive data, unauthenticated endpoints, CORS, cookie flags.",
    )
    group_analysis.add_argument(
        "--param-index",
        action="store_true",
        help="Extract all input parameters into param-index.json.\n"
             "  Sources: query params, body params, JSON fields, cookies, headers.",
    )
    group_analysis.add_argument(
        "--ai-prompts",
        action="store_true",
        help="Generate tailored Copilot prompts for this specific export.\n"
             "  Creates AI_ANALYSIS_PROMPTS.md with phased analysis plan.",
    )
    group_analysis.add_argument(
        "--diff",
        action="store_true",
        help="Compare EXACTLY TWO input XML files (baseline and comparison)\n"
             "  and generate DIFF_REPORT.md highlighting API changes and auth downgrades.",
    )
    group_analysis.add_argument(
        "--extract-clients",
        action="store_true",
        help="Extract all JS/WASM files to a folder and scan them for hardcoded endpoints.",
    )
    group_analysis.add_argument(
        "--graph",
        action="store_true",
        help="Generate a Semantic Graph (SEMANTIC_GRAPH.md) to trace parameter flow and hunt for BOLA.",
    )
    group_analysis.add_argument(
        "--logic",
        action="store_true",
        help="Infer and generate a State Machine diagram (STATE_MACHINE.md) from user journeys.",
    )
    group_analysis.add_argument(
        "--ask-llm",
        type=str,
        help="Ask the LLM a question about the export (requires OPENAI_API_KEY, ANTHROPIC_API_KEY, or GEMINI_API_KEY).",
    )
    group_analysis.add_argument(
        "--llm-provider",
        type=str,
        default="openai",
        choices=["openai", "anthropic", "gemini"],
        help="The LLM provider to use for --ask-llm and --rag-query. (Default: openai)",
    )
    group_analysis.add_argument(
        "--build-vector-db",
        action="store_true",
        help="Initialize a local ChromaDB and embed the proxy traffic for semantic search.",
    )
    group_analysis.add_argument(
        "--rag-query",
        type=str,
        help="Perform a RAG query (Retrieve from Vector DB -> Ask LLM). Requires --build-vector-db to have been run first.",
    )
    group_analysis.add_argument(
        "--fuzz",
        action="store_true",
        help="Generate a fuzz manifest (FUZZ_MANIFEST.json) and curl commands (FUZZ_COMMANDS.md)\n"
             "  from identified security findings. Requires --auto-findings (auto-enabled).",
    )
    group_analysis.add_argument(
        "--nuclei",
        action="store_true",
        help="Auto-generate Nuclei v3 YAML templates from security findings.\n"
             "  Creates nuclei-templates/ directory and NUCLEI_TEMPLATES.md.",
    )
    group_analysis.add_argument(
        "--full-analysis",
        action="store_true",
        help="Enable ALL analysis features: --auto-findings + --param-index + --ai-prompts\n"
             "  + --fuzz + --nuclei + --graph + --logic + --extract-clients.",
    )

    # --- Formatting Options ---
    group_format = parser.add_argument_group("Formatting Options (for --md)")
    group_format.add_argument(
        "--no-raw-request",
        action="store_true",
        help="Do not include the full raw HTTP request in the Markdown file.",
    )
    group_format.add_argument(
        "--no-raw-response",
        action="store_true",
        help="Do not include the full raw HTTP response in the Markdown file.",
    )
    group_format.add_argument(
        "--max-body-chars",
        type=int,
        default=8000,
        help="Max characters for inline request/response bodies. (Default: 8000)",
    )

    # --- General Options ---
    group_general = parser.add_argument_group("General Options")
    group_general.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output for debugging.",
    )
    group_general.add_argument(
        "--version",
        action="store_true",
        help="Show the version number and exit.",
    )

    return parser


def _parse_csv_values(value: str) -> set[str]:
    """Convert comma-separated values into a normalised set."""
    return {v.strip().lower() for v in value.split(",") if v.strip()}


def _status_matches(status: str, filters: set[str]) -> bool:
    """
    Check whether an HTTP status code matches provided filters.

    Supported filters:
    - Exact: 401
    - Class: 4xx, 5xx
    """
    if not filters:
        return True
    status = (status or "").strip()
    if not status:
        return False
    if status in filters:
        return True
    if len(status) >= 1 and status[0].isdigit():
        family = f"{status[0]}xx"
        if family in filters:
            return True
    return False


def _apply_filters(
    items: Iterable,
    only_tools: str = "",
    only_status: str = "",
    dedupe: bool = False,
    verbose: bool = False,
):
    """Apply tool/status filters and optional deduplication."""
    filtered = list(items)
    start_count = len(filtered)

    tool_filters = _parse_csv_values(only_tools)
    if tool_filters:
        filtered = [item for item in filtered if (item.tool or "").lower() in tool_filters]

    status_filters = _parse_csv_values(only_status)
    if status_filters:
        filtered = [item for item in filtered if _status_matches(item.status, status_filters)]

    if dedupe:
        seen = set()
        deduped = []
        for item in filtered:
            key = (item.url, item.sha256, hashlib.sha256(item.response_raw.encode("utf-8")).hexdigest())
            if key and key in seen:
                continue
            if key:
                seen.add(key)
            deduped.append(item)
        filtered = deduped

    # Re-index after filtering so filenames stay contiguous
    for idx, item in enumerate(filtered, start=1):
        item.index = idx
        item.slug = _rebuild_slug(item)

    if verbose and (tool_filters or status_filters or dedupe):
        print(f"[*] Applied filters: {start_count} -> {len(filtered)} items")

    return filtered


def _rebuild_slug(item) -> str:
    """Rebuild slug after filtering/reindexing."""
    method = re.sub(r"[^A-Z0-9_-]", "_", (item.method or "REQ").upper())[:10]
    path_part = re.sub(r"[^\w\-.]", "_", item.path or "root")
    path_part = re.sub(r"_+", "_", path_part).strip("_")[:60]
    return "{0:04d}_{1}_{2}".format(item.index, method, path_part or "root")


def _post_process_items(items, redact_secrets: bool = False, set_session_tags: bool = False):
    """Apply enrichment transforms after filtering."""
    for item in items:
        session_tag = _derive_session_tag(item)
        item.session_tag = session_tag
        if redact_secrets:
            _redact_item(item)
    if set_session_tags:
        for item in items:
            if not item.session_tag:
                item.session_tag = "session_anon"
    return items


def _derive_session_tag(item) -> str:
    """Derive a stable short session tag from auth/cookie headers."""
    req_headers = item.request_headers or {}
    token_sources = []
    for k, v in req_headers.items():
        k_low = (k or "").lower()
        if k_low in ("authorization", "cookie", "x-api-key", "x-auth-token"):
            token_sources.append("{0}:{1}".format(k_low, v or ""))

    if not token_sources:
        try:
            parsed = urlparse(item.url or "")
            for k, v in parse_qsl(parsed.query, keep_blank_values=True):
                if (k or "").lower() in {"token", "auth", "apikey", "api_key", "session"}:
                    token_sources.append("{0}:{1}".format(k, v))
        except Exception:
            pass

    if not token_sources:
        return "session_anon"

    digest = hashlib.sha256("|".join(sorted(token_sources)).encode("utf-8", errors="replace")).hexdigest()
    return "session_" + digest[:8]


def _redact_item(item):
    """Mask secret-like values in headers and raw/body fields."""
    from .redaction import redact_item
    redact_item(item)
    item.slug = _rebuild_slug(item)
    item.sha256 = hashlib.sha256((item.request_raw or "").encode("utf-8", errors="replace")).hexdigest()



if __name__ == "__main__":
    main()
