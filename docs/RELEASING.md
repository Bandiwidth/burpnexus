# Maintainer release procedure

This public release uses one version for all three components. The 1.1.0 assets are VSIX 1.1.0, Burp JAR 1.1.0, and Python CLI 1.1.0.

## Put this candidate at the repository root

GitHub reads workflows, issue templates, and security metadata only from the repository's root `.github` directory. This preserved working copy currently lives under `versions/burpnexus-github-1.1.0`; do not commit that enclosing `versions` path and expect its workflows to run.

Use the contents of `burpnexus-github-1.1.0` as the repository root. The safest publication path is:

1. Create a clean clone of `https://github.com/Bandiwidth/burpnexus.git` in a separate directory.
2. Create a release branch such as `codex/github-ready-1.1.0`.
3. Extract `burpnexus-github-1.1.0.zip` outside the clone.
4. Copy the extracted folder's contents into the clone root. Do not copy the outer extracted folder itself.
5. Run `git status` and confirm that `.github/workflows/ci.yml`, `README.md`, `Nexus_extension`, `burpmd-parser`, and `vscode-extension` are all at the checkout root.
6. Rerun the checks below, commit the reviewed files, push the branch, and open a pull request.

Example Git preparation commands:

```sh
git clone https://github.com/Bandiwidth/burpnexus.git
cd burpnexus
git switch -c codex/github-ready-1.1.0
# Copy the extracted candidate contents into this directory, then review:
git status
git diff --check
```

Do not tag from the preserved parent working tree or before the pull request is merged. A tag release uses the files at that tag; nested workflows under `versions/` are ignored by GitHub.

## Repository settings

Before the first public release:

1. Enable GitHub Actions with read/write workflow permissions sufficient for the tag release job's `contents: write` permission.
2. Enable private vulnerability reporting under the repository security settings, or publish another monitored private contact.
3. Protect `main` and require the **Validate BurpNexus** checks appropriate to the repository policy.
4. Review Dependabot pull requests rather than enabling blind automatic merges.
5. Confirm that GitHub Releases is the intended VSIX distribution channel. Marketplace publication is not configured.

## Pre-release checks

1. Update component versions only when those components changed.
2. Update `CHANGELOG.md`, README version table, workflow asset names, and documentation.
3. Run the complete local build from [INSTALLATION.md](INSTALLATION.md).
4. Load the JAR in the intended Burp version; export, search, unload, and reload it.
5. Install the exact packaged VSIX in an isolated VS Code profile and run the safe fixture.
6. Exercise the intended real VS Code model provider if the release makes model-workflow claims.
7. Inspect the VSIX file list and verify that the packaged skill/catalog are present.
8. Review dependency audit results and the documented RAG risk decision.
9. Update `REVIEW_REPORT.md` with measured results and remaining gates.

Do not describe the release as production-certified while required live checks remain open.

## Tag and publish

After the release branch is merged and the required checks pass on `main`, create the tag from the exact reviewed commit. The release workflow requires the tag to match the VSIX version exactly. For suite 1.1.0:

```sh
git switch main
git pull --ff-only
git tag -a v1.1.0 -m "BurpNexus 1.1.0"
git push origin v1.1.0
```

The tag workflow:

1. reruns Python, Java, and VS Code tests;
2. builds the Python wheel/source distribution, JAR, and VSIX;
3. creates `SHA256SUMS.txt`;
4. uploads the assets as a workflow artifact; and
5. creates a GitHub release using GitHub CLI and the workflow's `GITHUB_TOKEN`.

It does not publish to PyPI or the VS Code Marketplace. Those channels require separate owner accounts, names, tokens or trusted-publishing configuration, and explicit release authorization.

## Asset verification

Expected filenames for v1.1.0:

```text
burpnexus-1.1.0.jar
burpnexus-1.1.0.vsix
burpmd_parser-1.1.0-*.whl
burpmd_parser-1.1.0.tar.gz
SHA256SUMS.txt
```

After the workflow finishes, download the release assets, verify checksums, install the JAR and VSIX from those downloaded files, and repeat a minimal smoke test. A successful build job alone does not test live Burp behavior or provider access.
