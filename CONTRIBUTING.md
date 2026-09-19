# Contributing

Contributions are welcome through focused issues and pull requests. BurpNexus processes sensitive security evidence, so changes should preserve scope, redaction, bounded resource use, and the distinction between hypotheses and validated findings.

## Before opening a pull request

1. Search existing issues.
2. For a behavioral change, describe the user-visible problem and expected behavior.
3. Keep unrelated formatting or generated files out of the change.
4. Do not commit real Burp projects, customer traffic, credentials, API keys, model transcripts, or proprietary source excerpts.
5. Report product vulnerabilities privately according to [SECURITY.md](SECURITY.md).

## Development setup

Follow [docs/INSTALLATION.md](docs/INSTALLATION.md). The normal validation commands are:

```text
python -m pip install ./burpmd-parser -r burpmd-parser/requirements-test.txt
python -m unittest discover -s burpmd-parser/tests -p "test_*.py" -v
python -m build burpmd-parser

cd Nexus_extension/src
./gradlew test jar --no-daemon

cd ../../vscode-extension
npm ci
npm test
npm audit --audit-level=high
npm run package
node scripts/validate-contract.js ../Nexus_extension/src/build/release/contract-export
```

Use `gradlew.bat` on Windows. Optional RAG integration is not part of normal CI.

## Change expectations

- Java export schema changes must update the contract fixture and VS Code compatibility check.
- Mapping changes need positive and negative fixtures; avoid tests that only duplicate the implementation.
- Review/playbook changes must preserve `not-run` manual status and `needs-validation` model status.
- New external links must be fixed HTTPS allowlisted resources if the webview can open them.
- Webview changes must retain nonce-based CSP and text-only rendering for untrusted evidence/model output.
- New source or traffic collection must stay within explicit bounds and surface omissions.
- Documentation must distinguish implemented behavior, proposed roadmap work, and live validation that has not occurred.
- Dependency changes should include lockfile updates and audit results.

## Pull requests

Explain the concrete trigger, previous behavior, resulting behavior, security/data-handling effect, and validation performed. A PR that changes artifacts or versions should also update `CHANGELOG.md` and relevant installation/release documentation.

The CI workflow runs Python 3.10/3.12 on Windows and Linux, Java on Windows and Linux, the Java→VS Code contract, Node tests, dependency audit, and VSIX packaging. A green CI run does not replace a live Burp or provider check when the change affects those paths.
