# Installation and build guide

This repository contains three independently versioned components. Install only the components needed for your workflow.

## Requirements

| Task | Requirement |
| --- | --- |
| Load the Burp extension | Burp Suite with Montoya extension support and a runtime capable of loading Java 17 bytecode |
| Build the Burp extension | JDK 21; the Gradle wrapper downloads Gradle and Maven dependencies on first use |
| Run the VS Code extension | Desktop VS Code 1.95+ and a trusted local workspace |
| Build/package the VS Code extension | Node.js 24 and npm |
| Run/build the optional CLI | Python 3.10+ |
| Use a model in the panel | A provider that exposes a model through VS Code's Language Model API; optional |

Virtual VS Code workspaces and untrusted workspaces are intentionally unsupported. Native BurpNexus JSON exports do not require Python.

## Install release artifacts

When a GitHub release is available, download:

- `burpnexus-1.1.0.jar`
- `burpnexus-1.1.0.vsix`
- `SHA256SUMS.txt`
- Python wheel/source distribution only if you need the optional CLI

Verify checksums before installing. On Linux/macOS:

```sh
sha256sum -c SHA256SUMS.txt
```

On PowerShell, compare each value manually with the matching line in `SHA256SUMS.txt`:

```powershell
Get-FileHash .\burpnexus-1.1.0.jar -Algorithm SHA256
Get-FileHash .\burpnexus-1.1.0.vsix -Algorithm SHA256
```

### Burp Java extension

1. Open Burp Suite.
2. Open **Extensions → Installed**.
3. If an older BurpNexus instance is loaded, unload it first.
4. Select **Add**, choose extension type **Java**, and select `burpnexus-1.1.0.jar`.
5. Confirm that the **BurpNexus** suite tab appears and review the extension output for load errors.

The JAR has no model/API-key UI and makes no model requests. It writes each export to a new directory beneath `~/burpnexus_exports/`. The optional Python CLI is a separate import path and writes to the directory supplied with its `-o` option.

### VS Code extension

1. Open desktop VS Code.
2. Press **Ctrl+Shift+P** and run **Extensions: Install from VSIX...**.
3. Choose `burpnexus-1.1.0.vsix`.
4. Reload the window if prompted.
5. Open the application source repository and trust the workspace only if you trust its contents.
6. Run **BurpNexus: Connect Export to Source Repository**.

Command-line installation is also supported by VS Code:

```sh
code --install-extension burpnexus-1.1.0.vsix
```

This GitHub release process creates a VSIX. It does not publish the extension to the VS Code Marketplace.

### Optional Python CLI

Create a virtual environment from the repository root.

PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .\burpmd-parser
burpmd --version
```

Linux/macOS:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ./burpmd-parser
burpmd --version
```

Optional local-vector support installs additional dependencies and may download an embedding model when first used:

```sh
python -m pip install "./burpmd-parser[rag]"
```

Review the dependency warning in [the CLI README](../burpmd-parser/README.md) before enabling RAG. Do not open indexes obtained from untrusted sources.

## Build from source

Run commands from the repository root unless a step changes directories.

### Python CLI

```sh
python -m pip install ./burpmd-parser -r burpmd-parser/requirements-test.txt
python -m unittest discover -s burpmd-parser/tests -p "test_*.py" -v
python -m build burpmd-parser
```

Outputs:

```text
burpmd-parser/dist/*.whl
burpmd-parser/dist/*.tar.gz
```

The optional real-embedding test is intentionally excluded from normal CI because it requires the RAG extra and model download:

```sh
python burpmd-parser/tests/integration_rag.py --work-dir PATH
```

### Burp Java extension

Linux/macOS:

```sh
cd Nexus_extension/src
./gradlew test jar --no-daemon
```

Windows PowerShell or Command Prompt:

```powershell
cd Nexus_extension\src
.\gradlew.bat test jar --no-daemon
```

Output:

```text
Nexus_extension/src/build/release/libs/burpnexus-1.1.0.jar
```

The first build needs network access for the Gradle distribution and Maven dependencies. The build uses JDK 21 and emits Java 17-compatible bytecode.

If a synchronized directory locks the default build folder, select a new empty output directory:

```powershell
.\gradlew.bat test jar --no-daemon -PoutputDir=C:\path\to\fresh-build
```

### VS Code extension

```sh
cd vscode-extension
npm ci
npm test
npm audit --audit-level=high
npm run package
```

Output:

```text
vscode-extension/burpnexus-1.1.0.vsix
```

Verify the Java export contract after the Java tests have produced their fixture:

```sh
cd vscode-extension
node scripts/validate-contract.js ../Nexus_extension/src/build/release/contract-export
```

The VSIX has no runtime npm dependencies. `@vscode/vsce` is a development dependency used only for packaging.

## Local release verification

Before calling a build production-ready, also load the JAR in the intended Burp version, perform an in-scope redacted export, unload/reload it, install the VSIX in an isolated VS Code profile, and exercise the organization's intended model provider. Those live checks are not replaced by unit tests.
