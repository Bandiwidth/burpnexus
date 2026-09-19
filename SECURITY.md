# Security policy

## Reporting a BurpNexus vulnerability

Do not publish credentials, customer traffic, private source code, or a working exploit in a public issue.

If GitHub private vulnerability reporting is enabled for this repository, use **Security → Report a vulnerability**. If that option is not visible, open a minimal issue asking the maintainer to provide a private contact; include no exploit details or sensitive evidence. Maintainers should configure a monitored private channel before distributing a release.

Include the affected component/version, environment, impact, minimal reproduction conditions, and whether the issue may expose captured traffic, source excerpts, credentials, filesystem data, or requests outside selected scope.

There is currently no published response-time SLA. The latest release and current `main` are the maintained development lines; older snapshots may receive fixes only when a maintainer explicitly backports them.

## Data-handling boundaries

- Burp exports and saved review artifacts can contain sensitive application data. Store and share them according to the engagement's rules.
- Redaction covers common credential fields and token formats but cannot guarantee removal of arbitrary secrets, personal data, or proprietary business information.
- The Burp JAR performs no model requests. VS Code sends data only after the user prepares a preview and selects a registered model. The selected provider controls transport, retention, and billing.
- External review packs are ordinary Markdown files; BurpNexus cannot control what happens after they are given to another assistant.
- The optional Python cloud-provider commands send bounded redacted context only when explicitly invoked. Optional local embeddings may download a model.
- Use only vector indexes created locally by this tool. The optional RAG dependency decision is documented in the release report.
- Generated fuzz commands and Nuclei templates are not executed by BurpNexus. Review authorization, scope, credentials, redirects, request rate, and matcher logic before using another tool to run them.

## Repository hygiene

The `.gitignore` excludes common Burp project files, local exports, environment files, review packs, plans, logs, build outputs, and dependency directories. Ignore rules are not a security boundary. Inspect staged files and release assets before pushing.
