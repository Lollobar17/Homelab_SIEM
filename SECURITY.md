# Security Policy

## Supported Versions

This is a homelab/educational project. Only the latest commit on `main` is actively maintained.

| Version | Supported |
|---------|-----------|
| latest (`main`) | yes |
| older tags | no |

## Reporting a Vulnerability

If you discover a security issue in this repository — including accidental exposure of credentials, a vulnerability in the detection logic, or a misconfiguration in the Kubernetes/Helm setup — please **do not open a public GitHub Issue**.

Instead, report it privately via one of the following:

- **GitHub Private Vulnerability Reporting** (preferred): use the [Security tab → "Report a vulnerability"](../../security/advisories/new) on this repository.
- **Email**: open a GitHub Discussion tagged `[SECURITY]` if private advisory reporting is unavailable on your account.

Please include:
- A clear description of the issue
- Steps to reproduce (if applicable)
- Affected files or components
- Any suggested fix (optional but appreciated)

## What to expect

This is a solo homelab project maintained in personal time. I will acknowledge reports within **7 days** and aim to resolve confirmed issues within **30 days**, depending on severity.

## Scope

Security reports are welcome for:
- Hardcoded or accidentally committed credentials/secrets
- Insecure defaults in `config.example.json`, Helm `values.yaml`, or CI workflows
- Logic errors in detection rules that could cause silent blind spots
- Container/Kubernetes misconfigurations

Out of scope:
- Vulnerabilities in third-party dependencies (report upstream; Dependabot handles automated updates here)
- Issues requiring physical access to the OCI VM

## Responsible Use

See [CONTRIBUTING.md](CONTRIBUTING.md) for the project's stance on offensive tooling (ArachneC2, Nim purple-team lab) — all offensive components are simulation-only and must not be deployed outside isolated lab environments.
