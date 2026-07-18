# Contributing to HomeLab SIEM

First off — thank you for considering a contribution. This project started as a
personal, hands-on learning exercise in cybersecurity and platform engineering,
and it doubles as a portfolio piece. That context shapes how contributions are
reviewed: the goal is to keep the architecture coherent and the codebase
understandable end-to-end, not to accumulate features for their own sake.

The maintainer ([@Lollobar17](https://github.com/Lollobar17)) has final say on
what gets merged. This isn't meant to be bureaucratic — it's just an honest
heads-up before you invest time in a change.

-----

## Before you start

**Small, focused contributions** (bug fixes, new detection rules, documentation
improvements, minor script enhancements) can go straight to a pull request.

**Larger or structural changes** — anything that touches the Helm chart's shape,
the database backend abstraction, the CI/CD pipeline, or introduces a new
architectural pattern — should start as a **GitHub Issue** describing the
problem and proposed approach, before any code is written. This avoids spending
effort on a PR that doesn't fit the project's direction.

Please don't open a PR that:
- Replaces a core design choice (e.g. switching the CI/CD deploy mechanism,
  restructuring the Helm chart's `values.yaml` shape, changing the detection
  rule format) without a prior Issue discussion.
- Introduces a new language/runtime/framework for an existing component without
  discussion (the deliberate mix today is Python for the SIEM core and Go for
  the ArachneC2 simulator — each for a specific reason, not by accident).
- Bundles multiple unrelated changes into a single PR.

-----

## What's welcome

- **New detection rules** — on-premise, cloud, purple-team, or runtime — as long
  as they follow the existing rule format (see below) and include a MITRE
  ATT&CK mapping.
- **Bug fixes**, with a clear description of the symptom and root cause.
- **Documentation improvements** — README, CHANGELOG, `docs/*.md`, inline code
  comments.
- **Test coverage** for existing untested code paths.
- **Bash/automation script improvements** (`scripts/bash/`) that don't change
  their external behavior/flags without discussion.

-----

## Development setup

```bash
git clone https://github.com/Lollobar17/Homelab_SIEM.git
cd Homelab_SIEM
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install flake8 pytest pytest-cov
python app.py
```

Dashboard at `http://localhost:5000`. This runs the default SQLite backend,
no external dependencies required.

-----

## Code style

- **English only** — code, comments, commit messages, and docstrings. (CI/CD
  workflow YAML files are a documented exception, written in Italian by the
  maintainer's preference — don't worry about matching that in Python code.)
- Follow the existing style in the file you're editing rather than introducing
  a new convention. This codebase intentionally favors readability over
  cleverness.
- No emoji in code, comments, or committed documentation.
- Run `flake8` before opening a PR:
  ```bash
  flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
  ```
  This is the same check the `pr-check.yml` workflow runs automatically on
  every PR — if it fails there, the PR can't be merged.

-----

## Adding a new detection rule

Rules live in `siem/detector.py` (on-premise), `azure_siem/*_rules.py` (cloud),
`siem/caldera_rules.py` / `siem/arachne_rules.py` (purple team), or
`siem/falco_rules.py` (runtime). Follow the existing dict/lambda pattern:

```python
{
    "id": "CATEGORY-NNN",       # e.g. AUTH-007, CLOUD-015, ARC-015
    "name": "Human-readable rule name",
    "severity": "LOW|MEDIUM|HIGH|CRITICAL",
    "category": "auth|web|cloud|c2_communication|...",
    "mitre": "T1234",            # required — see attack.mitre.org
    "description": "One-sentence description of what this detects.",
    "match": lambda e: (...),    # boolean condition against the event dict
}
```

- IDs must be sequential within their category prefix and not collide with an
  existing one.
- Every rule needs a MITRE ATT&CK technique ID. If nothing fits precisely,
  open an Issue to discuss the closest reasonable mapping rather than
  guessing.
- Prefer simple, explainable conditions over elaborate heuristics — the rule
  engine's clarity is a feature, not a limitation to work around.

-----

## Pull request checklist

- [ ] Single logical change per PR (a rule addition, a bug fix, a doc update —
      not a mix of all three).
- [ ] `flake8` passes with no errors (see above).
- [ ] No secrets, API keys, tokens, or `config.json` values committed. Check
      `git diff` carefully before pushing — the `.gitignore` covers the common
      cases but can't catch everything.
- [ ] If you touched a detection rule, verify it against real or simulated
      events (`simulate_logs.py`, `simulate_caldera.py`, or equivalent) before
      submitting.
- [ ] Update `CHANGELOG.md` under an `[Unreleased]` heading if your change is
      user-visible (new rule, new endpoint, behavior change). The maintainer
      will fold it into the next version bump.
- [ ] PR description explains **what** changed and **why**, not just what the
      diff shows.

-----

## Reporting a security vulnerability

This is a security tool, so vulnerabilities in it are taken seriously — but
please **do not** open a public Issue for a security finding. Instead, contact
the maintainer directly via GitHub (a private security advisory, if enabled
on the repo, or a direct message) so it can be assessed and fixed before
public disclosure.

This applies to the SIEM application itself. The `arachne/` C2 simulator and
Falco/Caldera integrations are intentionally offensive-security tooling for
purple-team practice in a controlled homelab — issues *within their intended
scope* (e.g. "this detection rule has a bypass") are welcome as normal
Issues/PRs, not security reports.

-----

## Questions

If you're unsure whether an idea fits before writing any code, open a
GitHub Issue describing it. That's the fastest way to get a clear answer
and avoid wasted effort in either direction.
