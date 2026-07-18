# SOUL.md

> This file exists to answer a question the code itself can't: *why does this
> project look the way it does, and why does that matter?*

-----

## Why this exists

HomeLab SIEM started as a way to learn security engineering by building the
thing, not just reading about it — log collection, detection logic, MITRE
ATT&CK mapping, incident response workflows. It has since grown into something
broader: a real, end-to-end demonstration of infrastructure and platform
engineering, built and hardened iteratively, with this repository serving as
a working portfolio piece.

That context matters for how the project is built. It is not optimized to look
impressive in a single glance. It is optimized so that every component can be
explained, defended, and rebuilt from first principles by the person who wrote
it — because that's the actual point of the exercise.

-----

## The journey, briefly

The project didn't arrive at its current shape by design upfront — it arrived
by iterating honestly on a working system:

- **A Flask app with SQLite** and a handful of regex-based detection rules,
  because understanding log parsing and rule matching from scratch matters
  more than adopting a framework that hides it.
- **Azure Cloud Integration** (VNet Flow Logs, Activity Log, Microsoft
  Sentinel), because a homelab SIEM that only sees local logs doesn't teach
  hybrid on-prem/cloud security monitoring.
- **MITRE Caldera, then ArachneC2**, because understanding detection requires
  understanding what you're detecting — purple-team tooling generating real
  attack telemetry, not synthetic test data.
- **Kubernetes, first locally (k3d), then on real cloud infrastructure
  (Oracle Cloud, k3s)** — because a portfolio piece that only runs on one
  developer's laptop doesn't demonstrate much, and because the local k3d setup
  had real stability problems (nested virtualization on WSL2) that were worth
  solving properly rather than working around indefinitely.
- **Falco, a Helm chart, Prometheus/Grafana, an optional PostgreSQL backend**
  — each added when the previous layer was solid enough to build on, not
  before.

The CHANGELOG and the Troubleshooting section in the README document this
honestly, including the bugs found along the way (a Postgres autocommit
issue, a Falco rule using the wrong field type, a missing `fingerprint` line
that silently broke authentication for a week). That's deliberate. A project
that only shows the finished, working state teaches less than one that shows
what broke and why.

-----

## Deliberate choices, and why

**Pure Python core instead of an existing SIEM framework.**
The value of this project is in understanding how a SIEM works, not in
integrating one. Every detection rule, every ingestion path, every storage
query is something that can be read and reasoned about end to end.

**SQLite by default, PostgreSQL as an opt-in — not a hard migration.**
A single-replica homelab SIEM does not need a distributed database. Building
the PostgreSQL path in parallel (same public function signatures, selected by
an environment variable) means the option exists for when it's actually
needed, without paying its operational cost — an extra pod, a Secret to
manage, a new failure mode — before that need is real.

**A parametrized Helm chart instead of hand-maintained static manifests.**
Static YAML was fine for a single environment. The moment there's a real
possibility of a second environment (staging, a different cloud provider, a
different resource budget), hand-copying and hand-editing manifests becomes
a source of drift and bugs. A `values.yaml` is a single source of truth.

**GitHub-hosted CI runners connecting over SSH, instead of a self-hosted
runner.** This repository is public. A self-hosted runner triggered by a
`pull_request` event from an external fork is a well-documented attack
vector. The extra complexity of an SSH-based deploy step is a deliberate
trade against that risk — even though a self-hosted runner would have been
simpler to wire up.

**ArachneC2 as a decentralized, libp2p-based C2 simulator, in Go — not
another simple client-server beacon.** A basic HTTP beacon is a fine starting
point, but real-world C2 infrastructure increasingly avoids single points of
failure: DHT-based peer discovery, gossip propagation, NAT traversal. Building
a simulator with those properties makes the resulting detection engineering
(the `ARC-*` rules, the Falco network rules) exercise something closer to
what a serious purple-team engagement would actually need to detect.

**Manual approval gates in the deploy pipeline, rollback on failure, an
idempotent VM provisioner.** None of these are needed for a system with no
real users. They exist because building them correctly — and hitting the
real failure modes (a stuck deploy, a duplicate VM, a bad rollout) — is
exactly the skill this project exists to build.

-----

## What this project deliberately is not

- **Not a production security product.** It is a learning platform and a
  portfolio artifact. The purple-team tooling (`arachne/`, Caldera
  integration, custom Falco rules) is intentionally offensive-security
  material for a controlled homelab — never intended to leave that context.
- **Not trying to reinvent SIEM tooling that already exists.** Where a
  mature open-source project would be the right tool for a real deployment
  (a future exploration of Wazuh is planned separately, for exactly this
  reason), this project's value is in having built the fundamentals by hand
  first.
- **Not chasing feature count.** Every addition documented in the CHANGELOG
  exists because it taught something or solved a real problem hit during
  the build — not because it looked good on a feature list.

-----

## A note on how this was built

A meaningful part of this project's development — infrastructure debugging,
Helm chart authoring, CI/CD design, this documentation itself — was done in
collaboration with Claude (Anthropic), used as a hands-on technical partner
rather than a black box: every fix was verified end-to-end against the real
running system before being trusted, and several confident-sounding
suggestions turned out to be wrong on first try and were corrected once
tested (documented, not hidden, in the CHANGELOG and Troubleshooting
sections). That process — propose, test, verify, document the failure if
there was one — is itself part of what this project is trying to
demonstrate.
