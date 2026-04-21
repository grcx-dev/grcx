# GRCX

> Open source regulatory radar for financial services compliance teams.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

GRCX monitors publications from financial regulators — consultation papers, policy statements, Dear CEO letters, supervisory notices — and maps each one against your control frameworks as they land. When the FCA publishes something on Tuesday morning, GRCX catches it within its next polling cycle and tells you which of your controls are affected.

Every regulatory change management tool on the market is closed source and enterprise-priced. GRCX is the only open source option.

**Live:** [grcx.dev](https://grcx.dev) · [app.grcx.dev](https://app.grcx.dev)

---

## Why this exists

Compliance teams in regulated fintech are drowning in volume. The FCA alone publishes hundreds of items a year. Add the Bank of England, the SEC, MAS, and ESMA, and the reading backlog runs to weeks per publication when triaged manually.

Existing tools — CUBE, Archer Evolv, Ascent, Regology — are filing cabinets. They help compliance teams manage the controls they already know about. None of them are radar: none detect new regulatory publications and map them to affected controls before the team is even aware.

GRCX is radar.

---

## What it does

- **Monitors** regulators via their published feeds (IMAP, RSS, HTTP) — currently BoE, FCA, MAS, SEC, and ESMA.
- **Maps** each new publication to your control frameworks using an LLM.
- **Triages** — assesses severity, highlights affected controls, and surfaces a prioritised queue.
- **Audits** — writes every detection and assessment to a cryptographically chained audit log (SHA-256, append-only, verifiable).
- **Surfaces** everything in a live dashboard with jurisdiction filtering, severity badges, and flagged-only triage.

Every assessment is subject to human override. Compliance tools are trust products — GRCX augments the compliance team's judgement, it doesn't replace it. Overrides feed back into the resolver, improving accuracy over time.

---

## Control frameworks

Built-in:

- ISO 27001
- FCA SYSC
- MAS TRM
- NIST CSF
- BCBS 239
- SOC 2

Custom frameworks via YAML are always supported.

---

## Architecture

Three layers:

```
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│   SENTINEL    │ →  │   RESOLVER    │ →  │   AUDIT LOG   │
│               │    │               │    │               │
│  Ingests      │    │  LLM maps to  │    │  SHA-256      │
│  regulator    │    │  frameworks,  │    │  chained,     │
│  feeds (IMAP, │    │  assesses     │    │  append-only, │
│  RSS, HTTP)   │    │  severity     │    │  verifiable   │
└───────────────┘    └───────────────┘    └───────────────┘
                            ↓
                     ┌─────────────┐
                     │  DASHBOARD  │
                     │             │
                     │  Triage +   │
                     │  overrides  │
                     └─────────────┘
```

Adding a new regulator is a config change in `grcx.yaml`, not a code change.

---

## Quickstart

```bash
git clone https://github.com/grcx-dev/grcx.git
cd grcx
uv sync

cp .env.example .env      # add your Anthropic API key and SMTP config
source .env

grcx watch --poll 900
```

In a separate terminal, run the dashboard:

```bash
flask --app dashboard.app run --port 5001
```

Open [http://localhost:5001](http://localhost:5001).

See [`grcx.yaml`](grcx.yaml) for the full configuration reference — regulator feeds, active frameworks, resolver backend, audit log location, alerting.

---

## Hosted version

The open source engine is free under MIT. A hosted commercial version — GRCX Cloud — is available at [app.grcx.dev](https://app.grcx.dev):

- **Starter** — $1,000/mo
- **Pro** — $3,000/mo
- **Enterprise** — $10,000+/mo

14-day free trial.

---

## Roadmap

- DORA framework
- GDPR framework
- Trading exchange feeds
- Cross-jurisdictional regulatory intelligence (contradiction detection, ambiguity surfacing, drift tracking)
- Integrations: Jira, PagerDuty, Slack

---

## Contributing

GRCX is MIT licensed and welcomes contributors. The most useful contributions right now:

- Regulatory feed parsers for jurisdictions not yet covered
- Control framework YAML definitions for frameworks not yet built-in
- Resolver prompt improvements for specific framework/jurisdiction combinations

See [CONTRIBUTING.md](CONTRIBUTING.md). Good first issues are tagged `good-first-issue`.

---

## Who built this

GRCX is built by Neil Lowden, drawing on 30+ years of financial services infrastructure at Credit Suisse First Boston, Goldman Sachs, and UBS.

---

## Licence

MIT — see [LICENSE](LICENSE).
