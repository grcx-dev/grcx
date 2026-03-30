# GRCX

**The regulatory compliance monitoring agent that never sleeps.**

GRCX watches your infrastructure and regulatory feeds simultaneously. When something drifts — a new circular, a broken control, a policy conflict — it diagnoses the issue, executes the remediation, and writes an immutable audit trail. Automatically.

**Author:** Neil Lowden

![GRCX Demo](demo.gif)
---

## What just happened

```
03:14:07  [GRCX] New circular detected: MAS TRM 2025-003
03:14:09  [GRCX] Scanning 47 registered controls...
03:14:23  [GRCX] ⚠️  3 controls affected
           → TRM-12: Patch cadence policy — BREACHED (new 72hr requirement, current: 7 days)
           → TRM-31: Encryption standard — REVIEW REQUIRED (TLS 1.2 now deprecated)
           → TRM-44: Vendor risk assessment — BREACHED (annual → semi-annual required)
03:14:24  [GRCX] Remediating TRM-12...
03:17:11  [GRCX] ✅ TRM-12 resolved — patch policy updated, PR #847 raised, reviewer assigned
03:17:12  [GRCX] ✅ TRM-31 resolved — deprecation ticket opened, infra team notified
03:17:13  [GRCX] 🔴 TRM-44 requires human sign-off — ticket #1203 raised, CISO notified
03:17:14  [GRCX] Audit log written → grcx-audit-2025-03-14T03:17:14Z.json
```

That happened while you slept.

---

## The problem GRCX solves

Compliance in a regulated fintech is a moving target. Regulators publish new circulars. Infrastructure drifts from policy. Controls that passed last quarter fail today. And when your auditor asks what happened at 03:14 on a Tuesday in March, you need an answer.

Existing monitoring tools watch infrastructure. Existing GRC tools track policies. **Nothing connects the two automatically, in real time, with a full audit trail.**

That's GRCX.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                         GRCX                            │
│                                                         │
│  ┌──────────────┐   ┌──────────────┐   ┌─────────────┐ │
│  │   SENTINEL   │   │   RESOLVER   │   │  AUDIT LOG  │ │
│  │              │   │              │   │             │ │
│  │ Watches:     │──▶│ Diagnoses    │──▶│ Immutable   │ │
│  │ • Reg feeds  │   │ root cause   │   │ append-only │ │
│  │ • Infra state│   │              │   │ record of   │ │
│  │ • Policy docs│   │ Executes or  │   │ every       │ │
│  │ • Control DB │   │ escalates    │   │ action      │ │
│  └──────────────┘   └──────────────┘   └─────────────┘ │
└─────────────────────────────────────────────────────────┘
         │                    │
         ▼                    ▼
   Slack / Telegram     GitHub / Jira
   PagerDuty            Your ticketing system
```

**Sentinel** — ingests regulatory feeds (PDF circulars, RSS, structured APIs), infrastructure state (Terraform, Kubernetes, cloud configs), and your control framework.

**Resolver** — uses an LLM to reason about the gap between current state and required state, then executes safe remediations or escalates to humans with a full diagnosis.

**Audit Log** — append-only, cryptographically signed, human-readable JSON. Your auditor's best friend.

---

## Quickstart

```bash
pip install grcx
grcx init
grcx watch --config grcx.yaml
```

`grcx.yaml`:

```yaml
sentinels:
  regulatory:
    - type: rss
      url: https://www.mas.gov.sg/publications/circulars
      jurisdiction: MAS
    - type: pdf_watch
      path: ./circulars/
      jurisdiction: local

  infrastructure:
    - type: terraform_state
      path: ./terraform/
    - type: kubernetes
      context: prod-cluster

controls:
  framework: iso27001      # or: mas-trm, bsp-2023, fca-sysc, custom
  path: ./controls/

resolver:
  llm: claude-3-5-sonnet   # or: gpt-4o, local (ollama)
  auto_remediate: safe      # safe | aggressive | notify_only
  escalation:
    channel: slack
    webhook: ${SLACK_WEBHOOK}

audit:
  output: ./grcx-audit/
  sign: true
```

```bash
grcx watch
```

### Running from source

```bash
# Terminal 1 — watcher
.venv/bin/grcx watch

# Terminal 2 — dashboard (http://localhost:5001)
.venv/bin/python dashboard/app.py
```

---

## Control frameworks supported

| Framework | Status |
|-----------|--------|
| ISO 27001 | ✅ Built-in |
| MAS TRM | ✅ Built-in |
| BSP MORB / DITO | ✅ Built-in |
| FCA SYSC | ✅ Built-in |
| DORA | 🚧 In progress |
| SOC 2 | 🚧 In progress |
| Custom YAML | ✅ Always supported |

---

## Remediation modes

| Mode | Behaviour |
|------|-----------|
| `notify_only` | Detects and alerts. No automated action. |
| `safe` | Executes low-risk remediations (open tickets, update docs, raise PRs). Escalates anything requiring human judgement. |
| `aggressive` | Executes all remediations it can. Escalates only what it genuinely cannot do. |

Start with `notify_only`. Move to `safe` once you trust the audit log.

---

## Who built this

GRCX was created by [Neil Lowden](https://github.com/neillowden) — 30 years in financial services infrastructure across Goldman Sachs, UBS, and Credit Suisse First Boston, now building at the intersection of AI and regulated ops.

The infrastructure was never the problem. The problem was the gap between what the regulator published on Monday and what the controls actually said on Tuesday. That gap is where fines live. GRCX closes it.

---

## Contributing

GRCX is MIT licensed and actively welcoming contributors.

The most useful things right now:

- **Regulatory feed parsers** — if you know a jurisdiction's circular format, build a parser
- **Control framework mappings** — YAML definitions for frameworks not yet built-in
- **Resolver strategies** — better remediation logic for specific control types

See [CONTRIBUTING.md](./CONTRIBUTING.md) for how to get started.

Good first issues are tagged [`good-first-issue`](https://github.com/grcxdev/grcx/issues?q=is%3Aissue+label%3Agood-first-issue).

---

## Roadmap

- [x] Sentinel core (regulatory + infra feeds)
- [x] Resolver with audit log
- [x] MAS TRM, BSP, FCA, ISO 27001 built-in frameworks
- [ ] DORA framework
- [ ] SOC 2 framework
- [ ] Web UI (audit log explorer)
- [ ] GRCX Cloud (hosted feed hub — commercial)
- [ ] Multi-tenant enterprise mode

---

## Licence

MIT — see [LICENSE](./LICENSE)

The regulatory feed hub (real-time parsed circulars, pre-mapped controls) will be offered as a commercial hosted service. The core agent is and will remain open source.
