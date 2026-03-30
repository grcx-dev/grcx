# Contributing to GRCX

First off — thanks for taking the time to contribute. GRCX is a small project with big ambitions and every contribution matters.

## What we're looking for

The most useful contributions right now are:

- **Regulatory feed parsers** — if you know a jurisdiction's circular format, build a parser
- **Control framework mappings** — YAML definitions for frameworks not yet built-in (DORA, SOC 2, etc.)
- **Resolver action handlers** — Jira, PagerDuty, Slack, etc.
- **Infrastructure sentinels** — Kubernetes, Terraform, AWS Config
- **Bug fixes and documentation improvements**

Check the [open issues](https://github.com/grcxdev/grcx/issues) for specific tasks. Issues tagged [`good first issue`](https://github.com/grcxdev/grcx/issues?q=is%3Aissue+label%3A%22good+first+issue%22) are a good place to start.

---

## Getting started

```bash
git clone https://github.com/grcxdev/grcx.git
cd grcx

# Create virtual environment
uv venv
source .venv/bin/activate

# Install in editable mode
uv pip install -e .

# Set your API key
export ANTHROPIC_API_KEY=your_key_here
```

---

## How to contribute

1. Fork the repo
2. Create a branch: `git checkout -b feat/your-feature-name`
3. Make your changes
4. Run the tests: `uv run python -m pytest tests/`
5. Commit with a clear message (see below)
6. Push and open a pull request against `main`

---

## Commit message format

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add DORA framework YAML mapping
fix: handle empty RSS feed gracefully
docs: update quickstart guide
test: add resolver unit tests
```

---

## Code style

- Python 3.11+
- Type annotations on all public functions
- Pydantic for config and data validation where appropriate
- `rich` for all terminal output — no bare `print()` calls

Add this header to the top of every new `.py` file:

```python
# Copyright (c) 2026 Neil Lowden | GRCX | MIT License
```

---

## Adding a regulatory feed parser

Parsers live in `grcx/sentinel/regulatory/parsers/`. Each parser should:

1. Accept raw content (XML, HTML, or PDF text) and return a list of `RegulatoryItem` objects
2. Handle malformed or missing content gracefully
3. Include a docstring describing the jurisdiction and source format
4. Include at least one test using a fixture in `tests/fixtures/`

See `grcx/sentinel/regulatory/rss.py` for reference.

---

## Adding a control framework

Framework mappings live in `grcx/controls/frameworks/` as YAML files.

Minimum structure:

```yaml
framework: dora
version: "2025-01"
description: EU Digital Operational Resilience Act
controls:
  - id: DORA-ICT-1
    title: ICT Risk Management Framework
    description: Firms must maintain a comprehensive ICT risk management framework.
    category: ict_risk
  - id: DORA-ICT-2
    title: ICT-related incident reporting
    description: Firms must classify and report major ICT-related incidents.
    category: incident_management
```

---

## Pull request checklist

- [ ] Code follows the style guidelines above
- [ ] Copyright header added to new files
- [ ] Tests added or updated
- [ ] README or docs updated if behaviour changes
- [ ] Commit messages follow Conventional Commits format

---

## Questions?

Open an issue or start a discussion on GitHub. We're friendly.
