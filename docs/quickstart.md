# Quickstart

Get GRCX running in under 5 minutes.

## Prerequisites

- Python 3.11+
- An Anthropic API key ([get one here](https://console.anthropic.com/))
- `uv` package manager ([install](https://docs.astral.sh/uv/getting-started/installation/)) — or plain `pip` works too

## Install

```bash
pip install grcx
```

Or from source:

```bash
git clone https://github.com/grcxdev/grcx.git
cd grcx
uv venv && source .venv/bin/activate
uv pip install -e .
```

## Set your API key

```bash
export ANTHROPIC_API_KEY=your_key_here
```

Add this to your `.bashrc` or `.zshrc` to persist it.

## Initialise a project

```bash
mkdir my-grcx && cd my-grcx
grcx init
```

This creates:

- `grcx.yaml` — your configuration file
- `grcx-audit/` — where audit logs and state files are written

## Configure your feeds

Edit `grcx.yaml` and uncomment the feeds you want to watch:

```yaml
sentinels:
  regulatory:
    - type: rss
      url: https://www.bankofengland.co.uk/rss/publications
      jurisdiction: BOE

controls:
  framework: iso27001

resolver:
  llm: claude-sonnet-4-6
  auto_remediate: notify_only

audit:
  output: ./grcx-audit/
```

## Start watching

```bash
grcx watch
```

GRCX will poll your configured feeds, analyse new publications against your control framework, and write findings to the audit log.

For a faster feedback loop while testing:

```bash
grcx watch --poll 30
```

## Inspect the audit log

```bash
# Show last 10 entries
grcx audit --tail 10

# Verify log integrity
grcx audit --verify
```

## Dry run mode

Run GRCX without writing to the audit log or executing any remediations:

```bash
grcx watch --dry-run
```

## Next steps

- See [configuration.md](./configuration.md) for the full config reference
- See [frameworks.md](./frameworks.md) for supported control frameworks
- See [CONTRIBUTING.md](../CONTRIBUTING.md) to add a feed parser for your jurisdiction
