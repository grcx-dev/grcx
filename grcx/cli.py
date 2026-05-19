# Copyright (c) 2026 Neil Lowden | GRCX | MIT License
import click
from rich.console import Console
from rich.panel import Panel

console = Console()

@click.group()
@click.version_option(version="0.1.0")
def cli():
    """GRCX — the regulatory compliance monitoring agent that never sleeps."""
    pass

@cli.command()
def init():
    """Initialise a new GRCX project in the current directory."""
    import shutil
    from pathlib import Path

    config_path = Path("grcx.yaml")
    if config_path.exists():
        console.print("[yellow]grcx.yaml already exists — skipping.[/yellow]")
    else:
        config_path.write_text(_default_config())
        console.print("[green]✓[/green] Created grcx.yaml")

    audit_dir = Path("grcx-audit")
    audit_dir.mkdir(exist_ok=True)
    console.print("[green]✓[/green] Created grcx-audit/")

    console.print(Panel(
        "[bold]GRCX initialised.[/bold]\n\n"
        "Next steps:\n"
        "  1. Edit [cyan]grcx.yaml[/cyan] with your feeds and controls\n"
        "  2. Set [cyan]ANTHROPIC_API_KEY[/cyan] in your environment\n"
        "  3. Run [cyan]grcx watch[/cyan]",
        title="[bold green]✓ Done[/bold green]",
        expand=False
    ))

@cli.command()
@click.option("--config", default="grcx.yaml", help="Path to config file.", show_default=True)
@click.option("--dry-run", is_flag=True, help="Detect only, do not remediate.")
@click.option("--poll", default=300, help="Poll interval in seconds.", show_default=True)
def watch(config, dry_run, poll):
    """Start watching regulatory feeds and infrastructure."""
    from pathlib import Path
    import yaml
    from grcx.sentinel.runner import run

    config_path = Path(config)
    if not config_path.exists():
        console.print(f"[red]Config file not found: {config}[/red]")
        console.print("Run [cyan]grcx init[/cyan] first.")
        raise click.Abort()

    import os
    raw = config_path.read_text()
    cfg = yaml.safe_load(os.path.expandvars(raw))

    run(cfg, dry_run=dry_run, poll_interval=poll)

@cli.command()
@click.option("--log-dir", default="grcx-audit", help="Audit log directory.")
@click.option("--verify", "do_verify", is_flag=True, help="Verify log integrity.")
@click.option("--tail", default=10, help="Number of recent entries to show.", show_default=True)
@click.option("--usage", "do_usage", is_flag=True, help="Show token usage summary.")
@click.option("--since", default=None, metavar="YYYY-MM-DD", help="Filter usage from this date (inclusive).")
@click.option("--until", default=None, metavar="YYYY-MM-DD", help="Filter usage up to this date (inclusive).")
def audit(log_dir, do_verify, tail, do_usage, since, until):
    """Inspect the GRCX audit log."""
    from grcx.audit.log import AuditLog
    from rich.table import Table
    from collections import defaultdict

    log = AuditLog(log_dir=log_dir)

    if do_verify:
        valid, errors = log.verify()
        if valid:
            console.print("[bold green]✓ Audit log integrity verified — chain intact[/bold green]")
        else:
            console.print("[bold red]✗ Integrity errors detected:[/bold red]")
            for e in errors:
                console.print(f"  [red]• {e}[/red]")
        return

    if do_usage:
        import json as _json
        if not log.log_path.exists():
            console.print("[yellow]No audit log found.[/yellow]")
            return

        resolver_event_types = {"resolver.assessment", "resolver.no_implication"}
        buckets: dict[tuple, dict] = defaultdict(lambda: {
            "events": 0, "input_tokens": 0, "output_tokens": 0,
            "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
        })
        no_usage_count = 0

        for line in log.log_path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                entry = _json.loads(line)
            except Exception:
                continue
            if entry.get("event_type") not in resolver_event_types:
                continue
            ts = entry.get("timestamp", "")[:10]
            if since and ts < since:
                continue
            if until and ts > until:
                continue
            detail = entry.get("detail", {})
            rv = detail.get("resolver_version", "unknown")
            mv = detail.get("model_version", "unknown")
            u = detail.get("usage")
            key = (rv, mv)
            buckets[key]["events"] += 1
            if u:
                buckets[key]["input_tokens"] += u.get("input_tokens", 0)
                buckets[key]["output_tokens"] += u.get("output_tokens", 0)
                buckets[key]["cache_creation_input_tokens"] += u.get("cache_creation_input_tokens", 0)
                buckets[key]["cache_read_input_tokens"] += u.get("cache_read_input_tokens", 0)
            else:
                no_usage_count += 1

        title = "Token Usage Summary"
        if since or until:
            title += f" ({since or '…'} → {until or 'now'})"
        table = Table(title=title)
        table.add_column("resolver_version", style="cyan", width=18)
        table.add_column("model", width=30)
        table.add_column("events", justify="right", width=8)
        table.add_column("input_tokens", justify="right", width=14)
        table.add_column("output_tokens", justify="right", width=14)
        table.add_column("cache_read", justify="right", width=12)

        total_events = total_in = total_out = total_cache = 0
        for (rv, mv), b in sorted(buckets.items()):
            has_data = b["input_tokens"] > 0 or b["output_tokens"] > 0
            table.add_row(
                rv, mv,
                str(b["events"]),
                f"{b['input_tokens']:,}" if has_data else "—",
                f"{b['output_tokens']:,}" if has_data else "—",
                f"{b['cache_read_input_tokens']:,}" if has_data else "—",
            )
            total_events += b["events"]
            total_in += b["input_tokens"]
            total_out += b["output_tokens"]
            total_cache += b["cache_read_input_tokens"]

        console.print(table)
        console.print(
            f"[dim]Total: {total_events} events · "
            f"{total_in:,} input tokens · {total_out:,} output tokens · "
            f"{total_cache:,} cache reads[/dim]"
        )
        if no_usage_count:
            console.print(
                f"[dim]{no_usage_count} events have no usage data "
                f"(resolved before v1.3.0)[/dim]"
            )
        return

    entries = log.tail(tail)
    if not entries:
        console.print("[yellow]No audit log entries found.[/yellow]")
        return

    table = Table(title=f"Last {len(entries)} Audit Entries")
    table.add_column("Timestamp", style="dim", width=28)
    table.add_column("Severity", width=10)
    table.add_column("Event Type", style="cyan", width=30)
    table.add_column("Summary", width=50)

    severity_colours = {"info": "green", "warning": "yellow", "critical": "red"}
    for entry in entries:
        sev = entry.get("severity", "info")
        colour = severity_colours.get(sev, "white")
        table.add_row(
            entry.get("timestamp", "")[:26],
            f"[{colour}]{sev.upper()}[/{colour}]",
            entry.get("event_type", ""),
            entry.get("summary", "")[:50]
        )

    console.print(table)

@cli.command("backfill-titles")
@click.option("--log-dir", default="grcx-audit", help="Audit log directory.", show_default=True)
@click.option("--dry-run", is_flag=True, help="Preview changes without writing.")
def backfill_titles(log_dir, dry_run):
    """Fix existing log entries where the publication title is a bare URL."""
    import hashlib
    import json
    import sys
    from datetime import datetime
    from pathlib import Path
    from grcx.sentinel.regulatory.imap_email import fetch_page_title

    log_path = Path(log_dir) / "grcx.log.jsonl"

    lockfile = Path(log_dir) / ".lock"
    if lockfile.exists():
        console.print(f"[red]Lock file present ({lockfile}): a concurrent grcx watch process may be running. "
                      f"Stop it before running backfill-titles.[/red]")
        sys.exit(1)

    if not log_path.exists():
        console.print(f"[red]Log file not found: {log_path}[/red]")
        return

    lines = log_path.read_text().strip().splitlines()
    entries = []
    for line in lines:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    _JUNK_PATTERNS = ("/newsletter", "/form/newsletter", "unsubscribe", "optout", "/confirm/remove")

    def _is_junk(url: str) -> bool:
        return any(p in url for p in _JUNK_PATTERNS)

    to_fix = [
        e for e in entries
        if e.get("event_type") == "regulatory.new_publication"
        and e.get("summary", "").startswith("https://")
    ]

    if not to_fix:
        console.print("[green]No URL-titled entries found — nothing to fix.[/green]")
        return

    junk = [e for e in to_fix if _is_junk(e.get("summary", ""))]
    fixable = [e for e in to_fix if not _is_junk(e.get("summary", ""))]
    console.print(f"Found [yellow]{len(fixable)}[/yellow] to fix, [red]{len(junk)}[/red] junk to purge.")

    if dry_run:
        for e in fixable:
            console.print(f"  [yellow]fix[/yellow]  {e['timestamp'][:10]} {e['summary'][:80]}")
        for e in junk:
            console.print(f"  [red]purge[/red] {e['timestamp'][:10]} {e['summary'][:80]}")
        return

    junk_fps = {e["detail"].get("fingerprint") for e in junk}
    entries = [e for e in entries if e.get("detail", {}).get("fingerprint") not in junk_fps]

    fixed = 0
    # Track fingerprint swaps per seen-file so we can update them after
    # { seen_file_path: [(old_fp, new_fp), ...] }
    fp_updates: dict[str, list[tuple[str, str]]] = {}

    for entry in entries:
        if (entry.get("event_type") == "regulatory.new_publication"
                and entry.get("summary", "").startswith("https://")):
            url = entry["summary"]
            title = fetch_page_title(url)
            if title:
                console.print(f"  [green]✓[/green] {title[:70]}")

                old_fp = hashlib.sha256(f"{url}{url}".encode()).hexdigest()[:16]
                new_fp = hashlib.sha256(f"{url}{title}".encode()).hexdigest()[:16]

                feed_url = entry.get("detail", {}).get("feed_url", "")
                jur = (entry.get("jurisdiction") or "unknown").lower()
                seen_file = Path(log_dir) / (
                    f"seen_{jur}_email.txt" if feed_url.startswith("imap://")
                    else f"seen_{jur}.txt"
                )
                fp_updates.setdefault(str(seen_file), []).append((old_fp, new_fp))

                entry["summary"] = title
                fixed += 1
            else:
                console.print(f"  [yellow]![/yellow] Could not fetch title for {url[:70]}")

    # Rebuild the hash chain from scratch
    def _hash_entry(entry: dict) -> str:
        hashable = {k: v for k, v in entry.items() if k != "entry_hash"}
        return hashlib.sha256(json.dumps(hashable, sort_keys=True).encode()).hexdigest()

    prev_hash = "genesis"
    for entry in entries:
        entry["prev_hash"] = prev_hash
        entry["entry_hash"] = _hash_entry(entry)
        prev_hash = entry["entry_hash"]

    backup = log_path.with_name(f"grcx.log.jsonl.backup-{datetime.now().strftime('%Y%m%dT%H%M%S')}")
    backup.write_text(log_path.read_text())

    log_path.write_text("\n".join(json.dumps(e) for e in entries) + "\n")

    # Update seen fingerprint files so the next poll doesn't re-process fixed items
    for seen_path_str, swaps in fp_updates.items():
        seen_path = Path(seen_path_str)
        seen = set(seen_path.read_text().splitlines()) if seen_path.exists() else set()
        for old_fp, new_fp in swaps:
            seen.discard(old_fp)
            seen.add(new_fp)
        seen_path.write_text("\n".join(seen))

    console.print(f"\n[bold green]✓[/bold green] Fixed {fixed} entries, rebuilt hash chain, updated seen fingerprints.")


def _default_config():
    return """# GRCX configuration
sentinels:
  regulatory:
    - type: rss
      url: https://www.bankofengland.co.uk/rss/publications
      jurisdiction: BOE

controls:
  framework: iso27001

resolver:
  llm: claude-3-5-sonnet
  auto_remediate: notify_only

audit:
  output: ./grcx-audit/
  sign: false
"""

