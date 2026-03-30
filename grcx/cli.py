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
def audit(log_dir, do_verify, tail):
    """Inspect the GRCX audit log."""
    from grcx.audit.log import AuditLog
    from rich.table import Table

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

