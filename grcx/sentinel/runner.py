# Copyright (c) 2026 Neil Lowden | GRCX | MIT License
import time
from rich.console import Console
from rich.panel import Panel
from grcx.sentinel.regulatory.rss import RssSentinel
from grcx.sentinel.regulatory.imap_email import EmailSentinel
from grcx.audit.log import AuditLog
from grcx.resolver.resolver import Resolver

console = Console()


def run(config: dict, dry_run: bool = False, poll_interval: int = 300):
    """
    Main sentinel loop. Polls all configured feeds, analyses new items
    with the resolver, and writes everything to the audit log.
    """
    audit = AuditLog(
        log_dir=config.get("audit", {}).get("output", "grcx-audit")
    )

    resolver = Resolver(config=config, audit=audit)

    # Build sentinel list from config
    sentinels = []
    for feed in config.get("sentinels", {}).get("regulatory", []) or []:
        state_dir = config.get("audit", {}).get("output", "grcx-audit")
        if feed.get("type") == "rss":
            sentinels.append(
                RssSentinel(
                    url=feed["url"],
                    jurisdiction=feed.get("jurisdiction", "UNKNOWN"),
                    state_dir=state_dir,
                )
            )
        elif feed.get("type") == "imap":
            sentinels.append(
                EmailSentinel(
                    host=feed["host"],
                    username=feed["username"],
                    jurisdiction=feed.get("jurisdiction", "UNKNOWN"),
                    sender_filter=feed.get("sender_filter", ""),
                    port=feed.get("port", 993),
                    state_dir=state_dir,
                )
            )

    if not sentinels:
        console.print("[yellow]No sentinels configured. Edit grcx.yaml to add feeds.[/yellow]")
        return

    console.print(Panel(
        f"Watching [bold]{len(sentinels)}[/bold] regulatory feed(s)\n"
        f"Poll interval: [cyan]{poll_interval}s[/cyan]\n"
        f"Mode: {'[yellow]DRY RUN[/yellow]' if dry_run else '[green]LIVE[/green]'}",
        title="[bold]GRCX Sentinel Running[/bold]",
        expand=False
    ))

    audit.write(
        event_type="grcx.started",
        summary=f"GRCX started — watching {len(sentinels)} feed(s)",
        detail={"feeds": [s.url for s in sentinels], "dry_run": dry_run}
    )

    while True:
        for sentinel in sentinels:
            try:
                items = sentinel.fetch()

                if items:
                    console.print(
                        f"[bold]{len(items)} new item(s) from "
                        f"[cyan]{sentinel.jurisdiction}[/cyan][/bold]"
                    )

                for item in items:
                    audit.write(
                        event_type="regulatory.new_publication",
                        summary=item.title,
                        severity="warning",
                        jurisdiction=item.jurisdiction,
                        source=item.url,
                        detail={
                            "fingerprint": item.fingerprint,
                            "published": item.published,
                            "summary": item.summary,
                            "feed_url": item.feed_url,
                        }
                    )

                    if not dry_run:
                        resolver.analyse(item)
                    else:
                        console.print(f"[dim][DRY RUN] Would analyse: {item.title[:60]}[/dim]")

            except Exception as e:
                console.print(f"[red]Sentinel error ({sentinel.jurisdiction}): {e}[/red]")
                audit.write(
                    event_type="sentinel.error",
                    summary=f"Sentinel error for {sentinel.jurisdiction}: {e}",
                    severity="critical",
                    jurisdiction=sentinel.jurisdiction
                )

        console.print(f"[dim]Sleeping {poll_interval}s...[/dim]")
        time.sleep(poll_interval)