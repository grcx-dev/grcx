# Copyright (c) 2026 Neil Lowden | GRCX | MIT License
import json
import time
from collections import defaultdict
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

from grcx.sentinel.regulatory.rss import RegulatoryItem, RssSentinel, compute_fingerprint
from grcx.sentinel.regulatory.imap_email import EmailSentinel
from grcx.audit.log import AuditLog
from grcx.resolver.resolver import Resolver

console = Console()


def _build_log_state(log_path: Path) -> tuple[set[str], list[RegulatoryItem]]:
    """
    Derive ingestion and resolution state entirely from the audit log.

    Returns:
      ingested_urls  — source URLs that already have a regulatory.new_publication
                       event; used to skip re-ingestion on every poll.
      unresolved     — RegulatoryItems that have a new_publication but no
                       successful resolver.assessment or resolver.no_implication
                       for any of their known fingerprints; queued for resolver
                       retry on startup (covers previous errors and missed runs).

    Fingerprint matching is intentionally broad: for each URL we track both the
    fingerprint stored in the log (may be from an older scheme) and the current
    URL-only fingerprint. This means an item resolved under any prior scheme is
    not retried, and an item resolved under the new scheme after a retry is not
    re-queued on the next restart.
    """
    if not log_path.exists():
        return set(), []

    # url -> all fingerprints ever associated with it in the log, plus the
    # current-scheme fingerprint computed from the URL itself.
    url_to_fps: dict[str, set[str]] = defaultdict(set)
    # url -> most recent RegulatoryItem reconstructed from log (for retry)
    url_to_item: dict[str, RegulatoryItem] = {}
    # fingerprints that have a successful resolver outcome
    resolved_fps: set[str] = set()

    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue

            event = e.get("event_type", "")

            if event == "regulatory.new_publication":
                url = e.get("source", "")
                fp  = e.get("detail", {}).get("fingerprint", "")
                if not url:
                    continue
                url_to_fps[url].add(fp)
                # Always include the fingerprint the current scheme would produce
                # so that a retry-resolution written under the new scheme is
                # recognised on the next startup without a separate migration step.
                url_to_fps[url].add(compute_fingerprint(url))
                url_to_item[url] = RegulatoryItem(
                    title=e.get("summary", ""),
                    url=url,
                    published=e.get("detail", {}).get("published", ""),
                    summary=e.get("detail", {}).get("summary", ""),
                    jurisdiction=e.get("jurisdiction", ""),
                    feed_url=e.get("detail", {}).get("feed_url", ""),
                )

            elif event in ("resolver.assessment", "resolver.no_implication"):
                fp = e.get("detail", {}).get("fingerprint", "")
                if fp:
                    resolved_fps.add(fp)

    ingested_urls = set(url_to_fps.keys())
    unresolved = [
        item for url, item in url_to_item.items()
        if not url_to_fps[url].intersection(resolved_fps)
    ]
    return ingested_urls, unresolved


def run(config: dict, dry_run: bool = False, poll_interval: int = 300):
    """
    Main sentinel loop. Polls all configured feeds, analyses new items
    with the resolver, and writes everything to the audit log.
    Ingestion and resolution state is derived from the audit log at startup —
    no seen-files are read or written.
    """
    audit_dir = config.get("audit", {}).get("output", "grcx-audit")
    log_path  = Path(audit_dir) / "grcx.log.jsonl"

    audit    = AuditLog(log_dir=audit_dir)
    resolver = Resolver(config=config, audit=audit)

    # ── Log-derived state ────────────────────────────────────────────────────
    ingested_urls, unresolved = _build_log_state(log_path)
    console.print(
        f"[dim]Log state: {len(ingested_urls)} ingested URL(s), "
        f"{len(unresolved)} queued for resolution[/dim]"
    )

    # ── Build sentinel list from config ─────────────────────────────────────
    sentinels = []
    for feed in config.get("sentinels", {}).get("regulatory", []) or []:
        if feed.get("type") == "rss":
            sentinels.append(
                RssSentinel(
                    url=feed["url"],
                    jurisdiction=feed.get("jurisdiction", "UNKNOWN"),
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

    # Backlog queue — drained gradually inside the poll loop, not at startup.
    # This keeps the poll loop running (new items are never delayed) and avoids
    # firing hundreds of API calls in an unthrottled burst on restart.
    backlog = list(unresolved) if not dry_run else []
    _BACKLOG_PER_CYCLE = 5   # items per cycle  →  max 30 resolver calls per cycle
    _BACKLOG_ITEM_DELAY = 1  # seconds between backlog items within a batch

    # ── Main poll loop ───────────────────────────────────────────────────────
    while True:
        # Drain a small batch from the backlog before each feed poll.
        # 5 items × 6 frameworks = ≤30 API calls per cycle; the poll_interval
        # sleep that follows provides natural spacing between batches.
        if backlog:
            batch, backlog = backlog[:_BACKLOG_PER_CYCLE], backlog[_BACKLOG_PER_CYCLE:]
            console.print(
                f"[yellow]Backlog: processing {len(batch)} item(s) "
                f"({len(backlog)} remaining)[/yellow]"
            )
            for i, item in enumerate(batch):
                try:
                    resolver.analyse(item)
                except Exception as e:
                    console.print(f"[red]Resolver retry error for '{item.title[:50]}': {e}[/red]")
                if i < len(batch) - 1:
                    time.sleep(_BACKLOG_ITEM_DELAY)

        for sentinel in sentinels:
            try:
                items = sentinel.fetch(ingested_urls)

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
                    ingested_urls.add(item.url)

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
