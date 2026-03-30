from grcx.sentinel.regulatory.rss import RssSentinel
from rich.console import Console
from rich.table import Table

console = Console()

sentinel = RssSentinel(
    url="https://www.bankofengland.co.uk/rss/publications",
    jurisdiction="BOE"
)

console.print("[bold]Fetching Bank of England regulatory feed...[/bold]")
items = sentinel.fetch()

if not items:
    console.print("[yellow]No new items (all already seen, or feed unreachable)[/yellow]")
else:
    table = Table(title=f"[bold green]{len(items)} New Item(s) Detected[/bold green]")
    table.add_column("Jurisdiction", style="cyan", width=12)
    table.add_column("Title", width=55)
    table.add_column("Published", width=25)
    table.add_column("Fingerprint", style="dim", width=18)

    for item in items:
        table.add_row(
            item.jurisdiction,
            item.title[:55],
            item.published[:25] if item.published else "—",
            item.fingerprint
        )

    console.print(table)

console.print("\n[dim]Run again to confirm state tracking (should show 0 new items)[/dim]")
