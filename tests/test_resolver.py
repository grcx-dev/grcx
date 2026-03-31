from grcx.sentinel.regulatory.rss import RssSentinel, RegulatoryItem
from grcx.resolver.resolver import Resolver
from grcx.audit.log import AuditLog

# Use a real item from the BOE feed
item = RegulatoryItem(
    title="Bank Resolution Standards Instrument: The Technical Standards (COREP13) Instrument 2026",
    url="https://www.bankofengland.co.uk/prudential-regulation/publication/2026/february/bank-resolution-standards-instrument-2026",
    published="Thu, 12 Feb 2026 10:00:00",
    summary="The PRA has published the Bank Resolution Standards Instrument 2026, which amends technical standards relating to COREP13 reporting requirements for resolution planning.",
    jurisdiction="BOE",
    feed_url="https://www.bankofengland.co.uk/rss/publications"
)

config = {
    "controls": {"frameworks": ["iso27001", "fca_sysc", "mas_trm", "nist_csf", "bcbs239", "soc2"]},
    "resolver": {"llm": "models/gemini-2.5-flash", "auto_remediate": "notify_only"},
    "audit": {"output": "grcx-audit/test-resolver"}
}

audit = AuditLog(log_dir="grcx-audit/test-resolver")
resolver = Resolver(config=config, audit=audit)

print("\n--- Running Resolver ---\n")
results = resolver.analyse(item)

print(f"\n--- Summary ({len(results)} frameworks) ---")
for r in results:
    framework = r.raw_item.jurisdiction if hasattr(r.raw_item, 'jurisdiction') else '?'
    print(f"  {'⚠' if r.has_implications else '✓'} [{r.severity}] {r.summary[:80]}")
