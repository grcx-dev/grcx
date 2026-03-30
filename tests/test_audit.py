from grcx.audit.log import AuditLog

log = AuditLog(log_dir="grcx-audit/test")

# Write some entries
log.write(
    event_type="regulatory.new_publication",
    summary="BOE published: Bank Resolution Standards Instrument",
    severity="info",
    jurisdiction="BOE",
    source="https://www.bankofengland.co.uk/rss/publications",
    detail={"fingerprint": "c27fc7e11ff20420", "published": "Thu, 12 Feb 2026"}
)

log.write(
    event_type="control.breach",
    summary="TRM-12 patch cadence policy breached — new 72hr requirement",
    severity="critical",
    jurisdiction="MAS",
    detail={"control_id": "TRM-12", "required": "72h", "current": "7d"}
)

log.write(
    event_type="resolver.action",
    summary="TRM-12 remediated — patch policy updated, PR #847 raised",
    severity="info",
    jurisdiction="MAS",
    detail={"action": "github_pr", "pr_url": "https://github.com/example/repo/pull/847"}
)

# Verify chain integrity
valid, errors = log.verify()
if valid:
    print("\n✓ Audit log integrity verified — chain intact")
else:
    print(f"\n✗ Integrity errors: {errors}")
