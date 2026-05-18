# Live smoke tests — hit real external networks.
# Skipped by default; run with: pytest -m live
import pytest

pytestmark = pytest.mark.live


def test_boe_feed_reachable_and_parsable(tmp_audit_dir):
    from grcx.sentinel.regulatory.rss import RssSentinel

    sentinel = RssSentinel(
        url="https://www.bankofengland.co.uk/rss/publications",
        jurisdiction="BOE",
        state_dir=str(tmp_audit_dir),
    )
    items = sentinel.fetch()
    # May be empty if all already seen — that's fine; no exception is the contract.
    assert isinstance(items, list)


def test_esma_feed_reachable_and_parsable(tmp_audit_dir):
    from grcx.sentinel.regulatory.rss import RssSentinel

    sentinel = RssSentinel(
        url="https://www.esma.europa.eu/rss.xml",
        jurisdiction="ESMA",
        state_dir=str(tmp_audit_dir),
    )
    items = sentinel.fetch()
    assert isinstance(items, list)
