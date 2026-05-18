# Mutation-testing finding: no existing test caught a SHA-256 -> SHA-1 swap.
# This file pins the hash algorithm at SHA-256 specifically.
import hashlib


def test_entry_hash_is_sha256_shape(audit_log):
    """Pin the hash algorithm at SHA-256 specifically.

    Mutation-testing finding: swapping SHA-256 -> SHA-1 (or MD5) passed every
    other test in the suite because the chain-integrity property only requires
    write/verify to use the SAME hash, not a specific one. In a compliance
    product, the hash algorithm is part of the trust contract -- regulators
    expect SHA-256 (or stronger), not SHA-1 (broken since 2017) or MD5.

    This test fails on any algorithm whose hex digest length differs from 64.
    """
    entry = audit_log.write(event_type="test", summary="hash shape pin")
    h = entry["entry_hash"]
    assert len(h) == 64, (
        f"Expected SHA-256 hex digest (64 chars); got {len(h)} chars. "
        f"Has the hash algorithm been changed?"
    )
    assert all(c in "0123456789abcdef" for c in h)


def test_entry_hash_matches_independent_sha256(audit_log):
    """Stronger pin: not just SHA-256-shaped, but the actual SHA-256 of the
    canonical entry-without-hash. Catches any algorithm swap that happens to
    produce a 64-char hex output (e.g. SHA3-256, BLAKE2-256)."""
    import json
    entry = audit_log.write(event_type="test", summary="independent hash check")
    hashable = {k: v for k, v in entry.items() if k != "entry_hash"}
    expected = hashlib.sha256(
        json.dumps(hashable, sort_keys=True).encode()
    ).hexdigest()
    assert entry["entry_hash"] == expected
