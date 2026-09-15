# Tests for the IMAP connection layer in EmailSentinel.
import imaplib
import socket
import threading
import time

import pytest

from grcx.sentinel.regulatory.imap_email import EmailSentinel


class FakeIMAP:
    """Mimics the imaplib.IMAP4_SSL context-manager API."""

    def __init__(self, host, port=993, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.calls = []
        self._search_result = ("OK", [b"1 2 3"])
        self._fetch_result = ("OK", [(b"head", b"From: x\r\nSubject: hi\r\n\r\nbody")])

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def login(self, u, p):
        self.calls.append(("login", u, p))

    def select(self, mailbox, readonly=False):
        self.calls.append(("select", mailbox, readonly))

    def search(self, charset, criteria):
        return self._search_result

    def fetch(self, uid, parts):
        self.calls.append(("fetch", uid, parts))
        return self._fetch_result


def _make_sentinel(**kwargs):
    return EmailSentinel(
        host="imap.example.com",
        username="user@example.com",
        jurisdiction="TEST",
        sender_filter="alerts@example.com",
        **kwargs,
    )


def test_fetch_without_password_returns_empty_list(monkeypatch):
    monkeypatch.delenv("GRCX_IMAP_PASSWORD", raising=False)

    constructed = []

    class TrackingFakeIMAP(FakeIMAP):
        def __init__(self, host, port=993, timeout=None):
            super().__init__(host, port, timeout)
            constructed.append(self)

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.imaplib.IMAP4_SSL", TrackingFakeIMAP)

    result = _make_sentinel().fetch(set())

    assert result == []
    assert len(constructed) == 0


def test_imap_login_failure_returns_empty_list(monkeypatch):
    monkeypatch.setenv("GRCX_IMAP_PASSWORD", "pw")

    class LoginFailIMAP(FakeIMAP):
        def login(self, u, p):
            raise imaplib.IMAP4.error("bad creds")

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.imaplib.IMAP4_SSL", LoginFailIMAP)

    assert _make_sentinel().fetch(set()) == []


def test_search_returns_not_ok_returns_no_messages(monkeypatch):
    monkeypatch.setenv("GRCX_IMAP_PASSWORD", "pw")

    class NoSearchIMAP(FakeIMAP):
        def search(self, charset, criteria):
            return ("NO", [b""])

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.imaplib.IMAP4_SSL", NoSearchIMAP)

    assert _make_sentinel().fetch(set()) == []


def test_only_last_50_uids_fetched(monkeypatch):
    monkeypatch.setenv("GRCX_IMAP_PASSWORD", "pw")

    fetched_uids = []

    class Many100IMAP(FakeIMAP):
        def search(self, charset, criteria):
            uids_bytes = b" ".join(str(i).encode() for i in range(1, 101))
            return ("OK", [uids_bytes])

        def fetch(self, uid, parts):
            fetched_uids.append(uid)
            return ("OK", [(b"head", b"From: alerts@example.com\r\nSubject: Test\r\n\r\nbody")])

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.imaplib.IMAP4_SSL", Many100IMAP)

    _make_sentinel().fetch(set())

    assert len(fetched_uids) == 50
    # Last 50 UIDs should be 51..100 (as bytes)
    assert fetched_uids == [str(i).encode() for i in range(51, 101)]


def test_select_called_with_readonly_true(monkeypatch):
    monkeypatch.setenv("GRCX_IMAP_PASSWORD", "pw")

    instance_holder = []

    class TrackSelectIMAP(FakeIMAP):
        def __init__(self, host, port=993, timeout=None):
            super().__init__(host, port, timeout)
            instance_holder.append(self)

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.imaplib.IMAP4_SSL", TrackSelectIMAP)

    _make_sentinel().fetch(set())

    assert len(instance_holder) == 1
    assert ("select", "INBOX", True) in instance_holder[0].calls


def test_fetch_returning_non_ok_skipped(monkeypatch):
    monkeypatch.setenv("GRCX_IMAP_PASSWORD", "pw")

    call_count = []

    class FailFetchIMAP(FakeIMAP):
        def search(self, charset, criteria):
            return ("OK", [b"1 2 3"])

        def fetch(self, uid, parts):
            call_count.append(uid)
            return ("NO", [(b"err", b"")])

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.imaplib.IMAP4_SSL", FailFetchIMAP)

    result = _make_sentinel().fetch(set())

    assert len(call_count) == 3
    assert result == []


# ---------------------------------------------------------------------------
# Regression: connection must carry a socket timeout.
#
# Production incident 2026-09-07 — IMAP4_SSL was constructed without timeout=,
# the peer disappeared without a FIN, and imaplib blocked in read() forever with
# no kernel timer armed. Nothing raised, so the except-handler in fetch() never
# fired and the runner.py poll loop stopped dead for 7 days.
# ---------------------------------------------------------------------------


def test_connection_is_given_a_socket_timeout(monkeypatch):
    """A timeout must be passed to IMAP4_SSL — without it, reads can block forever."""
    monkeypatch.setenv("GRCX_IMAP_PASSWORD", "pw")

    seen = []

    class TimeoutTrackingIMAP(FakeIMAP):
        def __init__(self, host, port=993, timeout=None):
            super().__init__(host, port, timeout)
            seen.append(timeout)

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.imaplib.IMAP4_SSL", TimeoutTrackingIMAP)

    _make_sentinel().fetch(set())

    assert len(seen) == 1
    assert seen[0] is not None, "IMAP4_SSL constructed without a timeout"
    assert seen[0] > 0


def test_timeout_is_configurable(monkeypatch):
    monkeypatch.setenv("GRCX_IMAP_PASSWORD", "pw")

    seen = []

    class TimeoutTrackingIMAP(FakeIMAP):
        def __init__(self, host, port=993, timeout=None):
            super().__init__(host, port, timeout)
            seen.append(timeout)

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.imaplib.IMAP4_SSL", TimeoutTrackingIMAP)

    _make_sentinel(timeout=7).fetch(set())

    assert seen == [7]


def test_socket_timeout_is_caught_and_returns_empty_list(monkeypatch):
    """A timed-out read must surface as a caught error, not propagate to the runner."""
    monkeypatch.setenv("GRCX_IMAP_PASSWORD", "pw")

    class TimingOutIMAP(FakeIMAP):
        def search(self, charset, criteria):
            raise TimeoutError("timed out")

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.imaplib.IMAP4_SSL", TimingOutIMAP)

    assert _make_sentinel().fetch(set()) == []


def test_unresponsive_server_does_not_hang_forever():
    """End-to-end: a real socket that accepts and then goes silent must not wedge fetch().

    This is the exact production failure mode. Against a server that completes
    the TCP handshake and then sends nothing, the SSL handshake read blocks.
    With timeout= set it raises and fetch() returns; without it, this test hangs
    until pytest is killed.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    held = []
    stop = threading.Event()

    def accept_and_stay_silent():
        server.settimeout(30)
        try:
            conn, _ = server.accept()
            held.append(conn)   # hold the connection open, send nothing
            stop.wait(30)
        except OSError:
            pass

    thread = threading.Thread(target=accept_and_stay_silent, daemon=True)
    thread.start()

    sentinel = EmailSentinel(
        host="127.0.0.1",
        port=port,
        username="user@example.com",
        jurisdiction="TEST",
        sender_filter="alerts@example.com",
        timeout=2,
    )

    import os
    os.environ["GRCX_IMAP_PASSWORD"] = "pw"
    try:
        started = time.monotonic()
        result = sentinel.fetch(set())
        elapsed = time.monotonic() - started
    finally:
        stop.set()
        for c in held:
            c.close()
        server.close()
        thread.join(timeout=5)

    assert result == []
    assert elapsed < 15, f"fetch() took {elapsed:.1f}s — timeout did not govern the blocking read"
