# Tests for the IMAP connection layer in EmailSentinel.
import imaplib
import pytest

from grcx.sentinel.regulatory.imap_email import EmailSentinel


class FakeIMAP:
    """Mimics the imaplib.IMAP4_SSL context-manager API."""

    def __init__(self, host, port=993):
        self.host = host
        self.port = port
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


def _make_sentinel(tmp_path):
    return EmailSentinel(
        host="imap.example.com",
        username="user@example.com",
        jurisdiction="TEST",
        sender_filter="alerts@example.com",
        state_dir=str(tmp_path / "grcx-audit"),
    )


def test_fetch_without_password_returns_empty_list(monkeypatch, tmp_path):
    monkeypatch.delenv("GRCX_IMAP_PASSWORD", raising=False)

    constructed = []

    class TrackingFakeIMAP(FakeIMAP):
        def __init__(self, host, port=993):
            super().__init__(host, port)
            constructed.append(self)

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.imaplib.IMAP4_SSL", TrackingFakeIMAP)

    sentinel = _make_sentinel(tmp_path)
    result = sentinel.fetch()

    assert result == []
    assert len(constructed) == 0


def test_imap_login_failure_returns_empty_list(monkeypatch, tmp_path):
    monkeypatch.setenv("GRCX_IMAP_PASSWORD", "pw")

    class LoginFailIMAP(FakeIMAP):
        def login(self, u, p):
            raise imaplib.IMAP4.error("bad creds")

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.imaplib.IMAP4_SSL", LoginFailIMAP)

    sentinel = _make_sentinel(tmp_path)
    result = sentinel.fetch()

    assert result == []


def test_search_returns_not_ok_returns_no_messages(monkeypatch, tmp_path):
    monkeypatch.setenv("GRCX_IMAP_PASSWORD", "pw")

    class NoSearchIMAP(FakeIMAP):
        def search(self, charset, criteria):
            return ("NO", [b""])

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.imaplib.IMAP4_SSL", NoSearchIMAP)

    sentinel = _make_sentinel(tmp_path)
    result = sentinel.fetch()

    assert result == []


def test_only_last_50_uids_fetched(monkeypatch, tmp_path):
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

    sentinel = _make_sentinel(tmp_path)
    sentinel.fetch()

    assert len(fetched_uids) == 50
    # Last 50 UIDs should be 51..100 (as bytes)
    expected = [str(i).encode() for i in range(51, 101)]
    assert fetched_uids == expected


def test_select_called_with_readonly_true(monkeypatch, tmp_path):
    monkeypatch.setenv("GRCX_IMAP_PASSWORD", "pw")

    instance_holder = []

    class TrackSelectIMAP(FakeIMAP):
        def __init__(self, host, port=993):
            super().__init__(host, port)
            instance_holder.append(self)

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.imaplib.IMAP4_SSL", TrackSelectIMAP)

    sentinel = _make_sentinel(tmp_path)
    sentinel.fetch()

    assert len(instance_holder) == 1
    imap = instance_holder[0]
    assert ("select", "INBOX", True) in imap.calls


def test_fetch_returning_non_ok_skipped(monkeypatch, tmp_path):
    monkeypatch.setenv("GRCX_IMAP_PASSWORD", "pw")

    call_count = []

    class FailFetchIMAP(FakeIMAP):
        def search(self, charset, criteria):
            return ("OK", [b"1 2 3"])

        def fetch(self, uid, parts):
            call_count.append(uid)
            # Return non-OK for all fetches
            return ("NO", [(b"err", b"")])

    monkeypatch.setattr("grcx.sentinel.regulatory.imap_email.imaplib.IMAP4_SSL", FailFetchIMAP)

    sentinel = _make_sentinel(tmp_path)
    result = sentinel.fetch()

    # fetch() was called for all three UIDs (1, 2, 3)
    assert len(call_count) == 3
    # But no messages parsed — result is empty list (no items with new fingerprints)
    assert result == []
