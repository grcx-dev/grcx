# Copyright (c) 2026 Neil Lowden | GRCX | MIT License
import json
import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any
from rich.console import Console

console = Console()


class AuditLog:
    """
    Append-only audit log. Each entry is a JSON object on its own line (JSONL).
    Entries are chained — each one contains the hash of the previous entry,
    making tampering detectable.
    """

    def __init__(self, log_dir: str = "grcx-audit", sign: bool = False):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.sign = sign
        self.log_path = self.log_dir / "grcx.log.jsonl"
        self._last_hash = self._compute_last_hash()

    def _compute_last_hash(self) -> str:
        """Read the last entry's hash to chain the next entry to it."""
        if not self.log_path.exists():
            return "genesis"
        try:
            lines = self.log_path.read_text().strip().splitlines()
            if not lines:
                return "genesis"
            last = json.loads(lines[-1])
            return last.get("entry_hash", "genesis")
        except Exception:
            return "genesis"

    def _hash_entry(self, entry: dict) -> str:
        """SHA-256 hash of the entry content (excluding the hash field itself)."""
        hashable = {k: v for k, v in entry.items() if k != "entry_hash"}
        content = json.dumps(hashable, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def write(
        self,
        event_type: str,
        summary: str,
        detail: Optional[dict[str, Any]] = None,
        severity: str = "info",
        jurisdiction: Optional[str] = None,
        source: Optional[str] = None,
    ) -> dict:
        """
        Write a new entry to the audit log.

        event_type: e.g. 'regulatory.new_publication', 'control.breach', 'resolver.action'
        summary:    human-readable one-liner
        detail:     arbitrary structured data
        severity:   'info' | 'warning' | 'critical'
        """
        entry = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "severity": severity,
            "summary": summary,
            "jurisdiction": jurisdiction,
            "source": source,
            "detail": detail or {},
            "prev_hash": self._last_hash,
        }

        entry["entry_hash"] = self._hash_entry(entry)

        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

        self._last_hash = entry["entry_hash"]

        severity_colour = {
            "info": "green",
            "warning": "yellow",
            "critical": "red"
        }.get(severity, "white")

        console.print(
            f"[dim]{entry['timestamp']}[/dim] "
            f"[{severity_colour}][{severity.upper()}][/{severity_colour}] "
            f"[cyan]{event_type}[/cyan] — {summary}"
        )

        return entry

    def verify(self) -> tuple[bool, list[str]]:
        """
        Verify the integrity of the entire audit log by re-checking
        all entry hashes and the chain linkage.
        Returns (is_valid, list_of_errors).
        """
        if not self.log_path.exists():
            return True, []

        errors = []
        lines = self.log_path.read_text().strip().splitlines()
        prev_hash = "genesis"

        for i, line in enumerate(lines, 1):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                errors.append(f"Line {i}: invalid JSON")
                continue

            # Check chain linkage
            if entry.get("prev_hash") != prev_hash:
                errors.append(
                    f"Line {i}: chain broken — expected prev_hash={prev_hash}, "
                    f"got {entry.get('prev_hash')}"
                )

            # Re-compute and verify entry hash
            stored_hash = entry.get("entry_hash")
            computed_hash = self._hash_entry(entry)
            if stored_hash != computed_hash:
                errors.append(
                    f"Line {i}: hash mismatch — entry may have been tampered with"
                )

            prev_hash = entry.get("entry_hash", "")

        return len(errors) == 0, errors

    def tail(self, n: int = 10) -> list[dict]:
        """Return the last n entries."""
        if not self.log_path.exists():
            return []
        lines = self.log_path.read_text().strip().splitlines()
        return [json.loads(l) for l in lines[-n:]]