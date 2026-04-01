"""Core tamper-evident logging logic for SecureLogPlug."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class VerificationResult:
    """Result payload returned by verification methods."""

    ok: bool
    index: int | None = None
    reason: str | None = None


class SecureLogPlug:
    """Tamper-evident logger built with HMAC-SHA256 hash chaining."""

    def __init__(
        self,
        secret_key: str,
        logs_file: str = "logs.json",
        alerts_file: str = "alerts.log",
    ) -> None:
        if not secret_key or not secret_key.strip():
            raise ValueError(
                "Error: Secret key is required for SecureLogPlug. "
                "Provide via --secret or SECURELOGPLUG_SECRET."
            )

        self.secret_key = secret_key.encode("utf-8")
        self.logs_path = Path(logs_file)
        self.alerts_path = Path(alerts_file)

        # Ensure files exist for plug-and-play behavior.
        self.logs_path.touch(exist_ok=True)
        self.alerts_path.touch(exist_ok=True)

    @staticmethod
    def _now_iso8601() -> str:
        """UTC timestamp in deterministic ISO-8601 format."""
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    @staticmethod
    def _canonical_data(
        index: int,
        timestamp: str,
        event_type: str,
        description: str,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        """Create deterministic data payload for hashing."""
        return {
            "index": index,
            "timestamp": timestamp,
            "event_type": event_type,
            "description": description,
            "metadata": metadata,
        }

    def _compute_hash(self, data: dict[str, Any], previous_hash: str) -> str:
        """Compute HMAC-SHA256 over canonical JSON + previous hash."""
        serialized = json.dumps(data, sort_keys=True, separators=(",", ":"))
        payload = (serialized + previous_hash).encode("utf-8")
        return hmac.new(self.secret_key, payload, hashlib.sha256).hexdigest()

    def _read_logs(self) -> list[dict[str, Any]]:
        """Read append-only JSON-lines logs file."""
        logs: list[dict[str, Any]] = []
        with self.logs_path.open("r", encoding="utf-8") as file:
            for raw_line in file:
                line = raw_line.strip()
                if not line:
                    continue
                logs.append(json.loads(line))
        return logs

    def _read_last_log(self) -> dict[str, Any] | None:
        """Read only the last log entry for faster append operations."""
        if not self.logs_path.exists() or self.logs_path.stat().st_size == 0:
            return None

        with self.logs_path.open("rb") as file:
            file.seek(0, 2)
            position = file.tell() - 1

            # Skip trailing newlines.
            while position >= 0:
                file.seek(position)
                char = file.read(1)
                if char not in (b"\n", b"\r"):
                    break
                position -= 1

            if position < 0:
                return None

            # Find start of last line.
            while position >= 0:
                file.seek(position)
                if file.read(1) == b"\n":
                    position += 1
                    break
                position -= 1
            else:
                position = 0

            file.seek(position)
            last_line = file.readline().decode("utf-8").strip()
            return json.loads(last_line) if last_line else None

    def _append_log(self, entry: dict[str, Any]) -> None:
        """Append one JSON log line without mutating older lines."""
        with self.logs_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(entry, sort_keys=True) + "\n")

    def add_log(
        self,
        event_type: str,
        description: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create, hash-chain, and append a new log entry."""
        safe_metadata = metadata or {}

        # Ensure metadata is JSON-serializable before persisting.
        try:
            json.dumps(safe_metadata, sort_keys=True)
        except TypeError as exc:
            raise ValueError("metadata must be JSON-serializable") from exc

        last_entry = self._read_last_log()
        previous_hash = last_entry["current_hash"] if last_entry else "0"
        index = (last_entry["index"] + 1) if last_entry else 1
        timestamp = self._now_iso8601()

        data = self._canonical_data(index, timestamp, event_type, description, safe_metadata)
        current_hash = self._compute_hash(data, previous_hash)

        entry = {
            **data,
            "previous_hash": previous_hash,
            "current_hash": current_hash,
        }
        self._append_log(entry)
        return entry

    def trigger_alert(self, index: int, reason: str) -> None:
        """Print and persist tamper alerts."""
        timestamp = self._now_iso8601()
        message = f"[ALERT] {timestamp} | Tampering detected at index={index}: {reason}"
        print(message)
        with self.alerts_path.open("a", encoding="utf-8") as file:
            file.write(message + "\n")

    def _verify_entries(
        self,
        logs: list[dict[str, Any]],
        *,
        emit_output: bool,
        trigger_alerts: bool,
    ) -> VerificationResult:
        """Verify integrity of provided logs with configurable side-effects."""
        expected_previous_hash = "0"

        for entry in logs:
            index = entry.get("index")
            if entry.get("previous_hash") != expected_previous_hash:
                reason = (
                    "previous_hash mismatch "
                    f"(expected {expected_previous_hash}, got {entry.get('previous_hash')})"
                )
                if emit_output:
                    print("Tampering detected")
                if trigger_alerts:
                    self.trigger_alert(index, reason)
                return VerificationResult(ok=False, index=index, reason=reason)

            data = self._canonical_data(
                index=entry["index"],
                timestamp=entry["timestamp"],
                event_type=entry["event_type"],
                description=entry["description"],
                metadata=entry.get("metadata", {}),
            )
            recomputed_hash = self._compute_hash(data, entry["previous_hash"])
            if entry.get("current_hash") != recomputed_hash:
                reason = "current_hash mismatch (entry hash does not match recomputed hash)"
                if emit_output:
                    print("Tampering detected")
                if trigger_alerts:
                    self.trigger_alert(index, reason)
                return VerificationResult(ok=False, index=index, reason=reason)

            expected_previous_hash = entry["current_hash"]

        if emit_output:
            print("Logs verified: OK")
        return VerificationResult(ok=True)

    def verify_logs(self) -> VerificationResult:
        """Verify chain integrity; stop at first tampered entry."""
        logs = self._read_logs()
        return self._verify_entries(logs, emit_output=True, trigger_alerts=True)

    def view_logs(self, verify: bool = False) -> None:
        """Pretty-print logs, optionally showing verification status."""
        logs = self._read_logs()
        if not logs:
            print("No logs found.")
            return

        tampered_index: int | None = None
        if verify:
            result = self._verify_entries(logs, emit_output=False, trigger_alerts=False)
            if not result.ok:
                tampered_index = result.index

        for entry in logs:
            idx = entry["index"]
            status = ""
            if verify:
                if tampered_index is None:
                    status = "[OK]"
                elif idx == tampered_index:
                    status = "[TAMPERED <-- first failure]"
                elif idx < tampered_index:
                    status = "[OK]"
                else:
                    status = "[UNVERIFIED]"

            print(
                f"{status} index={idx} | time={entry['timestamp']} | "
                f"event={entry['event_type']} | desc={entry['description']}"
            )
            print(f"  metadata={entry.get('metadata', {})}")
            print(f"  previous_hash={entry['previous_hash']}")
            print(f"  current_hash={entry['current_hash']}")
            print("-" * 80)

