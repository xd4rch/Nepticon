"""Tamper-evident JSONL audit logging.

Each record contains the SHA-256 hash of the previous record.  Editing,
reordering or deleting a line in the middle of the file breaks the chain and
is reported by :meth:`AuditLog.verify`.  The chain is *not* a substitute for
shipping logs to an append-only external system; it is a cheap integrity
signal that fits a single-node deployment.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any, Dict, Optional

from .protocol import GENESIS_HASH


def _utc_timestamp() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class AuditLog:
    """Thread-safe append-only audit log with a SHA-256 hash chain."""

    def __init__(self, path: os.PathLike[str] | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last_hash = self._read_last_hash()

    # -- internals ---------------------------------------------------------

    def _read_last_hash(self) -> str:
        if not self.path.is_file():
            return GENESIS_HASH
        last = ""
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        last = line
        except OSError:
            return GENESIS_HASH
        if not last:
            return GENESIS_HASH
        try:
            record = json.loads(last)
            value = str(record.get("hash", ""))
            return value if len(value) == 64 else GENESIS_HASH
        except json.JSONDecodeError:
            return GENESIS_HASH

    @staticmethod
    def _canonical(record: Dict[str, Any]) -> bytes:
        return json.dumps(
            record,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")

    # -- public API --------------------------------------------------------

    def log(
        self,
        event: str,
        *,
        severity: str = "info",
        actor: str = "fleet-console",
        node: Optional[str] = None,
        peer: Optional[str] = None,
        detail: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Append one audit record and return it (including its hash)."""

        with self._lock:
            record: Dict[str, Any] = {
                "ts": _utc_timestamp(),
                "event": str(event),
                "severity": str(severity),
                "actor": str(actor),
                "node": node,
                "peer": peer,
                "detail": detail or {},
                "prev": self._last_hash,
            }
            digest = hashlib.sha256(self._canonical(record)).hexdigest()
            record["hash"] = digest
            line = json.dumps(record, ensure_ascii=False, separators=(",", ":"), default=str)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line + "\n")
                handle.flush()
                try:
                    os.fsync(handle.fileno())
                except OSError:
                    pass
            self._last_hash = digest
            return record

    def tail(self, count: int = 20) -> list[Dict[str, Any]]:
        """Return the most recent ``count`` parsed records."""

        if not self.path.is_file() or count <= 0:
            return []
        lines: list[str] = []
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    if line.strip():
                        lines.append(line)
        except OSError:
            return []
        result: list[Dict[str, Any]] = []
        for line in lines[-count:]:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                result.append(record)
        return result

    def verify(self) -> Dict[str, Any]:
        """Recompute the hash chain.

        Returns ``{"ok", "records", "error", "line"}``.
        """

        if not self.path.is_file():
            return {"ok": True, "records": 0, "error": None, "line": None}
        expected_prev = GENESIS_HASH
        count = 0
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    count += 1
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        return {
                            "ok": False,
                            "records": count,
                            "error": "line is not valid JSON",
                            "line": number,
                        }
                    if not isinstance(record, dict):
                        return {
                            "ok": False,
                            "records": count,
                            "error": "line is not a JSON object",
                            "line": number,
                        }
                    stored_hash = str(record.get("hash", ""))
                    if str(record.get("prev")) != expected_prev:
                        return {
                            "ok": False,
                            "records": count,
                            "error": "previous-hash link is broken",
                            "line": number,
                        }
                    body = {key: value for key, value in record.items() if key != "hash"}
                    computed = hashlib.sha256(self._canonical(body)).hexdigest()
                    if computed != stored_hash:
                        return {
                            "ok": False,
                            "records": count,
                            "error": "record hash does not match its contents",
                            "line": number,
                        }
                    expected_prev = stored_hash
        except OSError as exc:
            return {"ok": False, "records": count, "error": str(exc), "line": None}
        return {"ok": True, "records": count, "error": None, "line": None}
