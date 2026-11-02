"""Wire protocol shared by the Nepticon server and the node agent.

Every application message is a UTF-8 JSON object wrapped in a 4-byte
big-endian length prefix::

    +----------------+---------------------------+
    | uint32 length  | JSON object (N bytes)     |
    +----------------+---------------------------+

The framing removes every assumption about TCP packet boundaries.  A frame
larger than :data:`MAX_FRAME_SIZE` is rejected before allocation, which keeps
a hostile or broken peer from exhausting server memory.

Authentication happens inside the ``HELLO`` frame: the shared token itself is
never transmitted.  The agent proves possession of the token with an
HMAC-SHA256 signature over a canonical string that contains a per-connection
nonce and a Unix timestamp.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import struct
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from . import PROTOCOL_VERSION

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FRAME_HEADER = struct.Struct(">I")
HEADER_SIZE = FRAME_HEADER.size  # 4 bytes
MAX_FRAME_SIZE = 32 * 1024 * 1024  # 32 MiB of JSON per frame
CHUNK_SIZE = 64 * 1024  # 64 KiB plaintext file chunks
AUTH_MAX_SKEW_SECONDS = 300
NONCE_TTL_SECONDS = 600
HMAC_ALGORITHM = "HMAC-SHA256"
GENESIS_HASH = "0" * 64

# Message types
HELLO = "HELLO"
WELCOME = "WELCOME"
AUTH_FAIL = "AUTH_FAIL"
REQUEST = "REQUEST"
RESPONSE = "RESPONSE"
PING = "PING"
PONG = "PONG"
FILE_BEGIN = "FILE_BEGIN"
FILE_CHUNK = "FILE_CHUNK"
FILE_END = "FILE_END"
FILE_ABORT = "FILE_ABORT"
GOODBYE = "GOODBYE"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ProtocolError(Exception):
    """A peer sent data that violates the envelope protocol."""


class ConnectionClosed(ProtocolError):
    """The peer closed the connection while a frame was expected."""


class FrameTooLarge(ProtocolError):
    """A frame exceeded :data:`MAX_FRAME_SIZE`."""


class AuthenticationError(Exception):
    """The HELLO handshake could not be authenticated."""


class NodeDisconnected(Exception):
    """A node went away while a request was in flight."""


class RemoteCommandError(Exception):
    """The remote agent reported a failed operation."""


class RequestTimeout(Exception):
    """No response arrived before the request deadline."""


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------


def encode_frame(payload: Dict[str, Any]) -> bytes:
    """Serialize ``payload`` into one length-prefixed UTF-8 JSON frame."""

    if not isinstance(payload, dict):
        raise TypeError("a frame payload must be a dict")
    try:
        body = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProtocolError(f"frame is not JSON serialisable: {exc}") from exc
    if len(body) > MAX_FRAME_SIZE:
        raise FrameTooLarge(
            f"frame is {len(body)} bytes, limit is {MAX_FRAME_SIZE} bytes"
        )
    return FRAME_HEADER.pack(len(body)) + body


def send_frame(sock: socket.socket, payload: Dict[str, Any]) -> None:
    """Send a single frame.  Callers must serialise concurrent sends."""

    sock.sendall(encode_frame(payload))


def recv_exact(sock: socket.socket, size: int) -> bytes:
    """Read exactly ``size`` bytes or raise :class:`ConnectionClosed`."""

    chunks = []
    remaining = size
    while remaining:
        try:
            chunk = sock.recv(remaining)
        except socket.timeout:
            raise
        if not chunk:
            raise ConnectionClosed("peer closed the connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_frame(sock: socket.socket) -> Dict[str, Any]:
    """Receive and validate one frame."""

    header = recv_exact(sock, HEADER_SIZE)
    (size,) = FRAME_HEADER.unpack(header)
    if size == 0:
        raise ProtocolError("empty frame")
    if size > MAX_FRAME_SIZE:
        raise FrameTooLarge(
            f"peer announced a {size} byte frame, limit is {MAX_FRAME_SIZE} bytes"
        )
    body = recv_exact(sock, size)
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("frame body is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise ProtocolError("frame body must be a JSON object")
    return payload


def make_frame(
    frame_type: str,
    data: Optional[Dict[str, Any]] = None,
    *,
    frame_id: Optional[str] = None,
    ts: Optional[float] = None,
) -> Dict[str, Any]:
    """Build a protocol envelope."""

    return {
        "v": PROTOCOL_VERSION,
        "type": frame_type,
        "id": frame_id or uuid.uuid4().hex,
        "ts": time.time() if ts is None else ts,
        "data": data or {},
    }


def make_response(
    request_id: str,
    *,
    ok: bool,
    result: Any = None,
    error: Optional[str] = None,
    duration_ms: float = 0.0,
) -> Dict[str, Any]:
    """Build a ``RESPONSE`` envelope for a request id."""

    return make_frame(
        RESPONSE,
        {
            "ok": bool(ok),
            "result": result,
            "error": error,
            "duration_ms": round(float(duration_ms), 3),
        },
        frame_id=request_id,
    )


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------


def token_fingerprint(token: str) -> str:
    """A stable, non-reversible identifier for a shared token."""

    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]


def auth_message(
    agent_version: str,
    hostname: str,
    nonce: str,
    timestamp: int,
) -> bytes:
    """Canonical string covered by the HELLO HMAC signature."""

    return (
        f"nepticon-hello-v1\n{agent_version}\n{hostname}\n{nonce}\n{int(timestamp)}"
    ).encode("utf-8")


def sign_hello(token: str, agent_version: str, hostname: str, nonce: str, timestamp: int) -> str:
    return hmac.new(
        token.encode("utf-8"),
        auth_message(agent_version, hostname, nonce, timestamp),
        hashlib.sha256,
    ).hexdigest()


def build_hello(
    *,
    token: str,
    hostname: str,
    os_info: str,
    arch: str,
    cpu_cores: int,
    agent_version: str,
    privilege_level: str,
    cwd: str,
    username: str,
    uptime_seconds: float,
) -> Dict[str, Any]:
    """Create a signed HELLO envelope."""

    nonce = secrets.token_hex(16)
    timestamp = int(time.time())
    signature = sign_hello(token, agent_version, hostname, nonce, timestamp)
    return make_frame(
        HELLO,
        {
            "agent_version": agent_version,
            "protocol_version": PROTOCOL_VERSION,
            "hostname": hostname,
            "os_info": os_info,
            "arch": arch,
            "cpu_cores": int(cpu_cores),
            "privilege_level": privilege_level,
            "cwd": cwd,
            "username": username,
            "uptime_seconds": round(float(uptime_seconds), 3),
            "nonce": nonce,
            "auth": {
                "algorithm": HMAC_ALGORITHM,
                "token_id": token_fingerprint(token),
                "timestamp": timestamp,
                "signature": signature,
            },
        },
    )


class NonceCache:
    """Replay protection for HELLO nonces.

    Nonces are remembered for :data:`NONCE_TTL_SECONDS`; the cache is bounded
    so a flood of failed handshakes cannot grow memory without limit.
    """

    def __init__(self, ttl: float = NONCE_TTL_SECONDS, max_entries: int = 20_000):
        self.ttl = float(ttl)
        self.max_entries = int(max_entries)
        self._entries: Dict[str, float] = {}
        self._lock = threading.Lock()

    def _purge(self, now: float) -> None:
        expired = [nonce for nonce, seen in self._entries.items() if now - seen > self.ttl]
        for nonce in expired:
            self._entries.pop(nonce, None)
        if len(self._entries) > self.max_entries:
            # Drop the oldest half; this is only a safety valve under flood.
            for nonce, _ in sorted(self._entries.items(), key=lambda item: item[1])[
                : len(self._entries) // 2
            ]:
                self._entries.pop(nonce, None)

    def check_and_store(self, nonce: str) -> bool:
        """Return ``True`` when the nonce is fresh, ``False`` on replay."""

        if not nonce or len(nonce) < 16:
            return False
        now = time.monotonic()
        with self._lock:
            self._purge(now)
            if nonce in self._entries:
                return False
            self._entries[nonce] = now
            return True


def verify_hello(
    hello: Dict[str, Any],
    token: str,
    nonces: NonceCache,
    *,
    max_skew: int = AUTH_MAX_SKEW_SECONDS,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    """Validate a HELLO frame and return its ``data`` payload.

    Raises :class:`AuthenticationError` with a non-sensitive explanation.
    """

    if hello.get("type") != HELLO:
        raise AuthenticationError("expected a HELLO frame")
    try:
        version = int(hello.get("v", 0))
    except (TypeError, ValueError):
        raise AuthenticationError("invalid protocol version") from None
    if version != PROTOCOL_VERSION:
        raise AuthenticationError("unsupported protocol version")
    data = hello.get("data")
    if not isinstance(data, dict):
        raise AuthenticationError("HELLO payload is missing")

    required = (
        "hostname",
        "os_info",
        "arch",
        "cpu_cores",
        "agent_version",
        "privilege_level",
        "cwd",
        "nonce",
        "auth",
    )
    for field in required:
        if field not in data:
            raise AuthenticationError(f"HELLO field '{field}' is missing")

    auth = data.get("auth")
    if not isinstance(auth, dict):
        raise AuthenticationError("HELLO auth block is missing")
    if auth.get("algorithm") != HMAC_ALGORITHM:
        raise AuthenticationError("unsupported authentication algorithm")

    token_id = str(auth.get("token_id", ""))
    if not hmac.compare_digest(token_id, token_fingerprint(token)):
        raise AuthenticationError("unknown token id")

    try:
        timestamp = int(auth.get("timestamp"))
    except (TypeError, ValueError):
        raise AuthenticationError("invalid auth timestamp") from None
    current = time.time() if now is None else float(now)
    if abs(current - timestamp) > max_skew:
        raise AuthenticationError("auth timestamp outside allowed clock skew")

    nonce = str(data.get("nonce"))
    expected = sign_hello(
        token,
        str(data.get("agent_version", "")),
        str(data.get("hostname", "")),
        nonce,
        timestamp,
    )
    signature = str(auth.get("signature", ""))
    if not hmac.compare_digest(expected, signature):
        raise AuthenticationError("invalid HMAC signature")
    # Only reserve a nonce after the signature is known to be valid; this
    # prevents unauthenticated peers from polluting the replay cache.
    if not nonces.check_and_store(nonce):
        raise AuthenticationError("nonce replay detected")

    if data.get("privilege_level") not in ("admin", "user"):
        raise AuthenticationError("invalid privilege level")
    if not str(data.get("hostname", "")).strip():
        raise AuthenticationError("hostname must not be empty")
    if not str(data.get("agent_version", "")).strip():
        raise AuthenticationError("agent_version must not be empty")
    try:
        cores = int(data.get("cpu_cores"))
    except (TypeError, ValueError):
        raise AuthenticationError("invalid cpu_cores") from None
    if cores < 1 or cores > 4096:
        raise AuthenticationError("cpu_cores out of range")
    if len(str(data.get("hostname", ""))) > 255:
        raise AuthenticationError("hostname too long")

    return data


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: os.PathLike[str] | str, chunk_size: int = CHUNK_SIZE) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    try:
        return base64.b64decode(data.encode("ascii"), validate=True)
    except Exception as exc:  # binascii.Error, UnicodeEncodeError
        raise ProtocolError("invalid base64 chunk") from exc


def chunk_file(path: os.PathLike[str] | str, chunk_size: int = CHUNK_SIZE) -> Iterable[bytes]:
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk_size)
            if not block:
                break
            yield block


def safe_basename(name: str, fallback: str = "transfer.bin") -> str:
    """Reduce an arbitrary peer-supplied name to a harmless basename."""

    name = str(name or "").replace("\\", "/").split("/")[-1]
    name = "".join(ch for ch in name if ch.isprintable() and ch not in '<>:"|?*')
    name = name.strip().strip(".")
    if not name or name in (".", "..") or set(name) <= {" "}:
        return fallback
    return name[:180]


def unique_path(path: Path) -> Path:
    """Return a non-existing sibling of ``path`` by appending `` (n)``."""

    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    for index in range(1, 10_000):
        candidate = path.with_name(f"{stem} ({index}){suffix}")
        if not candidate.exists():
            return candidate
    raise FileExistsError(f"could not find a free name for {path}")
