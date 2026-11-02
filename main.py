#!/usr/bin/env python3
"""Nepticon fleet server and interactive console.

The server owns a TLS listener, authenticates agents with a shared-token
HMAC handshake, tracks node health, fans commands out across the fleet and
records every operator action in a tamper-evident audit log.  The interactive
console is a prompt_toolkit application with explicit session modes:

* ``SessionMode.FLEET_CONSOLE`` — fleet overview and bulk operations
* ``SessionMode.NODE_SHELL`` — one selected node

Remote output is always treated as opaque data.  It is never passed through
``str.format`` (a v1 bug that crashed on JSON or code containing braces).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import difflib
import hashlib
import hmac
import json
import logging
import os
import shlex
import signal
import socket
import ssl
import sys
import threading
import time
import uuid
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from prompt_toolkit import PromptSession
from prompt_toolkit.application.current import get_app_or_none
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.formatted_text import ANSI
from prompt_toolkit.history import FileHistory
from prompt_toolkit.patch_stdout import patch_stdout

import assets
from nepticon import PROTOCOL_VERSION, TAGLINE, __version__
from nepticon.audit import AuditLog
from nepticon.certs import certificate_fingerprint, generate_certificates
from nepticon.config import (
    DEFAULT_CONFIG_FILE,
    ConfigError,
    Settings,
    describe_settings,
    generate_token,
    mask_token,
    open_settings,
    persist_token,
)
from nepticon.protocol import (
    AUTH_FAIL,
    CHUNK_SIZE,
    FILE_ABORT,
    FILE_BEGIN,
    FILE_CHUNK,
    FILE_END,
    GOODBYE,
    PING,
    PONG,
    REQUEST,
    RESPONSE,
    WELCOME,
    AuthenticationError,
    ConnectionClosed,
    FrameTooLarge,
    NodeDisconnected,
    NonceCache,
    ProtocolError,
    RemoteCommandError,
    RequestTimeout,
    b64decode,
    b64encode,
    make_frame,
    recv_frame,
    safe_basename,
    send_frame,
    unique_path,
    verify_hello,
)
from nepticon.telemetry import privilege_level
from nepticon.ui import (
    BLUE,
    GREEN,
    GREY,
    RED,
    RESET,
    YELLOW,
    UI,
    format_bytes,
    format_duration,
    sanitize_terminal_text,
    strip_ansi,
    truncate,
)

SERVER_VERSION = __version__
MAX_TRANSFER_BYTES = 100 * 1024**3  # 100 GiB safety limit
AUTH_FAILURE_WINDOW = 60.0
AUTH_FAILURE_LIMIT = 8
HANDSHAKE_TIMEOUT = 15.0

logger = logging.getLogger("nepticon.server")


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------


class SessionMode(Enum):
    """Explicit console mode; replaces the old ``inspect.stack()`` hack."""

    FLEET_CONSOLE = "FLEET"
    NODE_SHELL = "NODE"


FLEET_COMMANDS: Dict[str, str] = {
    "list": "List connected nodes with live latency and status",
    "nodes": "Alias for list",
    "health-all": "Collect CPU/RAM/disk telemetry from every node concurrently",
    "metrics-all": "Alias for health-all",
    "fleet-health": "Alias for health-all",
    "broadcast": "Run a command on every connected node concurrently",
    "select": "Open an interactive shell on a node (id or hostname)",
    "audit": "Show recent audit records or verify the hash chain",
    "status": "Show server configuration and security state",
    "help": "Show this command reference",
    "banner": "Reprint the Nepticon banner",
    "clear": "Clear the terminal",
    "quit": "Shut the server down gracefully",
}

NODE_COMMANDS: Dict[str, str] = {
    "health": "Live CPU, memory, disk, uptime and network telemetry",
    "metrics": "Alias for health",
    "sysinfo": "Operating system, Python and agent information",
    "ps": "Running process table (top consumers first)",
    "env": "Environment variables and service/runtime context",
    "cd": "Change the agent working directory",
    "pwd": "Print the agent working directory",
    "upload": "Upload a local file to the node (SHA-256 verified)",
    "download": "Download a node file to the server (SHA-256 verified)",
    "exec": "Explicitly run a shell command",
    "back": "Return to the fleet console",
    "disconnect": "Drop this session (the agent will reconnect)",
    "shutdown": "Terminate the agent process (use --force)",
    "help": "Show this command reference",
    "banner": "Reprint the Nepticon banner",
    "clear": "Clear the terminal",
    "quit": "Return to the fleet console",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def split_command(raw: str) -> List[str]:
    """Split a line while preserving Windows paths.

    ``shlex`` in non-POSIX mode keeps backslashes literal and leaves quotes
    around tokens; matching quotes are removed afterwards.
    """

    lexer = shlex.shlex(raw, posix=False)
    lexer.whitespace_split = True
    lexer.commenters = ""
    tokens = list(lexer)
    cleaned: List[str] = []
    for token in tokens:
        if len(token) >= 2 and token[0] == token[-1] and token[0] in ("'", '"'):
            token = token[1:-1]
        cleaned.append(token)
    return cleaned


def split_head(raw: str) -> Tuple[str, str]:
    stripped = raw.strip()
    if not stripped:
        return "", ""
    parts = stripped.split(None, 1)
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], parts[1]


def _num(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _plural(count: int, singular: str, plural: Optional[str] = None) -> str:
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def _suggest(command: str, choices: Iterable[str]) -> str:
    matches = difflib.get_close_matches(command, list(choices), n=1, cutoff=0.6)
    return f" Did you mean '{matches[0]}'?" if matches else ""


def _tls_server_context(cert: Path, key: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    except (AttributeError, ValueError):
        pass
    if hasattr(ssl, "OP_NO_COMPRESSION"):
        context.options |= ssl.OP_NO_COMPRESSION
    if hasattr(ssl, "OP_NO_RENEGOTIATION"):
        context.options |= ssl.OP_NO_RENEGOTIATION
    context.load_cert_chain(certfile=str(cert), keyfile=str(key), password=None)
    return context


def _close_socket(sock: Optional[socket.socket]) -> None:
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Connected node
# ---------------------------------------------------------------------------


class NodeSession:
    """One authenticated agent connection."""

    def __init__(
        self,
        server: "FleetServer",
        connection: ssl.SSLSocket,
        address: Tuple[str, int],
        node_id: int,
        hello: Dict[str, Any],
    ) -> None:
        self.server = server
        self.connection = connection
        self.address = address
        self.node_id = node_id
        self.hello = hello

        self.hostname = str(hello.get("hostname") or "unknown")
        self.os_info = str(hello.get("os_info") or "")
        self.arch = str(hello.get("arch") or "")
        self.cpu_cores = _int(hello.get("cpu_cores"), 0)
        self.agent_version = str(hello.get("agent_version") or "?")
        self.privilege_level = str(hello.get("privilege_level") or "user")
        self.username = str(hello.get("username") or "")
        self.cwd = str(hello.get("cwd") or "")
        self.system_uptime_base = _num(hello.get("uptime_seconds"))

        self.status = "online"
        self.latency_ms: Optional[float] = None
        self.missed_pings = 0
        self.connected_at = time.time()
        self._connected_monotonic = time.monotonic()
        self.last_seen = time.time()

        self._send_lock = threading.Lock()
        self._pending: Dict[str, concurrent.futures.Future] = {}
        self._pending_lock = threading.Lock()
        self._pongs: Dict[str, Tuple[concurrent.futures.Future, float]] = {}
        self._pong_lock = threading.Lock()
        self._downloads: Dict[str, Dict[str, Any]] = {}
        self._download_lock = threading.Lock()
        self._transfer_lock = threading.Lock()
        self._close_lock = threading.Lock()
        self._closed = threading.Event()

    # -- identity and state -------------------------------------------------

    @property
    def peer(self) -> str:
        return f"{self.address[0]}:{self.address[1]}"

    @property
    def session_uptime_seconds(self) -> float:
        return max(0.0, time.monotonic() - self._connected_monotonic)

    @property
    def system_uptime_seconds(self) -> float:
        # HELLO carries system uptime; add the time spent connected.
        return self.system_uptime_base + self.session_uptime_seconds

    @property
    def is_closed(self) -> bool:
        return self._closed.is_set()

    def label(self) -> str:
        return f"{self.node_id} · {sanitize_terminal_text(self.hostname, 48)}"

    # -- wire ---------------------------------------------------------------

    def send(self, frame: Dict[str, Any]) -> None:
        if self._closed.is_set():
            raise NodeDisconnected("connection is closed")
        with self._send_lock:
            if self._closed.is_set():
                raise NodeDisconnected("connection is closed")
            try:
                send_frame(self.connection, frame)
            except (OSError, ProtocolError) as exc:
                raise NodeDisconnected(f"send failed: {exc}") from exc

    def _register_pending(self, request_id: str, future: concurrent.futures.Future) -> bool:
        with self._pending_lock:
            if request_id in self._pending:
                return False
            self._pending[request_id] = future
            return True

    def _pop_pending(self, request_id: str) -> Optional[concurrent.futures.Future]:
        with self._pending_lock:
            return self._pending.pop(request_id, None)

    def _resolve_pending(self, request_id: str, value: Any) -> None:
        future = self._pop_pending(request_id)
        if future is not None and not future.done():
            future.set_result(value)

    def _reject_pending(self, request_id: str, error: BaseException) -> None:
        future = self._pop_pending(request_id)
        if future is not None and not future.done():
            future.set_exception(error)

    def request(
        self,
        operation: str,
        arguments: Optional[Dict[str, Any]] = None,
        *,
        timeout: Optional[float] = None,
    ) -> Any:
        request_id = uuid.uuid4().hex
        future: concurrent.futures.Future = concurrent.futures.Future()
        if not self._register_pending(request_id, future):
            raise ProtocolError("duplicate request id")
        try:
            self.send(
                make_frame(
                    REQUEST,
                    {"op": operation, "args": arguments or {}},
                    frame_id=request_id,
                )
            )
            wait_for = self.server.settings.request_timeout if timeout is None else timeout
            try:
                return future.result(timeout=wait_for)
            except concurrent.futures.TimeoutError as exc:
                raise RequestTimeout(
                    f"{self.hostname} did not answer '{operation}' within {wait_for:.1f}s"
                ) from exc
        finally:
            self._pop_pending(request_id)

    def ping(self, timeout: float = 3.0) -> float:
        request_id = uuid.uuid4().hex
        future: concurrent.futures.Future = concurrent.futures.Future()
        started = time.perf_counter()
        with self._pong_lock:
            self._pongs[request_id] = (future, started)
        try:
            self.send(make_frame(PING, {"sent_at": time.time()}, frame_id=request_id))
            try:
                latency = float(future.result(timeout=timeout))
            except concurrent.futures.TimeoutError as exc:
                self.missed_pings += 1
                self.latency_ms = None
                self.status = "unreachable" if self.missed_pings >= 3 else "degraded"
                raise RequestTimeout(f"{self.hostname} missed heartbeat") from exc
            return latency
        finally:
            with self._pong_lock:
                self._pongs.pop(request_id, None)

    def audited(
        self,
        operation: str,
        arguments: Optional[Dict[str, Any]] = None,
        *,
        timeout: Optional[float] = None,
    ) -> Any:
        started = time.perf_counter()
        try:
            result = self.request(operation, arguments, timeout=timeout)
        except Exception as exc:
            self.server.audit_command(
                self,
                operation,
                result=None,
                error=str(exc),
                duration_ms=(time.perf_counter() - started) * 1000,
            )
            raise
        self.server.audit_command(
            self,
            operation,
            result=result,
            error=None,
            duration_ms=(time.perf_counter() - started) * 1000,
        )
        return result

    def execute(self, command: str, *, timeout: Optional[float] = None) -> Dict[str, Any]:
        started = time.perf_counter()
        try:
            result = self.request("exec", {"command": command}, timeout=timeout)
        except Exception as exc:
            self.server.audit_command(
                self,
                command,
                result=None,
                error=str(exc),
                duration_ms=(time.perf_counter() - started) * 1000,
            )
            raise
        self.server.audit_command(
            self,
            command,
            result=result,
            error=None,
            duration_ms=(time.perf_counter() - started) * 1000,
        )
        return result

    # -- receive loop -------------------------------------------------------

    def serve(self) -> None:
        reason = "connection closed"
        try:
            while not self._closed.is_set():
                frame = recv_frame(self.connection)
                self.last_seen = time.time()
                self._handle_frame(frame)
        except (ConnectionClosed, OSError) as exc:
            reason = str(exc) or "connection closed"
        except (ProtocolError, FrameTooLarge) as exc:
            reason = f"protocol error: {exc}"
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("node %s reader failed", self.hostname)
            reason = f"internal error: {exc}"
        finally:
            self.close(reason)

    def _handle_frame(self, frame: Dict[str, Any]) -> None:
        frame_type = str(frame.get("type", ""))
        if frame_type == RESPONSE:
            self._handle_response(frame)
        elif frame_type == PONG:
            self._handle_pong(frame)
        elif frame_type == PING:
            try:
                self.send(
                    make_frame(
                        PONG,
                        {
                            "echo": (frame.get("data") or {}).get("sent_at"),
                            "node_id": self.node_id,
                        },
                        frame_id=frame.get("id"),
                    )
                )
            except NodeDisconnected:
                pass
        elif frame_type in (FILE_BEGIN, FILE_CHUNK, FILE_END, FILE_ABORT):
            self._handle_download_frame(frame)
        elif frame_type == GOODBYE:
            self.close("server sent goodbye")
        else:
            logger.debug("ignoring frame type %s from %s", frame_type, self.hostname)

    def _handle_response(self, frame: Dict[str, Any]) -> None:
        request_id = str(frame.get("id", ""))
        data = frame.get("data") or {}
        if not isinstance(data, dict):
            self._reject_pending(request_id, ProtocolError("malformed RESPONSE"))
            return
        if data.get("ok"):
            self._resolve_pending(request_id, data.get("result"))
        else:
            self._reject_pending(
                request_id,
                RemoteCommandError(str(data.get("error") or "remote operation failed")),
            )

    def _handle_pong(self, frame: Dict[str, Any]) -> None:
        with self._pong_lock:
            entry = self._pongs.pop(str(frame.get("id", "")), None)
        if not entry:
            return
        future, started = entry
        latency = max(0.0, (time.perf_counter() - started) * 1000.0)
        self.last_seen = time.time()
        self.latency_ms = round(latency, 3)
        self.missed_pings = 0
        if latency <= 250:
            self.status = "online"
        elif latency <= 800:
            self.status = "degraded"
        else:
            self.status = "slow"
        if not future.done():
            future.set_result(self.latency_ms)

    # -- download (agent -> server) ----------------------------------------

    def download_file(
        self,
        remote_path: str,
        *,
        dest_dir: Optional[Path] = None,
        dest_name: Optional[str] = None,
        progress: Optional[Any] = None,
    ) -> Dict[str, Any]:
        if not remote_path:
            raise ValueError("remote path is required")
        target_dir = Path(dest_dir or self.server.settings.downloads)
        target_dir.mkdir(parents=True, exist_ok=True)
        with self._transfer_lock:
            request_id = uuid.uuid4().hex
            future: concurrent.futures.Future = concurrent.futures.Future()
            if not self._register_pending(request_id, future):
                raise ProtocolError("duplicate transfer id")
            context: Dict[str, Any] = {
                "dest_dir": target_dir,
                "dest_name": dest_name,
                "progress": progress,
                "started": time.perf_counter(),
                "handle": None,
                "temp": None,
                "final": None,
                "received": 0,
                "total": 0,
                "digest": hashlib.sha256(),
                "expected_seq": 0,
                "remote_path": remote_path,
                "finished": False,
            }
            with self._download_lock:
                self._downloads[request_id] = context
            try:
                self.send(
                    make_frame(
                        REQUEST,
                        {"op": "download", "args": {"path": remote_path}},
                        frame_id=request_id,
                    )
                )
                result = future.result(timeout=self.server.settings.transfer_timeout)
            except Exception as exc:
                self._cleanup_download(request_id)
                try:
                    self.send(
                        make_frame(
                            FILE_ABORT,
                            {"reason": "receiver aborted"},
                            frame_id=request_id,
                        )
                    )
                except Exception:
                    pass
                self.server.audit_transfer(
                    self,
                    direction="download",
                    remote=remote_path,
                    local=str(context.get("final") or ""),
                    ok=False,
                    bytes_count=_int(context.get("received")),
                    sha256="",
                    duration_ms=(time.perf_counter() - context["started"]) * 1000,
                    error=str(exc),
                )
                raise
            local_path = str(result.get("path", "")) if isinstance(result, dict) else ""
            self.server.audit_transfer(
                self,
                direction="download",
                remote=remote_path,
                local=local_path,
                ok=True,
                bytes_count=_int(result.get("bytes")) if isinstance(result, dict) else 0,
                sha256=str(result.get("sha256", "")) if isinstance(result, dict) else "",
                duration_ms=(time.perf_counter() - context["started"]) * 1000,
            )
            self._cleanup_download(request_id)
            return result if isinstance(result, dict) else {"path": local_path}

    def _cleanup_download(self, request_id: str) -> None:
        with self._download_lock:
            context = self._downloads.pop(request_id, None)
        if context:
            handle = context.get("handle")
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    pass
                context["handle"] = None
            temp = context.get("temp")
            if temp:
                try:
                    Path(temp).unlink()
                except OSError:
                    pass
        self._reject_pending(request_id, NodeDisconnected("transfer aborted"))

    def _handle_download_frame(self, frame: Dict[str, Any]) -> None:
        transfer_id = str(frame.get("id", ""))
        with self._download_lock:
            context = self._downloads.get(transfer_id)
        if context is None:
            logger.debug("ignoring file frame for unknown transfer %s", transfer_id)
            return
        if context.get("finished"):
            return
        frame_type = frame.get("type")
        try:
            if frame_type == FILE_BEGIN:
                self._download_begin(transfer_id, context, frame.get("data") or {})
            elif frame_type == FILE_CHUNK:
                self._download_chunk(context, frame.get("data") or {})
            elif frame_type == FILE_END:
                self._download_end(transfer_id, context, frame.get("data") or {})
            elif frame_type == FILE_ABORT:
                raise ProtocolError(
                    str((frame.get("data") or {}).get("reason") or "sender aborted")
                )
        except Exception as exc:
            self._fail_download(transfer_id, context, exc)

    def _download_begin(
        self, transfer_id: str, context: Dict[str, Any], data: Dict[str, Any]
    ) -> None:
        if context.get("handle") is not None:
            raise ProtocolError("duplicate FILE_BEGIN")
        size = _int(data.get("size"), -1)
        if size < 0 or size > MAX_TRANSFER_BYTES:
            raise ProtocolError("invalid file size")
        offered = str(data.get("name") or "download.bin")
        wanted = str(context.get("dest_name") or offered)
        final_path = unique_path(Path(context["dest_dir"]) / safe_basename(wanted))
        temp_path = Path(context["dest_dir"]) / f".nepticon-{transfer_id[:12]}.part"
        context["handle"] = open(temp_path, "wb")
        context["temp"] = temp_path
        context["final"] = final_path
        context["total"] = size
        context["received"] = 0
        context["digest"] = hashlib.sha256()
        context["expected_seq"] = 0
        self._report_progress(context)
        logger.debug(
            "download start %s -> %s (%s bytes)", self.hostname, final_path, size
        )

    def _download_chunk(self, context: Dict[str, Any], data: Dict[str, Any]) -> None:
        handle = context.get("handle")
        if handle is None:
            raise ProtocolError("FILE_CHUNK before FILE_BEGIN")
        sequence = _int(data.get("seq"), -1)
        if sequence != context.get("expected_seq"):
            raise ProtocolError("chunk out of order")
        raw = b64decode(str(data.get("data") or ""))
        if context["received"] + len(raw) > context["total"]:
            raise ProtocolError("chunk exceeds announced file size")
        handle.write(raw)
        context["digest"].update(raw)
        context["received"] += len(raw)
        context["expected_seq"] = sequence + 1
        self._report_progress(context)

    def _download_end(
        self, transfer_id: str, context: Dict[str, Any], data: Dict[str, Any]
    ) -> None:
        handle = context.get("handle")
        if handle is None:
            raise ProtocolError("FILE_END before FILE_BEGIN")
        handle.flush()
        try:
            os.fsync(handle.fileno())
        except OSError:
            pass
        handle.close()
        context["handle"] = None
        if context["received"] != context["total"]:
            raise ProtocolError(
                f"incomplete transfer: {context['received']} of {context['total']} bytes"
            )
        actual = context["digest"].hexdigest()
        expected = str(data.get("sha256") or "").lower()
        if not expected or not hmac.compare_digest(actual, expected):
            raise ProtocolError("SHA-256 checksum mismatch")
        temp = Path(context["temp"])
        final = Path(context["final"])
        os.replace(temp, final)
        context["finished"] = True
        result = {
            "path": str(final),
            "bytes": context["received"],
            "sha256": actual,
            "duration_ms": round((time.perf_counter() - context["started"]) * 1000, 3),
        }
        self._report_progress(context)
        self._resolve_pending(transfer_id, result)

    def _fail_download(
        self, transfer_id: str, context: Dict[str, Any], exc: BaseException
    ) -> None:
        handle = context.get("handle")
        if handle is not None:
            try:
                handle.close()
            except OSError:
                pass
            context["handle"] = None
        temp = context.get("temp")
        if temp:
            try:
                Path(temp).unlink()
            except OSError:
                pass
        logger.warning("download from %s failed: %s", self.hostname, exc)
        self._reject_pending(
            transfer_id,
            ProtocolError(f"transfer failed: {exc}") if not isinstance(exc, ProtocolError) else exc,
        )

    def _report_progress(self, context: Dict[str, Any]) -> None:
        callback = context.get("progress")
        if not callback:
            return
        try:
            callback(context["received"], context["total"])
        except Exception:
            logger.debug("progress callback failed", exc_info=True)

    # -- upload (server -> agent) ------------------------------------------

    def upload_file(
        self,
        local_path: os.PathLike[str] | str,
        remote_path: Optional[str] = None,
        *,
        progress: Optional[Any] = None,
    ) -> Dict[str, Any]:
        path = Path(local_path).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"local file not found: {path}")
        size = path.stat().st_size
        if size > MAX_TRANSFER_BYTES:
            raise ValueError("file exceeds the 100 GiB transfer limit")
        with self._transfer_lock:
            started = time.perf_counter()
            digest = hashlib.sha256()
            sent = 0
            transfer_id = ""
            try:
                ready = self.request(
                    "upload",
                    {
                        "name": path.name,
                        "path": remote_path,
                        "size": size,
                    },
                    timeout=self.server.settings.request_timeout,
                )
                if not isinstance(ready, dict) or not ready.get("transfer_id"):
                    raise ProtocolError("agent did not accept the upload")
                transfer_id = str(ready["transfer_id"])
                final_future: concurrent.futures.Future = concurrent.futures.Future()
                if not self._register_pending(transfer_id, final_future):
                    raise ProtocolError("duplicate transfer id from agent")
                sequence = 0
                with path.open("rb") as handle:
                    while True:
                        block = handle.read(CHUNK_SIZE)
                        if not block:
                            break
                        digest.update(block)
                        self.send(
                            make_frame(
                                FILE_CHUNK,
                                {"seq": sequence, "data": b64encode(block)},
                                frame_id=transfer_id,
                            )
                        )
                        sequence += 1
                        sent += len(block)
                        if progress:
                            try:
                                progress(sent, size)
                            except Exception:
                                logger.debug("upload progress callback failed", exc_info=True)
                self.send(
                    make_frame(
                        FILE_END,
                        {"sha256": digest.hexdigest(), "size": sent},
                        frame_id=transfer_id,
                    )
                )
                result = final_future.result(timeout=self.server.settings.transfer_timeout)
            except Exception as exc:
                if transfer_id:
                    try:
                        self.send(
                            make_frame(
                                FILE_ABORT,
                                {"reason": "sender aborted"},
                                frame_id=transfer_id,
                            )
                        )
                    except Exception:
                        pass
                    self._reject_pending(transfer_id, exc)
                self.server.audit_transfer(
                    self,
                    direction="upload",
                    remote=str(remote_path or path.name),
                    local=str(path),
                    ok=False,
                    bytes_count=sent,
                    sha256="",
                    duration_ms=(time.perf_counter() - started) * 1000,
                    error=str(exc),
                )
                raise
            actual_sha = digest.hexdigest()
            self.server.audit_transfer(
                self,
                direction="upload",
                remote=str(result.get("path", remote_path or path.name))
                if isinstance(result, dict)
                else str(remote_path or path.name),
                local=str(path),
                ok=True,
                bytes_count=sent,
                sha256=str(result.get("sha256", actual_sha))
                if isinstance(result, dict)
                else actual_sha,
                duration_ms=(time.perf_counter() - started) * 1000,
            )
            return result if isinstance(result, dict) else {}

    # -- shutdown -----------------------------------------------------------

    def close(self, reason: str = "closed", *, send_goodbye: bool = False) -> None:
        with self._close_lock:
            if self._closed.is_set():
                return
            if send_goodbye:
                try:
                    with self._send_lock:
                        send_frame(
                            self.connection,
                            make_frame(GOODBYE, {"reason": reason}),
                        )
                except Exception:
                    pass
            self._closed.set()
            _close_socket(self.connection)

            with self._pending_lock:
                pending = list(self._pending.items())
                self._pending.clear()
            for _, future in pending:
                if not future.done():
                    future.set_exception(NodeDisconnected(reason))
            with self._pong_lock:
                pongs = list(self._pongs.values())
                self._pongs.clear()
            for future, _ in pongs:
                if not future.done():
                    future.set_exception(NodeDisconnected(reason))
            with self._download_lock:
                downloads = list(self._downloads.items())
                self._downloads.clear()
            for request_id, context in downloads:
                handle = context.get("handle")
                if handle is not None:
                    try:
                        handle.close()
                    except OSError:
                        pass
                temp = context.get("temp")
                if temp:
                    try:
                        Path(temp).unlink()
                    except OSError:
                        pass
                if not context.get("finished"):
                    # The pending future was already rejected above.
                    pass
                _ = request_id
        self.server._unregister(self, reason)


# ---------------------------------------------------------------------------
# Fleet server
# ---------------------------------------------------------------------------


class FleetServer:
    """TLS listener, node registry, audit log and fleet operations."""

    def __init__(self, settings: Settings, *, on_event: Optional[Any] = None) -> None:
        if not settings.token:
            raise ValueError("a shared authentication token is required")
        self.settings = settings
        self.on_event = on_event
        self.audit = AuditLog(settings.audit_log)
        self._context = _tls_server_context(settings.cert, settings.key)
        self._tls_fingerprint = self._read_fingerprint()

        self._nodes: Dict[int, NodeSession] = {}
        self._lock = threading.RLock()
        self._next_id = 0
        self._stop = threading.Event()
        self._started = False
        self._listener: Optional[socket.socket] = None
        self._port = settings.port
        self._accept_thread: Optional[threading.Thread] = None
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._nonces = NonceCache()
        self._auth_failures: Dict[str, List[float]] = {}
        self._auth_lock = threading.Lock()
        self._conn_slots = threading.BoundedSemaphore(128)
        self._started_at = 0.0
        self._started_monotonic = 0.0

    # -- lifecycle ----------------------------------------------------------

    @property
    def port(self) -> int:
        return self._port

    @property
    def tls_fingerprint(self) -> str:
        return self._tls_fingerprint

    @property
    def uptime_seconds(self) -> float:
        if not self._started_at:
            return 0.0
        return max(0.0, time.monotonic() - self._started_monotonic)

    @property
    def node_count(self) -> int:
        with self._lock:
            return len(self._nodes)

    def _read_fingerprint(self) -> str:
        try:
            return certificate_fingerprint(self.settings.cert)
        except Exception:
            return "unavailable"

    def start(self) -> int:
        if self._started:
            return self._port
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.settings.host, self.settings.port))
        listener.listen(128)
        listener.settimeout(0.5)
        self._listener = listener
        self._port = int(listener.getsockname()[1])
        self._started = True
        self._started_at = time.time()
        self._started_monotonic = time.monotonic()
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="nepticon-accept", daemon=True
        )
        self._accept_thread.start()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop, name="nepticon-heartbeat", daemon=True
        )
        self._heartbeat_thread.start()
        self.audit.log(
            "server_start",
            detail={
                "host": self.settings.host,
                "port": self._port,
                "certificate_sha256": self._tls_fingerprint,
                "server_version": SERVER_VERSION,
                "protocol_version": PROTOCOL_VERSION,
                "heartbeat_interval": self.settings.heartbeat_interval,
            },
        )
        logger.info(
            "Nepticon TLS listener on %s:%s", self.settings.host, self._port
        )
        return self._port

    def stop(self) -> None:
        if not self._started:
            return
        if self._stop.is_set():
            return
        self._stop.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
            self._listener = None
        for node in self.nodes_snapshot():
            node.close("server shutdown", send_goodbye=True)
        if self._accept_thread and self._accept_thread is not threading.current_thread():
            self._accept_thread.join(timeout=3)
        if self._heartbeat_thread and self._heartbeat_thread is not threading.current_thread():
            self._heartbeat_thread.join(timeout=3)
        self._started = False
        self.audit.log(
            "server_stop",
            detail={"uptime_seconds": round(self.uptime_seconds, 1)},
        )
        logger.info("Nepticon server stopped")

    # -- accept / handshake -------------------------------------------------

    def _accept_loop(self) -> None:
        assert self._listener is not None
        while not self._stop.is_set():
            try:
                connection, address = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if self._stop.is_set():
                _close_socket(connection)
                break
            try:
                connection.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except OSError:
                pass
            if not self._conn_slots.acquire(blocking=False):
                self._emit(
                    "warning",
                    None,
                    "Connection limit (128) reached; dropping new peer.",
                    "warning",
                )
                _close_socket(connection)
                continue
            threading.Thread(
                target=self._serve_connection,
                args=(connection, address),
                name="nepticon-peer",
                daemon=True,
            ).start()

    def _serve_connection(self, raw: socket.socket, address: Tuple[str, int]) -> None:
        peer = f"{address[0]}:{address[1]}"
        tls_socket: Optional[ssl.SSLSocket] = None
        node: Optional[NodeSession] = None
        try:
            raw.settimeout(HANDSHAKE_TIMEOUT)
            try:
                tls_socket = self._context.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError) as exc:
                logger.warning("TLS handshake failed for %s: %s", peer, exc)
                self.audit.log(
                    "tls_handshake_failed",
                    severity="warning",
                    peer=peer,
                    detail={"error": str(exc)},
                )
                return
            tls_socket.settimeout(HANDSHAKE_TIMEOUT)
            try:
                hello = recv_frame(tls_socket)
            except (ConnectionClosed, ProtocolError, FrameTooLarge, socket.timeout) as exc:
                self.audit.log(
                    "handshake_failed",
                    severity="warning",
                    peer=peer,
                    detail={"error": str(exc)},
                )
                _send_auth_failure(tls_socket, "invalid or incomplete HELLO")
                return

            if self._auth_blocked(address[0]):
                self.audit.log(
                    "handshake_failed",
                    severity="warning",
                    peer=peer,
                    detail={"error": "too many authentication failures"},
                )
                _send_auth_failure(tls_socket, "too many authentication failures")
                return

            try:
                data = verify_hello(hello, self.settings.token, self._nonces)
            except AuthenticationError as exc:
                self._record_auth_failure(address[0])
                self.audit.log(
                    "node_auth_failed",
                    severity="warning",
                    peer=peer,
                    detail={"reason": str(exc)},
                )
                self._emit(
                    "auth_failed",
                    None,
                    f"Rejected unauthenticated agent from {peer}: {exc}",
                    "warning",
                )
                _send_auth_failure(tls_socket, str(exc))
                return

            with self._lock:
                if len(self._nodes) >= self.settings.max_nodes:
                    self.audit.log(
                        "node_rejected",
                        severity="warning",
                        peer=peer,
                        detail={"reason": "node capacity reached", "hostname": data.get("hostname")},
                    )
                    _send_auth_failure(tls_socket, "server node capacity reached")
                    return
                if self._stop.is_set():
                    _send_auth_failure(tls_socket, "server is shutting down")
                    return
                self._next_id += 1
                node_id = self._next_id

            node = NodeSession(self, tls_socket, address, node_id, data)
            with self._lock:
                self._nodes[node_id] = node
            tls_socket.settimeout(None)
            session_id = uuid.uuid4().hex
            welcome = make_frame(
                WELCOME,
                {
                    "node_id": node_id,
                    "session_id": session_id,
                    "server_version": SERVER_VERSION,
                    "protocol_version": PROTOCOL_VERSION,
                    "server_time": time.time(),
                    "heartbeat_interval": self.settings.heartbeat_interval,
                    "features": [
                        "exec",
                        "health",
                        "sysinfo",
                        "ps",
                        "env",
                        "file-transfer-v1",
                    ],
                },
            )
            try:
                node.send(welcome)
            except NodeDisconnected:
                node.close("welcome could not be delivered")
                return
            self.audit.log(
                "node_connect",
                node=node.hostname,
                peer=peer,
                detail={
                    "node_id": node_id,
                    "hostname": node.hostname,
                    "os_info": node.os_info,
                    "arch": node.arch,
                    "cpu_cores": node.cpu_cores,
                    "agent_version": node.agent_version,
                    "privilege_level": node.privilege_level,
                    "cwd": node.cwd,
                },
            )
            self._emit(
                "connect",
                node,
                f"Node {node_id} '{node.hostname}' connected from {peer} "
                f"({node.agent_version}, {node.privilege_level})",
                "ok",
            )
            node.serve()
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("connection handler failed for %s", peer)
            self.audit.log(
                "connection_error",
                severity="error",
                peer=peer,
                detail={"error": str(exc)},
            )
        finally:
            if node is not None:
                node.close("connection ended")
            elif tls_socket is not None:
                _close_socket(tls_socket)
            else:
                _close_socket(raw)
            self._conn_slots.release()

    def _auth_blocked(self, ip: str) -> bool:
        now = time.monotonic()
        with self._auth_lock:
            history = [stamp for stamp in self._auth_failures.get(ip, []) if now - stamp < AUTH_FAILURE_WINDOW]
            if history:
                self._auth_failures[ip] = history
            else:
                self._auth_failures.pop(ip, None)
            return len(history) >= AUTH_FAILURE_LIMIT

    def _record_auth_failure(self, ip: str) -> None:
        now = time.monotonic()
        with self._auth_lock:
            history = [stamp for stamp in self._auth_failures.get(ip, []) if now - stamp < AUTH_FAILURE_WINDOW]
            history.append(now)
            self._auth_failures[ip] = history

    # -- registry -----------------------------------------------------------

    def _unregister(self, node: NodeSession, reason: str) -> None:
        with self._lock:
            existing = self._nodes.pop(node.node_id, None)
        if existing is None:
            return
        self.audit.log(
            "node_disconnect",
            node=node.hostname,
            peer=node.peer,
            detail={
                "node_id": node.node_id,
                "reason": reason,
                "session_seconds": round(node.session_uptime_seconds, 1),
            },
        )
        self._emit(
            "disconnect",
            node,
            f"Node {node.node_id} '{node.hostname}' disconnected: {reason}",
            "warning",
        )

    def nodes_snapshot(self) -> List[NodeSession]:
        with self._lock:
            return [self._nodes[key] for key in sorted(self._nodes)]

    def get_node(self, token: str) -> Tuple[Optional[NodeSession], str]:
        token = str(token or "").strip()
        if not token:
            return None, "a node id or hostname is required"
        nodes = self.nodes_snapshot()
        if token.isdigit():
            target = _int(token)
            for node in nodes:
                if node.node_id == target:
                    return node, ""
            return None, f"no node with id {target}"
        exact = [node for node in nodes if node.hostname.lower() == token.lower()]
        if len(exact) == 1:
            return exact[0], ""
        prefix = [node for node in nodes if node.hostname.lower().startswith(token.lower())]
        if len(prefix) == 1:
            return prefix[0], ""
        if len(prefix) > 1:
            return None, f"ambiguous hostname '{token}' matches {len(prefix)} nodes"
        return None, f"no node matches '{token}'"

    # -- fleet operations ---------------------------------------------------

    def refresh_latency(self, timeout: float = 2.5) -> Dict[int, Optional[float]]:
        nodes = self.nodes_snapshot()
        results: Dict[int, Optional[float]] = {}
        if not nodes:
            return results

        def probe(node: NodeSession) -> Tuple[int, Optional[float]]:
            try:
                return node.node_id, node.ping(timeout=timeout)
            except Exception:
                return node.node_id, None

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(32, len(nodes)), thread_name_prefix="npt-ping"
        ) as pool:
            for node_id, latency in pool.map(probe, nodes):
                results[node_id] = latency
        return results

    def fleet_health(self, timeout: float = 20.0) -> List[Dict[str, Any]]:
        nodes = self.nodes_snapshot()
        started = time.perf_counter()
        records: List[Dict[str, Any]] = []
        if not nodes:
            return records

        def collect(node: NodeSession) -> Dict[str, Any]:
            local_started = time.perf_counter()
            try:
                health = node.request("health", timeout=timeout)
                return {
                    "node": node,
                    "ok": True,
                    "health": health,
                    "error": "",
                    "duration_ms": (time.perf_counter() - local_started) * 1000,
                }
            except Exception as exc:
                return {
                    "node": node,
                    "ok": False,
                    "health": {},
                    "error": str(exc),
                    "duration_ms": (time.perf_counter() - local_started) * 1000,
                }

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(32, len(nodes)), thread_name_prefix="npt-health"
        ) as pool:
            records = list(pool.map(collect, nodes))
        failed = sum(1 for record in records if not record["ok"])
        self.audit.log(
            "fleet_health",
            detail={
                "nodes": len(nodes),
                "ok": len(nodes) - failed,
                "failed": failed,
                "duration_ms": round((time.perf_counter() - started) * 1000, 1),
            },
            severity="warning" if failed else "info",
        )
        return records

    def broadcast(self, command: str, timeout: Optional[float] = None) -> List[Dict[str, Any]]:
        nodes = self.nodes_snapshot()
        started = time.perf_counter()
        results: List[Dict[str, Any]] = []
        if not nodes:
            return results

        def run_on(node: NodeSession) -> Dict[str, Any]:
            local_started = time.perf_counter()
            try:
                result = node.execute(command, timeout=timeout)
                return {
                    "node": node,
                    "ok": True,
                    "result": result,
                    "error": "",
                    "duration_ms": (time.perf_counter() - local_started) * 1000,
                }
            except Exception as exc:
                return {
                    "node": node,
                    "ok": False,
                    "result": {},
                    "error": str(exc),
                    "duration_ms": (time.perf_counter() - local_started) * 1000,
                }

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(32, len(nodes)), thread_name_prefix="npt-broadcast"
        ) as pool:
            results = list(pool.map(run_on, nodes))
        failed = sum(1 for record in results if not record["ok"])
        self.audit.log(
            "broadcast",
            detail={
                "command": truncate(command, 1000),
                "nodes": len(nodes),
                "failed": failed,
                "duration_ms": round((time.perf_counter() - started) * 1000, 1),
            },
            severity="warning" if failed else "info",
        )
        return results

    # -- audit helpers ------------------------------------------------------

    def audit_command(
        self,
        node: NodeSession,
        command: str,
        *,
        result: Optional[Dict[str, Any]],
        error: Optional[str],
        duration_ms: float,
    ) -> None:
        detail: Dict[str, Any] = {
            "command": truncate(command, 2000),
            "ok": error is None,
            "duration_ms": round(float(duration_ms), 3),
        }
        if isinstance(result, dict):
            if "exit_code" in result:
                detail["exit_code"] = result.get("exit_code")
            if "timed_out" in result:
                detail["timed_out"] = result.get("timed_out")
            if "stdout" in result:
                detail["stdout_bytes"] = len(str(result.get("stdout") or ""))
            if "stderr" in result:
                detail["stderr_bytes"] = len(str(result.get("stderr") or ""))
            if result.get("truncated"):
                detail["truncated"] = True
            if "path" in result:
                detail["path"] = result.get("path")
        if error:
            detail["error"] = truncate(error, 500)
        self.audit.log(
            "command",
            node=node.hostname,
            peer=node.peer,
            detail=detail,
            severity="warning" if error else "info",
        )

    def audit_transfer(
        self,
        node: NodeSession,
        *,
        direction: str,
        remote: str,
        local: str,
        ok: bool,
        bytes_count: int,
        sha256: str,
        duration_ms: float,
        error: Optional[str] = None,
    ) -> None:
        detail: Dict[str, Any] = {
            "direction": direction,
            "remote": remote,
            "local": local,
            "bytes": int(bytes_count),
            "sha256": sha256,
            "duration_ms": round(float(duration_ms), 1),
            "ok": bool(ok),
        }
        if error:
            detail["error"] = truncate(error, 500)
        self.audit.log(
            "file_transfer",
            node=node.hostname,
            peer=node.peer,
            detail=detail,
            severity="info" if ok else "warning",
        )

    def audit_session_select(self, node: NodeSession) -> None:
        self.audit.log(
            "session_select",
            node=node.hostname,
            peer=node.peer,
            detail={"node_id": node.node_id},
        )

    # -- heartbeat ----------------------------------------------------------

    def _heartbeat_loop(self) -> None:
        interval = self.settings.heartbeat_interval
        while not self._stop.wait(interval):
            nodes = self.nodes_snapshot()
            if not nodes:
                continue
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(16, len(nodes)), thread_name_prefix="npt-heartbeat"
            ) as pool:
                for node in nodes:
                    pool.submit(self._heartbeat_node, node)

    def _heartbeat_node(self, node: NodeSession) -> None:
        try:
            node.ping(timeout=min(5.0, max(2.0, self.settings.heartbeat_interval / 2)))
        except Exception:
            if node.is_closed:
                return
            if node.missed_pings >= 3:
                # A dead TCP session must not occupy a node slot forever: the
                # agent's reconnect loop will establish a fresh authenticated
                # session as soon as it can reach the server again.
                node.close("heartbeat timeout")
                return
            node.status = "degraded"
        self._emit("state", node, "", "info")

    # -- events -------------------------------------------------------------

    def _emit(
        self,
        event: str,
        node: Optional[NodeSession],
        message: str,
        level: str = "info",
    ) -> None:
        callback = self.on_event
        if not callback:
            return
        try:
            callback(event, node, message, level)
        except Exception:
            logger.debug("event callback failed", exc_info=True)


def _send_auth_failure(connection: ssl.SSLSocket, reason: str) -> None:
    try:
        send_frame(connection, make_frame(AUTH_FAIL, {"reason": reason}))
    except Exception:
        pass
    _close_socket(connection)


# ---------------------------------------------------------------------------
# Completion
# ---------------------------------------------------------------------------


class CustomCompleter(Completer):
    """Context-aware completion for both console modes."""

    def __init__(self, console: "FleetConsole") -> None:
        self.console = console

    def get_completions(self, document: Any, complete_event: Any) -> Iterable[Completion]:
        text = document.text_before_cursor
        parts = text.split()
        if not parts or (len(parts) == 1 and not text.endswith(" ")):
            prefix = parts[0] if parts else ""
            table = (
                FLEET_COMMANDS
                if self.console.mode is SessionMode.FLEET_CONSOLE
                else NODE_COMMANDS
            )
            for command, description in table.items():
                if command.startswith(prefix):
                    yield Completion(
                        command, start_position=-len(prefix), display_meta=description
                    )
            return
        if self.console.mode is SessionMode.FLEET_CONSOLE and parts[0].lower() == "select":
            prefix = "" if text.endswith(" ") else parts[-1]
            for node in self.console.server.nodes_snapshot():
                candidate_id = str(node.node_id)
                if candidate_id.startswith(prefix):
                    yield Completion(
                        candidate_id,
                        start_position=-len(prefix),
                        display_meta=sanitize_terminal_text(node.hostname, 40),
                    )
                hostname = sanitize_terminal_text(node.hostname, 60)
                if hostname.startswith(prefix):
                    yield Completion(
                        hostname,
                        start_position=-len(prefix),
                        display_meta=f"node {candidate_id} · {node.peer}",
                    )


# ---------------------------------------------------------------------------
# Interactive console
# ---------------------------------------------------------------------------


class FleetConsole:
    """prompt_toolkit console with explicit fleet/node modes."""

    def __init__(self, server: FleetServer, settings: Settings, ui: UI) -> None:
        self.server = server
        self.settings = settings
        self.ui = ui
        self.mode = SessionMode.FLEET_CONSOLE
        self.selected: Optional[NodeSession] = None
        self.node_cwd = ""
        self.running = True
        self.last_event = "ready"
        self._state_lock = threading.RLock()
        self._local_privilege = privilege_level()
        self._fleet_session: Optional[PromptSession] = None
        self._node_session: Optional[PromptSession] = None
        self._interactive = False
        self.server.on_event = self._on_event

    # -- prompt -------------------------------------------------------------

    def _prompt_text(self) -> str:
        with self._state_lock:
            mode = self.mode
            node = self.selected
        if mode is SessionMode.NODE_SHELL and node is not None:
            hostname = sanitize_terminal_text(node.hostname, 48) or "node"
            cwd = sanitize_terminal_text(self.node_cwd or node.cwd, 64) or "?"
            label = f"Nepticon@Node[{hostname}]"
            context = cwd
            marker = "#" if node.privilege_level == "admin" else "$"
        else:
            label = "Nepticon@Fleet"
            context = f"{self.server.node_count} node{'' if self.server.node_count == 1 else 's'}"
            marker = "#" if self._local_privilege == "admin" else "$"
        if not self.ui.color:
            return f"\n┌──({label})-[{context}]\n└─{marker} "
        return (
            f"\n{BLUE}┌──({RED}{label}{BLUE})-[{YELLOW}{context}{BLUE}]\n"
            f"{BLUE}└─{RED}{marker} {RESET}"
        )

    def _plain_prompt(self) -> str:
        text = strip_ansi(self._prompt_text())
        return " ".join(text.split()) + " "

    def _bottom_toolbar(self) -> ANSI:
        with self._state_lock:
            mode = self.mode
            node = self.selected
        parts = [f" * quartrinary · Nepticon v{SERVER_VERSION}", "TLS", mode.value]
        if mode is SessionMode.NODE_SHELL and node is not None:
            parts.append(f"node {node.node_id}: {sanitize_terminal_text(node.hostname, 40)}")
            parts.append(f"peer {node.peer}")
        else:
            parts.append(f"nodes {self.server.node_count}")
        if self.last_event:
            parts.append(sanitize_terminal_text(self.last_event, 90))
        return ANSI(truncate("  |  ".join(parts), self.ui.width - 2))

    def _ensure_sessions(self) -> None:
        if self._fleet_session is not None:
            return
        completer = CustomCompleter(self)
        self._fleet_session = PromptSession(
            completer=completer,
            history=FileHistory("ns.history"),
            auto_suggest=AutoSuggestFromHistory(),
            complete_while_typing=True,
            enable_history_search=False,
        )
        self._node_session = PromptSession(
            completer=completer,
            history=FileHistory("nc.history"),
            auto_suggest=AutoSuggestFromHistory(),
            complete_while_typing=True,
            enable_history_search=False,
        )

    def _read_line(self) -> Optional[str]:
        with self._state_lock:
            mode = self.mode
        if not self._interactive:
            try:
                return input(self._plain_prompt())
            except (EOFError, KeyboardInterrupt):
                self.ui.write("")
                return None
        self._ensure_sessions()
        session = self._fleet_session if mode is SessionMode.FLEET_CONSOLE else self._node_session
        assert session is not None
        try:
            return session.prompt(
                ANSI(self._prompt_text()),
                bottom_toolbar=self._bottom_toolbar,
            )
        except KeyboardInterrupt:
            self.ui.write("^C")
            return ""
        except EOFError:
            self.ui.write("")
            return None

    # -- event bridge -------------------------------------------------------

    def _on_event(
        self,
        event: str,
        node: Optional[NodeSession],
        message: str,
        level: str = "info",
    ) -> None:
        if message:
            self.last_event = f"{time.strftime('%H:%M:%S')} {message}"
        if event in ("connect", "disconnect", "auth_failed", "warning"):
            if message:
                self.ui.notify(level, message)
        if event == "disconnect" and node is not None:
            was_selected = False
            with self._state_lock:
                if self.selected is not None and self.selected.node_id == node.node_id:
                    self.selected = None
                    self.node_cwd = ""
                    self.mode = SessionMode.FLEET_CONSOLE
                    was_selected = True
            if was_selected:
                self.ui.warn("Session closed; returned to the fleet console.")
        app = get_app_or_none()
        if app is not None:
            app.invalidate()

    # -- main loop ----------------------------------------------------------

    def run(self) -> None:
        self._interactive = bool(sys.stdin.isatty() and sys.stdout.isatty())
        context = patch_stdout(raw=True) if self._interactive else contextlib.nullcontext()
        with context:
            self.ui.info(
                "Fleet console ready. Type 'help' for commands, "
                "'list' for connected nodes, 'quit' to stop."
            )
            while self.running:
                raw = self._read_line()
                if raw is None:
                    self.running = False
                    break
                line = raw.strip()
                if not line:
                    continue
                try:
                    if self.mode is SessionMode.FLEET_CONSOLE:
                        self._handle_fleet(line)
                    else:
                        self._handle_node(line)
                except KeyboardInterrupt:
                    self.ui.write("")
                except Exception as exc:  # pragma: no cover - defensive
                    logger.exception("console command failed")
                    self.ui.error(f"Unexpected error: {exc}")
            self.ui.write("")

    # -- fleet commands -----------------------------------------------------

    def _handle_fleet(self, line: str) -> None:
        command, rest = split_head(line)
        command = command.lower()
        if command in ("quit", "exit"):
            self.running = False
        elif command in ("help", "?"):
            self._print_help()
        elif command in ("list", "nodes"):
            self._cmd_list()
        elif command in ("health-all", "metrics-all", "fleet-health"):
            self._cmd_health_all()
        elif command == "broadcast":
            self._cmd_broadcast(rest)
        elif command == "select":
            self._cmd_select(rest)
        elif command == "audit":
            self._cmd_audit(rest)
        elif command == "status":
            self._cmd_status()
        elif command == "banner":
            assets.banner(self.ui.color)
        elif command == "clear":
            self.ui.clear()
        elif not command:
            return
        else:
            self.ui.error(f"Unknown fleet command: '{command}'." + _suggest(command, FLEET_COMMANDS))

    def _cmd_list(self) -> None:
        nodes = self.server.nodes_snapshot()
        if not nodes:
            self.ui.warn("No nodes are connected.")
            return
        self.server.refresh_latency(timeout=2.5)
        rows = []
        for node in nodes:
            latency = "—" if node.latency_ms is None else f"{node.latency_ms:.1f}"
            rows.append(
                [
                    node.node_id,
                    sanitize_terminal_text(node.hostname, 32),
                    node.peer,
                    sanitize_terminal_text(node.os_info, 30),
                    node.privilege_level,
                    format_duration(node.system_uptime_seconds),
                    latency,
                    node.status,
                ]
            )
        self.ui.print_table(
            rows,
            ["ID", "HOSTNAME", "IP:PORT", "OS", "PRIVILEGE", "UPTIME", "LATENCY (ms)", "STATUS"],
        )
        online = sum(1 for node in nodes if node.status == "online")
        self.ui.info(
            f"{_plural(len(nodes), 'node')} connected; {online} online, "
            f"{len(nodes) - online} degraded/unreachable."
        )

    def _cmd_select(self, rest: str) -> None:
        if not rest.strip():
            self.ui.error("Usage: select <id|hostname>")
            return
        node, error = self.server.get_node(rest.strip())
        if node is None:
            self.ui.error(error)
            return
        with self._state_lock:
            self.selected = node
            self.node_cwd = node.cwd
            self.mode = SessionMode.NODE_SHELL
        self.server.audit_session_select(node)
        self.ui.ok(
            f"Selected node {node.node_id} '{node.hostname}' ({node.peer}). "
            "Type 'back' to return to the fleet."
        )
        self.ui.info(
            f"{node.os_info} · {node.arch} · agent {node.agent_version} · "
            f"{node.privilege_level} privilege"
        )
        self.last_event = f"{time.strftime('%H:%M:%S')} selected node {node.node_id}"
        app = get_app_or_none()
        if app is not None:
            app.invalidate()

    def _cmd_health_all(self) -> None:
        nodes = self.server.nodes_snapshot()
        if not nodes:
            self.ui.warn("No nodes are connected.")
            return
        records = self.ui.run(
            self.server.fleet_health,
            (),
            text=f"Collecting telemetry from {_plural(len(nodes), 'node')}",
            success=self.ui.paint("[+] Fleet telemetry collected.", GREEN),
            error="Telemetry collection failed.",
        )
        rows = []
        failures = []
        for record in records:
            node: NodeSession = record["node"]
            if not record["ok"]:
                failures.append((node, record["error"]))
                rows.append(
                    [
                        node.node_id,
                        sanitize_terminal_text(node.hostname, 24),
                        "—",
                        "—",
                        "—",
                        "—",
                        "—",
                        "—",
                        format_duration(node.system_uptime_seconds),
                        "—",
                        truncate(record["error"], 28),
                    ]
                )
                continue
            health = record["health"] or {}
            cpu = health.get("cpu") or {}
            memory = health.get("memory") or {}
            disk = health.get("disk") or {}
            load = cpu.get("load")
            load_text = f"{_num(load[0]):.2f}" if isinstance(load, list) and load else "n/a"
            mem_total = _num(memory.get("total_mb"))
            mem_used = _num(memory.get("used_mb"))
            links = health.get("network") or []
            rows.append(
                [
                    node.node_id,
                    sanitize_terminal_text(node.hostname, 24),
                    f"{_num(cpu.get('percent')):.1f}",
                    load_text,
                    f"{_num(memory.get('percent')):.1f}",
                    f"{mem_used / 1024:.1f}/{mem_total / 1024:.1f} GB",
                    f"{_num(disk.get('percent')):.1f}",
                    f"{_num(disk.get('free_gb')):.1f} GB",
                    format_duration(_num(health.get("uptime_seconds"))),
                    len(links),
                    "ok",
                ]
            )
        self.ui.print_table(
            rows,
            [
                "ID",
                "NODE",
                "CPU%",
                "LOAD 1M",
                "RAM%",
                "RAM USED/TOTAL",
                "DISK%",
                "DISK FREE",
                "UPTIME",
                "IFACES",
                "STATUS",
            ],
        )
        if failures:
            for node, error in failures:
                self.ui.warn(
                    f"{sanitize_terminal_text(node.hostname, 40)}: {truncate(error, 200)}"
                )

    def _cmd_broadcast(self, rest: str) -> None:
        command = rest.strip()
        if not command:
            self.ui.error("Usage: broadcast <command>")
            return
        nodes = self.server.nodes_snapshot()
        if not nodes:
            self.ui.warn("No nodes are connected.")
            return
        self.ui.info(f"Broadcasting to {_plural(len(nodes), 'node')}: {command}")
        records = self.ui.run(
            self.server.broadcast,
            (command,),
            text="Running broadcast",
            success=self.ui.paint("[+] Broadcast finished.", GREEN),
            error="Broadcast failed.",
        )
        rows = []
        for record in records:
            node: NodeSession = record["node"]
            result = record.get("result") or {}
            if record["ok"]:
                exit_code = result.get("exit_code", "?")
                rows.append(
                    [
                        node.node_id,
                        sanitize_terminal_text(node.hostname, 28),
                        exit_code,
                        f"{record['duration_ms']:.1f}",
                        "ok",
                    ]
                )
            else:
                rows.append(
                    [
                        node.node_id,
                        sanitize_terminal_text(node.hostname, 28),
                        "—",
                        f"{record['duration_ms']:.1f}",
                        truncate(record["error"], 40),
                    ]
                )
        for record in records:
            node = record["node"]
            if not record["ok"]:
                self.ui.warn(
                    f"{sanitize_terminal_text(node.hostname, 40)}: "
                    f"{truncate(record['error'], 200)}"
                )
                continue
            result = record.get("result") or {}
            stdout = str(result.get("stdout") or "")
            stderr = str(result.get("stderr") or "")
            self.ui.rule(
                f"node {node.node_id} · {sanitize_terminal_text(node.hostname, 36)} · "
                f"exit={result.get('exit_code', '?')} · {record['duration_ms']:.1f} ms"
            )
            if stdout:
                self.ui.write(stdout, end="" if stdout.endswith("\n") else "\n")
            if stderr:
                self.ui.write(stderr, end="" if stderr.endswith("\n") else "\n")
            if not stdout and not stderr:
                self.ui.write(self.ui.paint("(no output)", GREY))
            if result.get("timed_out"):
                self.ui.warn("Command timed out on this node.")
            if result.get("truncated"):
                self.ui.warn("Output was truncated by the agent.")
        self.ui.print_table(rows, ["ID", "NODE", "EXIT", "MS", "STATUS"])

    def _cmd_audit(self, rest: str) -> None:
        argument = rest.strip().lower()
        if argument == "verify":
            result = self.server.audit.verify()
            if result["ok"]:
                self.ui.ok(
                    f"Audit chain intact ({_plural(result['records'], 'record')})."
                )
            else:
                self.ui.error(
                    f"Audit chain broken at line {result['line']}: {result['error']}"
                )
            return
        count = 20
        if argument:
            try:
                count = max(1, min(500, int(argument)))
            except ValueError:
                self.ui.error("Usage: audit [count|verify]")
                return
        records = self.server.audit.tail(count)
        if not records:
            self.ui.warn(f"No audit records in {self.server.audit.path}.")
            return
        rows = []
        for record in records:
            detail = record.get("detail") or {}
            summary = _audit_summary(detail)
            rows.append(
                [
                    str(record.get("ts", ""))[11:19],
                    record.get("event", ""),
                    sanitize_terminal_text(record.get("node") or "—", 24),
                    truncate(summary, 80),
                    str(record.get("hash", ""))[:10],
                ]
            )
        self.ui.print_table(rows, ["TIME", "EVENT", "NODE", "DETAIL", "HASH"])
        self.ui.info(f"Audit log: {self.server.audit.path}")

    def _cmd_status(self) -> None:
        rows = [
            [name, f"{self.settings.host}:{self.server.port}" if name == "Endpoint" else value]
            for name, value in describe_settings(self.settings)
        ]
        rows.extend(
            [
                ["Server version", SERVER_VERSION],
                ["Protocol version", str(PROTOCOL_VERSION)],
                ["Connected nodes", str(self.server.node_count)],
                ["Server uptime", format_duration(self.server.uptime_seconds)],
                ["TLS certificate SHA-256", self.server.tls_fingerprint],
                ["TLS minimum version", "TLS 1.2"],
                ["Audit chain", "intact" if self.server.audit.verify()["ok"] else "BROKEN"],
            ]
        )
        self.ui.print_table(rows, ["SETTING", "VALUE"], colalign=("left", "left"))

    def _print_help(self) -> None:
        if self.mode is SessionMode.FLEET_CONSOLE:
            self.ui.rule("Fleet console commands")
            rows = [[name, description] for name, description in FLEET_COMMANDS.items()]
            self.ui.print_table(rows, ["COMMAND", "DESCRIPTION"])
            self.ui.info(
                "Examples: list · health-all · broadcast uptime · select 1 · audit 30"
            )
        else:
            self.ui.rule("Node shell commands")
            rows = [[name, description] for name, description in NODE_COMMANDS.items()]
            self.ui.print_table(rows, ["COMMAND", "DESCRIPTION"])
            self.ui.info("Any other input is executed as a shell command on the node.")

    # -- node commands ------------------------------------------------------

    def _require_node(self) -> Optional[NodeSession]:
        with self._state_lock:
            node = self.selected
            mode = self.mode
        if node is None or mode is not SessionMode.NODE_SHELL:
            self.ui.warn("No node is selected.")
            self._detach()
            return None
        if node.is_closed:
            self.ui.warn("The selected node disconnected.")
            self._detach()
            return None
        return node

    def _detach(self) -> None:
        with self._state_lock:
            self.selected = None
            self.node_cwd = ""
            self.mode = SessionMode.FLEET_CONSOLE
        app = get_app_or_none()
        if app is not None:
            app.invalidate()

    def _handle_node(self, line: str) -> None:
        command, rest = split_head(line)
        command = command.lower()
        node = self._require_node()
        if node is None:
            return
        if command in ("back", "exit", "quit"):
            self.ui.info("Returned to the fleet console.")
            self._detach()
        elif command in ("help", "?"):
            self._print_help()
        elif command in ("health", "metrics"):
            self._node_health(node)
        elif command == "sysinfo":
            self._node_sysinfo(node)
        elif command == "ps":
            self._node_ps(node, rest)
        elif command == "env":
            self._node_env(node)
        elif command == "cd":
            self._node_cd(node, rest)
        elif command == "pwd":
            result = self._node_call(node, "pwd")
            if result is not None:
                self.ui.write(str(result.get("cwd", "")))
                self.node_cwd = str(result.get("cwd", self.node_cwd))
        elif command == "upload":
            self._node_upload(node, rest)
        elif command == "download":
            self._node_download(node, rest)
        elif command == "disconnect":
            node.close("operator disconnected the session")
            self.ui.ok("Session closed. The agent will reconnect automatically.")
            self._detach()
        elif command == "shutdown":
            self._node_shutdown(node, rest)
        elif command == "banner":
            assets.banner(self.ui.color)
        elif command == "clear":
            self.ui.clear()
        elif command == "exec":
            if not rest.strip():
                self.ui.error("Usage: exec <command>")
            else:
                self._exec_remote(node, rest)
        else:
            self._exec_remote(node, line)

    def _node_call(
        self, node: NodeSession, operation: str, arguments: Optional[Dict[str, Any]] = None
    ) -> Optional[Any]:
        try:
            return node.audited(operation, arguments)
        except NodeDisconnected as exc:
            self._lost_node(node, str(exc))
        except RequestTimeout as exc:
            self.ui.error(str(exc))
        except RemoteCommandError as exc:
            self.ui.error(str(exc))
        except (ConnectionClosed, OSError, ProtocolError) as exc:
            self._lost_node(node, str(exc))
        except Exception as exc:  # pragma: no cover - defensive
            self.ui.error(f"Request failed: {exc}")
        return None

    def _lost_node(self, node: NodeSession, reason: str) -> None:
        self.ui.warn(f"Connection to '{node.hostname}' lost: {reason}")
        with self._state_lock:
            if self.selected is not None and self.selected.node_id == node.node_id:
                self.selected = None
                self.node_cwd = ""
                self.mode = SessionMode.FLEET_CONSOLE

    def _exec_remote(self, node: NodeSession, command: str) -> None:
        try:
            result = node.execute(command)
        except NodeDisconnected as exc:
            self._lost_node(node, str(exc))
            return
        except RequestTimeout as exc:
            self.ui.error(str(exc))
            return
        except RemoteCommandError as exc:
            self.ui.error(str(exc))
            return
        except (ConnectionClosed, OSError, ProtocolError) as exc:
            self._lost_node(node, str(exc))
            return
        self._setup_prompt_cwd(result)
        self._render_exec_result(result)

    def _setup_prompt_cwd(self, result: Any) -> None:
        if isinstance(result, dict) and result.get("cwd"):
            self.node_cwd = str(result["cwd"])
            app = get_app_or_none()
            if app is not None:
                app.invalidate()

    def _render_exec_result(self, result: Any) -> None:
        if not isinstance(result, dict):
            self.ui.info("Remote command completed.")
            return
        stdout = str(result.get("stdout") or "")
        stderr = str(result.get("stderr") or "")
        if stdout:
            self.ui.write(stdout, end="" if stdout.endswith("\n") else "\n")
        if stderr:
            self.ui.write(stderr, end="" if stderr.endswith("\n") else "\n")
        exit_code = result.get("exit_code", "?")
        duration = _num(result.get("duration_ms"))
        cwd = sanitize_terminal_text(result.get("cwd", self.node_cwd), 80)
        label = f"exit={exit_code} · {duration:.1f} ms · cwd={cwd}"
        if result.get("timed_out"):
            self.ui.warn("Command timed out. " + label)
        elif _int(exit_code, 1) != 0:
            self.ui.warn("Command failed. " + label)
        else:
            self.ui.info(label)
        if result.get("truncated"):
            self.ui.warn("Output exceeded the agent capture limit and was truncated.")

    def _node_health(self, node: NodeSession) -> None:
        health = self._node_call(node, "health")
        if not isinstance(health, dict):
            return
        cpu = health.get("cpu") or {}
        memory = health.get("memory") or {}
        disk = health.get("disk") or {}
        load = cpu.get("load")
        load_text = (
            " / ".join(f"{_num(value):.2f}" for value in load)
            if isinstance(load, list) and load
            else "n/a (Windows)"
        )
        self.ui.rule(
            f"Health · {sanitize_terminal_text(node.hostname, 40)} · {node.peer} · "
            f"{health.get('sampled_at', '')}"
        )
        rows = [
            ["Operating system", health.get("os_info", "")],
            ["Architecture", health.get("arch", "")],
            ["Privilege", health.get("privilege_level", "")],
            ["CPU cores", cpu.get("cores", "")],
            ["CPU usage", f"{_num(cpu.get('percent')):.1f}%"],
            ["Load average", load_text],
            [
                "Memory",
                f"{_num(memory.get('used_mb')):,.1f} / {_num(memory.get('total_mb')):,.1f} MiB "
                f"({_num(memory.get('percent')):.1f}% used, "
                f"{_num(memory.get('free_mb')):,.1f} MiB free)",
            ],
            [
                "Disk",
                f"{_num(disk.get('used_gb')):,.2f} / {_num(disk.get('total_gb')):,.2f} GiB "
                f"({_num(disk.get('percent')):.1f}% used, "
                f"{_num(disk.get('free_gb')):,.2f} GiB free) · {disk.get('mount', '')}",
            ],
            ["System uptime", format_duration(_num(health.get("uptime_seconds")))],
            ["Agent uptime", format_duration(_num(health.get("agent_uptime_seconds")))],
            ["Python", health.get("python_version", "")],
            ["Network interfaces", len(health.get("network") or [])],
        ]
        self.ui.print_table(rows, ["METRIC", "VALUE"], colalign=("left", "left"))
        network = health.get("network") or []
        if network:
            net_rows = [
                [
                    sanitize_terminal_text(item.get("name", ""), 28),
                    item.get("address", ""),
                    item.get("netmask", ""),
                    item.get("mac", ""),
                    item.get("state", ""),
                    item.get("gateway", ""),
                ]
                for item in network
            ]
            self.ui.print_table(
                net_rows, ["INTERFACE", "ADDRESS", "NETMASK", "MAC", "STATE", "GATEWAY"]
            )
        errors = health.get("errors") or []
        for error in errors:
            self.ui.warn(f"Telemetry warning: {truncate(error, 200)}")

    def _node_sysinfo(self, node: NodeSession) -> None:
        info = self._node_call(node, "sysinfo")
        if not isinstance(info, dict):
            return
        self.ui.rule(f"System information · {sanitize_terminal_text(node.hostname, 40)}")
        rows = [
            ["Hostname", info.get("hostname", "")],
            ["Operating system", info.get("os_info", "")],
            ["System / release", f"{info.get('system', '')} {info.get('release', '')}"],
            ["Version", info.get("version", "")],
            ["Architecture", info.get("arch", "")],
            ["CPU cores", info.get("cpu_cores", "")],
            ["Python", f"{info.get('python_version', '')} ({info.get('python_implementation', '')})"],
            ["Python executable", info.get("python_executable", "")],
            ["User", info.get("user", "")],
            ["Privilege", info.get("privilege_level", "")],
            ["PID", info.get("pid", "")],
            ["Working directory", info.get("cwd", "")],
            ["Boot time", info.get("boot_time") or "unknown"],
            ["System uptime", format_duration(_num(info.get("uptime_seconds")))],
            ["Agent uptime", format_duration(_num(info.get("agent_uptime_seconds")))],
            ["Agent started", info.get("agent_started_at", "")],
        ]
        self.ui.print_table(rows, ["FIELD", "VALUE"], colalign=("left", "left"))

    def _node_ps(self, node: NodeSession, rest: str) -> None:
        limit = 20
        if rest.strip():
            try:
                limit = max(1, min(100, int(rest.strip())))
            except ValueError:
                self.ui.error("Usage: ps [1-100]")
                return
        result = self._node_call(node, "ps", {"limit": limit})
        if not isinstance(result, dict):
            return
        processes = result.get("processes") or []
        self.ui.rule(
            f"Processes · {sanitize_terminal_text(node.hostname, 40)} · "
            f"top {len(processes)} by resident memory"
        )
        rows = [
            [
                item.get("pid", ""),
                item.get("ppid", ""),
                sanitize_terminal_text(item.get("name", ""), 40),
                f"{_num(item.get('rss_mb')):.1f}",
                item.get("threads", ""),
                item.get("state", ""),
            ]
            for item in processes
        ]
        self.ui.print_table(rows, ["PID", "PPID", "NAME", "RSS (MB)", "THREADS", "STATE"])
        self.ui.info(f"Sampled at {result.get('sampled_at', '')}.")

    def _node_env(self, node: NodeSession) -> None:
        result = self._node_call(node, "env")
        if not isinstance(result, dict):
            return
        self.ui.rule(f"Environment · {sanitize_terminal_text(node.hostname, 40)}")
        python_info = result.get("python") or {}
        runtime_rows = [
            ["Python", f"{python_info.get('version', '')} ({python_info.get('implementation', '')})"],
            ["Executable", python_info.get("executable", "")],
            ["Virtualenv", python_info.get("virtualenv") or "—"],
            ["Working directory", result.get("cwd", "")],
            ["PID", result.get("pid", "")],
            ["Environment variables", result.get("count", 0)],
            ["Secret values redacted", result.get("redacted", 0)],
        ]
        self.ui.print_table(runtime_rows, ["RUNTIME", "VALUE"], colalign=("left", "left"))
        services = result.get("services") or []
        if services:
            self.ui.print_table(
                [[item.get("name", ""), item.get("state", ""), item.get("detail", "")] for item in services],
                ["SERVICE / CONTEXT", "STATE", "DETAIL"],
            )
        variables = result.get("variables") or []
        shown = variables[:30]
        self.ui.print_table(
            [
                [
                    sanitize_terminal_text(item.get("name", ""), 32),
                    truncate(item.get("value", ""), 80),
                ]
                for item in shown
            ],
            ["VARIABLE", "VALUE"],
            colalign=("left", "left"),
        )
        if len(variables) > len(shown):
            self.ui.info(f"Showing 30 of {len(variables)} variables.")

    def _node_cd(self, node: NodeSession, rest: str) -> None:
        if not rest.strip():
            result = self._node_call(node, "pwd")
            if isinstance(result, dict):
                self.ui.write(str(result.get("cwd", "")))
                self.node_cwd = str(result.get("cwd", self.node_cwd))
            return
        try:
            arguments = split_command(rest)
        except ValueError:
            arguments = [rest]
        target = " ".join(arguments).strip() or rest.strip()
        result = self._node_call(node, "cd", {"path": target})
        if isinstance(result, dict):
            self.node_cwd = str(result.get("cwd", ""))
            self.ui.ok(f"Working directory: {self.node_cwd}")

    def _node_upload(self, node: NodeSession, rest: str) -> None:
        try:
            arguments = split_command(rest)
        except ValueError as exc:
            self.ui.error(f"Cannot parse arguments: {exc}")
            return
        if not 1 <= len(arguments) <= 2:
            self.ui.error("Usage: upload <local_path> [remote_path]")
            return
        local = Path(arguments[0]).expanduser()
        if not local.is_file():
            self.ui.error(f"Local file not found: {local}")
            return
        remote = arguments[1] if len(arguments) == 2 else None
        size = local.stat().st_size
        bar = self.ui.progress(size, f"Upload {local.name}")
        try:
            result = node.upload_file(local, remote, progress=bar.update)
        except Exception as exc:
            bar.finish()
            self.ui.error(f"Upload failed: {exc}")
            if isinstance(exc, (NodeDisconnected, ConnectionClosed, OSError)):
                self._lost_node(node, str(exc))
            return
        bar.finish()
        path = result.get("path", remote or local.name)
        sha = result.get("sha256", "")
        self.ui.ok(
            f"Uploaded {format_bytes(size)} to {path} · SHA-256 {truncate(sha, 24)} "
            "(verified)"
        )

    def _node_download(self, node: NodeSession, rest: str) -> None:
        try:
            arguments = split_command(rest)
        except ValueError as exc:
            self.ui.error(f"Cannot parse arguments: {exc}")
            return
        if not 1 <= len(arguments) <= 2:
            self.ui.error("Usage: download <remote_path> [local_path]")
            return
        remote = arguments[0]
        dest_dir: Optional[Path] = None
        dest_name: Optional[str] = None
        if len(arguments) == 2:
            local = Path(arguments[1]).expanduser()
            if arguments[1].endswith(("/", "\\")) or local.is_dir():
                dest_dir = local
            else:
                dest_dir = local.parent if str(local.parent) else Path(".")
                dest_name = local.name
        bar = self.ui.progress(0, f"Download {safe_basename(remote)}")

        def on_progress(done: int, total: int) -> None:
            if total and bar.total != total:
                bar.total = total
            bar.update(done)

        try:
            result = node.download_file(
                remote, dest_dir=dest_dir, dest_name=dest_name, progress=on_progress
            )
        except Exception as exc:
            bar.finish()
            self.ui.error(f"Download failed: {exc}")
            if isinstance(exc, (NodeDisconnected, ConnectionClosed, OSError)):
                self._lost_node(node, str(exc))
            return
        bar.finish()
        path = result.get("path", "")
        self.ui.ok(
            f"Downloaded {format_bytes(_num(result.get('bytes')))} to {path} · "
            f"SHA-256 {truncate(str(result.get('sha256', '')), 24)} (verified)"
        )

    def _node_shutdown(self, node: NodeSession, rest: str) -> None:
        if "--force" not in rest.split():
            self.ui.warn(
                "This terminates the agent process on the node. "
                "Re-run as 'shutdown --force' to confirm."
            )
            return
        try:
            result = node.audited("shutdown", {}, timeout=10)
        except Exception as exc:
            self.ui.error(f"Shutdown request failed: {exc}")
            return
        self.ui.alert(
            f"Agent on '{sanitize_terminal_text(node.hostname, 40)}' is terminating: "
            f"{truncate(result.get('message', 'acknowledged') if isinstance(result, dict) else 'acknowledged', 120)}"
        )
        node.close("agent shutdown requested")
        self._detach()


def _audit_summary(detail: Dict[str, Any]) -> str:
    if not isinstance(detail, dict):
        return truncate(str(detail), 100)
    for key in ("command", "reason", "error"):
        if detail.get(key):
            return f"{key}: {truncate(detail[key], 90)}"
    if detail.get("direction"):
        return (
            f"{detail.get('direction')}: {truncate(detail.get('remote', ''), 50)} "
            f"({detail.get('bytes', 0)} bytes, {'ok' if detail.get('ok') else 'failed'})"
        )
    if detail.get("hostname"):
        return f"hostname: {truncate(detail['hostname'], 60)}"
    try:
        return truncate(json.dumps(detail, ensure_ascii=False), 100)
    except (TypeError, ValueError):
        return truncate(str(detail), 100)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description=(
            f"Nepticon {__version__} — {TAGLINE}. "
            "Starts the TLS fleet server and the interactive console."
        ),
    )
    parser.add_argument("--host", help="Bind address (default 0.0.0.0)")
    parser.add_argument("--port", type=int, help="TLS listener port (default 1536)")
    parser.add_argument("--token", help="Shared HMAC authentication token")
    parser.add_argument("--cert", help="Server certificate PEM path")
    parser.add_argument("--key", help="Server private key PEM path")
    parser.add_argument("--ca", help="CA certificate path used for documentation/trust")
    parser.add_argument("--audit-log", help="Audit JSONL path (default logs/audit.jsonl)")
    parser.add_argument("--downloads", help="Directory for received files")
    parser.add_argument("--config", dest="config_path", metavar="FILE", help="JSON config file")
    parser.add_argument("--heartbeat", dest="heartbeat_interval", type=float, help="Heartbeat seconds")
    parser.add_argument("--request-timeout", dest="request_timeout", type=float, help="Request timeout seconds")
    parser.add_argument("--transfer-timeout", dest="transfer_timeout", type=float, help="Transfer timeout seconds")
    parser.add_argument("--max-nodes", dest="max_nodes", type=int, help="Maximum concurrent nodes")
    parser.add_argument(
        "--generate-certs",
        nargs="?",
        const="",
        default=None,
        metavar="DIR",
        help="Generate a local CA and server certificate, then exit",
    )
    parser.add_argument(
        "--force-certs",
        action="store_true",
        help="Overwrite existing certificates with --generate-certs",
    )
    parser.add_argument(
        "--san",
        action="append",
        default=[],
        metavar="NAME",
        help="Additional DNS name or IP for the certificate SAN (repeatable)",
    )
    parser.add_argument(
        "--no-color", dest="color", action="store_false", default=None, help="Disable ANSI colour"
    )
    parser.add_argument(
        "--no-animations",
        dest="animations",
        action="store_false",
        default=None,
        help="Disable spinners",
    )
    parser.add_argument("--verbose", action="store_true", default=None, help="Verbose logging")
    parser.add_argument("--version", action="version", version=f"Nepticon {__version__}")
    return parser


def _cli_values(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "host": args.host,
        "port": args.port,
        "token": args.token,
        "cert": args.cert,
        "key": args.key,
        "ca": args.ca,
        "audit_log": args.audit_log,
        "downloads": args.downloads,
        "heartbeat_interval": args.heartbeat_interval,
        "request_timeout": args.request_timeout,
        "transfer_timeout": args.transfer_timeout,
        "max_nodes": args.max_nodes,
        "config_path": args.config_path,
        "color": args.color,
        "animations": args.animations,
        "verbose": args.verbose,
    }


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _install_sigterm_handler() -> None:
    """Make ``SIGTERM`` unwind through the normal cleanup path on Linux."""

    def _terminate(signum: int, frame: Any) -> None:
        raise SystemExit(128 + int(signum))

    try:
        signal.signal(signal.SIGTERM, _terminate)
    except (AttributeError, OSError, ValueError):
        pass


def _ensure_tls_material(settings: Settings, san: Sequence[str], ui: UI) -> None:
    if settings.cert.is_file() and settings.key.is_file():
        return
    if settings.cert.parent != settings.key.parent:
        raise ConfigError("certificate and key must share a directory for auto-generation")
    ui.warn(
        "TLS certificate/key not found — generating a local development CA and "
        "server certificate."
    )
    paths = generate_certificates(
        settings.cert.parent,
        hostname=socket.gethostname(),
        extra_sans=san,
        cert_name=settings.cert.name,
        key_name=settings.key.name,
        ca_name=settings.ca.name,
    )
    ui.ok(f"CA certificate: {paths['ca']}")
    ui.ok(f"Server certificate: {paths['cert']}")
    ui.info(f"Server certificate SHA-256: {certificate_fingerprint(paths['cert'])}")
    ui.warn(
        "This is a lab certificate. Use certificates from your PKI in production "
        "and distribute the CA certificate to agents."
    )


def _generate_certs_command(args: argparse.Namespace, settings: Settings, ui: UI) -> int:
    directory = Path(args.generate_certs).expanduser() if args.generate_certs else settings.cert.parent
    cert_path = directory / settings.cert.name
    key_path = directory / settings.key.name
    ca_path = directory / settings.ca.name
    if not args.force_certs and cert_path.is_file() and key_path.is_file() and ca_path.is_file():
        ui.info("Certificates already exist; use --force-certs to regenerate them.")
        ui.info(f"Server certificate SHA-256: {certificate_fingerprint(cert_path)}")
        return 0
    paths = generate_certificates(
        directory,
        hostname=socket.gethostname(),
        extra_sans=args.san,
        cert_name=settings.cert.name,
        key_name=settings.key.name,
        ca_name=settings.ca.name,
        force=args.force_certs,
    )
    ui.ok(f"Generated CA: {paths['ca']}")
    ui.ok(f"Generated server certificate: {paths['cert']}")
    ui.ok(f"Generated server key: {paths['key']}")
    ui.info(f"Server certificate SHA-256: {certificate_fingerprint(paths['cert'])}")
    ui.warn("Protect the private keys and distribute only the CA certificate to agents.")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        settings = open_settings(
            "server", cli=_cli_values(args), config_path=args.config_path
        )
    except ConfigError as exc:
        print(f"[!] Configuration error: {exc}", file=sys.stderr)
        return 2

    ui = UI(color=settings.color, animations=settings.animations)
    _configure_logging(settings.verbose)
    assets.banner(ui.color)
    for warning in settings.warnings:
        ui.warn(warning)

    try:
        if args.generate_certs is not None:
            return _generate_certs_command(args, settings, ui)
        _ensure_tls_material(settings, args.san, ui)

        if not settings.token:
            token = generate_token()
            target = persist_token(
                token, settings.config_path or DEFAULT_CONFIG_FILE
            )
            settings.token = token
            settings.config_path = target
            ui.warn(
                "No shared token was configured. Generated a strong token and saved "
                f"it to {target} (mode 0600)."
            )
            ui.info(f"Shared token: {token}")
            ui.info(
                "Provide the same token to agents via config.json, "
                "NEPTICON_TOKEN or --token."
            )
        else:
            ui.info(f"Shared token: {mask_token(settings.token)}")

        server = FleetServer(settings)
        port = ui.run(
            server.start,
            (),
            text="Starting TLS listener",
            success=ui.paint("[+] TLS listener ready.", GREEN),
            error="Could not start the TLS listener.",
        )
        ui.info(
            f"Listening on {settings.host}:{port} · audit log {settings.audit_log}"
        )
        ui.info(f"Server certificate SHA-256: {server.tls_fingerprint}")
        if settings.host in ("0.0.0.0", "::"):
            ui.info(
                "Agents can connect with: python client.py --host <this-host> "
                "--port " + str(port)
            )
        _install_sigterm_handler()
        console = FleetConsole(server, settings, ui)
        try:
            console.run()
        finally:
            ui.info("Shutting down fleet server...")
            server.on_event = None
            server.stop()
            ui.alert("Nepticon stopped.")
        return 0
    except FileExistsError as exc:
        ui.error(str(exc))
        return 2
    except (ConfigError, ssl.SSLError, OSError) as exc:
        ui.error(f"Startup failed: {exc}")
        return 2
    except KeyboardInterrupt:
        ui.write("")
        return 130


if __name__ == "__main__":
    sys.exit(main())
