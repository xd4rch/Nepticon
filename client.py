#!/usr/bin/env python3
"""Nepticon node agent.

The agent connects *out* to the fleet server over TLS, proves possession of
the shared token with an HMAC-signed HELLO frame, then serves authenticated
requests (shell, telemetry, file transfer).  It reconnects with exponential
backoff and creates a fresh socket for every attempt, so a failed handshake
can never poison the next one.

The agent has no inbound listener: a node only needs outbound access to the
server port.  This is deliberate and documented in the README's security
model.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import getpass
import hashlib
import hmac
import locale
import logging
import os
import platform
import random
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Sequence

import assets
from nepticon import PROTOCOL_VERSION, TAGLINE, __version__
from nepticon.config import (
    ConfigError,
    Settings,
    open_settings,
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
    WELCOME,
    AuthenticationError,
    ConnectionClosed,
    FrameTooLarge,
    ProtocolError,
    b64decode,
    b64encode,
    build_hello,
    make_frame,
    make_response,
    recv_frame,
    safe_basename,
    send_frame,
    unique_path,
)
from nepticon.telemetry import Telemetry, privilege_level
from nepticon.ui import UI, coloring as _ui_coloring

AGENT_VERSION = __version__
MAX_TRANSFER_BYTES = 100 * 1024**3
MAX_OUTPUT_CHARS = 2_000_000
DEFAULT_COMMAND_TIMEOUT = 120.0
MAX_COMMAND_TIMEOUT = 300.0

logger = logging.getLogger("nepticon.agent")


def coloring(string: str, *args: Any) -> str:
    """Colour a tagged console message and always return text.

    The v1 implementation accidentally returned the module-level
    ``SSLContext`` (``return context``), which corrupted agent messages and
    leaked a TLS object into output paths.  This wrapper keeps the familiar
    helper name while delegating to the shared, tested implementation.
    """

    return _ui_coloring(string, *args)


class AgentConnectionLost(Exception):
    """The current TLS session is gone; the reconnect loop owns recovery."""


def _build_client_context(settings: Settings) -> ssl.SSLContext:
    if settings.insecure:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        ca = settings.ca if settings.ca.is_file() else settings.cert
        if not ca.is_file():
            raise ConfigError(
                f"trust anchor not found: {ca} (use --ca, NEPTICON_CA/NEPTICON_CERT, "
                "or --insecure for a lab)"
            )
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca))
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
    try:
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    except (AttributeError, ValueError):
        pass
    if hasattr(ssl, "OP_NO_COMPRESSION"):
        context.options |= ssl.OP_NO_COMPRESSION
    return context


def _raise_keyboard_interrupt(signum: int, frame: Any) -> None:
    raise KeyboardInterrupt


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


def _decode_output(data: bytes) -> str:
    if not data:
        return ""
    encoding = locale.getpreferredencoding(False) or "utf-8"
    for candidate in (encoding, "utf-8", "cp1254", "cp1252"):
        try:
            return data.decode(candidate)
        except (LookupError, UnicodeDecodeError):
            continue
    return data.decode("utf-8", errors="replace")


def _truncate_output(text: str, limit: int = MAX_OUTPUT_CHARS) -> tuple[str, bool]:
    if len(text) <= limit:
        return text, False
    half = max(1000, limit // 2)
    return (
        text[:half]
        + "\n\n...[output truncated by Nepticon agent]...\n\n"
        + text[-half:],
        True,
    )


class Agent:
    """Reconnecting Nepticon node agent."""

    def __init__(self, settings: Settings, ui: Optional[UI] = None) -> None:
        if not settings.token:
            raise ConfigError(
                "no shared token configured; pass --token, set NEPTICON_TOKEN "
                "or provide config.json"
            )
        self.settings = settings
        self.ui = ui
        self.telemetry = Telemetry()
        self._context = _build_client_context(settings)
        self._stop = threading.Event()
        self._socket: Optional[ssl.SSLSocket] = None
        self._socket_lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="npt-agent"
        )
        self._uploads: Dict[str, Dict[str, Any]] = {}
        self._upload_lock = threading.Lock()
        self._cwd_lock = threading.Lock()
        self.node_id: Optional[int] = None
        self.session_id: Optional[str] = None
        self.server_version = ""
        self.connected = threading.Event()
        self._fatal_error: Optional[str] = None
        self._launcher: Optional[threading.Thread] = None

    # -- logging ------------------------------------------------------------

    def _notify(self, level: str, message: str) -> None:
        if self.ui is not None:
            getattr(self.ui, level, self.ui.info)(message)
        else:
            getattr(logger, "warning" if level in ("warn", "error") else "info")(
                "%s", message
            )

    # -- lifecycle ----------------------------------------------------------

    def start_background(self) -> threading.Thread:
        """Start the reconnect loop in a daemon thread (used by tests/embedding)."""

        if self._launcher and self._launcher.is_alive():
            return self._launcher
        self._launcher = threading.Thread(
            target=self.run_forever, name="nepticon-agent", daemon=True
        )
        self._launcher.start()
        return self._launcher

    def stop(self) -> None:
        self._stop.set()
        with self._socket_lock:
            sock = self._socket
            self._socket = None
        _close_socket(sock)
        self.connected.clear()
        self._cleanup_uploads()
        self._executor.shutdown(wait=False, cancel_futures=True)

    def wait_connected(self, timeout: float = 15.0) -> bool:
        return self.connected.wait(timeout)

    def run_forever(self) -> int:
        """Blocking reconnect loop.  Returns a process exit code."""

        backoff = 1.0
        self._notify(
            "info",
            f"Agent {AGENT_VERSION} targeting {self.settings.host}:{self.settings.port} "
            f"as '{self.settings.node_name}'",
        )
        if self.settings.insecure:
            self._notify(
                "warn",
                "TLS certificate verification is DISABLED (--insecure). "
                "Never use this outside an isolated lab.",
            )
        while not self._stop.is_set():
            connected_at: Optional[float] = None
            try:
                connected_at = self._connect_once()
            except AuthenticationError as exc:
                self._fatal_error = f"authentication rejected: {exc}"
                self._notify("error", self._fatal_error)
                self._stop.set()
                break
            except ConfigError as exc:
                self._fatal_error = str(exc)
                self._notify("error", self._fatal_error)
                self._stop.set()
                break
            except ssl.SSLCertVerificationError as exc:
                self._fatal_error = f"TLS certificate verification failed: {exc}"
                self._notify("error", self._fatal_error)
                self._stop.set()
                break
            except (ConnectionClosed, OSError, ProtocolError, ssl.SSLError) as exc:
                logger.info("connection attempt failed: %s", exc)
                self._notify("warn", f"Connection failed: {exc}")
            except Exception as exc:  # pragma: no cover - defensive
                logger.exception("unexpected agent error")
                self._notify("error", f"Unexpected agent error: {exc}")
            finally:
                self.connected.clear()
                self._cleanup_uploads()

            if self._stop.is_set():
                break
            if connected_at is not None and time.monotonic() - connected_at >= 10.0:
                backoff = 1.0
            delay = min(backoff, 30.0) + random.uniform(0.0, min(1.0, backoff * 0.25))
            self._notify(
                "info",
                f"Reconnecting in {delay:.1f}s (backoff {backoff:.1f}s).",
            )
            if self._stop.wait(delay):
                break
            backoff = min(backoff * 2.0, 30.0)

        self._notify("info", "Agent stopped.")
        return 3 if self._fatal_error and "authentication" in self._fatal_error else 0

    # -- connection ---------------------------------------------------------

    def _connect_once(self) -> float:
        """Connect, handshake and serve one session.

        A brand-new socket and TLS context wrapper are created inside the
        ``try`` block for every attempt.  The old implementation reused a
        socket created outside the loop, which poisoned every reconnect.
        """

        sock: Optional[socket.socket] = None
        tls: Optional[ssl.SSLSocket] = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15.0)
            sock.connect((self.settings.host, self.settings.port))
            tls = self._context.wrap_socket(sock, server_hostname=self.settings.host)
            tls.settimeout(15.0)
            self._handshake(tls)
            connected_at = time.monotonic()
            with self._socket_lock:
                if self._stop.is_set():
                    raise ConnectionClosed("agent is stopping")
                self._socket = tls
            self.connected.set()
            self._notify(
                "ok",
                f"Authenticated as node #{self.node_id} at "
                f"{self.settings.host}:{self.settings.port} "
                f"(session {self.session_id or '?'}, TLS verified"
                f"{' OFF' if self.settings.insecure else ''}).",
            )
            tls.settimeout(None)
            self._frame_loop(tls)
            return connected_at
        except (socket.timeout, TimeoutError) as exc:
            raise TimeoutError(f"connection to {self.settings.host}:{self.settings.port} timed out") from exc
        finally:
            self.connected.clear()
            with self._socket_lock:
                if self._socket is tls:
                    self._socket = None
            _close_socket(tls if tls is not None else sock)
            self._cleanup_uploads()

    def _handshake(self, tls: ssl.SSLSocket) -> None:
        hello = build_hello(
            token=self.settings.token,
            hostname=self.settings.node_name,
            os_info=platform.platform(),
            arch=platform.machine(),
            cpu_cores=os.cpu_count() or 1,
            agent_version=AGENT_VERSION,
            privilege_level=privilege_level(),
            cwd=self._current_cwd(),
            username=getpass.getuser(),
            uptime_seconds=self.telemetry.uptime(),
        )
        send_frame(tls, hello)
        reply = recv_frame(tls)
        reply_type = reply.get("type")
        data = reply.get("data") or {}
        if reply_type == AUTH_FAIL:
            raise AuthenticationError(str(data.get("reason") or "server rejected the handshake"))
        if reply_type != WELCOME:
            raise ProtocolError(f"expected WELCOME, received {reply_type!r}")
        if int(reply.get("v", 0)) != PROTOCOL_VERSION:
            raise ProtocolError("server protocol version mismatch")
        self.node_id = int(data.get("node_id", 0)) or None
        self.session_id = str(data.get("session_id") or "")
        self.server_version = str(data.get("server_version") or "")
        logger.debug(
            "welcome from server %s, heartbeat=%s",
            self.server_version,
            data.get("heartbeat_interval"),
        )

    # -- frame loop ---------------------------------------------------------

    def _frame_loop(self, tls: ssl.SSLSocket) -> None:
        while not self._stop.is_set():
            try:
                frame = recv_frame(tls)
            except ConnectionClosed:
                self._notify("warn", "Server closed the connection.")
                return
            except OSError as exc:
                if not self._stop.is_set():
                    self._notify("warn", f"Connection error: {exc}")
                return
            except (ProtocolError, FrameTooLarge) as exc:
                self._notify("error", f"Protocol error: {exc}")
                return
            frame_type = frame.get("type")
            if frame_type == REQUEST:
                self._executor.submit(self._handle_request, tls, frame)
            elif frame_type == PING:
                try:
                    self._send(
                        tls,
                        make_frame(
                            PONG,
                            {
                                "echo": (frame.get("data") or {}).get("sent_at"),
                                "agent_uptime": round(self.telemetry.agent_uptime_seconds, 1),
                                "node_id": self.node_id,
                            },
                            frame_id=frame.get("id"),
                        ),
                    )
                except AgentConnectionLost:
                    return
            elif frame_type == GOODBYE:
                reason = (frame.get("data") or {}).get("reason") or "server shutdown"
                self._notify("info", f"Server requested disconnect: {reason}")
                return
            elif frame_type in (FILE_CHUNK, FILE_END, FILE_ABORT):
                self._handle_upload_frame(tls, frame)
            elif frame_type == FILE_BEGIN:
                logger.warning("unexpected FILE_BEGIN from server")
            else:
                logger.debug("ignoring frame type %s", frame_type)

    def _send(self, tls: ssl.SSLSocket, frame: Dict[str, Any]) -> None:
        with self._send_lock:
            with self._socket_lock:
                current = self._socket
            if current is not tls or self._stop.is_set():
                raise AgentConnectionLost("session is no longer active")
            try:
                send_frame(tls, frame)
            except (OSError, ProtocolError) as exc:
                raise AgentConnectionLost(f"send failed: {exc}") from exc

    def _send_response(
        self,
        tls: ssl.SSLSocket,
        request_id: str,
        *,
        ok: bool,
        result: Any = None,
        error: Optional[str] = None,
        duration_ms: float = 0.0,
    ) -> None:
        try:
            self._send(
                tls,
                make_response(
                    request_id,
                    ok=ok,
                    result=result,
                    error=error,
                    duration_ms=duration_ms,
                ),
            )
        except AgentConnectionLost:
            logger.debug("could not deliver response for %s", request_id)

    # -- request handling ---------------------------------------------------

    def _handle_request(self, tls: ssl.SSLSocket, frame: Dict[str, Any]) -> None:
        request_id = str(frame.get("id", ""))
        data = frame.get("data") or {}
        operation = str(data.get("op") or "")
        arguments = data.get("args") or {}
        if not isinstance(arguments, dict):
            arguments = {}
        started = time.perf_counter()
        logger.debug("request %s op=%s", request_id, operation)
        try:
            result = self._execute(operation, arguments, request_id)
            duration = (time.perf_counter() - started) * 1000
            if operation == "download":
                # The file stream already carries the completion signal.
                return
            self._send_response(
                tls, request_id, ok=True, result=result, duration_ms=duration
            )
            if operation in ("shutdown", "close"):
                time.sleep(0.1)
                self.stop()
        except Exception as exc:
            duration = (time.perf_counter() - started) * 1000
            logger.warning("request %s failed: %s", operation, exc)
            self._send_response(
                tls,
                request_id,
                ok=False,
                error=str(exc) or exc.__class__.__name__,
                duration_ms=duration,
            )

    def _execute(
        self, operation: str, arguments: Dict[str, Any], request_id: str
    ) -> Any:
        if operation == "exec":
            command = str(arguments.get("command") or "")
            timeout = arguments.get("timeout")
            return self._run_command(command, timeout)
        if operation == "pwd":
            return {"cwd": self._current_cwd()}
        if operation == "cd":
            return self._change_directory(str(arguments.get("path") or ""))
        if operation == "sysinfo":
            return self.telemetry.sysinfo()
        if operation == "health":
            return self.telemetry.health()
        if operation == "ps":
            return self.telemetry.processes(int(arguments.get("limit", 25) or 25))
        if operation == "env":
            return self.telemetry.environment()
        if operation == "download":
            path = str(arguments.get("path") or "")
            return self._send_file(request_id, path)
        if operation == "upload":
            return self._reserve_upload(request_id, arguments)
        if operation in ("shutdown", "close"):
            return {"message": "agent is shutting down", "node": self.settings.node_name}
        if operation == "ping":
            return {"agent_uptime": round(self.telemetry.agent_uptime_seconds, 1)}
        raise ValueError(f"unsupported operation: {operation or '<empty>'}")

    # -- shell --------------------------------------------------------------

    def _run_command(self, command: str, timeout: Any) -> Dict[str, Any]:
        if not command.strip():
            raise ValueError("command is empty")
        try:
            limit = float(timeout) if timeout is not None else DEFAULT_COMMAND_TIMEOUT
        except (TypeError, ValueError):
            limit = DEFAULT_COMMAND_TIMEOUT
        limit = max(1.0, min(MAX_COMMAND_TIMEOUT, limit))
        started = time.perf_counter()
        cwd = self._current_cwd()
        encoding = locale.getpreferredencoding(False) or "utf-8"
        timed_out = False
        try:
            completed = subprocess.run(
                command,
                shell=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=limit,
                cwd=cwd,
            )
            stdout = _decode_output(completed.stdout)
            stderr = _decode_output(completed.stderr)
            exit_code = int(completed.returncode)
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = _decode_output(exc.stdout or b"")
            stderr = f"command timed out after {limit:.0f}s"
            if exc.stderr:
                stderr = _decode_output(exc.stderr)
            exit_code = -1
        stdout, stdout_truncated = _truncate_output(stdout)
        stderr, stderr_truncated = _truncate_output(stderr)
        return {
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "truncated": stdout_truncated or stderr_truncated,
            "duration_ms": round((time.perf_counter() - started) * 1000, 3),
            "cwd": self._current_cwd(),
            "shell_encoding": encoding,
        }

    def _current_cwd(self) -> str:
        with self._cwd_lock:
            try:
                return os.getcwd()
            except OSError:
                return str(Path.home())

    def _change_directory(self, path: str) -> Dict[str, Any]:
        if not path:
            raise ValueError("cd requires a path")
        expanded = os.path.expanduser(os.path.expandvars(path))
        with self._cwd_lock:
            os.chdir(expanded)
            return {"cwd": os.getcwd()}

    # -- file download (agent -> server) -----------------------------------

    def _send_file(self, request_id: str, remote_path: str) -> Dict[str, Any]:
        """Stream a file to the server using FILE_BEGIN/CHUNK/END frames."""

        if not remote_path:
            raise ValueError("download requires a path")
        path = Path(os.path.expanduser(os.path.expandvars(remote_path)))
        if not path.is_file():
            raise FileNotFoundError(f"file not found: {path}")
        size = path.stat().st_size
        if size > MAX_TRANSFER_BYTES:
            raise ValueError("file exceeds the transfer limit")
        tls = self._active_socket()
        self._send(
            tls,
            make_frame(FILE_BEGIN, {"name": path.name, "size": size}, frame_id=request_id),
        )
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            sequence = 0
            while True:
                block = handle.read(CHUNK_SIZE)
                if not block:
                    break
                digest.update(block)
                self._send(
                    tls,
                    make_frame(
                        FILE_CHUNK,
                        {"seq": sequence, "data": b64encode(block)},
                        frame_id=request_id,
                    ),
                )
                sequence += 1
        actual = digest.hexdigest()
        self._send(
            tls,
            make_frame(
                FILE_END,
                {"sha256": actual, "size": size},
                frame_id=request_id,
            ),
        )
        return {"path": str(path), "bytes": size, "sha256": actual}

    def _active_socket(self) -> ssl.SSLSocket:
        with self._socket_lock:
            if self._socket is None:
                raise AgentConnectionLost("not connected")
            return self._socket

    # -- file upload (server -> agent) -------------------------------------

    def _handle_upload_frame(self, tls: ssl.SSLSocket, frame: Dict[str, Any]) -> None:
        transfer_id = str(frame.get("id", ""))
        with self._upload_lock:
            context = self._uploads.get(transfer_id)
        if context is None:
            logger.debug("upload frame for unknown transfer %s", transfer_id)
            return
        frame_type = frame.get("type")
        data = frame.get("data") or {}
        if frame_type == FILE_CHUNK:
            try:
                sequence = int(data.get("seq", -1))
                if sequence != context["expected_seq"]:
                    raise ProtocolError("upload chunk out of order")
                raw = b64decode(str(data.get("data") or ""))
                if context["received"] + len(raw) > context["size"]:
                    raise ProtocolError("upload chunk exceeds declared size")
                context["handle"].write(raw)
                context["digest"].update(raw)
                context["received"] += len(raw)
                context["expected_seq"] = sequence + 1
            except Exception as exc:
                self._fail_upload(transfer_id, context, str(exc), tls)
            return
        if frame_type == FILE_END:
            self._finish_upload(transfer_id, context, tls, data)
            return
        if frame_type == FILE_ABORT:
            reason = str(data.get("reason") or "sender aborted")
            self._fail_upload(transfer_id, context, reason, tls)
            return
        if frame_type == FILE_BEGIN:
            self._fail_upload(transfer_id, context, "unexpected FILE_BEGIN", tls)

    def _finish_upload(
        self,
        transfer_id: str,
        context: Dict[str, Any],
        tls: ssl.SSLSocket,
        data: Dict[str, Any],
    ) -> None:
        with self._upload_lock:
            self._uploads.pop(transfer_id, None)
        try:
            context["handle"].flush()
            try:
                os.fsync(context["handle"].fileno())
            except OSError:
                pass
            context["handle"].close()
            if context["received"] != context["size"]:
                raise ProtocolError(
                    f"incomplete upload: {context['received']} of {context['size']} bytes"
                )
            expected = str(data.get("sha256") or "").lower()
            actual = context["digest"].hexdigest()
            if not expected or not hmac.compare_digest(expected, actual):
                raise ProtocolError("SHA-256 checksum mismatch")
            final = context["final"]
            os.replace(context["temp"], final)
            self._send_response(
                tls,
                transfer_id,
                ok=True,
                result={
                    "path": str(final),
                    "bytes": context["received"],
                    "sha256": actual,
                },
                duration_ms=(time.perf_counter() - context["started"]) * 1000,
            )
        except Exception as exc:
            try:
                context["handle"].close()
            except Exception:
                pass
            try:
                Path(context["temp"]).unlink()
            except OSError:
                pass
            logger.warning("upload %s failed: %s", transfer_id, exc)
            self._send_response(
                tls,
                transfer_id,
                ok=False,
                error=str(exc),
                duration_ms=(time.perf_counter() - context["started"]) * 1000,
            )

    def _fail_upload(
        self,
        transfer_id: str,
        context: Dict[str, Any],
        error: str,
        tls: Optional[ssl.SSLSocket] = None,
    ) -> None:
        with self._upload_lock:
            self._uploads.pop(transfer_id, None)
        try:
            context["handle"].close()
        except Exception:
            pass
        try:
            Path(context["temp"]).unlink()
        except OSError:
            pass
        logger.warning("upload %s aborted: %s", transfer_id, error)
        if tls is not None:
            self._send_response(
                tls,
                transfer_id,
                ok=False,
                error=error,
                duration_ms=(time.perf_counter() - context["started"]) * 1000,
            )

    def _cleanup_uploads(self) -> None:
        with self._upload_lock:
            contexts = list(self._uploads.values())
            self._uploads.clear()
        for context in contexts:
            try:
                context["handle"].close()
            except Exception:
                pass
            try:
                Path(context["temp"]).unlink()
            except OSError:
                pass

    # -- upload begin needs the request id ---------------------------------

    def _reserve_upload(self, request_id: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        name = safe_basename(str(arguments.get("name") or "upload.bin"))
        size = int(arguments.get("size") or 0)
        if size < 0 or size > MAX_TRANSFER_BYTES:
            raise ValueError("invalid file size")
        requested = arguments.get("path")
        if requested:
            destination = Path(os.path.expanduser(os.path.expandvars(str(requested))))
            if str(requested).endswith(("/", "\\")) or destination.is_dir():
                destination = destination / name
        else:
            destination = Path(self.settings.downloads) / name
        if destination.exists() and destination.is_dir():
            raise IsADirectoryError(f"destination is a directory: {destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination = unique_path(destination)
        temp = destination.with_name(f".{destination.name}.{request_id[:8]}.part")
        handle = open(temp, "wb")
        context = {
            "handle": handle,
            "temp": temp,
            "final": destination,
            "size": size,
            "received": 0,
            "digest": hashlib.sha256(),
            "expected_seq": 0,
            "started": time.perf_counter(),
        }
        with self._upload_lock:
            self._uploads[request_id] = context
        return {
            "transfer_id": request_id,
            "path": str(destination),
            "chunk_size": CHUNK_SIZE,
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="client.py",
        description=(
            f"Nepticon {__version__} node agent — {TAGLINE}. "
            "Connects out to a Nepticon fleet server and serves authenticated requests."
        ),
    )
    parser.add_argument("--host", help="Fleet server hostname/IP (default 127.0.0.1)")
    parser.add_argument("--port", type=int, help="Fleet server TLS port (default 1536)")
    parser.add_argument("--token", help="Shared HMAC authentication token")
    parser.add_argument("--cert", help="Server certificate or CA certificate (alias for --ca)")
    parser.add_argument("--ca", help="CA certificate used to verify the server")
    parser.add_argument("--name", dest="node_name", help="Node display name (default hostname)")
    parser.add_argument("--config", dest="config_path", metavar="FILE", help="JSON config file")
    parser.add_argument("--downloads", help="Directory for files uploaded to this node")
    parser.add_argument("--insecure", action="store_true", default=None, help="Disable TLS verification (lab only)")
    parser.add_argument("--no-color", dest="color", action="store_false", default=None, help="Disable ANSI colour")
    parser.add_argument("--no-animations", dest="animations", action="store_false", default=None, help="Disable spinners")
    parser.add_argument("--verbose", action="store_true", default=None, help="Verbose logging")
    parser.add_argument("--version", action="version", version=f"Nepticon agent {__version__}")
    return parser


def _cli_values(args: argparse.Namespace) -> Dict[str, Any]:
    cert = args.cert
    ca = args.ca or args.cert
    return {
        "host": args.host,
        "port": args.port,
        "token": args.token,
        "cert": cert,
        "ca": ca,
        "node_name": args.node_name,
        "config_path": args.config_path,
        "downloads": args.downloads,
        "insecure": args.insecure,
        "color": args.color,
        "animations": args.animations,
        "verbose": args.verbose,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        settings = open_settings("agent", cli=_cli_values(args), config_path=args.config_path)
    except ConfigError as exc:
        print(f"[!] Configuration error: {exc}", file=sys.stderr)
        return 2
    logging.basicConfig(
        level=logging.DEBUG if settings.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    ui = UI(color=settings.color, animations=settings.animations)
    assets.banner(ui.color, subtitle=False)
    ui.info(f"Node agent {AGENT_VERSION} — {TAGLINE}")
    for warning in settings.warnings:
        ui.warn(warning)
    if not settings.token:
        ui.error(
            "No shared token configured. Set NEPTICON_TOKEN, pass --token, or use "
            "the config.json generated by the server."
        )
        return 2
    if settings.insecure:
        ui.warn("TLS verification disabled (--insecure). Use only in an isolated lab.")
    try:
        agent = Agent(settings, ui=ui)
    except ConfigError as exc:
        ui.error(str(exc))
        return 2
    try:
        signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)
    except (AttributeError, OSError, ValueError):
        pass
    try:
        return agent.run_forever()
    except KeyboardInterrupt:
        ui.write("")
        return 130
    finally:
        agent.stop()


if __name__ == "__main__":
    sys.exit(main())
