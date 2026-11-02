"""Terminal presentation helpers shared by the server and the agent.

The visual language (ANSI colours, ``[!] [i] [+] [#]`` tags, spinner) is
kept from Nepticon v1 but the implementation is thread-aware, safe on
non-TTY streams and never crashes because a remote string contains control
characters.
"""

from __future__ import annotations

import datetime as _dt
import os
import re
import shutil
import sys
import threading
import time
from typing import Any, Callable, Iterable, Optional, Sequence

from tabulate import tabulate

COLOR_CODES = {
    "[!]": "\033[1;31m",
    "[i]": "\033[1;36m",
    "[+]": "\033[1;32m",
    "[#]": "\033[1;37;41m",
}
RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
BLUE = "\033[1;34m"
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
CYAN = "\033[1;36m"
GREY = "\033[90m"

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

BRAILLE_FRAMES = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")
ASCII_FRAMES = ("/", "|", "\\", "-")

_TABLE_FORMATS = ("rounded_outline", "fancy_grid", "grid", "simple")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", str(text))


def sanitize_terminal_text(value: Any, max_length: int = 120) -> str:
    """Make peer-supplied text safe for prompts and toolbars.

    Newlines, ANSI escapes and other C0 controls are removed so a malicious
    hostname cannot redraw the operator's terminal.
    """

    text = strip_ansi(str(value if value is not None else ""))
    text = CONTROL_RE.sub("", text)
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    text = " ".join(text.split())
    if len(text) > max_length:
        text = text[: max(0, max_length - 1)] + "…"
    return text


def coloring(string: str, *args: Any) -> str:
    """Colour a tagged message (original Nepticon helper, now returning text)."""

    prefix = COLOR_CODES.get(string[:3])
    suffix = " ".join(str(arg) for arg in args)
    body = f"{string} {suffix}".rstrip()
    return f"{prefix}{string}{RESET} {suffix}".rstrip() if prefix else body


def format_bytes(size: float) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024.0 or unit == "TiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024.0
    return f"{value:.1f} TiB"


def format_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "—"
    seconds = max(0, int(float(seconds)))
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)
    if days:
        return f"{days}d {hours:02d}h {minutes:02d}m"
    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def truncate(text: Any, width: int = 80, suffix: str = "…") -> str:
    value = str(text if text is not None else "")
    if len(value) <= width:
        return value
    return value[: max(0, width - len(suffix))] + suffix


class UI:
    """A small, thread-safe terminal façade."""

    def __init__(
        self,
        *,
        color: bool = True,
        animations: bool = True,
        stream: Optional[Any] = None,
    ) -> None:
        self._stream = stream
        for target in (self.stream, sys.stderr):
            try:
                target.reconfigure(errors="replace")
            except Exception:
                pass
        self.color = (
            bool(color)
            and not os.environ.get("NO_COLOR")
            and self._stream_is_tty()
        )
        self.animations = bool(animations) and self._stream_is_tty()
        self._lock = threading.RLock()
        if os.name == "nt":
            self._enable_windows_vt()

    @property
    def stream(self) -> Any:
        """Resolve stdout lazily so ``patch_stdout`` can intercept writes.

        ``UI`` is created before prompt_toolkit installs its stdout proxy.
        Storing the original stream would bypass that proxy and let a
        background node notification corrupt the active prompt.
        """

        return self._stream if self._stream is not None else sys.stdout

    # -- capability detection ---------------------------------------------

    def _stream_is_tty(self) -> bool:
        try:
            return bool(self.stream.isatty())
        except Exception:
            return False

    @staticmethod
    def _enable_windows_vt() -> None:
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass

    @property
    def width(self) -> int:
        try:
            return max(60, min(200, shutil.get_terminal_size((100, 25)).columns))
        except Exception:
            return 100

    def frames(self) -> Sequence[str]:
        encoding = getattr(self.stream, "encoding", None) or "utf-8"
        try:
            "⠋".encode(encoding)
            return BRAILLE_FRAMES
        except (UnicodeEncodeError, LookupError):
            return ASCII_FRAMES

    # -- primitives --------------------------------------------------------

    def paint(self, text: str, code: str) -> str:
        if not self.color or not code:
            return str(text)
        return f"{code}{text}{RESET}"

    def write(self, text: str = "", *, end: str = "\n", flush: bool = True) -> None:
        with self._lock:
            self.stream.write(text + end)
            if flush:
                self.stream.flush()

    def clear(self) -> None:
        with self._lock:
            self.stream.write("\033[2J\033[3J\033[H")
            self.stream.flush()

    def rule(self, label: str = "", width: Optional[int] = None) -> None:
        width = width or min(self.width, 100)
        if label:
            text = f"── {label} " + "─" * max(0, width - len(label) - 4)
        else:
            text = "─" * width
        self.write(self.paint(text, GREY))

    def msg(self, tag: str, *parts: Any) -> None:
        """Print ``[+] message`` style output, keeping the original tags."""

        body = " ".join(str(part) for part in parts)
        rendered = coloring(tag, body)
        if not self.color:
            rendered = f"{tag} {body}".rstrip()
        self.write(rendered)

    def info(self, *parts: Any) -> None:
        self.msg("[i]", *parts)

    def ok(self, *parts: Any) -> None:
        self.msg("[+]", *parts)

    def warn(self, *parts: Any) -> None:
        self.msg("[!]", *parts)

    def error(self, *parts: Any) -> None:
        self.msg("[!]", *parts)

    def alert(self, *parts: Any) -> None:
        self.msg("[#]", *parts)

    def notify(self, level: str, message: str) -> None:
        """Timestamped event line used for asynchronous fleet notifications."""

        stamp = _dt.datetime.now().strftime("%H:%M:%S")
        tags = {"info": "[i]", "ok": "[+]", "warn": "[!]", "error": "[!]", "alert": "[#]"}
        tag = tags.get(level, "[i]")
        with self._lock:
            prefix = f"{self.paint(stamp, GREY)} "
            self.write(prefix + coloring(tag, sanitize_terminal_text(message, 300)))

    def print_table(
        self,
        rows: Iterable[Sequence[Any]],
        headers: Sequence[str],
        *,
        tablefmt: Optional[str] = None,
        colalign: Optional[Sequence[str]] = None,
    ) -> None:
        text = render_table(rows, headers, tablefmt=tablefmt, colalign=colalign)
        if text:
            self.write(text)

    # -- animation ---------------------------------------------------------

    def animate(
        self,
        text: str,
        success: str,
        error: str,
        finished_event: threading.Event,
        interval: float = 0.08,
        anim_chars: Optional[Sequence[str]] = None,
    ) -> None:
        """Indeterminate spinner that stops when ``finished_event`` is set.

        Kept API-compatible with Nepticon v1's ``animate()`` helper.
        """

        frames = anim_chars or self.frames()
        if not self.animations:
            finished_event.wait()
            if success:
                self.write(success)
            return
        started = time.monotonic()
        with self._lock:
            self.stream.write("\033[?25l")
            self.stream.flush()
        try:
            index = 0
            while not finished_event.is_set():
                frame = frames[index % len(frames)]
                index += 1
                elapsed = time.monotonic() - started
                line = f"\r\033[K{self.paint(frame, CYAN)} {text} {self.paint(f'({elapsed:.1f}s)', GREY)}"
                with self._lock:
                    self.stream.write(line)
                    self.stream.flush()
                time.sleep(interval)
            with self._lock:
                self.stream.write("\r\033[K")
                if success:
                    self.stream.write(f"{success}\n")
                self.stream.flush()
        finally:
            with self._lock:
                self.stream.write("\033[?25h")
                self.stream.flush()

    def run(
        self,
        target: Callable[..., Any],
        args: tuple = (),
        text: str = "",
        success: str = "",
        error: str = "",
        interval: float = 0.08,
        anim_chars: Optional[Sequence[str]] = None,
    ) -> Any:
        """Run ``target`` while showing an indeterminate spinner."""

        finished = threading.Event()
        thread = threading.Thread(
            target=self.animate,
            args=(text, "", "", finished, interval, anim_chars),
            daemon=True,
        )
        thread.start()
        try:
            result = target(*args)
        except BaseException:
            finished.set()
            thread.join(timeout=2)
            if error:
                self.error(error)
            raise
        finished.set()
        thread.join(timeout=2)
        if success:
            self.write(success)
        return result

    def progress(self, total: int, label: str = "Transfer") -> "ProgressBar":
        return ProgressBar(self, total, label)


class ProgressBar:
    """Single-line determinate progress bar with throughput display."""

    def __init__(self, ui: UI, total: int, label: str = "Transfer") -> None:
        self.ui = ui
        self.total = max(0, int(total))
        self.label = label
        self.done = 0
        self.started = time.monotonic()
        self._last_render = 0.0
        self._finished = False

    def update(self, done: int, *, force: bool = False) -> None:
        self.done = max(0, min(int(done), self.total))
        now = time.monotonic()
        if not force and now - self._last_render < 0.08:
            return
        self._last_render = now
        if not self.ui.animations:
            return
        width = max(20, min(40, self.ui.width - 60))
        ratio = (self.done / self.total) if self.total else 1.0
        filled = int(width * ratio)
        if self.ui.color:
            bar = self.ui.paint("█" * filled, GREEN) + self.ui.paint("░" * (width - filled), GREY)
        else:
            bar = "#" * filled + "-" * (width - filled)
        elapsed = max(0.001, now - self.started)
        speed = self.done / elapsed
        percent = ratio * 100
        line = (
            f"\r\033[K{self.label} [{bar}] {percent:5.1f}% "
            f"{format_bytes(self.done)}/{format_bytes(self.total)} "
            f"{format_bytes(speed)}/s"
        )
        with self.ui._lock:
            self.ui.stream.write(line)
            self.ui.stream.flush()

    def finish(self, message: str = "") -> None:
        if self._finished:
            return
        self._finished = True
        if self.ui.animations:
            with self.ui._lock:
                self.ui.stream.write("\r\033[K")
                self.ui.stream.flush()
        if message:
            self.ui.ok(message)

    def __enter__(self) -> "ProgressBar":
        self.update(0, force=True)
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if not self._finished:
            self.finish()


def render_table(
    rows: Iterable[Sequence[Any]],
    headers: Sequence[str],
    *,
    tablefmt: Optional[str] = None,
    colalign: Optional[Sequence[str]] = None,
) -> str:
    data = [list(row) for row in rows]
    if not data:
        return ""
    attempted = [tablefmt] if tablefmt else list(_TABLE_FORMATS)
    last_error: Optional[Exception] = None
    for fmt in attempted:
        if not fmt:
            continue
        try:
            return tabulate(
                data,
                headers=list(headers),
                tablefmt=fmt,
                colalign=colalign,
                disable_numparse=False,
            )
        except (ValueError, KeyError) as exc:
            last_error = exc
            continue
    if last_error:
        raise last_error
    return tabulate(data, headers=list(headers))


_DEFAULT_UI: Optional[UI] = None
_UI_LOCK = threading.Lock()


def default_ui() -> UI:
    global _DEFAULT_UI
    with _UI_LOCK:
        if _DEFAULT_UI is None:
            _DEFAULT_UI = UI(
                color=os.environ.get("NO_COLOR") is None,
                animations=True,
            )
        return _DEFAULT_UI


def animate(
    text: str,
    success: str,
    error: str,
    finished_event: threading.Event,
    interval: float = 0.08,
    anim_chars: Optional[Sequence[str]] = None,
) -> None:
    """Compatibility wrapper around :meth:`UI.animate`."""

    default_ui().animate(text, success, error, finished_event, interval, anim_chars)


def run(
    target: Callable[..., Any],
    args: tuple = (),
    text: str = "",
    success: str = "",
    error: str = "",
    interval: float = 0.08,
    anim_chars: Optional[Sequence[str]] = None,
) -> Any:
    """Compatibility wrapper around :meth:`UI.run`."""

    return default_ui().run(target, args, text, success, error, interval, anim_chars)
