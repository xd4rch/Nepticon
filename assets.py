"""Static visual assets for Nepticon.

The v1.2 ASCII banner is intentionally preserved unchanged; only a version
and purpose line is added underneath it so the tool remains recognisable to
existing users while presenting its new enterprise role.
"""

from __future__ import annotations

import sys

from nepticon import TAGLINE, __version__

# Original Nepticon v1.2 banner — do not reflow.
context = r"""
   _  __         __  _
  / |/ /__ ___  / /_(_)______  ___
 /    / -_) _ \/ __/ / __/ _ \/ _ \  ╱
/_/|_/\__/ .__/\__/_/\__/\___/_//_/ ╱  v1.2
        /_/                  ──────╱──────
 24-26               quartrinary  ╱
                                 ╱

"""

BANNER = context
SUBTITLE = f"quartrinary  ·  Nepticon v{__version__}  ·  {TAGLINE}"


def _safe_print(text: str, end: str = "\n") -> None:
    """Print even when stdout cannot encode the box-drawing characters."""

    try:
        print(text, end=end, flush=True)
    except UnicodeEncodeError:
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        fallback = text.encode(encoding, errors="replace").decode(encoding, errors="replace")
        print(fallback, end=end, flush=True)


def banner(color: bool = True, subtitle: bool = True) -> None:
    """Print the Nepticon banner.

    ``color=False`` honours ``NO_COLOR`` and non-TTY streams.
    """

    if color:
        _safe_print(f"\033[1;31m{context}\033[0m", end="")
        if subtitle:
            _safe_print(f"\033[2;36m  {SUBTITLE}\033[0m\n")
    else:
        _safe_print(context, end="")
        if subtitle:
            _safe_print(f"  {SUBTITLE}\n")
