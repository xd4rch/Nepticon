"""Nepticon — TLS-encrypted fleet telemetry and remote node orchestration.

The package contains the shared protocol, configuration, telemetry and UI
helpers used by both the fleet server (``main.py``) and the node agent
(``client.py``).  Nothing in this module performs I/O at import time.
"""

from __future__ import annotations

__version__ = "2.0.0"
PROTOCOL_VERSION = 1
DEFAULT_PORT = 1536
APP_NAME = "Nepticon"
TAGLINE = "TLS-Secured Fleet Telemetry & Remote Node Orchestration"

__all__ = [
    "APP_NAME",
    "DEFAULT_PORT",
    "PROTOCOL_VERSION",
    "TAGLINE",
    "__version__",
]
