"""Configuration loading for Nepticon.

Precedence (highest first):

1. command line arguments
2. ``NEPTICON_*`` environment variables
3. ``config.json`` (or ``--config``)
4. built-in defaults

The same loader serves the fleet server and the node agent.  Relative paths
are resolved against the current working directory so a checkout can be
moved without rewriting its configuration.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

DEFAULT_CONFIG_FILE = Path("config.json")
DEFAULT_PORT = 1536

DEFAULTS: Dict[str, Any] = {
    "host": "0.0.0.0",
    "port": DEFAULT_PORT,
    "token": "",
    "cert": "certs/server.crt",
    "key": "certs/server.key",
    "ca": "certs/ca.crt",
    "audit_log": "logs/audit.jsonl",
    "downloads": "downloads",
    "node_name": "",
    "heartbeat_interval": 10.0,
    "request_timeout": 30.0,
    "transfer_timeout": 300.0,
    "max_nodes": 256,
    "insecure": False,
    "verbose": False,
    "color": True,
    "animations": True,
}

ENV_MAP = {
    "NEPTICON_HOST": ("host", str),
    "NEPTICON_PORT": ("port", int),
    "NEPTICON_TOKEN": ("token", str),
    "NEPTICON_CERT": ("cert", str),
    "NEPTICON_KEY": ("key", str),
    "NEPTICON_CA": ("ca", str),
    "NEPTICON_AUDIT_LOG": ("audit_log", str),
    "NEPTICON_DOWNLOADS": ("downloads", str),
    "NEPTICON_NAME": ("node_name", str),
    "NEPTICON_HEARTBEAT": ("heartbeat_interval", float),
    "NEPTICON_REQUEST_TIMEOUT": ("request_timeout", float),
    "NEPTICON_MAX_NODES": ("max_nodes", int),
    "NEPTICON_INSECURE": ("insecure", "bool"),
    "NEPTICON_VERBOSE": ("verbose", "bool"),
    "NEPTICON_NO_COLOR": ("color", "invert_bool"),
    "NEPTICON_NO_ANIMATIONS": ("animations", "invert_bool"),
}

CONFIG_FILE_KEYS = set(DEFAULTS)


class ConfigError(Exception):
    """Raised when configuration values are missing or malformed."""


@dataclass
class Settings:
    role: str
    host: str
    port: int
    token: str
    cert: Path
    key: Path
    ca: Path
    audit_log: Path
    downloads: Path
    node_name: str
    heartbeat_interval: float
    request_timeout: float
    transfer_timeout: float
    max_nodes: int
    insecure: bool
    verbose: bool
    color: bool
    animations: bool
    config_path: Optional[Path] = None
    warnings: list[str] = field(default_factory=list)

    @property
    def is_server(self) -> bool:
        return self.role == "server"

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    def masked_token(self) -> str:
        return mask_token(self.token)

    def cert_dir(self) -> Path:
        return self.cert.parent


def _parse_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on", "y"):
        return True
    if text in ("0", "false", "no", "off", "n", ""):
        return False
    raise ConfigError(f"invalid boolean value: {value!r}")


def _coerce(value: Any, kind: Any, key: str) -> Any:
    try:
        if kind == "bool":
            return _parse_bool(value)
        if kind == "invert_bool":
            return not _parse_bool(value)
        if kind is int:
            return int(str(value).strip())
        if kind is float:
            return float(str(value).strip())
        return str(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"invalid value for '{key}': {value!r}") from exc


def _read_config_file(path: Path, warnings: list[str]) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"config file {path} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"config file {path} must contain a JSON object")
    for key in raw:
        if key not in CONFIG_FILE_KEYS:
            warnings.append(f"unknown config key ignored: {key}")
    return {key: value for key, value in raw.items() if key in CONFIG_FILE_KEYS}


def open_settings(
    role: str,
    *,
    cli: Optional[Dict[str, Any]] = None,
    config_path: Optional[os.PathLike[str] | str] = None,
) -> Settings:
    """Load settings for ``role`` (``server`` or ``agent``)."""

    if role not in ("server", "agent"):
        raise ValueError("role must be 'server' or 'agent'")
    cli = {key: value for key, value in (cli or {}).items() if value is not None}
    warnings: list[str] = []

    env_path = os.environ.get("NEPTICON_CONFIG")
    chosen_path = Path(config_path or cli.get("config_path") or env_path or DEFAULT_CONFIG_FILE)
    explicit = bool(config_path or cli.get("config_path") or env_path)
    if explicit and not chosen_path.is_file():
        raise ConfigError(f"config file not found: {chosen_path}")
    file_values = _read_config_file(chosen_path, warnings)

    values: Dict[str, Any] = dict(DEFAULTS)
    if role == "agent":
        values["host"] = "127.0.0.1"
        values["audit_log"] = "logs/agent-audit.jsonl"
    values.update(file_values)

    for env_name, (key, kind) in ENV_MAP.items():
        if env_name in os.environ:
            values[key] = _coerce(os.environ[env_name], kind, key)

    for key, value in cli.items():
        if key == "config_path":
            continue
        if key in DEFAULTS and value is not None:
            values[key] = value

    port = _coerce(values["port"], int, "port")
    if not 1 <= port <= 65535:
        raise ConfigError(f"port out of range: {port}")
    heartbeat = _coerce(values["heartbeat_interval"], float, "heartbeat_interval")
    if heartbeat < 1:
        raise ConfigError("heartbeat_interval must be at least 1 second")
    request_timeout = _coerce(values["request_timeout"], float, "request_timeout")
    transfer_timeout = _coerce(values["transfer_timeout"], float, "transfer_timeout")
    if request_timeout <= 0:
        raise ConfigError("request_timeout must be positive")
    if transfer_timeout <= 0:
        raise ConfigError("transfer_timeout must be positive")
    max_nodes = _coerce(values["max_nodes"], int, "max_nodes")
    if max_nodes < 1:
        raise ConfigError("max_nodes must be positive")

    host = str(values["host"]).strip()
    if not host:
        raise ConfigError("host must not be empty")
    if role == "agent" and host in ("0.0.0.0", "::", "[::]"):
        host = "127.0.0.1"
        warnings.append("config host 0.0.0.0 is a server bind address; using 127.0.0.1")

    node_name = str(values.get("node_name") or "").strip() or socket.gethostname()

    settings = Settings(
        role=role,
        host=host,
        port=port,
        token=str(values.get("token") or ""),
        cert=Path(str(values["cert"])).expanduser(),
        key=Path(str(values["key"])).expanduser(),
        ca=Path(str(values["ca"])).expanduser(),
        audit_log=Path(str(values["audit_log"])).expanduser(),
        downloads=Path(str(values["downloads"])).expanduser(),
        node_name=node_name,
        heartbeat_interval=heartbeat,
        request_timeout=request_timeout,
        transfer_timeout=transfer_timeout,
        max_nodes=max_nodes,
        insecure=bool(values.get("insecure", False)),
        verbose=bool(values.get("verbose", False)),
        color=bool(values.get("color", True)),
        animations=bool(values.get("animations", True)),
        config_path=chosen_path if chosen_path.is_file() else None,
        warnings=warnings,
    )

    if role == "agent" and not settings.insecure:
        # A typical single-host checkout uses certs/ca.crt.  If only a
        # self-signed server.crt exists, accepting it as the CA is correct.
        if not settings.ca.is_file() and settings.cert.is_file():
            settings.ca = settings.cert
            warnings.append(f"CA file missing; trusting server certificate {settings.cert}")
    return settings


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def mask_token(token: str) -> str:
    if not token:
        return "<unset>"
    if len(token) <= 8:
        return "*" * len(token)
    return f"{token[:4]}...{token[-4:]} ({len(token)} chars)"


def persist_token(token: str, config_path: Optional[os.PathLike[str] | str] = None) -> Path:
    """Write ``token`` into config.json without disturbing other settings."""

    path = Path(config_path or DEFAULT_CONFIG_FILE)
    payload: Dict[str, Any] = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                payload = loaded
        except (OSError, json.JSONDecodeError):
            payload = {}
    payload["token"] = token
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    )
    temp_path = Path(handle.name)
    try:
        with handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        try:
            os.chmod(temp_path, 0o600)
        except OSError:
            pass
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except OSError:
                pass
    return path


def describe_settings(settings: Settings) -> list[tuple[str, str]]:
    """Human-readable configuration rows for the status screen."""

    rows = [
        ("Role", settings.role),
        ("Endpoint", settings.endpoint),
        ("Shared token", settings.masked_token()),
        ("TLS certificate", str(settings.cert)),
        ("TLS private key", str(settings.key)),
        ("Trust anchor", str(settings.ca)),
        ("Audit log", str(settings.audit_log)),
        ("Downloads", str(settings.downloads)),
        ("Heartbeat", f"{settings.heartbeat_interval:.1f}s"),
        ("Request timeout", f"{settings.request_timeout:.1f}s"),
        ("Config file", str(settings.config_path) if settings.config_path else "<defaults>"),
    ]
    return rows
