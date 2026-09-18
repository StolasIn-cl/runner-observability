"""Configuration and process-command seams for the Windows monitor service."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Mapping


class ServiceConfigError(ValueError):
    """A service configuration failure identified only by a stable reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ServiceConfig:
    """Non-secret settings required to start one monitor child process."""

    service_name: str = "RunnerObservabilityMonitor"
    python_executable: str = sys.executable
    database: str = "runner-observability.sqlite"
    token_file: str = ""
    host: str = "0.0.0.0"
    port: int = 8765
    tls_cert: str | None = None
    tls_key: str | None = None
    release_root: str | None = None

    _FIELDS = frozenset(
        {
            "service_name",
            "python_executable",
            "database",
            "token_file",
            "host",
            "port",
            "tls_cert",
            "tls_key",
            "release_root",
        }
    )

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> ServiceConfig:
        if not isinstance(raw, Mapping) or any(key not in cls._FIELDS for key in raw):
            raise ServiceConfigError("invalid_service_configuration")
        defaults = cls()
        values: dict[str, Any] = {
            "service_name": defaults.service_name,
            "python_executable": defaults.python_executable,
            "database": defaults.database,
            "token_file": defaults.token_file,
            "host": defaults.host,
            "port": defaults.port,
            "tls_cert": defaults.tls_cert,
            "tls_key": defaults.tls_key,
            "release_root": defaults.release_root,
        }
        values.update(raw)
        for key in ("service_name", "python_executable", "database", "token_file", "host"):
            value = values[key]
            if not isinstance(value, str) or not value.strip():
                raise ServiceConfigError("invalid_service_configuration")
        port = values["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ServiceConfigError("invalid_service_configuration")
        for key in ("tls_cert", "tls_key", "release_root"):
            value = values[key]
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ServiceConfigError("invalid_service_configuration")
        if (values["tls_cert"] is None) != (values["tls_key"] is None):
            raise ServiceConfigError("tls_partial_configuration")
        return cls(**values)

    @classmethod
    def from_json(cls, path: Path | str) -> ServiceConfig:
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ServiceConfigError("invalid_service_configuration") from error
        return cls.from_mapping(raw)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "service_name": self.service_name,
            "python_executable": self.python_executable,
            "database": self.database,
            "token_file": self.token_file,
            "host": self.host,
            "port": self.port,
            "tls_cert": self.tls_cert,
            "tls_key": self.tls_key,
            "release_root": self.release_root,
        }

    def write_atomic(self, path: Path | str) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=target.parent,
                prefix=f".{target.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                json.dump(self.to_mapping(), temporary, ensure_ascii=True, sort_keys=True)
                temporary.write("\n")
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary_path, target)
            temporary_path = None
        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass


def build_monitor_command(config: ServiceConfig) -> tuple[str, ...]:
    """Build the child argv without ever accepting a token value."""
    command = [
        config.python_executable,
        "-m",
        "runner_observability",
        "serve",
        "--token-file",
        config.token_file,
        "--database",
        config.database,
        "--host",
        config.host,
        "--port",
        str(config.port),
    ]
    if config.tls_cert is not None and config.tls_key is not None:
        command.extend(("--tls-cert", config.tls_cert, "--tls-key", config.tls_key))
    return tuple(command)


def build_service_bin_path(config_path: Path | str, python_executable: Path | str) -> str:
    """Build a Windows SCM command that carries only a config-file path."""
    return subprocess.list2cmdline(
        [
            str(python_executable),
            "-m",
            "runner_observability.service",
            "run",
            "--config",
            str(config_path),
        ]
    )
