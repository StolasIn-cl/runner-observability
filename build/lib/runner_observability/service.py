"""Configuration and process-command seams for the Windows monitor service."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Callable, Mapping, Protocol, Sequence


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


class ChildProcess(Protocol):
    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def kill(self) -> None: ...


class StopEvent(Protocol):
    def is_set(self) -> bool: ...

    def wait(self, timeout: float | None = None) -> bool: ...


PopenFactory = Callable[..., ChildProcess]


class MonitorChildSupervisor:
    """Run one monitor child and stop it with a bounded termination sequence."""

    def __init__(
        self,
        command: Sequence[str],
        popen_factory: PopenFactory = subprocess.Popen,
        *,
        stop_timeout: float = 10.0,
        poll_interval: float = 0.25,
    ) -> None:
        self._command = tuple(command)
        self._popen_factory = popen_factory
        self._stop_timeout = stop_timeout
        self._poll_interval = poll_interval
        self._child: ChildProcess | None = None

    def run(self, stop_event: StopEvent) -> int:
        self._child = self._popen_factory(
            self._command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        child = self._child
        while True:
            return_code = child.poll()
            if return_code is not None:
                return return_code
            if stop_event.is_set():
                self.stop()
                return_code = child.poll()
                return 0 if return_code is None else return_code
            stop_event.wait(self._poll_interval)

    def stop(self) -> None:
        child = self._child
        if child is None or child.poll() is not None:
            return
        try:
            child.terminate()
            child.wait(timeout=self._stop_timeout)
            return
        except (OSError, TimeoutError, subprocess.TimeoutExpired):
            pass
        try:
            child.kill()
            child.wait(timeout=self._stop_timeout)
        except (OSError, TimeoutError, subprocess.TimeoutExpired):
            pass


REASON_WINDOWS_SERVICE_UNAVAILABLE = "windows_service_unavailable"
REASON_SERVICE_CHILD_START_FAILED = "service_child_start_failed"
REASON_SERVICE_CHILD_FAILED = "service_child_failed"


def _load_service_api() -> Any | None:
    if os.name != "nt":
        return None
    try:
        import servicemanager
        import win32event
        import win32service
        import win32serviceutil
    except ImportError:
        return None
    return type(
        "WindowsServiceApi",
        (),
        {
            "servicemanager": servicemanager,
            "win32event": win32event,
            "win32service": win32service,
            "win32serviceutil": win32serviceutil,
        },
    )()


def _make_service_class(config: ServiceConfig, service_api: Any, popen_factory: PopenFactory) -> type:
    class MonitorWindowsService(service_api.win32serviceutil.ServiceFramework):
        _svc_name_ = config.service_name
        _svc_display_name_ = "Runner Observability Monitor"
        _svc_description_ = "Runner Observability Monitor telemetry service"

        def __init__(self, args: Sequence[str]) -> None:
            super().__init__(args)
            self._stop_handle = service_api.win32event.CreateEvent(None, 0, 0, None)
            self._supervisor = MonitorChildSupervisor(
                build_monitor_command(config), popen_factory=popen_factory
            )

        def SvcStop(self) -> None:  # noqa: N802 - pywin32 callback name
            self.ReportServiceStatus(service_api.win32service.SERVICE_STOP_PENDING)
            self._supervisor.stop()
            service_api.win32event.SetEvent(self._stop_handle)

        def SvcDoRun(self) -> None:  # noqa: N802 - pywin32 callback name
            try:
                exit_code = self._supervisor.run(_Win32StopEvent(service_api, self._stop_handle))
            except OSError:
                _log_service_reason(service_api, REASON_SERVICE_CHILD_START_FAILED)
                return
            if exit_code:
                _log_service_reason(service_api, REASON_SERVICE_CHILD_FAILED)

    return MonitorWindowsService


class _Win32StopEvent:
    def __init__(self, service_api: Any, handle: Any) -> None:
        self._service_api = service_api
        self._handle = handle

    def is_set(self) -> bool:
        return self._service_api.win32event.WaitForSingleObject(self._handle, 0) == self._service_api.win32event.WAIT_OBJECT_0

    def wait(self, timeout: float | None = None) -> bool:
        milliseconds = self._service_api.win32event.INFINITE if timeout is None else max(0, int(timeout * 1000))
        return self._service_api.win32event.WaitForSingleObject(self._handle, milliseconds) == self._service_api.win32event.WAIT_OBJECT_0


def _log_service_reason(service_api: Any, reason: str) -> None:
    try:
        service_api.servicemanager.LogErrorMsg(reason)
    except Exception:
        pass


def run_service(
    config_path: Path | str,
    *,
    service_api: Any | None = None,
    popen_factory: PopenFactory = subprocess.Popen,
) -> int:
    """Connect the configured service class to SCM, or return a safe reason code."""
    config = ServiceConfig.from_json(config_path)
    api = service_api if service_api is not None else _load_service_api()
    if api is None:
        print(f"service failed reason={REASON_WINDOWS_SERVICE_UNAVAILABLE}", file=sys.stderr)
        return 2
    service_class = _make_service_class(config, api, popen_factory)
    # This process is launched directly by SCM via ``python -m`` rather than
    # through pywin32's generated pythonservice.exe.  HandleCommandLine with
    # only argv[0] prints usage and exits, so it never connects to SCM and the
    # service is reported as error 1053.  Host the class through the native
    # service-manager dispatcher instead.
    api.servicemanager.Initialize()
    api.servicemanager.PrepareToHostSingle(service_class)
    api.servicemanager.StartServiceCtrlDispatcher()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="runner-observability-service")
    subcommands = parser.add_subparsers(dest="command", required=True)
    run = subcommands.add_parser("run", help="run the configured Windows service host")
    run.add_argument("--config", required=True)
    arguments = parser.parse_args(argv)
    if arguments.command != "run":
        return 2
    try:
        return run_service(arguments.config)
    except ServiceConfigError as error:
        print(f"service failed reason={error.reason}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
