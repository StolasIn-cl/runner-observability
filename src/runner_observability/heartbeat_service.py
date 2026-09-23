"""Windows SCM adapter for the Runner heartbeat producer."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
from typing import Any, Sequence

from .heartbeat import HeartbeatConfig, HeartbeatConfigError, HeartbeatLoop
from .service import _Win32StopEvent, _load_service_api, _log_service_reason


REASON_WINDOWS_SERVICE_UNAVAILABLE = "windows_service_unavailable"
REASON_HEARTBEAT_SERVICE_FAILED = "heartbeat_service_failed"


def build_heartbeat_service_bin_path(
    config_path: Path | str,
    python_executable: Path | str,
    module_path: Path | str,
) -> str:
    """Build an SCM command rooted at the managed release source directory.

    ``config_path`` remains part of this function's contract for callers that
    already provide the complete service configuration, but it is deliberately
    not placed in the SCM command line.  The managed launcher derives it from
    its own release path so SCM starts the pywin32 host with a bare argv.
    """
    del config_path
    launcher_path = Path(module_path) / "runner_heartbeat_service.py"
    return subprocess.list2cmdline(
        [
            str(python_executable),
            str(launcher_path),
        ]
    )


def _make_service_class(config: HeartbeatConfig, service_api: Any) -> type:
    class RunnerHeartbeatWindowsService(service_api.win32serviceutil.ServiceFramework):
        _svc_name_ = config.service_name
        _svc_display_name_ = "Runner Observability Runner Heartbeat"
        _svc_description_ = "Runner Observability fail-open heartbeat service"

        def __init__(self, args: Sequence[str]) -> None:
            super().__init__(args)
            self._stop_handle = service_api.win32event.CreateEvent(None, 0, 0, None)
            self._loop = HeartbeatLoop(
                config,
                diagnostic=lambda message: _log_service_reason(service_api, message),
            )

        def SvcStop(self) -> None:  # noqa: N802 - pywin32 callback name
            self.ReportServiceStatus(service_api.win32service.SERVICE_STOP_PENDING)
            service_api.win32event.SetEvent(self._stop_handle)

        def SvcDoRun(self) -> None:  # noqa: N802 - pywin32 callback name
            try:
                self._loop.run(_Win32StopEvent(service_api, self._stop_handle))
            except Exception:
                _log_service_reason(service_api, REASON_HEARTBEAT_SERVICE_FAILED)

    return RunnerHeartbeatWindowsService


def run_service(config_path: Path | str, *, service_api: Any | None = None) -> int:
    """Connect the heartbeat service class to SCM or report a stable reason."""
    config = HeartbeatConfig.from_json(config_path)
    api = service_api if service_api is not None else _load_service_api()
    if api is None:
        print(f"service failed reason={REASON_WINDOWS_SERVICE_UNAVAILABLE}", file=sys.stderr)
        return 2
    service_class = _make_service_class(config, api)
    # The service is launched directly by SCM through ``python -m``.  The
    # pywin32 command-line helper expects to install/control a generated
    # pythonservice.exe host and does not connect this process to SCM, which
    # causes SCM start requests to time out with error 1053.
    api.servicemanager.Initialize()
    api.servicemanager.PrepareToHostSingle(service_class)
    api.servicemanager.StartServiceCtrlDispatcher()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="runner-observability-heartbeat-service")
    subcommands = parser.add_subparsers(dest="command", required=True)
    run = subcommands.add_parser("run", help="run the configured Windows heartbeat service host")
    run.add_argument("--config", required=True)
    arguments = parser.parse_args(argv)
    if arguments.command != "run":
        return 2
    try:
        return run_service(arguments.config)
    except HeartbeatConfigError as error:
        print(f"service failed reason={error.reason}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
