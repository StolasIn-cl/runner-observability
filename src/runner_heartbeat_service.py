"""Managed-release launcher for the Windows Runner heartbeat service."""

from pathlib import Path
import sys

from runner_observability.heartbeat_service import main


def get_managed_config_path() -> Path:
    """Return the config beside the managed install's release directory."""
    # The launcher is staged as <install>\releases\<revision>\src\*.py.
    return Path(__file__).resolve().parents[3] / "heartbeat-config.json"


if __name__ == "__main__":
    # SCM starts the executable with no service-specific arguments.  Keep the
    # process argv bare so pywin32 can complete its SCM dispatcher handshake,
    # then pass the managed config path to the application parser explicitly.
    arguments = sys.argv[1:]
    if not arguments:
        arguments = ["run", "--config", str(get_managed_config_path())]
    raise SystemExit(main(arguments))
