"""Managed-release launcher for the Windows Runner heartbeat service."""

from runner_observability.heartbeat_service import main


if __name__ == "__main__":
    raise SystemExit(main())
