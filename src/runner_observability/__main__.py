"""Command-line entry point for the local monitor and fail-open sender."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from typing import Any

from .agent import main as emit_main
from .server import create_server
from .store import Store


def main(argv: Sequence[str] | None = None, **emit_options: Any) -> int:
    """Dispatch monitor serving or event emission without importing runner APIs."""
    parser = argparse.ArgumentParser(prog="runner-observability")
    subcommands = parser.add_subparsers(dest="command", required=True)
    serve = subcommands.add_parser("serve", help="run the local telemetry monitor")
    serve.add_argument("--token", required=True)
    serve.add_argument("--database", default="runner-observability.sqlite")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    emit = subcommands.add_parser("emit", help="validate and deliver one schema-v1 event")
    emit.add_argument("--endpoint", required=True)
    emit.add_argument("--token", required=True)
    emit.add_argument("--event-json", required=True)
    arguments = parser.parse_args(argv)
    if arguments.command == "emit":
        return emit_main(
            [
                "emit",
                "--endpoint",
                arguments.endpoint,
                "--token",
                arguments.token,
                "--event-json",
                arguments.event_json,
            ],
            **emit_options,
        )
    store = Store(arguments.database)
    server = create_server(store, arguments.token, host=arguments.host, port=arguments.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
