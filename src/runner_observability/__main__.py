"""Command-line entry point for the local monitor and fail-open sender."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path
import sys
from typing import Any

from .agent import main as emit_main
from .credentials import CredentialFileError, read_token_file
from .server import REASON_TLS_PARTIAL_CONFIGURATION, TlsConfigurationError, create_server
from .store import Store


def main(argv: Sequence[str] | None = None, **emit_options: Any) -> int:
    """Dispatch monitor serving or event emission without importing runner APIs."""
    parser = argparse.ArgumentParser(prog="runner-observability")
    subcommands = parser.add_subparsers(dest="command", required=True)
    serve = subcommands.add_parser("serve", help="run the local telemetry monitor")
    token_arguments = serve.add_mutually_exclusive_group()
    token_arguments.add_argument("--token", default=None)
    token_arguments.add_argument("--token-file", default=None)
    serve.add_argument("--database", default="runner-observability.sqlite")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument(
        "--tls-cert",
        default=None,
        help="TLS certificate file; must be paired with --tls-key to serve HTTPS instead of plain HTTP",
    )
    serve.add_argument(
        "--tls-key",
        default=None,
        help="TLS private key file; must be paired with --tls-cert to serve HTTPS instead of plain HTTP",
    )
    emit = subcommands.add_parser("emit", help="validate and deliver one schema-v1 event")
    emit.add_argument("--endpoint", required=True)
    emit.add_argument("--token", required=True)
    emit.add_argument("--event-json", required=True)
    emit.add_argument("--outbox-dir", default=None)
    flush = subcommands.add_parser("flush", help="replay pending schema-v1 events")
    flush.add_argument("--endpoint", required=True)
    flush.add_argument("--token-file", required=True)
    flush.add_argument("--outbox-dir", required=True)
    arguments = parser.parse_args(argv)
    if arguments.command in {"emit", "flush"}:
        forwarded = ["--endpoint", arguments.endpoint]
        if arguments.outbox_dir is not None:
            forwarded.extend(["--outbox-dir", arguments.outbox_dir])
        if arguments.command == "emit":
            forwarded = [
                "emit",
                *forwarded,
                "--token",
                arguments.token,
                "--event-json",
                arguments.event_json,
            ]
        else:
            forwarded = [
                "flush",
                *forwarded,
                "--token-file",
                arguments.token_file,
            ]
        return emit_main([item for item in forwarded if item is not None], **emit_options)
    if arguments.token is None and arguments.token_file is None:
        print("serve failed reason=auth_credential_missing", file=sys.stderr)
        return 2
    if arguments.token_file is None:
        bearer_token = arguments.token
    else:
        try:
            bearer_token = read_token_file(Path(arguments.token_file))
        except CredentialFileError as error:
            print(f"serve failed reason={error.reason}", file=sys.stderr)
            return 2
    # Check the --tls-cert/--tls-key pairing before touching the database
    # at all: create_server() re-validates this (it is the single source
    # of truth for the check), but a mistyped/partial TLS configuration is
    # a likely, ordinary operator mistake, and it should fail without the
    # side effect of creating/migrating the SQLite database file first.
    if (arguments.tls_cert is None) != (arguments.tls_key is None):
        print(f"serve failed reason={REASON_TLS_PARTIAL_CONFIGURATION}", file=sys.stderr)
        return 2
    store = Store(arguments.database)
    try:
        server = create_server(
            store,
            bearer_token,
            host=arguments.host,
            port=arguments.port,
            tls_cert_path=arguments.tls_cert,
            tls_key_path=arguments.tls_key,
        )
    except TlsConfigurationError as error:
        # Redacted, controlled failure: never a raw traceback, never the
        # configured cert/key path, never the underlying ssl/OSError text.
        # No partially-started server is left behind -- create_server()
        # raises before any listening socket is bound.
        print(f"serve failed reason={error.reason}", file=sys.stderr)
        store.close()
        return 2
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
