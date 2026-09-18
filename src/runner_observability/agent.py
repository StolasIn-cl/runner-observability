"""Fail-open schema-v1 telemetry sender with bounded retry behavior."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
import argparse
import json
import select
import socket
import ssl
import sys
from threading import Event, Thread
import time
from typing import Any
from urllib.error import URLError
from urllib.parse import urlsplit

from .contracts import ValidationError, validate_event


MAX_RETRIES = 2
MAX_DELIVERY_SECONDS = 5.0
MAX_RESPONSE_HEADER_BYTES = 8 * 1024
Transport = Callable[[str, Mapping[str, str], bytes], int]
Diagnostic = Callable[[str], None]
Clock = Callable[[], float]
Sleeper = Callable[[float], None]
Resolver = Callable[[str, int], Sequence[tuple[Any, ...]]]
Connector = Callable[[tuple[Any, ...], float], socket.socket]


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    """Safe, payload-free outcome of a single agent delivery attempt."""

    delivered: bool
    attempts: int
    reason: str | None = None


def deliver_event(
    event: object,
    endpoint: str,
    bearer_token: str,
    *,
    transport: Transport | None = None,
    clock: Clock = time.monotonic,
    sleeper: Sleeper = time.sleep,
    diagnostic: Diagnostic | None = None,
    resolver: Resolver | None = None,
    connector: Connector | None = None,
) -> DeliveryResult:
    """Validate and deliver one event without ever surfacing a delivery failure.

    Only network errors, HTTP 429, and HTTP 5xx responses are retried. Every
    diagnostic is a stable reason code and intentionally excludes the event,
    endpoint, token, and remote error text.
    """
    report = _safe_diagnostic(diagnostic or _stderr_diagnostic)
    try:
        validated = validate_event(event)
    except ValidationError as error:
        result = DeliveryResult(False, 0, error.reason)
        report(f"telemetry_event_rejected reason={error.reason}")
        return result

    body = json.dumps(_json_payload(validated.payload), ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    }
    started_at = clock()
    attempts = 0
    reason = "temporary_network_failure"
    while True:
        remaining = MAX_DELIVERY_SECONDS - (clock() - started_at)
        if attempts and remaining <= 0:
            result = DeliveryResult(False, attempts, reason)
            report(f"telemetry_delivery_failed reason={reason}")
            return result
        attempts += 1
        try:
            if transport is None:
                status = _http_transport(
                    endpoint,
                    headers,
                    body,
                    timeout=max(0.001, remaining),
                    resolver=resolver or _default_resolver,
                    connector=connector or _default_connector,
                )
            else:
                status = transport(endpoint, headers, body)
        except (OSError, TimeoutError, URLError):
            reason = "temporary_network_failure"
            retryable = True
        except Exception:
            result = DeliveryResult(False, attempts, "transport_failure")
            report("telemetry_delivery_failed reason=transport_failure")
            return result
        else:
            if 200 <= status < 300:
                return DeliveryResult(True, attempts)
            reason = "temporary_http_failure" if status == 429 or 500 <= status < 600 else "rejected_http_response"
            retryable = reason == "temporary_http_failure"

        if not retryable or attempts > MAX_RETRIES:
            result = DeliveryResult(False, attempts, reason)
            report(f"telemetry_delivery_failed reason={reason}")
            return result
        remaining = MAX_DELIVERY_SECONDS - (clock() - started_at)
        if remaining <= 0:
            result = DeliveryResult(False, attempts, reason)
            report(f"telemetry_delivery_failed reason={reason}")
            return result
        sleeper(min(float(2 ** (attempts - 1)), remaining))


def _http_transport(
    endpoint: str,
    headers: Mapping[str, str],
    body: bytes,
    *,
    timeout: float,
    resolver: Resolver,
    connector: Connector,
) -> int:
    """Send one request without redirect handling and with an absolute deadline."""
    parsed = urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise OSError("invalid_endpoint")
    deadline = time.monotonic() + timeout
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    sock = _connect_with_deadline(parsed.hostname, port, deadline, resolver, connector)
    try:
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=parsed.hostname, do_handshake_on_connect=False)
        request_path = parsed.path or "/"
        if parsed.query:
            request_path += f"?{parsed.query}"
        host = parsed.hostname if parsed.port is None else f"{parsed.hostname}:{parsed.port}"
        lines = [f"POST {request_path} HTTP/1.1", f"Host: {host}"]
        lines.extend(f"{key}: {value}" for key, value in headers.items())
        request = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body
        sock.setblocking(False)
        if parsed.scheme == "https":
            _handshake_with_deadline(sock, deadline)
        _send_with_deadline(sock, request, deadline)
        return _read_status_with_deadline(sock, deadline)
    finally:
        sock.close()


def main(
    argv: Sequence[str] | None = None,
    *,
    transport: Transport | None = None,
    clock: Clock = time.monotonic,
    sleeper: Sleeper = time.sleep,
    diagnostic: Diagnostic | None = None,
) -> int:
    """Run the ``emit`` command; delivery failures remain successful process exits."""
    parser = argparse.ArgumentParser(prog="runner-observability")
    parser.add_argument("--version", action="version", version="runner-observability schema-v1")
    subcommands = parser.add_subparsers(dest="command", required=True)
    emit = subcommands.add_parser("emit", help="validate and deliver one schema-v1 event")
    emit.add_argument("--endpoint", required=True)
    emit.add_argument("--token", required=True)
    emit.add_argument("--event-json", required=True)
    args = parser.parse_args(argv)
    if args.command != "emit":
        return 2
    report = _safe_diagnostic(diagnostic or _stderr_diagnostic)
    try:
        event: Any = json.loads(args.event_json)
    except json.JSONDecodeError:
        report("telemetry_event_rejected reason=invalid_json")
        return 0
    deliver_event(
        event,
        args.endpoint,
        args.token,
        transport=transport,
        clock=clock,
        sleeper=sleeper,
        diagnostic=report,
    )
    return 0


def _stderr_diagnostic(message: str) -> None:
    print(message, file=sys.stderr)


def _safe_diagnostic(diagnostic: Diagnostic) -> Diagnostic:
    """Keep a failed stderr/logger sink outside the telemetry failure path."""
    def report(message: str) -> None:
        try:
            diagnostic(message)
        except Exception:
            pass

    return report


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("delivery_deadline_elapsed")
    return remaining


def _default_resolver(host: str, port: int) -> Sequence[tuple[Any, ...]]:
    return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)


def _default_connector(candidate: tuple[Any, ...], timeout: float) -> socket.socket:
    family, socket_type, protocol, _canonical_name, address = candidate
    sock = socket.socket(family, socket_type, protocol)
    try:
        sock.settimeout(timeout)
        sock.connect(address)
        return sock
    except Exception:
        sock.close()
        raise


def _connect_with_deadline(
    host: str, port: int, deadline: float, resolver: Resolver, connector: Connector
) -> socket.socket:
    candidates = _run_with_deadline(lambda: resolver(host, port), deadline)
    last_error: OSError | None = None
    for candidate in candidates:
        try:
            return _run_with_deadline(
                lambda candidate=candidate: connector(candidate, _remaining(deadline)),
                deadline,
                on_late_result=_close_socket,
            )
        except TimeoutError:
            raise
        except OSError as error:
            last_error = error
    if last_error is not None:
        raise last_error
    raise OSError("no_connect_addresses")


def _run_with_deadline(
    operation: Callable[[], Any], deadline: float, *, on_late_result: Callable[[Any], None] | None = None
) -> Any:
    """Return promptly if an uninterruptible resolver/connect call outlives the deadline."""
    completed = Event()
    abandoned = Event()
    outcome: dict[str, Any] = {}

    def run() -> None:
        try:
            value = operation()
        except Exception as error:
            outcome["error"] = error
        else:
            if abandoned.is_set() and on_late_result is not None:
                on_late_result(value)
            else:
                outcome["value"] = value
        finally:
            completed.set()

    Thread(target=run, daemon=True).start()
    if not completed.wait(_remaining(deadline)):
        abandoned.set()
        if completed.is_set() and "value" in outcome and on_late_result is not None:
            on_late_result(outcome["value"])
        raise TimeoutError("delivery_deadline_elapsed")
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]


def _close_socket(value: Any) -> None:
    try:
        value.close()
    except Exception:
        pass


def _handshake_with_deadline(sock: Any, deadline: float) -> None:
    while True:
        try:
            sock.do_handshake()
            return
        except ssl.SSLWantReadError:
            _wait_for_socket(sock, deadline, write=False)
        except ssl.SSLWantWriteError:
            _wait_for_socket(sock, deadline, write=True)


def _send_with_deadline(sock: Any, request: bytes, deadline: float) -> None:
    remaining = memoryview(request)
    while remaining:
        try:
            sent = sock.send(remaining)
        except (BlockingIOError, ssl.SSLWantWriteError):
            _wait_for_socket(sock, deadline, write=True)
            continue
        except ssl.SSLWantReadError:
            _wait_for_socket(sock, deadline, write=False)
            continue
        if sent <= 0:
            raise OSError("connection_closed")
        remaining = remaining[sent:]


def _read_status_with_deadline(sock: Any, deadline: float) -> int:
    response = bytearray()
    while b"\r\n\r\n" not in response:
        if len(response) >= MAX_RESPONSE_HEADER_BYTES:
            raise OSError("response_headers_too_large")
        _wait_for_socket(sock, deadline, write=False)
        try:
            chunk = sock.recv(min(1024, MAX_RESPONSE_HEADER_BYTES - len(response)))
        except (BlockingIOError, ssl.SSLWantReadError):
            continue
        except ssl.SSLWantWriteError:
            _wait_for_socket(sock, deadline, write=True)
            continue
        if not chunk:
            raise OSError("connection_closed")
        response.extend(chunk)
    try:
        status_line = bytes(response).split(b"\r\n", 1)[0].decode("ascii")
        version, status, _reason = status_line.split(" ", 2)
        if not version.startswith("HTTP/"):
            raise ValueError
        return int(status)
    except (UnicodeDecodeError, ValueError) as error:
        raise OSError("invalid_http_response") from error


def _wait_for_socket(sock: Any, deadline: float, *, write: bool) -> None:
    readable, writable, _ = select.select([sock] if not write else [], [sock] if write else [], [], _remaining(deadline))
    if not readable and not writable:
        raise TimeoutError("delivery_deadline_elapsed")


def _json_payload(value: object) -> object:
    """Copy the immutable validated payload into JSON-compatible primitives."""
    if isinstance(value, Mapping):
        return {key: _json_payload(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_payload(item) for item in value]
    return value
