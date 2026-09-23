"""Fail-open, stateful runner heartbeat scheduling."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import sys
import tempfile
import time
from typing import Any, ClassVar
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID, uuid4

from .agent import DeliveryResult, deliver_event
from .credentials import CredentialFileError, read_token_file


HEARTBEAT_EVENT_TYPE = "runner.heartbeat"
DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 60
DEFAULT_NETWORK_POLL_SECONDS = 5


def _canonical_event_endpoint(endpoint: str) -> str:
    parsed = urlsplit(endpoint)
    path = parsed.path.rstrip("/")
    if path.casefold() in {"", "/"}:
        path = "/v1/events"
    elif path.casefold() == "/v1/events":
        path = "/v1/events"
    return urlunsplit((parsed.scheme, parsed.netloc, path, parsed.query, parsed.fragment))


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

Clock = Callable[[], float]
Sleeper = Callable[[float], None]
NetworkProbe = Callable[[str, float], bool]
Deliver = Callable[[object, str, str], DeliveryResult]
Diagnostic = Callable[[str], None]


class HeartbeatConfigError(ValueError):
    """A non-secret heartbeat configuration failure."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class HeartbeatStateError(ValueError):
    """A non-secret producer-state failure."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class HeartbeatConfig:
    """Non-secret settings needed by one Runner heartbeat service."""

    endpoint: str
    token_file: str
    runner_id: str
    state_file: str
    producer_id: str = "runner-heartbeat"
    service_name: str = "RunnerObservabilityHeartbeat"
    python_executable: str = sys.executable
    interval_seconds: int = DEFAULT_HEARTBEAT_INTERVAL_SECONDS
    network_poll_seconds: int = DEFAULT_NETWORK_POLL_SECONDS
    allow_insecure_http: bool = False

    _FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "endpoint",
            "token_file",
            "runner_id",
            "state_file",
            "producer_id",
            "service_name",
            "python_executable",
            "interval_seconds",
            "network_poll_seconds",
            "allow_insecure_http",
        }
    )

    def __post_init__(self) -> None:
        for value in (self.endpoint, self.token_file, self.runner_id, self.state_file, self.producer_id, self.service_name, self.python_executable):
            if not isinstance(value, str) or not value.strip():
                raise HeartbeatConfigError("invalid_heartbeat_configuration")
        try:
            parsed = urlsplit(self.endpoint)
            parsed.port  # Force validation of an explicit port at config load.
        except ValueError as error:
            raise HeartbeatConfigError("invalid_endpoint") from error
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise HeartbeatConfigError("invalid_endpoint")
        if parsed.scheme == "http" and not self.allow_insecure_http:
            raise HeartbeatConfigError("insecure_endpoint")
        try:
            UUID(self.runner_id)
        except (ValueError, AttributeError, TypeError) as error:
            raise HeartbeatConfigError("invalid_runner_id") from error
        if not _IDENTIFIER.fullmatch(self.producer_id) or not _IDENTIFIER.fullmatch(self.service_name):
            raise HeartbeatConfigError("invalid_heartbeat_configuration")
        if isinstance(self.interval_seconds, bool) or not isinstance(self.interval_seconds, int) or not 1 <= self.interval_seconds <= 86400:
            raise HeartbeatConfigError("invalid_heartbeat_configuration")
        if isinstance(self.network_poll_seconds, bool) or not isinstance(self.network_poll_seconds, int) or not 1 <= self.network_poll_seconds <= 300:
            raise HeartbeatConfigError("invalid_heartbeat_configuration")
        if not isinstance(self.allow_insecure_http, bool):
            raise HeartbeatConfigError("invalid_heartbeat_configuration")

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> HeartbeatConfig:
        if not isinstance(raw, Mapping) or any(key not in cls._FIELDS for key in raw):
            raise HeartbeatConfigError("invalid_heartbeat_configuration")
        values: dict[str, Any] = {
            "producer_id": "runner-heartbeat",
            "service_name": "RunnerObservabilityHeartbeat",
            "python_executable": sys.executable,
            "interval_seconds": DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
            "network_poll_seconds": DEFAULT_NETWORK_POLL_SECONDS,
            "allow_insecure_http": False,
        }
        values.update(raw)
        for required in ("endpoint", "token_file", "runner_id", "state_file"):
            if required not in values or not isinstance(values[required], str) or not values[required].strip():
                raise HeartbeatConfigError("invalid_heartbeat_configuration")
        try:
            return cls(**values)
        except TypeError as error:
            raise HeartbeatConfigError("invalid_heartbeat_configuration") from error

    @classmethod
    def from_json(cls, path: Path | str) -> HeartbeatConfig:
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise HeartbeatConfigError("invalid_heartbeat_configuration") from error
        return cls.from_mapping(raw)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "token_file": self.token_file,
            "runner_id": self.runner_id,
            "state_file": self.state_file,
            "producer_id": self.producer_id,
            "service_name": self.service_name,
            "python_executable": self.python_executable,
            "interval_seconds": self.interval_seconds,
            "network_poll_seconds": self.network_poll_seconds,
            "allow_insecure_http": self.allow_insecure_http,
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
        except (OSError, TypeError) as error:
            raise HeartbeatConfigError("config_file_unwritable") from error
        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass


@dataclass(frozen=True, slots=True)
class HeartbeatState:
    """Persisted producer identity and the next sequence to reserve."""

    runner_id: str
    producer_id: str
    producer_epoch: str
    next_sequence: int

    @classmethod
    def load(
        cls,
        path: Path | str,
        runner_id: str,
        producer_id: str,
        *,
        epoch_factory: Callable[[], str] = lambda: str(uuid4()),
    ) -> HeartbeatState:
        target = Path(path)
        if not target.is_file():
            state = cls(runner_id, producer_id, epoch_factory(), 1)
            state._save(target)
            return state
        try:
            raw = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            raw = None
        if isinstance(raw, Mapping) and "runner_id" in raw and raw.get("runner_id") != runner_id:
            raise HeartbeatStateError("state_identity_mismatch")
        if isinstance(raw, Mapping) and "producer_id" in raw and raw.get("producer_id") != producer_id:
            raise HeartbeatStateError("state_identity_mismatch")
        if isinstance(raw, Mapping) and _IDENTIFIER.fullmatch(str(raw.get("producer_epoch", ""))) and isinstance(raw.get("next_sequence"), int) and not isinstance(raw.get("next_sequence"), bool) and raw["next_sequence"] >= 1:
            return cls(runner_id, producer_id, str(raw["producer_epoch"]), int(raw["next_sequence"]))
        state = cls(runner_id, producer_id, epoch_factory(), 1)
        state._save(target)
        return state

    def reserve(self, path: Path | str) -> tuple[HeartbeatState, int]:
        sequence = self.next_sequence
        next_state = HeartbeatState(self.runner_id, self.producer_id, self.producer_epoch, sequence + 1)
        next_state._save(Path(path))
        return next_state, sequence

    def _save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=path.parent,
                prefix=f".{path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                json.dump(
                    {
                        "runner_id": self.runner_id,
                        "producer_id": self.producer_id,
                        "producer_epoch": self.producer_epoch,
                        "next_sequence": self.next_sequence,
                    },
                    temporary,
                    ensure_ascii=True,
                    sort_keys=True,
                )
                temporary.write("\n")
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary_path, path)
            temporary_path = None
        except OSError as error:
            raise HeartbeatStateError("state_file_unwritable") from error
        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _heartbeat_event(config: HeartbeatConfig, state: HeartbeatState, sequence: int) -> dict[str, object]:
    return {
        "schema_version": 1,
        "event_type": HEARTBEAT_EVENT_TYPE,
        "event_id": str(uuid4()),
        "runner_id": config.runner_id,
        "producer_id": config.producer_id,
        "producer_epoch": state.producer_epoch,
        "producer_sequence": sequence,
        "occurred_at": _utc_timestamp(),
    }


def _safe_diagnostic(diagnostic: Diagnostic) -> Diagnostic:
    def report(message: str) -> None:
        try:
            diagnostic(message)
        except Exception:
            pass

    return report


def _probe_endpoint(endpoint: str, timeout: float) -> bool:
    parsed = urlsplit(endpoint)
    if parsed.hostname is None:
        return False
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        with socket.create_connection((parsed.hostname, port), timeout=timeout):
            return True
    except OSError:
        return False


class HeartbeatLoop:
    """Run one fail-open heartbeat producer with drift-free scheduling."""

    def __init__(
        self,
        config: HeartbeatConfig,
        *,
        clock: Clock = time.monotonic,
        sleeper: Sleeper = time.sleep,
        network_probe: NetworkProbe = _probe_endpoint,
        deliver: Deliver | None = None,
        diagnostic: Diagnostic | None = None,
    ) -> None:
        self.config = config
        self._clock = clock
        self._sleeper = sleeper
        self._network_probe = network_probe
        self._diagnostic = _safe_diagnostic(diagnostic or (lambda _message: None))
        self._state: HeartbeatState | None = None
        self._event_endpoint = _canonical_event_endpoint(config.endpoint)
        if deliver is None:
            self._deliver = lambda event, _endpoint, token: deliver_event(
                event,
                self._event_endpoint,
                token,
                clock=clock,
                sleeper=sleeper,
                diagnostic=self._diagnostic,
            )
        else:
            self._deliver = deliver

    def emit_once(self) -> DeliveryResult:
        try:
            token = read_token_file(self.config.token_file)
        except CredentialFileError as error:
            self._diagnostic(f"heartbeat_delivery_failed reason={error.reason}")
            return DeliveryResult(False, 0, error.reason)
        try:
            if self._state is None:
                self._state = HeartbeatState.load(
                    self.config.state_file,
                    self.config.runner_id,
                    self.config.producer_id,
                )
            self._state, sequence = self._state.reserve(self.config.state_file)
        except HeartbeatStateError as error:
            self._diagnostic(f"heartbeat_delivery_failed reason={error.reason}")
            return DeliveryResult(False, 0, error.reason)
        event = _heartbeat_event(self.config, self._state, sequence)
        result = self._deliver(event, self._event_endpoint, token)
        if not result.delivered:
            self._diagnostic(f"heartbeat_delivery_failed reason={result.reason or 'delivery_failed'}")
        return result

    def _wait_for_network(self, stop_event: Any) -> bool:
        while not stop_event.is_set():
            try:
                if self._network_probe(self.config.endpoint, float(self.config.network_poll_seconds)):
                    return True
            except Exception:
                pass
            self._diagnostic("heartbeat_network_unavailable")
            if stop_event.wait(float(self.config.network_poll_seconds)):
                return False
        return False

    def run(self, stop_event: Any) -> int:
        next_due: float | None = None
        while not stop_event.is_set():
            first_heartbeat = next_due is None
            if next_due is None:
                if not self._wait_for_network(stop_event):
                    return 0
                next_due = self._clock()
            delay = next_due - self._clock()
            if delay > 0 and stop_event.wait(delay):
                return 0
            if stop_event.is_set():
                return 0
            if not first_heartbeat and not self._wait_for_network(stop_event):
                return 0
            self.emit_once()
            next_due += float(self.config.interval_seconds)
            now = self._clock()
            while next_due <= now:
                next_due += float(self.config.interval_seconds)
        return 0
