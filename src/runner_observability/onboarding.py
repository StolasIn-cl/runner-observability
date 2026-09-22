"""Pure validation seams for safe Runner and Monitor onboarding."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
from typing import Final


_REVISION_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SUPPORTED_CERTIFICATE_MODES: Final = {"public-ca", "private-ca", "self-signed", "existing"}
_SAFE_REASON_CODES: Final = frozenset(
    {
        "already_present",
        "added",
        "certificate_key_pair_missing",
        "conflicting_hosts_mapping",
        "duplicate_hosts_mapping",
        "install_root_not_directory",
        "install_root_unreadable",
        "invalid_certificate_mode",
        "invalid_hosts_input",
        "invalid_hostname",
        "invalid_monitor_ip",
        "invalid_release_pointer",
        "non_empty_without_release_pointer",
        "release_pointer_not_file",
        "replaced",
        "self_signed_not_allowed",
        "unknown_error",
        "unsupported_certificate_mode",
    }
)


class OnboardingValidationError(ValueError):
    """A safe, stable validation failure for an onboarding operation."""

    def __init__(self, reason: str) -> None:
        self.reason = safe_reason(reason)
        super().__init__(self.reason)


@dataclass(frozen=True, slots=True)
class InstallRootInspection:
    state: str
    reason: str = ""
    revision: str | None = None


@dataclass(frozen=True, slots=True)
class HostsUpdate:
    contents: str
    changed: bool
    reason: str = ""


def safe_reason(value: object) -> str:
    """Return one known reason code, collapsing all untrusted values."""

    candidate = getattr(value, "reason", value)
    return candidate if isinstance(candidate, str) and candidate in _SAFE_REASON_CODES else "unknown_error"


def inspect_install_root(root: Path | str) -> InstallRootInspection:
    """Classify an install root using only bounded filesystem metadata."""

    path = Path(root)
    try:
        if not path.exists():
            return InstallRootInspection("new")
        if not path.is_dir():
            return InstallRootInspection("inspect-before-use", "install_root_not_directory")

        pointer = path / "current-release.txt"
        if pointer.exists():
            if not pointer.is_file():
                return InstallRootInspection("inspect-before-use", "release_pointer_not_file")
            revision = pointer.read_text(encoding="utf-8").strip()
            if not _REVISION_PATTERN.fullmatch(revision) or ".." in revision:
                return InstallRootInspection("inspect-before-use", "invalid_release_pointer")
            return InstallRootInspection("existing", revision=revision)

        if any(path.iterdir()):
            return InstallRootInspection("inspect-before-use", "non_empty_without_release_pointer")
        return InstallRootInspection("new")
    except (OSError, UnicodeError):
        return InstallRootInspection("inspect-before-use", "install_root_unreadable")


def validate_monitor_ip(value: object) -> str:
    """Validate a confirmed, routable IPv4 address and return it unchanged."""

    if not isinstance(value, str) or not value or value != value.strip():
        raise OnboardingValidationError("invalid_monitor_ip")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise OnboardingValidationError("invalid_monitor_ip") from error
    if not isinstance(address, ipaddress.IPv4Address):
        raise OnboardingValidationError("invalid_monitor_ip")
    if address.is_loopback or address.is_multicast or address.is_unspecified or address.is_reserved:
        raise OnboardingValidationError("invalid_monitor_ip")
    if int(address) == 0xFFFFFFFF or address.is_link_local:
        raise OnboardingValidationError("invalid_monitor_ip")
    return value


def validate_certificate_mode(
    mode: str,
    *,
    cert_present: bool,
    key_present: bool,
    allow_dev_self_signed: bool,
) -> None:
    """Validate certificate trust-mode prerequisites without reading files."""

    if not isinstance(mode, str):
        raise OnboardingValidationError("unsupported_certificate_mode")
    normalized = mode.strip().lower().replace("_", "-")
    if normalized not in _SUPPORTED_CERTIFICATE_MODES:
        raise OnboardingValidationError("unsupported_certificate_mode")
    if normalized == "existing":
        return
    if not cert_present or not key_present:
        raise OnboardingValidationError("certificate_key_pair_missing")
    if normalized == "self-signed" and not allow_dev_self_signed:
        raise OnboardingValidationError("self_signed_not_allowed")


def upsert_hosts_mapping(
    contents: str,
    *,
    hostname: str,
    monitor_ip: str,
    replace_conflicting: bool = False,
) -> HostsUpdate:
    """Add or safely update one exact hostname mapping in hosts text."""

    if not isinstance(contents, str) or not isinstance(hostname, str) or not hostname.strip():
        raise OnboardingValidationError("invalid_hosts_input")
    if any(character.isspace() for character in hostname) or "#" in hostname:
        raise OnboardingValidationError("invalid_hostname")
    monitor_ip = validate_monitor_ip(monitor_ip)
    normalized_hostname = hostname.casefold()

    lines = contents.splitlines(keepends=True)
    matching_indexes: list[int] = []
    addresses: list[str] = []
    for index, line in enumerate(lines):
        tokens = line.split("#", 1)[0].split()
        matching_tokens = [token for token in tokens if token.casefold() == normalized_hostname]
        if matching_tokens and tokens.index(matching_tokens[0]) > 0:
            matching_indexes.append(index)
            addresses.append(tokens[0])

    if len(matching_indexes) > 1:
        raise OnboardingValidationError("duplicate_hosts_mapping")
    if matching_indexes and addresses[0] != monitor_ip and not replace_conflicting:
        raise OnboardingValidationError("conflicting_hosts_mapping")
    if matching_indexes and addresses[0] == monitor_ip:
        return HostsUpdate(contents, False, "already_present")

    if matching_indexes:
        index = matching_indexes[0]
        line = lines[index]
        newline = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
        body = line[: -len(newline)] if newline else line
        prefix_length = len(body) - len(body.lstrip())
        tokens = body.split()
        tokens[0] = monitor_ip
        lines[index] = body[:prefix_length] + " ".join(tokens) + newline
        return HostsUpdate("".join(lines), True, "replaced")

    separator = "" if not contents or contents.endswith(("\n", "\r")) else "\n"
    return HostsUpdate(
        contents + separator + f"{monitor_ip}\t{hostname}\n",
        True,
        "added",
    )
