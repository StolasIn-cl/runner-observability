"""Redacted credential-file helpers for service-managed monitor startup."""

from __future__ import annotations

from pathlib import Path


class CredentialFileError(ValueError):
    """A safe credential-file failure identified only by a stable reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def read_token_file(path: Path | str) -> str:
    """Read one non-empty token without retaining its path or value in errors."""
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as error:
        raise CredentialFileError("auth_credential_file_missing") from error
    if not value:
        raise CredentialFileError("auth_credential_invalid")
    if "\n" in value or "\r" in value:
        raise CredentialFileError("auth_credential_invalid")
    return value
