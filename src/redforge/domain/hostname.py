"""Conservative canonical DNS hostname normalization."""

from ipaddress import ip_address
from typing import cast


def normalize_dns_hostname(
    value: str,
    *,
    reject_ip: bool = True,
) -> str:
    """Return a canonical ASCII DNS name or reject non-hostname input."""
    if not isinstance(cast(object, value), str) or not value:
        raise ValueError("invalid hostname")
    if value != value.strip() or any(
        character.isspace() or ord(character) < 32 or ord(character) == 127
        for character in value
    ):
        raise ValueError("invalid hostname")
    hostname = value.lower()
    if hostname.endswith("."):
        hostname = hostname[:-1]
    if not hostname or len(hostname) > 253 or hostname.startswith("*."):
        raise ValueError("invalid hostname")
    if any(marker in hostname for marker in ("://", "/", "?", "#", ":")):
        raise ValueError("invalid hostname")

    labels = hostname.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        raise ValueError("invalid hostname")
    encoded_labels: list[str] = []
    try:
        for label in labels:
            encoded = label.encode("idna").decode("ascii")
            if (
                not encoded
                or len(encoded) > 63
                or encoded.startswith("-")
                or encoded.endswith("-")
                or any(
                    not (character.isascii() and character.isalnum())
                    and character != "-"
                    for character in encoded
                )
            ):
                raise ValueError("invalid hostname")
            encoded_labels.append(encoded)
    except UnicodeError as error:
        raise ValueError("invalid hostname") from error

    normalized = ".".join(encoded_labels)
    if len(normalized) > 253:
        raise ValueError("invalid hostname")
    if reject_ip:
        try:
            ip_address(normalized)
        except ValueError:
            pass
        else:
            raise ValueError("invalid hostname")
    return normalized
