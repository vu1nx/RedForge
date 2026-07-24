"""Deterministic hostname normalization and resolution capability."""

from ipaddress import ip_address
from typing import cast

from redforge.adapters.host_resolver import (
    HostResolver,
    HostResolverError,
    StandardHostResolver,
)
from redforge.adapters.subfinder import SubdomainDiscoveryResult
from redforge.domain.host import Host, HostAddress, HostResolution, IPVersion
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, Status


def normalize_hostname(value: str) -> str:
    """Return a conservative canonical ASCII hostname."""
    hostname = value.strip().lower()
    if hostname.endswith("."):
        hostname = hostname[:-1]
    if not hostname or len(hostname) > 253:
        raise ValueError("invalid hostname")
    if any(marker in hostname for marker in ("://", "/", "?", "#", ":")):
        raise ValueError("invalid hostname")

    labels = hostname.split(".")
    if any(not label for label in labels):
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
    return normalized


class HostResolutionCapability(Capability):
    """Resolve discovered hostname strings into explicit Host objects."""

    def __init__(self, resolver: HostResolver | None = None) -> None:
        self._resolver = resolver or StandardHostResolver()

    def execute(self, context: Context) -> Result[HostResolution]:
        """Normalize, deduplicate, and resolve discovered names."""
        if PipelineStateKey.SUBDOMAINS not in context.state:
            return Result(
                status=Status.FAILURE,
                data=HostResolution(),
                errors=["Required discovered hostname input is missing"],
                metadata={"missing_prerequisite": PipelineStateKey.SUBDOMAINS},
            )

        input_value = context.state[PipelineStateKey.SUBDOMAINS]
        if not isinstance(input_value, SubdomainDiscoveryResult):
            return self._invalid_input()
        subdomains = input_value.hostnames

        if not subdomains:
            return self._result(Status.SUCCESS, (), (), 0, 0)

        errors: list[str] = []
        normalized_names: set[str] = set()
        for index, item in enumerate(cast(tuple[object, ...], subdomains)):
            if not isinstance(item, str):
                errors.append(f"Invalid hostname input at index {index}")
                continue
            try:
                normalized_names.add(normalize_hostname(item))
            except ValueError:
                errors.append(f"Invalid hostname input at index {index}")

        hosts: list[Host] = []
        malformed_address_count = 0
        unresolved_count = 0
        for hostname in sorted(normalized_names):
            try:
                response = cast(object, self._resolver.resolve(hostname))
            except HostResolverError:
                unresolved_count += 1
                errors.append(f"Unable to resolve hostname '{hostname}'")
                continue
            except Exception:
                return Result(
                    status=Status.ERROR,
                    data=HostResolution(),
                    errors=[
                        "Host resolver failed with an unexpected execution error"
                    ],
                    metadata={"error_kind": "unexpected_resolver_error"},
                )
            if not isinstance(response, tuple):
                return Result(
                    status=Status.ERROR,
                    data=HostResolution(),
                    errors=["Host resolver returned an invalid response"],
                    metadata={"error_kind": "invalid_resolver_response"},
                )

            addresses: set[HostAddress] = set()
            hostname_has_malformed_address = False
            for address_value in cast(tuple[object, ...], response):
                if not isinstance(address_value, str):
                    malformed_address_count += 1
                    hostname_has_malformed_address = True
                    continue
                try:
                    parsed = ip_address(address_value)
                except ValueError:
                    malformed_address_count += 1
                    hostname_has_malformed_address = True
                    continue
                addresses.add(
                    HostAddress(
                        value=str(parsed),
                        version=(
                            IPVersion.IPV4
                            if parsed.version == 4
                            else IPVersion.IPV6
                        ),
                    )
                )
            if hostname_has_malformed_address:
                errors.append(
                    f"Resolver returned malformed address data for hostname "
                    f"'{hostname}'"
                )
            if not addresses:
                unresolved_count += 1
                errors.append(f"Unable to resolve hostname '{hostname}'")
                continue

            ordered_addresses = tuple(
                sorted(
                    addresses,
                    key=lambda address: (
                        4 if address.version == IPVersion.IPV4 else 6,
                        address.value,
                    ),
                )
            )
            hosts.append(
                Host(
                    hostname=hostname,
                    addresses=ordered_addresses,
                    evidence=(
                        f"hostname-input:{hostname}",
                        *(
                            f"resolved-address:{address.value}"
                            for address in ordered_addresses
                        ),
                    ),
                )
            )

        ordered_hosts = tuple(sorted(hosts, key=lambda host: host.hostname or ""))
        issue_count = len(errors) + malformed_address_count
        if ordered_hosts:
            status = Status.PARTIAL if issue_count else Status.SUCCESS
        else:
            status = Status.FAILURE
        return self._result(
            status,
            ordered_hosts,
            tuple(errors),
            unresolved_count,
            malformed_address_count,
        )

    def _invalid_input(self) -> Result[HostResolution]:
        return Result(
            status=Status.ERROR,
            data=HostResolution(),
            errors=["Discovered hostname input has an invalid type"],
            metadata={
                "invalid_input": PipelineStateKey.SUBDOMAINS,
                "expected_type": "subdomain discovery mapping",
            },
        )

    def _result(
        self,
        status: Status,
        hosts: tuple[Host, ...],
        errors: tuple[str, ...],
        unresolved_count: int,
        malformed_address_count: int,
    ) -> Result[HostResolution]:
        return Result(
            status=status,
            data=HostResolution(hosts=hosts),
            errors=list(errors),
            metadata={
                "host_count": len(hosts),
                "unresolved_hostname_count": unresolved_count,
                "malformed_address_count": malformed_address_count,
            },
        )

    @property
    def name(self) -> str:
        return "host_resolution"
