"""Technology detection capability using WhatWeb."""

from typing import Any

from redforge.adapters.technology_detection import (
    TechnologyDetectionAdapter,
    TechnologyDetectionAdapterError,
)
from redforge.domain.endpoint import Endpoint
from redforge.domain.technology import Technology
from redforge.runtime.pipeline_state import PipelineStateKey
from redforge.sdk.capability import Capability
from redforge.sdk.context import Context
from redforge.sdk.result import Result, Status


class TechnologyDetectionCapability(Capability):
    """Technology detection capability using WhatWeb.

    This capability detects technologies on discovered endpoints using the
    WhatWeb external tool through the adapter pattern.
    """

    _ENDPOINTS_STATE_KEY = PipelineStateKey.ENDPOINTS

    def __init__(self, binary_path: str = "whatweb") -> None:
        """Initialize the technology detection capability.

        Args:
            binary_path: Path to the WhatWeb binary (default: "whatweb").
        """
        self._adapter = TechnologyDetectionAdapter(binary_path=binary_path)

    def execute(self, context: Context) -> Result[list[Technology]]:
        """Execute technology detection against endpoints from pipeline state.

        Args:
            context: Runtime context containing discovered endpoints in state.

        Returns:
            Result containing detected technologies or error information.
        """
        endpoints = self._get_endpoints_from_state(context.state)

        if not endpoints:
            return Result(status=Status.SUCCESS, data=[])

        try:
            technologies = self._adapter.detect_technologies(endpoints)
            return Result(status=Status.SUCCESS, data=technologies)
        except TechnologyDetectionAdapterError as e:
            return Result(status=Status.ERROR, data=[], errors=[str(e)])

    def _get_endpoints_from_state(self, state: dict[str, Any]) -> list[str]:  # type: ignore[reportUnknownParameterType]
        endpoints_data = state.get(self._ENDPOINTS_STATE_KEY, [])
        if not isinstance(endpoints_data, list):
            return []

        # Convert Endpoint objects to URL strings for WhatWeb input
        endpoint_urls: list[str] = []
        for endpoint in endpoints_data:  # type: ignore[reportUnknownVariableType]
            if isinstance(endpoint, Endpoint):
                url = self._endpoint_to_url(endpoint)
                endpoint_urls.append(url)

        return endpoint_urls

    def _endpoint_to_url(self, endpoint: Endpoint) -> str:
        """Convert an Endpoint object to a URL string."""
        protocol = endpoint.protocol
        host = endpoint.host
        port = endpoint.port
        path = endpoint.path or "/"

        # Skip default ports for cleaner URLs
        if (protocol == "http" and port == 80) or (protocol == "https" and port == 443):
            return f"{protocol}://{host}{path}"
        else:
            return f"{protocol}://{host}:{port}{path}"

    @property
    def name(self) -> str:
        """Get the name of the capability.

        Returns:
            The capability name.
        """
        return "technology_detection"
