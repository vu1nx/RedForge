"""Capability abstract base class."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from redforge.sdk.context import Context
    from redforge.sdk.result import Result


class Capability(ABC):
    """Abstract base class for capabilities.

    A capability represents a specific action or operation that can be
    performed within the RedForge framework. Implementations must define
    the execute method which takes a Context and returns a Result.
    """

    @abstractmethod
    def execute(self, context: "Context") -> "Result[Any]":
        """Execute the capability with the given context.

        Args:
            context: Runtime context containing state and configuration.

        Returns:
            Result containing the outcome of the capability execution.
        """
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        """Get the name of the capability.

        Returns:
            Unique name identifying this capability.
        """
        ...
