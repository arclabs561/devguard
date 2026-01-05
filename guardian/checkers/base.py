"""Base checker interface."""

from abc import ABC, abstractmethod

from guardian.config import Settings
from guardian.models import CheckResult


class BaseChecker(ABC):
    """Base class for all checkers."""

    def __init__(self, settings: Settings):
        """Initialize checker with settings."""
        self.settings = settings

    @abstractmethod
    async def check(self) -> CheckResult:
        """Perform the check and return results."""
        pass

    @property
    @abstractmethod
    def check_type(self) -> str:
        """Return the type of check this checker performs."""
        pass
