# backend/app/features/scanner/packs/protocol.py
"""Pack protocol definition for scanner plugin system."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List
from enum import Enum

from backend.app.features.scanner.attacks.base import AttackModule


class PackTier(str, Enum):
    """Pack tier/licensing level."""
    COMMUNITY = "community"
    PRO = "pro"


@dataclass
class PackMetadata:
    """Metadata for a scanner pack."""
    name: str           # e.g., "community-security"
    version: str        # e.g., "1.0.0"
    tier: PackTier
    description: str


class Pack(ABC):
    """Abstract base class for scanner packs.

    All packs (community and pro) must implement this interface.

    Example implementation:

        class CommunitySecurityPack(Pack):
            @property
            def metadata(self) -> PackMetadata:
                return PackMetadata(
                    name="community-security",
                    version="1.0.0",
                    tier=PackTier.COMMUNITY,
                    description="Core security vulnerability tests",
                )

            def get_attack_modules(self, **kwargs) -> List[AttackModule]:
                return [
                    PromptInjector(),
                    PIILeaker(),
                ]
    """

    @property
    @abstractmethod
    def metadata(self) -> PackMetadata:
        """Return pack metadata."""
        pass

    @abstractmethod
    def get_attack_modules(self, **kwargs) -> List[AttackModule]:
        """Return instantiated attack modules.

        Args:
            **kwargs: Configuration options (e.g., competitors list)

        Returns:
            List of instantiated AttackModule objects ready for use.
        """
        pass
