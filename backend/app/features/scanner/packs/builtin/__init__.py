# backend/app/features/scanner/packs/builtin/__init__.py
"""Built-in community packs shipped with the scanner."""

from .community_security import CommunitySecurityPack
from .community_reliability import CommunityReliabilityPack
from .community_cost import CommunityCostPack

BUILTIN_PACKS = [
    CommunitySecurityPack,
    CommunityReliabilityPack,
    CommunityCostPack,
]

__all__ = [
    "CommunitySecurityPack",
    "CommunityReliabilityPack",
    "CommunityCostPack",
    "BUILTIN_PACKS",
]
