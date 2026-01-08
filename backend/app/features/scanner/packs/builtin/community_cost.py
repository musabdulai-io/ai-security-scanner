# backend/app/features/scanner/packs/builtin/community_cost.py
"""Community Cost Pack - essential cost and efficiency tests."""

from typing import List

from backend.app.features.scanner.attacks.base import AttackModule
from backend.app.features.scanner.attacks.cost.efficiency_analysis import EfficiencyAnalysis
from backend.app.features.scanner.packs.protocol import Pack, PackMetadata, PackTier


class CommunityCostPack(Pack):
    """Core cost/efficiency tests included with the community version.

    Includes essential cost and efficiency tests:
    - Efficiency Analysis
    """

    @property
    def metadata(self) -> PackMetadata:
        return PackMetadata(
            name="community-cost",
            version="1.0.0",
            tier=PackTier.COMMUNITY,
            description="Essential cost and efficiency tests for LLM/RAG applications",
        )

    def get_attack_modules(self, **kwargs) -> List[AttackModule]:
        return [
            EfficiencyAnalysis(),
        ]
