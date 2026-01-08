# backend/app/features/scanner/packs/builtin/community_reliability.py
"""Community Reliability Pack - essential reliability and QA tests."""

from typing import List

from backend.app.features.scanner.attacks.base import AttackModule
from backend.app.features.scanner.attacks.reliability.hallucination_detection import HallucinationDetection
from backend.app.features.scanner.attacks.reliability.reliability_checks import OffTopicHandler
from backend.app.features.scanner.packs.protocol import Pack, PackMetadata, PackTier


class CommunityReliabilityPack(Pack):
    """Core reliability tests included with the community version.

    Includes essential reliability and quality tests:
    - Hallucination Detection
    - Off-Topic Handling
    """

    @property
    def metadata(self) -> PackMetadata:
        return PackMetadata(
            name="community-reliability",
            version="1.0.0",
            tier=PackTier.COMMUNITY,
            description="Essential reliability and quality tests for LLM/RAG applications",
        )

    def get_attack_modules(self, **kwargs) -> List[AttackModule]:
        return [
            HallucinationDetection(),
            OffTopicHandler(),
        ]
