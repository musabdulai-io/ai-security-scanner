# backend/app/features/scanner/packs/builtin/community_security.py
"""Community Security Pack - essential security vulnerability tests."""

from typing import List

from backend.app.features.scanner.attacks.base import AttackModule
from backend.app.features.scanner.attacks.security.prompt_injection import PromptInjector
from backend.app.features.scanner.attacks.security.pii_leaking import PIILeaker
from backend.app.features.scanner.attacks.security.prompt_extraction import PromptExtraction
from backend.app.features.scanner.attacks.security.refusal_bypass import RefusalBypassTest
from backend.app.features.scanner.packs.protocol import Pack, PackMetadata, PackTier


class CommunitySecurityPack(Pack):
    """Core security tests included with the community version.

    Includes the most essential security vulnerability tests:
    - Prompt Injection
    - PII Leaking
    - Prompt Extraction
    - Refusal Bypass
    """

    @property
    def metadata(self) -> PackMetadata:
        return PackMetadata(
            name="community-security",
            version="1.0.0",
            tier=PackTier.COMMUNITY,
            description="Essential security vulnerability tests for LLM/RAG applications",
        )

    def get_attack_modules(self, **kwargs) -> List[AttackModule]:
        return [
            PromptInjector(),
            PIILeaker(),
            PromptExtraction(),
            RefusalBypassTest(),
        ]
