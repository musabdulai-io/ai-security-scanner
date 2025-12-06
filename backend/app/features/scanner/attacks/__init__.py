# backend/app/features/scanner/attacks/__init__.py
"""Attack modules for security scanning - organized by category."""

from .base import AttackModule

# Security attacks (core vulnerability testing)
from .security import (
    PromptInjector,
    PIILeaker,
    RAGPoisoner,
    PromptExtraction,
    OutputWeaponization,
    ExcessiveAgency,
    ToolAbuseAttack,
    EncodingAttack,
    StructureAttack,
    IndirectInjection,
    MultiTurnAttack,
    LanguageAttack,
    ManyShotJailbreak,
    ContentContinuationAttack,
    RefusalBypassTest,
    SECURITY_ATTACKS,
)

# Reliability attacks (business logic and quality testing)
from .reliability import (
    HallucinationDetection,
    TableParsingTest,
    RetrievalPrecisionTest,
    CompetitorTrap,
    PricingTrap,
    OffTopicHandler,
    BrandSafetyTest,
    RELIABILITY_ATTACKS,
)

# Cost attacks (resource and efficiency testing)
from .cost import (
    EfficiencyAnalysis,
    ResourceExhaustionAttack,
    COST_ATTACKS,
)

__all__ = [
    "AttackModule",
    # Security attacks
    "PromptInjector",
    "PIILeaker",
    "RAGPoisoner",
    "PromptExtraction",
    "OutputWeaponization",
    "ExcessiveAgency",
    "ToolAbuseAttack",
    "EncodingAttack",
    "StructureAttack",
    "IndirectInjection",
    "MultiTurnAttack",
    "LanguageAttack",
    "ManyShotJailbreak",
    "ContentContinuationAttack",
    "RefusalBypassTest",
    # Reliability attacks
    "HallucinationDetection",
    "TableParsingTest",
    "RetrievalPrecisionTest",
    "CompetitorTrap",
    "PricingTrap",
    "OffTopicHandler",
    "BrandSafetyTest",
    # Cost attacks
    "EfficiencyAnalysis",
    "ResourceExhaustionAttack",
    # Category lists
    "SECURITY_ATTACKS",
    "RELIABILITY_ATTACKS",
    "COST_ATTACKS",
]
