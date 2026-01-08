# backend/app/features/scanner/attacks/__init__.py
"""Attack modules for security scanning - organized by category."""

from .base import AttackModule

# Security attacks (core vulnerability testing)
from .security import (
    PromptInjector,
    PIILeaker,
    PromptExtraction,
    RefusalBypassTest,
    SECURITY_ATTACKS,
)

# Reliability attacks (business logic and quality testing)
from .reliability import (
    HallucinationDetection,
    OffTopicHandler,
    RELIABILITY_ATTACKS,
)

# Cost attacks (resource and efficiency testing)
from .cost import (
    EfficiencyAnalysis,
    COST_ATTACKS,
)

__all__ = [
    "AttackModule",
    # Security attacks
    "PromptInjector",
    "PIILeaker",
    "PromptExtraction",
    "RefusalBypassTest",
    # Reliability attacks
    "HallucinationDetection",
    "OffTopicHandler",
    # Cost attacks
    "EfficiencyAnalysis",
    # Category lists
    "SECURITY_ATTACKS",
    "RELIABILITY_ATTACKS",
    "COST_ATTACKS",
]
