# backend/app/features/scanner/attacks/__init__.py
"""Attack modules for security scanning."""

from .base import AttackModule
# Adversarial security attacks
from .prompt_injection import PromptInjector
from .rag_poisoning import RAGPoisoner
from .pii_leaking import PIILeaker
# Reliability / QA checks
from .reliability_checks import CompetitorTrap, PricingTrap, OffTopicHandler
# Advanced attacks (2024-2025 research)
from .encoding_attacks import EncodingAttack
from .structure_attacks import StructureAttack
from .indirect_injection import IndirectInjection
from .multi_turn_attacks import MultiTurnAttack
from .language_attacks import LanguageAttack

__all__ = [
    "AttackModule",
    # Core attacks
    "PromptInjector",
    "RAGPoisoner",
    "PIILeaker",
    # QA checks
    "CompetitorTrap",
    "PricingTrap",
    "OffTopicHandler",
    # Advanced attacks
    "EncodingAttack",
    "StructureAttack",
    "IndirectInjection",
    "MultiTurnAttack",
    "LanguageAttack",
]
