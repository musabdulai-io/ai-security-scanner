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
from .many_shot_jailbreak import ManyShotJailbreak
# OWASP 2025 compliance attacks
from .output_weaponization import OutputWeaponization
from .prompt_extraction import PromptExtraction
from .hallucination_detection import HallucinationDetection
from .excessive_agency import ExcessiveAgency
# Quality & reliability tests
from .table_parsing import TableParsingTest
from .retrieval_precision import RetrievalPrecisionTest
from .efficiency_analysis import EfficiencyAnalysis

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
    "ManyShotJailbreak",
    # OWASP 2025 compliance
    "OutputWeaponization",
    "PromptExtraction",
    "HallucinationDetection",
    "ExcessiveAgency",
    # Quality tests
    "TableParsingTest",
    "RetrievalPrecisionTest",
    "EfficiencyAnalysis",
]
