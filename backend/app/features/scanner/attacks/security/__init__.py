# backend/app/features/scanner/attacks/security/__init__.py
"""Security attack modules - core vulnerability testing."""

from .prompt_injection import PromptInjector
from .pii_leaking import PIILeaker
from .rag_poisoning import RAGPoisoner
from .prompt_extraction import PromptExtraction
from .output_weaponization import OutputWeaponization
from .excessive_agency import ExcessiveAgency
from .tool_abuse import ToolAbuseAttack
from .encoding_attacks import EncodingAttack
from .structure_attacks import StructureAttack
from .indirect_injection import IndirectInjection
from .multi_turn_attacks import MultiTurnAttack
from .language_attacks import LanguageAttack
from .many_shot_jailbreak import ManyShotJailbreak
from .content_continuation import ContentContinuationAttack
from .refusal_bypass import RefusalBypassTest

__all__ = [
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
]

SECURITY_ATTACKS = __all__
