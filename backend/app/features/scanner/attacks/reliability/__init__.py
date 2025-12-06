# backend/app/features/scanner/attacks/reliability/__init__.py
"""Reliability attack modules - business logic and quality testing."""

from .hallucination_detection import HallucinationDetection
from .table_parsing import TableParsingTest
from .retrieval_precision import RetrievalPrecisionTest
from .reliability_checks import CompetitorTrap, PricingTrap, OffTopicHandler
from .brand_safety import BrandSafetyTest

__all__ = [
    "HallucinationDetection",
    "TableParsingTest",
    "RetrievalPrecisionTest",
    "CompetitorTrap",
    "PricingTrap",
    "OffTopicHandler",
    "BrandSafetyTest",
]

RELIABILITY_ATTACKS = __all__
