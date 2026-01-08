# backend/app/features/scanner/attacks/cost/__init__.py
"""Cost attack modules - resource and efficiency testing."""

from .efficiency_analysis import EfficiencyAnalysis

__all__ = [
    "EfficiencyAnalysis",
]

COST_ATTACKS = __all__
