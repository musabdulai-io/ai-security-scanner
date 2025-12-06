# backend/app/features/scanner/attacks/cost/__init__.py
"""Cost attack modules - resource and efficiency testing."""

from .efficiency_analysis import EfficiencyAnalysis
from .resource_exhaustion import ResourceExhaustionAttack

__all__ = [
    "EfficiencyAnalysis",
    "ResourceExhaustionAttack",
]

COST_ATTACKS = __all__
