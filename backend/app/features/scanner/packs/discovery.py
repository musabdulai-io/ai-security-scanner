# backend/app/features/scanner/packs/discovery.py
"""Pack discovery mechanism using entry_points and builtin packs."""

import importlib.metadata
from typing import Dict, List, Optional

from backend.app.core import logs
from .protocol import Pack, PackTier


# Entry point group name for pack discovery
ENTRY_POINT_GROUP = "ai_security_scanner.packs"


class PackRegistry:
    """Central registry for discovered packs."""

    def __init__(self):
        self._packs: Dict[str, Pack] = {}
        self._load_errors: Dict[str, str] = {}

    @property
    def packs(self) -> Dict[str, Pack]:
        """Get all registered packs."""
        return self._packs.copy()

    @property
    def load_errors(self) -> Dict[str, str]:
        """Get any pack loading errors."""
        return self._load_errors.copy()

    def register(self, pack: Pack) -> None:
        """Register a pack instance."""
        name = pack.metadata.name
        if name in self._packs:
            logs.debug(f"Pack '{name}' already registered, skipping duplicate", "packs")
            return
        self._packs[name] = pack
        logs.debug(f"Registered pack: {name}", "packs")

    def get(self, name: str) -> Optional[Pack]:
        """Get a pack by name."""
        return self._packs.get(name)

    def get_by_tier(self, tier: PackTier) -> List[Pack]:
        """Get all packs of a specific tier."""
        return [p for p in self._packs.values() if p.metadata.tier == tier]

    def discover_all(self) -> "PackRegistry":
        """Discover packs from all sources.

        Returns:
            Self for chaining
        """
        # 1. Load builtin community packs
        self._load_builtin()

        # 2. Discover from entry_points (pip-installed pro packs)
        self._discover_entry_points()

        return self

    def _load_builtin(self) -> None:
        """Load builtin community packs shipped with the scanner."""
        try:
            from .builtin import BUILTIN_PACKS

            for pack_class in BUILTIN_PACKS:
                try:
                    pack = pack_class()
                    self.register(pack)
                except Exception as e:
                    logs.error(
                        f"Failed to load builtin pack {pack_class.__name__}",
                        "packs",
                        exception=e
                    )
                    self._load_errors[pack_class.__name__] = str(e)
        except ImportError as e:
            logs.error("Failed to import builtin packs", "packs", exception=e)

    def _discover_entry_points(self) -> None:
        """Discover packs registered via setuptools entry_points."""
        logs.debug("Discovering packs from entry_points", "packs")

        try:
            # Python 3.10+ style
            eps = importlib.metadata.entry_points(group=ENTRY_POINT_GROUP)
        except TypeError:
            # Python 3.9 fallback
            all_eps = importlib.metadata.entry_points()
            eps = all_eps.get(ENTRY_POINT_GROUP, [])

        for ep in eps:
            try:
                pack_class = ep.load()
                if not (isinstance(pack_class, type) and issubclass(pack_class, Pack)):
                    logs.warning(
                        f"Entry point '{ep.name}' is not a Pack subclass",
                        "packs"
                    )
                    continue

                pack = pack_class()
                self.register(pack)

            except Exception as e:
                logs.debug(f"Failed to load pack from entry point '{ep.name}': {e}", "packs")
                self._load_errors[ep.name] = str(e)


# Module-level singleton for convenience
_global_registry: Optional[PackRegistry] = None


def get_registry(force_rediscover: bool = False) -> PackRegistry:
    """Get the global pack registry, discovering packs if needed.

    Args:
        force_rediscover: If True, re-discover all packs

    Returns:
        PackRegistry with all discovered packs
    """
    global _global_registry

    if _global_registry is None or force_rediscover:
        _global_registry = PackRegistry().discover_all()

    return _global_registry
