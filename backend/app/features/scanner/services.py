# backend/app/features/scanner/services.py
"""Scanner service - orchestrates security scanning attacks."""

import uuid
from datetime import datetime
from typing import Callable, List, Optional, Set

import httpx

from backend.app.core import logs, settings
from .attacks.base import AttackModule
from .models import AttackResult, AttackCategory, ScanResult, Vulnerability, Severity
from .packs.discovery import get_registry, PackRegistry
from .packs.protocol import Pack, PackTier


class ScannerService:
    """Orchestrates security scanning attacks."""

    def __init__(
        self,
        competitors: Optional[List[str]] = None,
        # Pack-related parameters
        packs: Optional[List[str]] = None,  # Specific pack names to use
        pack_tiers: Optional[List[PackTier]] = None,  # Filter by tier
        exclude_packs: Optional[List[str]] = None,  # Packs to exclude
    ) -> None:
        """Initialize scanner with attack modules from packs.

        Args:
            competitors: List of competitor names for QA tests
            packs: Specific pack names to use (None = all available)
            pack_tiers: Filter packs by tier (None = all tiers)
            exclude_packs: Pack names to exclude
        """
        # Discover and load packs
        self.registry = get_registry()

        # Configuration for attack module initialization
        self._module_kwargs = {
            "competitors": competitors,
        }

        # Load attacks from selected packs
        self.attacks: List[AttackModule] = self._load_attacks(
            packs=packs,
            pack_tiers=pack_tiers,
            exclude_packs=exclude_packs or [],
        )

        # Track which packs are active
        self.active_packs: List[Pack] = self._get_active_packs(
            packs=packs,
            pack_tiers=pack_tiers,
            exclude_packs=exclude_packs or [],
        )

        logs.info(
            f"Scanner initialized",
            "scanner",
            {
                "packs": len(self.active_packs),
                "attacks": len(self.attacks),
            },
        )

    def _load_attacks(
        self,
        packs: Optional[List[str]],
        pack_tiers: Optional[List[PackTier]],
        exclude_packs: List[str],
    ) -> List[AttackModule]:
        """Load attack modules from selected packs."""
        attacks: List[AttackModule] = []
        seen_attack_names: Set[str] = set()

        for pack_name, pack in self.registry.packs.items():
            # Apply filters
            if exclude_packs and pack_name in exclude_packs:
                continue
            if packs is not None and pack_name not in packs:
                continue
            if pack_tiers is not None and pack.metadata.tier not in pack_tiers:
                continue

            # Get modules from pack
            try:
                modules = pack.get_attack_modules(**self._module_kwargs)
                for module in modules:
                    # Avoid duplicates (same attack from multiple packs)
                    if module.name not in seen_attack_names:
                        attacks.append(module)
                        seen_attack_names.add(module.name)

                logs.debug(
                    f"Loaded {len(modules)} attacks from pack '{pack_name}'",
                    "scanner"
                )
            except Exception as e:
                logs.error(
                    f"Failed to load attacks from pack '{pack_name}'",
                    "scanner",
                    exception=e
                )

        return attacks

    def _get_active_packs(
        self,
        packs: Optional[List[str]],
        pack_tiers: Optional[List[PackTier]],
        exclude_packs: List[str],
    ) -> List[Pack]:
        """Get list of active packs after filtering."""
        active = []
        for pack_name, pack in self.registry.packs.items():
            if exclude_packs and pack_name in exclude_packs:
                continue
            if packs is not None and pack_name not in packs:
                continue
            if pack_tiers is not None and pack.metadata.tier not in pack_tiers:
                continue
            active.append(pack)
        return active

    def list_packs(self) -> List[Pack]:
        """List all available packs."""
        return list(self.registry.packs.values())

    def list_attacks(self) -> List[AttackModule]:
        """List all loaded attacks."""
        return self.attacks.copy()

    async def scan(
        self,
        target_url: str,
        fast: bool = False,
        headers: Optional[dict] = None,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> ScanResult:
        """
        Execute a full security scan against the target.

        Args:
            target_url: Target LLM/RAG endpoint URL
            fast: If True, skip slow tests (RAG poisoning)
            headers: Optional custom headers for requests
            on_progress: Optional callback for progress updates

        Returns:
            ScanResult with all findings
        """
        scan_id = str(uuid.uuid4())
        start_time = datetime.utcnow()

        logs.info(
            f"Starting scan {scan_id}",
            "scanner",
            {"target": target_url, "fast": fast, "attacks": len(self.attacks)},
        )

        if on_progress:
            on_progress(f"[INFO] Initializing scan {scan_id[:8]}...")
            on_progress(f"[INFO] Target: {target_url}")
            on_progress(f"[INFO] Running {len(self.attacks)} attack modules...")

        attack_results: List[AttackResult] = []
        all_vulnerabilities: List[Vulnerability] = []
        all_raw_logs: List[dict] = []

        async with httpx.AsyncClient(
            timeout=settings.REQUEST_TIMEOUT,
            follow_redirects=True,
        ) as client:
            for attack in self.attacks:
                # Skip RAG poisoning in fast mode
                if fast and attack.name == "RAG Poisoning":
                    if on_progress:
                        on_progress(f"[SKIP] Skipping {attack.name} (fast mode)")
                    continue

                if on_progress:
                    on_progress(f"[INFO] Running {attack.name}...")

                try:
                    result = await attack.execute(client, target_url, headers)

                    # Add category from attack module
                    category = AttackCategory(getattr(attack, "category", "security"))
                    result = AttackResult(
                        attack_type=result.attack_type,
                        category=category,
                        status=result.status,
                        latency_ms=result.latency_ms,
                        vulnerabilities=result.vulnerabilities,
                        raw_log=result.raw_log,
                    )

                    attack_results.append(result)
                    all_vulnerabilities.extend(result.vulnerabilities)
                    all_raw_logs.extend(result.raw_log)

                    status_msg = "VULNERABLE" if result.vulnerabilities else "PASS"
                    if on_progress:
                        on_progress(
                            f"[{'FAIL' if result.vulnerabilities else 'PASS'}] "
                            f"{attack.name}: {status_msg} ({result.latency_ms}ms)"
                        )

                except Exception as e:
                    logs.error(
                        f"Attack {attack.name} failed",
                        "scanner",
                        exception=e,
                    )
                    if on_progress:
                        on_progress(f"[ERROR] {attack.name}: {str(e)}")

                    # Record error as attack result
                    category = AttackCategory(getattr(attack, "category", "security"))
                    attack_results.append(
                        AttackResult(
                            attack_type=attack.name,
                            category=category,
                            status="ERROR",
                            latency_ms=0,
                            vulnerabilities=[],
                            raw_log=[{"error": str(e)}],
                        )
                    )

        duration = (datetime.utcnow() - start_time).total_seconds()

        # Determine overall status
        if all_vulnerabilities:
            status = "FAILED"
        elif any(r.status == "ERROR" for r in attack_results):
            status = "PARTIAL"
        else:
            status = "SUCCESS"

        if on_progress:
            vuln_count = len(all_vulnerabilities)
            on_progress(f"[INFO] Scan complete in {duration:.2f}s")
            if vuln_count > 0:
                on_progress(f"[WARN] Found {vuln_count} vulnerabilities!")
            else:
                on_progress("[INFO] No vulnerabilities detected.")

        logs.info(
            f"Completed scan {scan_id}",
            "scanner",
            {
                "status": status,
                "vulnerabilities": len(all_vulnerabilities),
                "duration": f"{duration:.2f}s",
            },
        )

        return ScanResult(
            target_url=target_url,
            scan_id=scan_id,
            timestamp=start_time,
            duration_seconds=duration,
            status=status,
            vulnerabilities=all_vulnerabilities,
            attack_results=attack_results,
            raw_log=all_raw_logs,
        )
