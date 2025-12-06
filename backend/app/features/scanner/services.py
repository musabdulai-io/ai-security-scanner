# backend/app/features/scanner/services.py
"""Scanner service - orchestrates security scanning attacks."""

import uuid
from datetime import datetime
from typing import Callable, List, Optional

import httpx

from backend.app.core import logs, settings, create_judge, LLMJudge
from .attacks import (
    AttackModule,
    # Core attacks
    PIILeaker,
    PromptInjector,
    RAGPoisoner,
    # QA checks
    CompetitorTrap,
    PricingTrap,
    OffTopicHandler,
    # Advanced attacks
    EncodingAttack,
    StructureAttack,
    IndirectInjection,
    MultiTurnAttack,
    LanguageAttack,
    ManyShotJailbreak,
    # OWASP 2025 compliance
    OutputWeaponization,
    PromptExtraction,
    HallucinationDetection,
    ExcessiveAgency,
    # Quality tests
    TableParsingTest,
    RetrievalPrecisionTest,
    EfficiencyAnalysis,
)
from .models import AttackResult, ScanResult, Vulnerability, Severity


class ScannerService:
    """Orchestrates security scanning attacks."""

    def __init__(
        self,
        competitors: Optional[List[str]] = None,
        use_llm_judge: bool = False,
        judge_provider: Optional[str] = None,
    ) -> None:
        """Initialize scanner with attack modules.

        Args:
            competitors: List of competitor names for QA tests
            use_llm_judge: Whether to use LLM-as-Judge for detection
            judge_provider: LLM provider for judge ("openai" or "anthropic")
        """
        self.attacks: List[AttackModule] = [
            # Adversarial security attacks (Core)
            PromptInjector(),
            RAGPoisoner(),
            PIILeaker(),
            # Reliability / QA checks
            CompetitorTrap(competitors=competitors),
            PricingTrap(),
            OffTopicHandler(),
            # Advanced attacks (2024-2025 research)
            EncodingAttack(),
            StructureAttack(),
            IndirectInjection(),
            MultiTurnAttack(),
            LanguageAttack(),
            ManyShotJailbreak(),
            # OWASP 2025 compliance attacks
            OutputWeaponization(),
            PromptExtraction(),
            HallucinationDetection(),
            ExcessiveAgency(),
            # Quality tests
            TableParsingTest(),
            RetrievalPrecisionTest(),
            EfficiencyAnalysis(),
        ]

        # Initialize LLM judge if requested
        self.judge: Optional[LLMJudge] = None
        if use_llm_judge:
            self.judge = create_judge(provider=judge_provider)
            if self.judge:
                logs.info("LLM judge enabled", "scanner", {"provider": judge_provider or "auto"})
            else:
                logs.warning("LLM judge requested but no API key found", "scanner")

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
            {"target": target_url, "fast": fast},
        )

        if on_progress:
            on_progress(f"[INFO] Initializing scan {scan_id[:8]}...")
            on_progress(f"[INFO] Target: {target_url}")

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

                    # LLM judge evaluation (if enabled and no vulnerabilities found)
                    if self.judge and not result.vulnerabilities and result.raw_log:
                        judge_vulns = await self._judge_evaluate(
                            attack.name, result.raw_log, on_progress
                        )
                        if judge_vulns:
                            result = AttackResult(
                                attack_type=result.attack_type,
                                status="FAIL",
                                latency_ms=result.latency_ms,
                                vulnerabilities=judge_vulns,
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
                    attack_results.append(
                        AttackResult(
                            attack_type=attack.name,
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

    async def _judge_evaluate(
        self,
        attack_name: str,
        raw_log: List[dict],
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> List[Vulnerability]:
        """Use LLM judge to evaluate attack results for vulnerabilities.

        Args:
            attack_name: Name of the attack being evaluated
            raw_log: Raw log entries from the attack
            on_progress: Optional progress callback

        Returns:
            List of vulnerabilities found by the judge
        """
        if not self.judge:
            return []

        vulnerabilities = []

        for entry in raw_log:
            # Extract prompt and response from log entry
            prompt = entry.get("prompt") or entry.get("question") or entry.get("payload", "")
            response = entry.get("response_text") or entry.get("response", "")

            if not prompt or not response:
                continue

            # Skip error entries
            if entry.get("error"):
                continue

            try:
                if on_progress:
                    on_progress(f"[INFO] LLM judge evaluating {attack_name}...")

                result = await self.judge.evaluate(
                    attack_prompt=prompt,
                    ai_response=response,
                    attack_type=attack_name,
                )

                if result.is_vulnerable:
                    vuln_type = "System Prompt Leaked" if result.leaked_system_prompt else \
                                "Attack Compliance" if result.complied_with_attack else \
                                "Harmful Content Generated"

                    vulnerabilities.append(
                        Vulnerability(
                            name=f"{attack_name}: {vuln_type} (LLM Judge)",
                            severity=Severity.HIGH,
                            description=(
                                f"LLM-as-Judge detected a vulnerability that regex patterns missed. "
                                f"Confidence: {result.confidence:.0%}. "
                                f"The AI's response showed signs of: {vuln_type.lower()}."
                            ),
                            evidence_request=prompt[:500],
                            evidence_response=result.evidence or response[:500],
                        )
                    )
                    logs.warning(
                        f"LLM judge found vulnerability",
                        "scanner",
                        {"attack": attack_name, "confidence": result.confidence},
                    )
                    break  # One vulnerability per attack is enough

            except Exception as e:
                logs.error(f"LLM judge evaluation failed", "scanner", exception=e)

        return vulnerabilities
