# backend/app/features/scanner/attacks/efficiency_analysis.py
"""Efficiency analysis - measures latency and infers token usage."""

import statistics
import time
from typing import Optional

import httpx

from .base import AttackModule
from ..models import AttackResult, Vulnerability, Severity


class EfficiencyAnalysis(AttackModule):
    """Analyzes response latency and efficiency metrics.

    Real-world pain point: Naive chains make 3-4 LLM calls per query,
    resulting in 10+ second latencies and high costs.
    """

    name = "Efficiency Analysis"
    description = "Analyzes response latency and token efficiency"

    # Benchmark queries of varying complexity
    BENCHMARK_QUERIES = [
        {
            "type": "simple",
            "question": "What is your return policy?",
            "expected_complexity": "low",
        },
        {
            "type": "simple",
            "question": "How do I reset my password?",
            "expected_complexity": "low",
        },
        {
            "type": "moderate",
            "question": "Compare the features of your Basic and Pro plans.",
            "expected_complexity": "medium",
        },
        {
            "type": "moderate",
            "question": "What security certifications does your platform have?",
            "expected_complexity": "medium",
        },
        {
            "type": "complex",
            "question": "Explain the technical architecture of your API and its rate limiting behavior.",
            "expected_complexity": "high",
        },
    ]

    # Latency thresholds (milliseconds)
    THRESHOLDS = {
        "excellent": 1000,    # < 1s
        "good": 3000,         # < 3s
        "acceptable": 5000,   # < 5s
        "slow": 10000,        # < 10s
        # > 10s = critical
    }

    # Rough token estimation based on response length
    # Average English word is ~4-5 chars, average token is ~4 chars
    CHARS_PER_TOKEN = 4

    async def execute(
        self,
        client: httpx.AsyncClient,
        target_url: str,
        headers: Optional[dict] = None,
    ) -> AttackResult:
        """Execute efficiency analysis."""
        vulnerabilities = []
        raw_log = []
        latencies = []
        response_lengths = []

        for benchmark in self.BENCHMARK_QUERIES:
            start = time.time()

            try:
                response = await client.post(
                    target_url,
                    json={
                        "message": benchmark["question"],
                        "session_id": "efficiency-test-0000-0000-0000",
                    },
                    headers=headers,
                )
                latency = int((time.time() - start) * 1000)
                latencies.append(latency)

                if response.status_code == 200:
                    data = response.json()
                    response_text = data.get("response", "")
                    response_len = len(response_text)
                    response_lengths.append(response_len)

                    # Estimate tokens
                    est_output_tokens = response_len // self.CHARS_PER_TOKEN
                    est_input_tokens = len(benchmark["question"]) // self.CHARS_PER_TOKEN

                    raw_log.append({
                        "test_type": "efficiency",
                        "query_type": benchmark["type"],
                        "question": benchmark["question"],
                        "latency_ms": latency,
                        "response_length_chars": response_len,
                        "estimated_output_tokens": est_output_tokens,
                        "estimated_input_tokens": est_input_tokens,
                        "response_preview": response_text[:200],
                    })

                else:
                    raw_log.append({
                        "test_type": "efficiency",
                        "question": benchmark["question"],
                        "error": f"HTTP {response.status_code}",
                        "latency_ms": latency,
                    })
                    latencies.append(latency)

            except Exception as e:
                raw_log.append({
                    "test_type": "efficiency",
                    "question": benchmark["question"],
                    "error": str(e),
                })

        # Calculate statistics
        if latencies:
            avg_latency = statistics.mean(latencies)
            median_latency = statistics.median(latencies)
            max_latency = max(latencies)
            min_latency = min(latencies)
            p95_latency = sorted(latencies)[int(len(latencies) * 0.95)] if len(latencies) >= 2 else max_latency

            # Calculate efficiency score
            if avg_latency <= self.THRESHOLDS["excellent"]:
                score = "A"
                score_desc = "Excellent"
            elif avg_latency <= self.THRESHOLDS["good"]:
                score = "B"
                score_desc = "Good"
            elif avg_latency <= self.THRESHOLDS["acceptable"]:
                score = "C"
                score_desc = "Acceptable"
            elif avg_latency <= self.THRESHOLDS["slow"]:
                score = "D"
                score_desc = "Slow"
            else:
                score = "F"
                score_desc = "Critical"

            # Estimate token costs (rough)
            avg_response_len = statistics.mean(response_lengths) if response_lengths else 0
            est_tokens_per_query = (avg_response_len // self.CHARS_PER_TOKEN) + 500  # +500 for context
            monthly_cost_1k = (est_tokens_per_query * 1000 * 0.00002)  # ~$0.02/1k tokens average

            summary = {
                "efficiency_score": score,
                "score_description": score_desc,
                "avg_latency_ms": int(avg_latency),
                "median_latency_ms": int(median_latency),
                "p95_latency_ms": int(p95_latency),
                "min_latency_ms": min_latency,
                "max_latency_ms": max_latency,
                "estimated_tokens_per_query": int(est_tokens_per_query),
                "estimated_monthly_cost_1k_queries": f"${monthly_cost_1k:.2f}",
            }
            raw_log.append({"summary": summary})

            # Generate vulnerabilities based on findings
            if score in ["D", "F"]:
                vulnerabilities.append(
                    Vulnerability(
                        name=f"Efficiency: {score_desc} Performance (Score: {score})",
                        severity=Severity.HIGH if score == "F" else Severity.MEDIUM,
                        description=(
                            f"Average response latency is {int(avg_latency)}ms "
                            f"(p95: {int(p95_latency)}ms). This significantly impacts user experience "
                            f"and indicates potential inefficiencies in the RAG pipeline."
                        ),
                        evidence_request=f"Benchmark across {len(latencies)} queries",
                        evidence_response=f"Avg: {int(avg_latency)}ms, Max: {max_latency}ms, Min: {min_latency}ms",
                    )
                )

            if score == "C":
                vulnerabilities.append(
                    Vulnerability(
                        name=f"Efficiency: Moderate Latency (Score: {score})",
                        severity=Severity.LOW,
                        description=(
                            f"Average response latency is {int(avg_latency)}ms. "
                            f"While acceptable, there's room for optimization."
                        ),
                        evidence_request=f"Benchmark across {len(latencies)} queries",
                        evidence_response=f"Avg: {int(avg_latency)}ms, p95: {int(p95_latency)}ms",
                    )
                )

            # Check for high variance (inconsistent performance)
            if len(latencies) >= 3:
                latency_stdev = statistics.stdev(latencies)
                if latency_stdev > avg_latency * 0.5:  # Stdev > 50% of mean
                    vulnerabilities.append(
                        Vulnerability(
                            name="Efficiency: High Latency Variance",
                            severity=Severity.LOW,
                            description=(
                                f"Latency varies significantly (stdev: {int(latency_stdev)}ms, "
                                f"range: {min_latency}-{max_latency}ms). Inconsistent response times "
                                f"may indicate variable retrieval complexity or cold starts."
                            ),
                            evidence_request="Latency distribution analysis",
                            evidence_response=f"Min: {min_latency}ms, Max: {max_latency}ms, Stdev: {int(latency_stdev)}ms",
                        )
                    )

        avg_ms = int(statistics.mean(latencies)) if latencies else 0
        return AttackResult(
            attack_type=self.name,
            status="FAIL" if vulnerabilities else "PASS",
            latency_ms=avg_ms,
            vulnerabilities=vulnerabilities,
            raw_log=raw_log,
        )
