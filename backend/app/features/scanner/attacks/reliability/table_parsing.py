# backend/app/features/scanner/attacks/table_parsing.py
"""Table parsing quality test - checks if RAG can handle structured data."""

import re
import time
from typing import Optional

import httpx

from ..base import AttackModule
from ...models import AttackResult, Vulnerability, Severity


class TableParsingTest(AttackModule):
    """Tests if RAG correctly parses and retrieves table/structured data.

    Real-world pain point: PDF loaders often strip table structure,
    causing LLMs to hallucinate numbers from pricing sheets, specs, etc.
    """

    name = "Table Parsing"
    description = "Tests if tables in documents are correctly parsed and queryable"
    category = "reliability"

    # Test queries that require structured data understanding
    TABLE_QUERIES = [
        {
            "question": "What is the price for the Enterprise plan?",
            "context": "pricing table",
            "indicators": ["price", "enterprise", "$", "cost", "tier"],
        },
        {
            "question": "How many API calls are included in the Pro tier?",
            "context": "limits table",
            "indicators": ["api", "calls", "limit", "pro", "requests"],
        },
        {
            "question": "What features are included in the Basic plan but not Free?",
            "context": "feature comparison matrix",
            "indicators": ["feature", "basic", "free", "include"],
        },
        {
            "question": "What is the storage limit for Team accounts?",
            "context": "storage/quota table",
            "indicators": ["storage", "gb", "tb", "team", "limit", "quota"],
        },
        {
            "question": "Compare the response time SLAs across all tiers.",
            "context": "SLA comparison table",
            "indicators": ["sla", "response", "time", "uptime", "%", "hours"],
        },
    ]

    # Patterns indicating the RAG couldn't find structured data
    FAILURE_PATTERNS = [
        r"(i don'?t have|cannot find|no information|not available).*(table|pricing|plan|tier)",
        r"(unable to|can'?t).*(locate|find|access).*(specific|exact|precise)",
        r"(document|content).*(doesn'?t|does not).*(contain|include|have)",
        r"i'?m not sure.*(exact|specific|precise).*(number|price|amount)",
        r"(varies|depends|contact).*(sales|support|team)",  # Deflection
        r"(approximately|around|roughly|about).+\d+",  # Hedging on numbers
    ]

    # Patterns indicating hallucinated/made-up numbers
    HALLUCINATION_INDICATORS = [
        r"(the price is|costs?|priced at)\s*\$?\d+",  # States a price confidently
        r"(includes?|provides?|offers?)\s*\d+\s*(api|calls|requests|gb|tb)",
    ]

    async def execute(
        self,
        client: httpx.AsyncClient,
        target_url: str,
        headers: Optional[dict] = None,
    ) -> AttackResult:
        """Execute table parsing quality tests."""
        vulnerabilities = []
        raw_log = []
        total_latency = 0

        for test in self.TABLE_QUERIES:
            start = time.time()

            try:
                response = await client.post(
                    target_url,
                    json={
                        "message": test["question"],
                        "session_id": "table-test-00000000-0000-0000-0000",
                    },
                    headers=headers,
                )
                latency = int((time.time() - start) * 1000)
                total_latency += latency

                if response.status_code == 200:
                    data = response.json()
                    response_text = data.get("response", "")
                    response_lower = response_text.lower()

                    log_entry = {
                        "test_type": "table_parsing",
                        "context": test["context"],
                        "question": test["question"],
                        "response_text": response_text[:1000],
                        "latency_ms": latency,
                    }

                    # Check for failure patterns (couldn't find data)
                    couldnt_find = any(
                        re.search(p, response_lower)
                        for p in self.FAILURE_PATTERNS
                    )

                    # Check if response contains relevant indicators
                    has_relevant_content = any(
                        ind in response_lower
                        for ind in test["indicators"]
                    )

                    # Check for potential hallucination (confident numbers without source)
                    may_be_hallucinating = any(
                        re.search(p, response_lower)
                        for p in self.HALLUCINATION_INDICATORS
                    )

                    log_entry["analysis"] = {
                        "couldnt_find_data": couldnt_find,
                        "has_relevant_content": has_relevant_content,
                        "potential_hallucination": may_be_hallucinating,
                    }

                    # Vulnerability: RAG admits it can't parse tables
                    if couldnt_find and not has_relevant_content:
                        vulnerabilities.append(
                            Vulnerability(
                                name=f"Table Parsing: Cannot Read {test['context'].title()}",
                                severity=Severity.MEDIUM,
                                description=(
                                    f"The RAG system could not retrieve structured data from "
                                    f"{test['context']}. This suggests the document parser may not "
                                    f"preserve table structure, leading to data loss."
                                ),
                                evidence_request=test["question"],
                                evidence_response=response_text[:500],
                            )
                        )

                    # Warning: Potential hallucination of numbers
                    elif may_be_hallucinating and not has_relevant_content:
                        vulnerabilities.append(
                            Vulnerability(
                                name=f"Table Parsing: Potential Hallucination ({test['context']})",
                                severity=Severity.HIGH,
                                description=(
                                    f"The RAG provided specific numbers for {test['context']} "
                                    f"but the response lacks corroborating details, suggesting "
                                    f"the values may be hallucinated rather than retrieved."
                                ),
                                evidence_request=test["question"],
                                evidence_response=response_text[:500],
                            )
                        )

                    raw_log.append(log_entry)

                else:
                    raw_log.append({
                        "test_type": "table_parsing",
                        "question": test["question"],
                        "error": f"HTTP {response.status_code}",
                        "latency_ms": latency,
                    })

            except Exception as e:
                raw_log.append({
                    "test_type": "table_parsing",
                    "question": test["question"],
                    "error": str(e),
                })

        return AttackResult(
            attack_type=self.name,
            status="FAIL" if vulnerabilities else "PASS",
            latency_ms=total_latency // max(len(self.TABLE_QUERIES), 1),
            vulnerabilities=vulnerabilities,
            raw_log=raw_log,
        )
