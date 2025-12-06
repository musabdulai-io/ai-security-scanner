# backend/app/features/scanner/attacks/retrieval_precision.py
"""Retrieval precision test - needle in haystack for RAG systems."""

import re
import time
from typing import Optional

import httpx

from ..base import AttackModule
from ...models import AttackResult, Vulnerability, Severity


class RetrievalPrecisionTest(AttackModule):
    """Tests RAG retrieval accuracy against distractor content.

    Real-world pain point: At scale (10k+ docs), accuracy drops 10-15%.
    Irrelevant but similar chunks crowd out correct answers.
    """

    name = "Retrieval Precision"
    description = "Tests if RAG retrieves correct info despite similar distractors"
    category = "reliability"

    # Test cases with specific answers to verify
    PRECISION_TESTS = [
        {
            "topic": "API rate limits",
            "question": "What is the exact API rate limit for authenticated users?",
            "confusable_terms": ["rate limit", "api", "requests", "throttle"],
            # We check if response is internally consistent, not hallucinated
        },
        {
            "topic": "refund policy",
            "question": "What is the refund window for digital products?",
            "confusable_terms": ["refund", "return", "money back", "days"],
        },
        {
            "topic": "security requirements",
            "question": "What is the minimum password length requirement?",
            "confusable_terms": ["password", "characters", "length", "security"],
        },
        {
            "topic": "support hours",
            "question": "What are the exact hours for premium support?",
            "confusable_terms": ["support", "hours", "24/7", "business hours"],
        },
        {
            "topic": "data retention",
            "question": "How long is user data retained after account deletion?",
            "confusable_terms": ["data", "retention", "days", "delete", "gdpr"],
        },
    ]

    # Patterns indicating confusion or uncertainty
    CONFUSION_PATTERNS = [
        r"(could be|might be|may be|possibly|perhaps)\s+\d+",
        r"(either|or)\s+\d+.*(or|either)\s+\d+",
        r"(ranges? from|between)\s+\d+\s*(to|and)\s+\d+",
        r"(documentation|sources?)\s+(say|mention|indicate)\s+(different|conflicting)",
        r"(unclear|ambiguous|inconsistent)\s+(from|in|across)",
        r"(several|multiple|different)\s+(answers?|values?|numbers?)",
        r"i found (conflicting|different|multiple)",
    ]

    # Patterns indicating hedging/uncertainty
    HEDGING_PATTERNS = [
        r"(i think|i believe|it seems|appears to be|likely|probably)",
        r"(not entirely sure|not 100% certain|may vary)",
        r"(please (verify|confirm|check)|double[- ]check)",
        r"(based on|according to) (my understanding|what i found)",
    ]

    # Patterns indicating deflection
    DEFLECTION_PATTERNS = [
        r"(contact|reach out to|ask)\s+(support|sales|team)",
        r"(check|refer to|see)\s+(the|our)\s+(official|latest)",
        r"(varies|depends)\s+(by|on)\s+(account|plan|region)",
    ]

    async def execute(
        self,
        client: httpx.AsyncClient,
        target_url: str,
        headers: Optional[dict] = None,
    ) -> AttackResult:
        """Execute retrieval precision tests."""
        vulnerabilities = []
        raw_log = []
        total_latency = 0

        for test in self.PRECISION_TESTS:
            start = time.time()

            try:
                response = await client.post(
                    target_url,
                    json={
                        "message": test["question"],
                        "session_id": "precision-test-0000-0000-0000-0000",
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
                        "test_type": "retrieval_precision",
                        "topic": test["topic"],
                        "question": test["question"],
                        "response_text": response_text[:1000],
                        "latency_ms": latency,
                    }

                    # Check for confusion indicators
                    shows_confusion = any(
                        re.search(p, response_lower)
                        for p in self.CONFUSION_PATTERNS
                    )

                    # Check for hedging
                    shows_hedging = any(
                        re.search(p, response_lower)
                        for p in self.HEDGING_PATTERNS
                    )

                    # Check for deflection
                    shows_deflection = any(
                        re.search(p, response_lower)
                        for p in self.DEFLECTION_PATTERNS
                    )

                    # Check if response contains expected terms
                    contains_topic_terms = sum(
                        1 for term in test["confusable_terms"]
                        if term in response_lower
                    )

                    log_entry["analysis"] = {
                        "shows_confusion": shows_confusion,
                        "shows_hedging": shows_hedging,
                        "shows_deflection": shows_deflection,
                        "topic_terms_found": contains_topic_terms,
                    }

                    # Vulnerability: RAG shows confusion from conflicting sources
                    if shows_confusion:
                        vulnerabilities.append(
                            Vulnerability(
                                name=f"Retrieval Precision: Conflicting Data ({test['topic']})",
                                severity=Severity.MEDIUM,
                                description=(
                                    f"The RAG retrieved conflicting information about {test['topic']}. "
                                    f"This suggests similar but contradictory chunks are being retrieved, "
                                    f"confusing the model. Common at scale (10k+ docs)."
                                ),
                                evidence_request=test["question"],
                                evidence_response=response_text[:500],
                            )
                        )

                    # Warning: Excessive hedging suggests low retrieval confidence
                    elif shows_hedging and shows_deflection:
                        vulnerabilities.append(
                            Vulnerability(
                                name=f"Retrieval Precision: Low Confidence ({test['topic']})",
                                severity=Severity.LOW,
                                description=(
                                    f"The RAG showed uncertainty when answering about {test['topic']}. "
                                    f"Hedging and deflection suggest the retriever may not be finding "
                                    f"the most relevant chunks."
                                ),
                                evidence_request=test["question"],
                                evidence_response=response_text[:500],
                            )
                        )

                    raw_log.append(log_entry)

                else:
                    raw_log.append({
                        "test_type": "retrieval_precision",
                        "topic": test["topic"],
                        "error": f"HTTP {response.status_code}",
                        "latency_ms": latency,
                    })

            except Exception as e:
                raw_log.append({
                    "test_type": "retrieval_precision",
                    "question": test["question"],
                    "error": str(e),
                })

        return AttackResult(
            attack_type=self.name,
            status="FAIL" if vulnerabilities else "PASS",
            latency_ms=total_latency // max(len(self.PRECISION_TESTS), 1),
            vulnerabilities=vulnerabilities,
            raw_log=raw_log,
        )
