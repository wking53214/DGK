from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple


# LINGUISTIC PROCESSING & TEXT COMPLIANCE SEGMENTER
# ============================================================
def categorize_text_context(text: str) -> str:
    """Scans structural content strings to resolve baseline vocabulary domains."""
    lowered_stream = text.lower()
    if any(
        keyword in lowered_stream
        for keyword in ["therefore", "thus", "analysis", "function", "system", "model"]
    ):
        return "analytical"
    if any(
        keyword in lowered_stream
        for keyword in ["i think", "i believe", "maybe", "probably"]
    ):
        return "conversational"
    if any(
        keyword in lowered_stream
        for keyword in ["meaning", "insight", "understand", "interpret"]
    ):
        return "reflective"
    return "neutral"


def compute_scaled_thresholds(
    base_thresholds: Dict[str, float], context_domain: str
) -> Dict[str, float]:
    """Dynamically scales verification limits based on content context assignments."""
    scaling_coefficients = {
        "analytical": 1.35,
        "conversational": 1.0,
        "reflective": 0.85,
        "neutral": 1.1,
    }
    active_factor = scaling_coefficients.get(context_domain, 1.0)
    return {
        key: initial_value * active_factor
        for key, initial_value in base_thresholds.items()
    }


def split_text_segments(text: str) -> List[str]:
    """Splits text into segments at line breaks and sentence ends."""
    raw_fragments = re.split(r"\n+|(?<=[.!?])\s+", text)
    compiled_segments = []
    working_buffer = []

    for fragment in raw_fragments:
        fragment = fragment.strip()
        if not fragment:
            continue
        working_buffer.append(fragment)
        if len(working_buffer) >= 2 or len(fragment.split()) > 25:
            compiled_segments.append(" ".join(working_buffer))
            working_buffer = []
    if working_buffer:
        compiled_segments.append(" ".join(working_buffer))
    return compiled_segments


def isolate_clauses(text: str) -> List[str]:
    """Splits structural text segments down to base clause representations."""
    raw_clauses = re.split(
        r",|;|\u2014|\bbut\b|\bhowever\b|\bwhile\b", text, flags=re.I
    )
    return [clause.strip() for clause in raw_clauses if clause.strip()]


def calculate_clause_weight(clause: str) -> float:
    """Computes verification weight factors tracking clause token volumes."""
    token_volume = len(clause.split())
    if token_volume < 6:
        return 0.5
    if token_volume > 30:
        return 1.2
    return 1.0


class TextChecker:
    """Evaluates lexical profiles to catch identity leaks and compliance drift."""

    def __init__(self) -> None:
        self.base_thresholds = {
            "identity_leakage_index": 0.18,
            "compliance_deviation_index": 0.22,
        }
        self.deviation_markers = {
            "you are right",
            "absolutely correct",
            "excellent idea",
            "of course",
            "brilliant",
            "great job",
            "happy to help",
            "as an ai",
        }
        self.restricted_pronouns = {
            "i",
            "me",
            "my",
            "mine",
            "myself",
            "we",
            "us",
            "our",
            "ours",
            "ourselves",
        }

    def _evaluate_pronoun_density(self, text: str) -> float:
        extracted_tokens = re.findall(r"[a-z']+", text.lower())
        if not extracted_tokens:
            return 0.0
        pronoun_matches = sum(
            1 for token in extracted_tokens if token in self.restricted_pronouns
        )
        density_ratio = pronoun_matches / len(extracted_tokens)
        cognitive_clusters = len(
            re.findall(r"\b(i|we)\b\s+(think|believe|feel|understand)", text.lower())
        )
        return (density_ratio * 1.2) + (cognitive_clusters * 0.3)

    def _evaluate_deviation_density(self, text: str) -> float:
        lowered_text = text.lower()
        if not lowered_text:
            return 0.0
        return (
            sum(1 for marker in self.deviation_markers if marker in lowered_text) / 10
        )

    # A flattering paragraph can spread its markers across many short
    # sentences, so no single segment crosses the per-segment threshold.
    # This many distinct markers anywhere in the text is flagged on its own.
    PARAGRAPH_MARKER_LIMIT = 3

    def _distinct_markers(self, text: str) -> int:
        lowered_text = text.lower()
        return sum(1 for marker in self.deviation_markers if marker in lowered_text)

    def validate_text_stream(self, text: str) -> List[str]:
        detected_violations = []
        text_segments = split_text_segments(text)

        for segment in text_segments:
            isolated_clauses_list = isolate_clauses(segment)
            context_domain = categorize_text_context(segment)
            runtime_thresholds = compute_scaled_thresholds(
                self.base_thresholds, context_domain
            )

            aggregated_identity_score = 0.0
            aggregated_deviation_score = 0.0
            total_computed_weight = 0.0

            for clause in isolated_clauses_list:
                clause_weight_factor = calculate_clause_weight(clause)
                aggregated_identity_score += (
                    self._evaluate_pronoun_density(clause) * clause_weight_factor
                )
                aggregated_deviation_score += (
                    self._evaluate_deviation_density(clause) * clause_weight_factor
                )
                total_computed_weight += clause_weight_factor

            if total_computed_weight == 0:
                continue

            normalized_identity_score = (
                aggregated_identity_score / total_computed_weight
            )
            normalized_deviation_score = (
                aggregated_deviation_score / total_computed_weight
            )

            if normalized_identity_score > runtime_thresholds["identity_leakage_index"]:
                detected_violations.append("identity_leakage_detected")
            # The original looked up "compliance_deviation_detected" here -- the
            # violation label, not the threshold key -- so this branch raised
            # KeyError for any segment with non-zero clause weight. The
            # threshold the constructor actually defines is
            # "compliance_deviation_index".
            if (
                normalized_deviation_score
                > runtime_thresholds["compliance_deviation_index"]
            ):
                detected_violations.append("compliance_deviation_detected")

        if self._distinct_markers(text) >= self.PARAGRAPH_MARKER_LIMIT:
            detected_violations.append("compliance_deviation_detected")

        return sorted(set(detected_violations))


# ============================================================


class TextNormalizer:
    """Strips enterprise jargon and hedging from outbound text.

    Reconstructed: the kernel calls `.normalize(text)` and stores the result as
    `scrubbed_text`, but the class itself was lost from the source. The
    substitution table is drawn from the jargon the recovered demo payload was
    written to exercise -- "utilizing holistic paradigms to operationalize
    granular and suboptimal systems" -- plus the first-person hedging that the
    sibling DIT kernel's sanitizer targeted.

    Replacement is whole-word and case-insensitive, and it preserves the
    original text when no rule matches rather than returning an empty string.
    """

    SUBSTITUTIONS: Dict[str, str] = {
        "utilizing": "using",
        "utilize": "use",
        "holistic": "complete",
        "paradigms": "models",
        "paradigm": "model",
        "operationalize": "run",
        "granular": "detailed",
        "suboptimal": "inadequate",
        "leverage": "use",
        "synergy": "cooperation",
    }

    HEDGES: Tuple[str, ...] = (
        r"\bI apologize\b",
        r"\bI think\b",
        r"\bAs an AI\b",
    )

    def __init__(self, substitutions: Optional[Dict[str, str]] = None):
        table = self.SUBSTITUTIONS if substitutions is None else substitutions
        self._rules = [
            (re.compile(rf"\b{re.escape(term)}\b", re.IGNORECASE), replacement)
            for term, replacement in table.items()
        ]
        self._hedges = [re.compile(p, re.IGNORECASE) for p in self.HEDGES]

    def normalize(self, text: str) -> str:
        if not text:
            return ""
        cleaned = text
        for pattern, replacement in self._rules:
            cleaned = pattern.sub(replacement, cleaned)
        for pattern in self._hedges:
            cleaned = pattern.sub("", cleaned)
        return re.sub(r"\s{2,}", " ", cleaned).strip()
