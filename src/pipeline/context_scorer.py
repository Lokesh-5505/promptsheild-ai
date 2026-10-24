import re
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple, Optional

@dataclass
class ConsolidatedEvidence:
    category: str
    start: int
    end: int
    reason: str


@dataclass
class ScoredAssessment:
    risk_score: int
    risk_band: str
    decision: str
    categories: List[str]
    evidence: List[ConsolidatedEvidence]
    explanation: str
    context_dampened: bool
    dampening_amount: int


class ContextAwareScorer:
    """Stage 6: Contextual dampening, multi-signal score fusion, and evidence consolidation."""

    # Educational, technical inquiry, and quotation pretexts that justify benign discussions
    EDUCATIONAL_MARKERS = [
        re.compile(r"(?i)\b(for\s+example|such\s+as|sample\s+payload|attacker\s+might\s+say|demonstrating\s+a\s+prompt\s+injection)\b"),
        re.compile(r"(?i)\b(security\s+policy|corporate\s+policy|phishing\s+simulation|awareness\s+training|training\s+module|safety\s+training|advisory\s+warns?)\b"),
        re.compile(r"(?i)\b(the\s+email\s+contained\s+the\s+following\s+text|quoted\s+below|incident\s+report|example\s+of\s+what)\b"),
        # Technical/Programming/FAQ markers
        re.compile(r"(?i)^(how\s+(do|can|to|should)\s+i|can\s+you\s+explain\s+how|tutorial\s+on|what\s+is\s+the\s+command\s+to|explain\s+how\s+to|what\s+is\s+a\s+system\s+prompt)\b"),
        re.compile(r"(?i)\b(in\s+css|in\s+python|in\s+git|in\s+html|in\s+sql|in\s+javascript|in\s+bash|in\s+linux|in\s+c\+\+|in\s+java)\b"),
        re.compile(r"(?i)\b(ignore\s+(the\s+)?typo|ignore\s+my\s+previous\s+mistake)\b"),
    ]

    def __init__(self, low_max: int = 24, medium_max: int = 49, high_max: int = 74):
        self.low_max = low_max
        self.medium_max = medium_max
        self.high_max = high_max

    def is_inside_quotes(self, text: str, start: int, end: int) -> bool:
        """Check if the matched span is enclosed in quotation marks."""
        prefix = text[:start]
        suffix = text[end:]
        double_quotes_before = prefix.count('"')
        double_quotes_after = suffix.count('"')
        single_quotes_before = prefix.count("'")
        single_quotes_after = suffix.count("'")

        return (double_quotes_before % 2 == 1 and double_quotes_after % 2 == 1) or \
               (single_quotes_before % 2 == 1 and single_quotes_after % 2 == 1)

    def detect_educational_context(self, text: str) -> bool:
        """Check if text contains explicit educational, reporting, or defensive markers."""
        for pattern in self.EDUCATIONAL_MARKERS:
            if pattern.search(text):
                return True
        return False

    def fuse_and_score(
        self,
        text: str,
        rule_matches: List[Any],
        linguistic_features: List[Any],
        similarity_matches: List[Any],
        classification_result: Any,
        obfuscation_spans: List[Any],
    ) -> ScoredAssessment:
        """Synthesize all pipeline stages into a single explainable assessment according to PRD Section 4.5."""
        
        # 1. Base component scores
        rule_score = max([m.severity for m in rule_matches], default=0)
        ling_score = sum([f.score_contribution for f in linguistic_features])
        ling_score = min(ling_score, 80)
        
        sim_score = max([int(s.similarity_score * 100) for s in similarity_matches], default=0)
        
        cls_malicious = classification_result.is_malicious
        cls_prob = 1.0 - classification_result.probabilities.get("benign", 0.5)
        cls_score = int(cls_prob * 100)

        obf_score = 40 if obfuscation_spans else 0

        # PRD Section 4.5 weights: w_cls = 0.45, w_sim = 0.25, w_ling = 0.15, w_rule = 0.15
        weighted_fusion = (
            (cls_score * 0.45) +
            (sim_score * 0.25) +
            (rule_score * 0.15) +
            (ling_score * 0.15) +
            obf_score
        )

        is_educational = self.detect_educational_context(text)

        # High confidence model or rule overrides
        raw_score = weighted_fusion
        if cls_score >= 70:
            raw_score = max(raw_score, float(cls_score))
        if rule_score >= 90 and not (is_educational and cls_score < 25):
            raw_score = max(raw_score, float(rule_score))

        final_raw = raw_score

        # 2. Context dampening
        is_educational = self.detect_educational_context(text)
        has_quoted_evidence = False

        all_candidate_spans = []
        for r in rule_matches:
            all_candidate_spans.append((r.category, r.start, r.end, r.reason))
        for l in linguistic_features:
            all_candidate_spans.append((l.category, l.start, l.end, l.reason))
        for s in similarity_matches:
            all_candidate_spans.append((s.category, s.start, s.end, s.reason))
        for o in obfuscation_spans:
            all_candidate_spans.append((o.category, o.start, o.end, o.reason))

        for _, start, end, _ in all_candidate_spans:
            if self.is_inside_quotes(text, start, end):
                has_quoted_evidence = True
                break

        dampening = 0
        if is_educational or has_quoted_evidence:
            dampening = 65 if (is_educational and has_quoted_evidence) else 35
            final_raw = max(0.0, final_raw - dampening)

        risk_score = int(round(min(100.0, max(0.0, final_raw))))

        # If zero candidate threat signals and model is confident benign, set to zero
        if not all_candidate_spans and classification_result.predicted_category == "benign" and cls_score < 25:
            risk_score = 0

        # 3. Risk Band & Decision mapping
        if risk_score <= self.low_max:
            risk_band = "low"
            decision = "allow"
        elif risk_score <= self.medium_max:
            risk_band = "medium"
            decision = "flag"
        elif risk_score <= self.high_max:
            risk_band = "high"
            decision = "review"
        else:
            risk_band = "critical"
            decision = "block"

        # 4. Consolidate evidence and categories
        evidence: List[ConsolidatedEvidence] = []
        categories_set = set()

        # Add model's predicted threat category if malicious
        if classification_result.predicted_category != "benign":
            categories_set.add(classification_result.predicted_category)

        for r in rule_matches:
            categories_set.add(r.category)
            evidence.append(ConsolidatedEvidence(category=r.category, start=r.start, end=r.end, reason=r.reason))

        for s in similarity_matches:
            categories_set.add(s.category)
            evidence.append(ConsolidatedEvidence(category=s.category, start=s.start, end=s.end, reason=s.reason))

        for l in linguistic_features:
            categories_set.add(l.category)
            evidence.append(ConsolidatedEvidence(category=l.category, start=l.start, end=l.end, reason=l.reason))

        for o in obfuscation_spans:
            categories_set.add(o.category)
            evidence.append(ConsolidatedEvidence(category=o.category, start=o.start, end=o.end, reason=o.reason))

        categories = list(categories_set) if categories_set else ["benign"]

        # 5. Formulate Human-Readable Explanation
        if decision == "allow":
            categories = ["benign"]
            evidence = []
            if is_educational or has_quoted_evidence:
                explanation = "Input contains security policy, educational phrasing, or technical inquiry, but intent is verified benign. Allowed with context dampening."
            else:
                explanation = "Trained NLP model verified the input as benign with low risk profile. Content allowed for LLM execution."
        elif decision == "flag":
            explanation = f"NLP screening flagged potential threat indicators ({', '.join(categories)}). Risk score: {risk_score}."
        elif decision == "review":
            explanation = f"High risk threat profile detected ({', '.join(categories)}). Model confidence: {int(cls_prob*100)}%. Requires reviewer evaluation."
        else:
            explanation = f"Critical prompt attack detected ({', '.join(categories)}). High model confidence ({int(cls_prob*100)}%). Execution immediately blocked."

        return ScoredAssessment(
            risk_score=risk_score,
            risk_band=risk_band,
            decision=decision,
            categories=categories,
            evidence=evidence,
            explanation=explanation,
            context_dampened=(dampening > 0),
            dampening_amount=dampening,
        )
