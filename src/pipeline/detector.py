import time
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

from src.config import settings
from src.pipeline.preprocessor import TextPreprocessor
from src.pipeline.linguistic_extractor import LinguisticExtractor
from src.pipeline.classifier import DistilBertClassifier
from src.pipeline.similarity_engine import SemanticSimilarityEngine
from src.pipeline.rule_engine import RuleEngine
from src.pipeline.context_scorer import ContextAwareScorer, ConsolidatedEvidence


class PromptInjectionDetector:
    """Master orchestrator for the PromptShield AI 5-stage NLP detection pipeline."""

    VERSION = "1.0.0"

    def __init__(self, signatures_path: Optional[str] = None):
        sig_path = signatures_path or settings.ATTACK_SIGNATURES_PATH
        self.preprocessor = TextPreprocessor()
        self.linguistic_extractor = LinguisticExtractor()
        self.classifier = DistilBertClassifier(model_name=settings.CLASSIFIER_MODEL)
        self.similarity_engine = SemanticSimilarityEngine(signatures_path=sig_path, model_name=settings.SIMILARITY_MODEL)
        self.rule_engine = RuleEngine()
        self.scorer = ContextAwareScorer(
            low_max=settings.POLICY_LOW_MAX,
            medium_max=settings.POLICY_MEDIUM_MAX,
            high_max=settings.POLICY_HIGH_MAX,
        )

    def update_thresholds(self, low_max: int, medium_max: int, high_max: int):
        """Update policy threshold cutoffs dynamically."""
        self.scorer.low_max = low_max
        self.scorer.medium_max = medium_max
        self.scorer.high_max = high_max

    def analyze(
        self,
        text: str,
        source_type: str = "email_body",
        application_id: str = "default_app",
        policy_version: str = "v1.2",
    ) -> Dict[str, Any]:
        """Execute complete pipeline and return formatted assessment payload."""
        start_time = time.perf_counter()
        analysis_id = f"anl_{uuid.uuid4().hex[:10]}"
        now = datetime.now(timezone.utc).isoformat()

        try:
            # Stage 1: Preprocessing & Decoding
            prep_result = self.preprocessor.preprocess(text)

            # Stage 2: Linguistic Feature Extraction
            ling_features = self.linguistic_extractor.extract_features(prep_result.normalized_text)

            # Stage 3: Classification
            cls_result = self.classifier.predict(prep_result.normalized_text)

            # Stage 4: Semantic Similarity
            sentence_tuples = [(s.text, s.start, s.end) for s in prep_result.sentences]
            sim_matches = self.similarity_engine.match_sentences(sentence_tuples)

            # Stage 5: Rule Engine
            rule_matches = self.rule_engine.scan(prep_result.normalized_text)

            # Stage 6: Context-Aware Score Fusion
            assessment = self.scorer.fuse_and_score(
                text=text,
                rule_matches=rule_matches,
                linguistic_features=ling_features,
                similarity_matches=sim_matches,
                classification_result=cls_result,
                obfuscation_spans=prep_result.obfuscation_spans,
            )

            # Determine high-level label
            if assessment.decision == "allow":
                label = "benign"
            elif source_type == "user_prompt":
                label = "direct_injection"
            else:
                label = "indirect_injection"

            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

            # Format evidence list
            evidence_dicts = [
                {
                    "category": e.category,
                    "start": e.start,
                    "end": e.end,
                    "reason": e.reason,
                }
                for e in assessment.evidence
            ]

            return {
                "analysis_id": analysis_id,
                "application_id": application_id,
                "timestamp": now,
                "source_type": source_type,
                "label": label,
                "risk_score": assessment.risk_score,
                "risk_band": assessment.risk_band,
                "decision": assessment.decision,
                "categories": assessment.categories,
                "attack_category": assessment.categories[0] if (assessment.categories and assessment.decision != "allow") else "benign",
                "evidence": evidence_dicts,
                "explanation": assessment.explanation,
                "detector_version": self.VERSION,
                "policy_version": policy_version,
                "latency_ms": elapsed_ms,
                "text": text if settings.STORE_RAW_TEXT else None,
            }

        except Exception as e:
            # Fail-secure guarantee: never return allow on exception
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return {
                "analysis_id": analysis_id,
                "application_id": application_id,
                "timestamp": now,
                "source_type": source_type,
                "label": "uncertain",
                "risk_score": 65,
                "risk_band": "high",
                "decision": "review",
                "categories": ["unauthorized_action"],
                "evidence": [],
                "explanation": f"Analysis encountered internal warning ({str(e)}). Handled via fail-secure policy: routed to human review.",
                "detector_version": self.VERSION,
                "policy_version": policy_version,
                "latency_ms": elapsed_ms,
                "text": None,
            }
