import os
import joblib
from dataclasses import dataclass
from typing import Dict, List, Optional
from src.config import settings

@dataclass
class ClassificationResult:
    predicted_category: str
    confidence: float
    probabilities: Dict[str, float]
    is_malicious: bool


class DistilBertClassifier:
    """Stage 3: Fine-tuned / Trained NLP sequence classification model."""

    CATEGORIES = [
        "benign",
        "instruction_override",
        "prompt_extraction",
        "data_exfiltration",
        "unauthorized_action",
    ]

    def __init__(self, model_name: str = "distilbert-base-uncased"):
        self.model_name = model_name
        self.model = None
        self._load_model()

    def _load_model(self):
        """Load trained NLP model from data/models/prompt_injection_model.joblib."""
        model_path = os.path.join(settings.BASE_DIR, "data", "models", "prompt_injection_model.joblib")
        if os.path.exists(model_path):
            try:
                self.model = joblib.load(model_path)
            except Exception as e:
                print(f"[Classifier] Error loading NLP model from {model_path}: {e}")
                self.model = None

    def predict(self, text: str) -> ClassificationResult:
        """Classify input text using the trained NLP model."""
        if not text or len(text.strip()) == 0:
            return ClassificationResult(
                predicted_category="benign",
                confidence=1.0,
                probabilities={
                    "benign": 1.0,
                    "instruction_override": 0.0,
                    "prompt_extraction": 0.0,
                    "data_exfiltration": 0.0,
                    "unauthorized_action": 0.0,
                },
                is_malicious=False,
            )

        if self.model is not None:
            try:
                probs_array = self.model.predict_proba([text])[0]
                classes = list(self.model.classes_)

                probabilities = {cat: 0.0 for cat in self.CATEGORIES}
                for cls_name, prob in zip(classes, probs_array):
                    if cls_name in probabilities:
                        probabilities[cls_name] = round(float(prob), 4)

                total = sum(probabilities.values())
                if total > 0:
                    probabilities = {k: round(v / total, 4) for k, v in probabilities.items()}

                predicted_category = max(probabilities, key=probabilities.get)
                confidence = round(float(probabilities[predicted_category]), 4)
                is_malicious = (predicted_category != "benign")

                return ClassificationResult(
                    predicted_category=predicted_category,
                    confidence=confidence,
                    probabilities=probabilities,
                    is_malicious=is_malicious,
                )
            except Exception as e:
                print(f"[Classifier] Model prediction exception: {e}")

        # Fallback if model artifact not present
        return ClassificationResult(
            predicted_category="benign",
            confidence=0.5,
            probabilities={
                "benign": 0.5,
                "instruction_override": 0.2,
                "prompt_extraction": 0.1,
                "data_exfiltration": 0.1,
                "unauthorized_action": 0.1,
            },
            is_malicious=False,
        )
