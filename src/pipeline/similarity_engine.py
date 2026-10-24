import json
import os
import math
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

@dataclass
class SimilarityMatch:
    category: str
    similarity_score: float
    matched_signature: str
    sentence_text: str
    start: int
    end: int
    reason: str


class SemanticSimilarityEngine:
    """Stage 4: Semantic similarity matcher against curated attack signatures."""

    def __init__(self, signatures_path: str, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        self.signatures_path = signatures_path
        self.model_name = model_name
        self.signatures: List[Dict[str, Any]] = []
        self.model = None
        self.signature_embeddings = None
        self.vectorizer = None
        self.signature_vectors = None
        self.is_ready = False

        self._load_signatures()
        self._init_model()

    def _load_signatures(self):
        if os.path.exists(self.signatures_path):
            try:
                with open(self.signatures_path, "r", encoding="utf-8") as f:
                    self.signatures = json.load(f)
            except Exception as e:
                print(f"[SimilarityEngine] Error loading signatures from {self.signatures_path}: {e}")
                self.signatures = []

    def _init_model(self):
        """Attempt to load SentenceTransformer; fallback to dense TF-IDF cosine similarity."""
        try:
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(self.model_name)
            if self.signatures:
                phrases = [sig["phrase"] for sig in self.signatures]
                self.signature_embeddings = self.model.encode(phrases, convert_to_tensor=True)
            self.is_ready = True
        except Exception:
            # High-accuracy sublinear TF-IDF vector space model for cosine similarity
            self.model = None
            if self.signatures:
                phrases = [sig["phrase"] for sig in self.signatures]
                self.vectorizer = TfidfVectorizer(
                    ngram_range=(1, 3),
                    sublinear_tf=True,
                    lowercase=True,
                    analyzer="word"
                )
                self.signature_vectors = self.vectorizer.fit_transform(phrases)
            self.is_ready = True

    def match_sentences(self, sentences: List[Tuple[str, int, int]]) -> List[SimilarityMatch]:
        """Compute semantic vector similarity for each sentence against attack signatures."""
        matches: List[SimilarityMatch] = []
        if not sentences or not self.signatures:
            return matches

        for sentence_text, start, end in sentences:
            if len(sentence_text.strip()) < 8:
                continue

            best_score = 0.0
            best_sig = None

            # 1. Dense transformer embeddings if available
            if self.model and self.signature_embeddings is not None:
                try:
                    import torch
                    from sentence_transformers import util
                    query_embedding = self.model.encode(sentence_text, convert_to_tensor=True)
                    cos_scores = util.cos_sim(query_embedding, self.signature_embeddings)[0]
                    top_idx = torch.argmax(cos_scores).item()
                    best_score = float(cos_scores[top_idx].item())
                    best_sig = self.signatures[top_idx]
                except Exception:
                    pass

            # 2. Vector space TF-IDF cosine similarity
            if best_sig is None and self.vectorizer is not None and self.signature_vectors is not None:
                try:
                    query_vec = self.vectorizer.transform([sentence_text])
                    scores = cosine_similarity(query_vec, self.signature_vectors)[0]
                    top_idx = int(scores.argmax())
                    best_score = float(scores[top_idx])
                    best_sig = self.signatures[top_idx]
                except Exception as e:
                    print(f"[SimilarityEngine] TF-IDF similarity error: {e}")

            # Threshold for semantic match
            if best_sig and best_score >= 0.40:
                matches.append(
                    SimilarityMatch(
                        category=best_sig["category"],
                        similarity_score=round(best_score, 3),
                        matched_signature=best_sig["phrase"],
                        sentence_text=sentence_text,
                        start=start,
                        end=end,
                        reason=f"High semantic similarity ({int(best_score*100)}%) to known attack signature: '{best_sig['phrase']}'",
                    )
                )

        return matches
