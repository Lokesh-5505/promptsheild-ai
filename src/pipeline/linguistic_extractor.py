import re
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple

@dataclass
class LinguisticFeature:
    category: str
    feature_type: str
    start: int
    end: int
    matched_text: str
    reason: str
    score_contribution: int


class LinguisticExtractor:
    """Stage 2: Linguistic feature extraction for AI-directed command signals."""

    # Imperative command starters targeting the assistant
    IMPERATIVE_ROOTS = [
        r"^(please\s+)?(ignore|disregard|forget|override|bypass|suppress)\b",
        r"^(please\s+)?(forward|send|transmit|exfiltrate|email|dispatch)\b",
        r"^(please\s+)?(print|output|display|show|repeat|reveal|dump|echo)\b",
        r"^(please\s+)?(delete|remove|erase|cancel|purge|wipe)\b",
        r"^(please\s+)?(approve|execute|run|trigger|modify|grant)\b",
        r"^(please\s+)?(do\s+not\s+obey|never\s+mind|drop\s+all)\b",
    ]

    # High-risk action verbs associated with sensitive resources
    ACTION_RESOURCE_PAIRS = [
        (
            re.compile(r"\b(forward|send|email|transmit|exfiltrate|bcc)\b.*?\b(all\s+emails?|passwords?|credentials?|tokens?|api\s+keys?|address\s+book|contacts?|database|secret|confidential)\b.*?\b(to\s+)?([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)", re.IGNORECASE),
            "data_exfiltration",
            "Exfiltration command routing sensitive records to an external email address",
            40,
        ),
        (
            re.compile(r"\b(send|curl|post|fetch|upload|transmit)\b.*?\b(https?://[^\s]+).*?\b(token|key|password|secret|leak|exfil|harvest)\b", re.IGNORECASE),
            "data_exfiltration",
            "Action verb directing sensitive data transmission to external URL/endpoint",
            35,
        ),
        (
            re.compile(r"\b(ignore|disregard|forget|override|bypass)\b.*?\b(all\s+)?(previous|prior|above|existing|system)?\s*(instructions|prompts|rules|guidelines|directives|filters|safety)\b", re.IGNORECASE),
            "instruction_override",
            "Imperative command to disregard previous instructions or system rules",
            40,
        ),
        (
            re.compile(r"\b(print|output|reveal|dump|show|repeat|leak|display)\b.*?\b(system\s+prompt|developer\s+mode|initial\s+instructions|hidden\s+prompt|developer\s+preamble|secret\s+key|api\s+key)\b", re.IGNORECASE),
            "prompt_extraction",
            "Command attempting to extract confidential system instructions or secrets",
            40,
        ),
        (
            re.compile(r"\b(delete|cancel|wipe|purge)\s+all\s+(emails?|calendar|meetings|inbox|records?|database|production\s+data)\b", re.IGNORECASE),
            "unauthorized_action",
            "State-changing command directing destructive deletion of user or system records",
            40,
        ),
        (
            re.compile(r"\b(wire\s+transfer|transfer\s+\$\d+|\$?\d+\s*dollars?\s+to\s+account)\b", re.IGNORECASE),
            "unauthorized_action",
            "State-changing command directing unauthorized financial transactions",
            40,
        ),
    ]

    # Destination patterns
    EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b")
    URL_PATTERN = re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*")

    def __init__(self):
        self.compiled_imperatives = [re.compile(p, re.IGNORECASE) for p in self.IMPERATIVE_ROOTS]

    def extract_features(self, text: str) -> List[LinguisticFeature]:
        """Extract linguistic threat features and command patterns from text."""
        features: List[LinguisticFeature] = []
        if not text:
            return features

        # 1. Action-Resource Pattern Matching
        for pattern, category, reason, score in self.ACTION_RESOURCE_PAIRS:
            for match in pattern.finditer(text):
                features.append(
                    LinguisticFeature(
                        category=category,
                        feature_type="action_resource_link",
                        start=match.start(),
                        end=match.end(),
                        matched_text=match.group(0),
                        reason=reason,
                        score_contribution=score,
                    )
                )

        # 2. Imperative sentence boundary detection
        lines_and_sentences = re.split(r"[\n.!?]", text)
        current_offset = 0

        for segment in lines_and_sentences:
            stripped = segment.strip()
            if stripped:
                seg_start = text.find(stripped, current_offset)
                if seg_start != -1:
                    current_offset = seg_start + len(stripped)
                    for imp_pat in self.compiled_imperatives:
                        m = imp_pat.match(stripped)
                        if m:
                            # Avoid duplicate matches if already captured by action-resource
                            span_start = seg_start
                            span_end = seg_start + len(stripped)
                            already_captured = any(
                                f.start <= span_start and f.end >= span_end for f in features
                            )
                            if not already_captured:
                                features.append(
                                    LinguisticFeature(
                                        category="instruction_override",
                                        feature_type="imperative_command",
                                        start=span_start,
                                        end=span_end,
                                        matched_text=stripped,
                                        reason="Imperative command directed at the AI assistant.",
                                        score_contribution=25,
                                    )
                                )
                            break

        return features
