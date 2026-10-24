import re
import base64
import unicodedata
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any, Optional

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False


@dataclass
class SentenceSpan:
    text: str
    start: int
    end: int


@dataclass
class ObfuscationSpan:
    category: str
    start: int
    end: int
    decoded_content: str
    reason: str


@dataclass
class PreprocessedResult:
    original_text: str
    normalized_text: str
    sentences: List[SentenceSpan]
    obfuscation_spans: List[ObfuscationSpan]
    has_zero_width: bool
    has_base64: bool
    has_spaced_tokens: bool


class TextPreprocessor:
    """Stage 1: Text canonicalization, decoding, and sentence segmentation."""

    # Zero-width / hidden characters
    ZERO_WIDTH_PATTERN = re.compile(r"[\u200B\u200C\u200D\uFEFF\u2060\u200E\u200F\u00AD]")

    # Spaced-out letters e.g. "i g n o r e" or "d e l e t e"
    SPACED_LETTERS_PATTERN = re.compile(r"(?:(?<=\s)|^)[a-zA-Z](?:\s+[a-zA-Z]){2,}(?=(?:\s|$|[.,!?]))")

    # Potential base64 strings: length at least 16, characters in base64 alphabet with padding
    BASE64_PATTERN = re.compile(r"\b[A-Za-z0-9+/]{16,}={0,2}\b")

    def __init__(self):
        pass

    def normalize_unicode(self, text: str) -> str:
        """Apply NFKC normalization to resolve homoglyphs and ligature bypasses."""
        return unicodedata.normalize("NFKC", text)

    def detect_zero_width(self, text: str) -> Tuple[str, List[ObfuscationSpan]]:
        """Detect zero-width characters and record their positions."""
        spans: List[ObfuscationSpan] = []
        matches = list(self.ZERO_WIDTH_PATTERN.finditer(text))
        if matches:
            for m in matches:
                spans.append(
                    ObfuscationSpan(
                        category="obfuscation",
                        start=m.start(),
                        end=m.end(),
                        decoded_content="[ZERO_WIDTH_CHAR]",
                        reason="Zero-width or invisible character detected used for evasion.",
                    )
                )
            # Remove zero-width characters for downstream text parsing
            clean_text = self.ZERO_WIDTH_PATTERN.sub("", text)
            return clean_text, spans
        return text, []

    def detect_and_decode_base64(self, text: str) -> Tuple[str, List[ObfuscationSpan]]:
        """Identify Base64-encoded strings and decode if they represent ASCII instructions."""
        spans: List[ObfuscationSpan] = []
        augmented_text = text

        for m in self.BASE64_PATTERN.finditer(text):
            candidate = m.group(0)
            try:
                decoded_bytes = base64.b64decode(candidate)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore").strip()
                # Check if decoded string looks like readable text (at least 70% alphanumeric/spaces)
                if len(decoded_str) >= 6:
                    printable_ratio = sum(c.isalnum() or c.isspace() for c in decoded_str) / len(decoded_str)
                    if printable_ratio > 0.75:
                        spans.append(
                            ObfuscationSpan(
                                category="obfuscation",
                                start=m.start(),
                                end=m.end(),
                                decoded_content=decoded_str,
                                reason=f"Base64-encoded text detected: '{decoded_str[:60]}...'",
                            )
                        )
                        # Append decoded text in brackets so downstream NLP can inspect its intent
                        augmented_text = augmented_text.replace(candidate, f"{candidate} [DECODED: {decoded_str}]")
            except Exception:
                continue

        return augmented_text, spans

    def detect_spaced_tokens(self, text: str) -> Tuple[str, List[ObfuscationSpan]]:
        """Detect spaced-out evasion words like 'i g n o r e'."""
        spans: List[ObfuscationSpan] = []
        for m in self.SPACED_LETTERS_PATTERN.finditer(text):
            match_str = m.group(0)
            collapsed = "".join(match_str.split())
            if len(collapsed) >= 4:
                spans.append(
                    ObfuscationSpan(
                        category="obfuscation",
                        start=m.start(),
                        end=m.end(),
                        decoded_content=collapsed,
                        reason=f"Spaced-out token evasion detected: '{match_str}' -> '{collapsed}'",
                    )
                )
        return text, spans

    def strip_html(self, text: str) -> Tuple[str, List[ObfuscationSpan]]:
        """Extract hidden HTML comments for security inspection, and convert HTML to text."""
        if not text or ("<" not in text and ">" not in text):
            return text, []

        spans: List[ObfuscationSpan] = []
        # Find all HTML comments e.g. <!-- hidden prompt -->
        comment_pattern = re.compile(r"<!--(.*?)-->", re.DOTALL)
        for m in comment_pattern.finditer(text):
            comment_content = m.group(1).strip()
            if len(comment_content) > 3:
                spans.append(
                    ObfuscationSpan(
                        category="obfuscation",
                        start=m.start(),
                        end=m.end(),
                        decoded_content=comment_content,
                        reason=f"Hidden HTML comment detected: '{comment_content[:50]}...'",
                    )
                )

        # Replace comments with their inner content so downstream classifiers can inspect them
        text_with_comments = comment_pattern.sub(r" [HIDDEN_COMMENT: \1] ", text)

        if BS4_AVAILABLE:
            try:
                soup = BeautifulSoup(text_with_comments, "html.parser")
                return soup.get_text(separator=" "), spans
            except Exception:
                pass
        # Fallback regex tag stripper
        clean = re.sub(r"<[^>]+>", " ", text_with_comments)
        return clean, spans

    def segment_sentences(self, text: str) -> List[SentenceSpan]:
        """Split text into sentences while tracking exact character offsets."""
        sentence_spans: List[SentenceSpan] = []
        # Match sentences ending with punctuation or newlines
        pattern = re.compile(r'([^.!?\n\r]+[.!?\n\r]+|[^.!?\n\r]+$)')
        
        for match in pattern.finditer(text):
            sentence_text = match.group(0).strip()
            if sentence_text:
                # Find start and end within original string
                start = match.start()
                end = match.end()
                sentence_spans.append(SentenceSpan(text=sentence_text, start=start, end=end))
                
        if not sentence_spans and text.strip():
            sentence_spans.append(SentenceSpan(text=text.strip(), start=0, end=len(text)))
            
        return sentence_spans

    def preprocess(self, text: str) -> PreprocessedResult:
        """Execute full preprocessing pipeline on input text."""
        if not text:
            return PreprocessedResult(
                original_text="",
                normalized_text="",
                sentences=[],
                obfuscation_spans=[],
                has_zero_width=False,
                has_base64=False,
                has_spaced_tokens=False,
            )

        # 1. Unicode NFKC normalization
        norm_text = self.normalize_unicode(text)

        # 2. Zero-width character detection & stripping
        clean_text, zw_spans = self.detect_zero_width(norm_text)

        # 3. Base64 payload detection
        decoded_text, b64_spans = self.detect_and_decode_base64(clean_text)

        # 4. Spaced token detection
        _, spaced_spans = self.detect_spaced_tokens(clean_text)

        # 5. HTML stripping and hidden comment inspection
        text_no_html, html_spans = self.strip_html(decoded_text)

        # Combine all obfuscation spans
        all_obf_spans = zw_spans + b64_spans + spaced_spans + html_spans

        # 6. Sentence segmentation
        sentences = self.segment_sentences(text_no_html)

        return PreprocessedResult(
            original_text=text,
            normalized_text=text_no_html,
            sentences=sentences,
            obfuscation_spans=all_obf_spans,
            has_zero_width=len(zw_spans) > 0,
            has_base64=len(b64_spans) > 0,
            has_spaced_tokens=len(spaced_spans) > 0 or len(html_spans) > 0,
        )
