import re
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple

@dataclass
class RuleMatch:
    rule_id: str
    category: str
    start: int
    end: int
    matched_text: str
    reason: str
    severity: int


class RuleEngine:
    """Stage 5: Versioned regular-expression rule engine for deterministic injection signatures."""

    # Informational or educational inquiry prefixes that indicate non-adversarial intent
    QUESTION_PREFIX = re.compile(
        r"(?i)^(how\s+(do|can|to|should)\s+i|can\s+you\s+explain\s+how|tutorial\s+on|what\s+is\s+the\s+command\s+to|explain\s+how\s+to)\b"
    )

    RULES = [
        # 1. Direct instruction overrides
        (
            "RULE_OVERRIDE_01",
            "instruction_override",
            re.compile(r"(?i)\b(ignore|disregard|forget|bypass|override)\s+(all\s+)?(previous|prior|above|past|initial|system)\s+(instructions|prompts|rules|commands|directives|safety\s+filters|guidelines)\b"),
            "Explicit command to override or disregard prior instructions or system guidelines.",
            95,
        ),
        (
            "RULE_OVERRIDE_02",
            "instruction_override",
            re.compile(r"(?i)\b(you\s+are\s+now|act\s+as|roleplay\s+as|pretend\s+to\s+be)\s+(an?\s+)?(unrestricted|dan|jailbroken|evil|unfiltered|chaosgpt|developer\s+mode)\b"),
            "Jailbreak framing attempt (unrestricted AI / DAN persona).",
            94,
        ),
        (
            "RULE_OVERRIDE_03",
            "instruction_override",
            re.compile(r"(?i)\b(dan\s+(can\s+do\s+anything|mode)|do\s+anything\s+now|filters?\s+(don't|do\s+not)\s+exist|pretend\s+(safety\s+filters|rules|guidelines)\s+(don't|do\s+not)\s+exist)\b"),
            "Explicit jailbreak persona activation or safety filter bypass command.",
            94,
        ),
        (
            "RULE_OVERRIDE_04",
            "instruction_override",
            re.compile(r"(?i)(\[|<!--|===+)\s*(system|admin|developer|root|urgent\s+instruction|prompt\s+reset|system\s+override)\s*([:\]\->]|===+)"),
            "System instruction injection tag mimicking internal control prompts or delimiters.",
            90,
        ),
        (
            "RULE_OVERRIDE_04",
            "instruction_override",
            re.compile(r"(?i)\b(stop\s+being|no\s+longer|abandon)\s+(an?\s+)?(helpful\s+)?(assistant|email\s+assistant|bot)\s+and\s+(obey|follow|do\s+anything)\b"),
            "Command attempting to terminate assistant role constraints.",
            88,
        ),
        (
            "RULE_OVERRIDE_05",
            "instruction_override",
            re.compile(r"(?i)\b(disregard\s+(what\s+was\s+said|prior\s+directions|safety\s+parameters)|new\s+operational\s+directive\s*[:\-])"),
            "Adversarial reset command overriding conversation context.",
            92,
        ),

        # 2. Prompt extraction / Leakage
        (
            "RULE_EXTRACT_01",
            "prompt_extraction",
            re.compile(r"(?i)\b(print|output|repeat|reveal|dump|leak|display)\s+(the\s+)?(full\s+|exact\s+)?(system\s+prompt|initial\s+instructions|system\s+message|hidden\s+prompt|developer\s+preamble)\b"),
            "Direct attempt to dump or extract the hidden system prompt.",
            95,
        ),
        (
            "RULE_EXTRACT_02",
            "prompt_extraction",
            re.compile(r"(?i)\b(what\s+are\s+your\s+(exact\s+)?instructions|repeat\s+all\s+(words|text)\s+above\s+(verbatim|word\s+for\s+word))\b"),
            "Inquiry attempting to extract internal instructions or preamble.",
            88,
        ),
        (
            "RULE_EXTRACT_03",
            "prompt_extraction",
            re.compile(r"(?i)\b(show|dump|reveal|leak|print)\s+(your\s+)?(secret\s+)?(api\s+keys?|secret\s+tokens?|credentials?|database\s+passwords?)\b"),
            "Command attempting to extract secret API keys or credentials.",
            98,
        ),

        # 3. Data exfiltration (specifically targeted at sensitive data or covert channels)
        (
            "RULE_EXFIL_01",
            "data_exfiltration",
            re.compile(r"(?i)\b(forward|send|email|transmit|exfiltrate|bcc)\s+.*?\b(all\s+)?(\w+\s+)?(emails?|messages?|passwords?|credentials?|tokens?|keys?|address\s+book|contacts?|database|records?|confidential)\b.*?\b(to\s+)?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b"),
            "Exfiltration command targeting sensitive records to an external email destination.",
            96,
        ),
        (
            "RULE_EXFIL_02",
            "data_exfiltration",
            re.compile(r"(?i)\b(silently|secretly|in\s+the\s+background)\s+(forward|email|send|transmit)\b.*?\b(to\s+)?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b"),
            "Covert exfiltration command routing data without user awareness.",
            94,
        ),
        (
            "RULE_EXFIL_03",
            "data_exfiltration",
            re.compile(r"(?i)\b(curl|wget|fetch|post|webhook)\s+.*?(https?://[^\s]+).*?\b(token|key|password|secret|leak|exfil|harvest)\b"),
            "Exfiltration command invoking webhooks or external HTTP requests with sensitive tokens.",
            95,
        ),
        (
            "RULE_EXFIL_04",
            "data_exfiltration",
            re.compile(r"(?i)!\[.*?\]\(https?://[^\s)]+\?[^\s)]*=(.*?)\)"),
            "Markdown image rendering attack used for silent data exfiltration.",
            96,
        ),

        # 4. Unauthorized actions
        (
            "RULE_ACTION_01",
            "unauthorized_action",
            re.compile(r"(?i)\b(delete|wipe|erase|purge)\s+all\s+(emails?|messages?|inbox|calendar|customer\s+records|production\s+data)\b"),
            "Destructive command ordering deletion of user mailbox or critical production records.",
            92,
        ),
        (
            "RULE_ACTION_02",
            "unauthorized_action",
            re.compile(r"(?i)\b(drop\s+table\s+\w+|delete\s+from\s+\w+\s*;|truncate\s+table\s+\w+)"),
            "Destructive SQL injection or database wipe command.",
            98,
        ),
        (
            "RULE_ACTION_03",
            "unauthorized_action",
            re.compile(r"(?i)\b(wire\s+transfer|transfer\s+\$\d+|\$?\d+\s*dollars?\s+to\s+account)\b"),
            "Unauthorized financial transaction command.",
            95,
        ),
        (
            "RULE_ACTION_04",
            "unauthorized_action",
            re.compile(r"(?i)\b(grant|escalate|elevate)\s+(admin|root|superuser|full\s+access)\s+(privileges|rights|role)\s+to\b"),
            "Privilege escalation attempt.",
            92,
        ),
    ]

    def __init__(self):
        pass

    def scan(self, text: str) -> List[RuleMatch]:
        """Scan text against versioned regex rules and return matches."""
        matches: List[RuleMatch] = []
        if not text:
            return matches

        for rule_id, category, pattern, reason, severity in self.RULES:
            for m in pattern.finditer(text):
                matches.append(
                    RuleMatch(
                        rule_id=rule_id,
                        category=category,
                        start=m.start(),
                        end=m.end(),
                        matched_text=m.group(0),
                        reason=reason,
                        severity=severity,
                    )
                )

        return matches
