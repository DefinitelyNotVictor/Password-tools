import math
import re
from dataclasses import dataclass, field

# Estimated attack speed (guesses/second)
# Reference: hashcat with modern GPU on MD5 hash
GUESSES_PER_SECOND = 10_000_000  # 10 million guesses per second (can be adjusted based on attack type)

@dataclass
class AnalysisResult:
    password: str
    length: int
    score: int                    # 0–6
    strength_label: str
    entropy_bits: float
    charset_size: int
    crack_time_seconds: float
    crack_time_human: str
    checks: dict[str, bool] = field(default_factory=dict)
    suggestions: list[str] = field(default_factory=list)

def get_charset_size(password: str) -> int:
    """Calculates the size of the character pool based on the types of characters present in the password."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32  # Common symbols on US keyboards (can be adjusted if needed)
    return pool

def calc_entropy(password: str) -> float:
    """Calculates the entropy in bits: log2(pool^length)."""
    pool = get_charset_size(password)
    if pool == 0 or len(password) == 0:
        return 0.0
    return len(password) * math.log2(pool)

def crack_time_human(seconds: float) -> str:
    """Converts seconds into a human-readable format with appropriate time units."""
    if seconds < 1:
        return "instantly"
    thresholds = [
        (60,          "second(s)",       1),
        (3_600,       "minute(s)",        60),
        (86_400,      "hour(s)",          3_600),
        (31_536_000,  "day(s)",           86_400),
        (3.154e9,     "year(s)",           31_536_000),
        (3.154e12,    "millennium",         3.154e9),
        (3.154e15,    "millions of years",  3.154e12),
    ]
    for limit, label, divisor in thresholds:
        if seconds < limit:
            value = round(seconds / divisor)
            return f"{value} {label}"
    return "billions of years (practically impossible)"

def run_checks(password: str) -> dict[str, bool]:
    return {
        "min_8_chars":     len(password) >= 8,
        "has_uppercase":   bool(re.search(r"[A-Z]", password)),
        "has_lowercase":   bool(re.search(r"[a-z]", password)),
        "has_digit":       bool(re.search(r"[0-9]", password)),
        "has_symbol":      bool(re.search(r"[^a-zA-Z0-9]", password)),
        "min_16_chars":    len(password) >= 16,
    }


def build_suggestions(checks: dict[str, bool]) -> list[str]:
    messages = {
        "min_8_chars":   "Use at least 8 characters.",
        "has_uppercase": "Add uppercase letters (A-Z).",
        "has_lowercase": "Add lowercase letters (a-z).",
        "has_digit":     "Add numbers (0-9).",
        "has_symbol":    "Add symbols (!@#$%...).",
        "min_16_chars":  "Prefer 16 or more characters for greater security.",
    }
    return [messages[k] for k, passed in checks.items() if not passed]


STRENGTH_LEVELS = [
    (0, "very weak"),
    (2, "weak"),
    (3, "reasonable"),
    (4, "good"),
    (5, "strong"),
    (6, "very strong"),
]


def get_strength(score: int) -> str:
    label = "very weak"
    for min_score, strength in STRENGTH_LEVELS:
        if score >= min_score:
            label = strength
    return label


def analyze(password: str) -> AnalysisResult:
    """Analyze a password and return an AnalysisResult."""
    checks = run_checks(password)
    score = sum(checks.values())
    entropy = calc_entropy(password)
    charset = get_charset_size(password)

    # Average guesses needed is half the total combinations (assuming uniform distribution)
    combinations = 2 ** entropy
    avg_guesses = combinations / 2
    seconds = avg_guesses / GUESSES_PER_SECOND

    return AnalysisResult(
        password=password,
        length=len(password),
        score=score,
        strength_label=get_strength(score),
        entropy_bits=round(entropy, 2),
        charset_size=charset,
        crack_time_seconds=seconds,
        crack_time_human=crack_time_human(seconds),
        checks=checks,
        suggestions=build_suggestions(checks),
    )