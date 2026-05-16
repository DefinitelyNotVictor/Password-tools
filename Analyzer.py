import math
import re
from dataclasses import dataclass, field

from DictionaryChecker import DictionaryCheckResult, check_dictionary
from WordVariants import WordScanResult, scan_word

# Estimated attack speed (guesses/second)
# Reference: hashcat with modern GPU on MD5 hash
GUESSES_PER_SECOND = 10_000_000  # 10 million guesses per second (can be adjusted based on attack type)


# ---------------------------------------------------------------------------
# Dictionary risk index
# ---------------------------------------------------------------------------
# Measures exposure to targeted dictionary attacks based on how many
# variants of the password's base word appear in known breach databases.
#
# Scale:
#   0   — none      : no variants found
#   1   — low       : 1–3 variants found
#   2   — moderate  : 4–10 variants found
#   3   — high      : 11–30 variants found
#   4   — critical  : 31+ variants found
#
# This is intentionally separate from entropy: a password can have high
# entropy (hard to brute-force) but still carry a high dictionary risk
# (its base word is heavily targeted in rule-based attacks).

DICTIONARY_RISK_THRESHOLDS: list[tuple[int, str]] = [
    (0,  "none"),
    (1,  "low"),
    (4,  "moderate"),
    (11, "high"),
    (31, "critical"),
]


def get_dictionary_risk(found_count: int) -> tuple[int, str]:
    """
    Returns (risk_level 0-4, risk_label) based on the number of
    compromised variants found in HIBP.
    """
    level, label = 0, "none"
    for threshold, name in DICTIONARY_RISK_THRESHOLDS:
        if found_count >= threshold:
            level, label = DICTIONARY_RISK_THRESHOLDS.index((threshold, name)), name
    return level, label


@dataclass
class AnalysisResult:
    password: str
    length: int
    score: int                      # 0-6
    strength_label: str
    entropy_bits: float             # theoretical entropy — never penalized
    charset_size: int
    crack_time_seconds: float       # based on full entropy (brute-force estimate)
    crack_time_human: str
    dictionary_risk_level: int      # 0-4
    dictionary_risk_label: str      # none / low / moderate / high / critical
    checks: dict[str, bool] = field(default_factory=dict)
    suggestions: list[str] = field(default_factory=list)
    dictionary: DictionaryCheckResult | None = None   # None if check was skipped
    variant_scan: WordScanResult | None = None        # None if scan was skipped


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
        pool += 32  # Common symbols on US keyboards
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
        (60,          "second(s)",         1),
        (3_600,       "minute(s)",         60),
        (86_400,      "hour(s)",           3_600),
        (31_536_000,  "day(s)",            86_400),
        (3.154e9,     "year(s)",           31_536_000),
        (3.154e12,    "millennium",        3.154e9),
        (3.154e15,    "millions of years", 3.154e12),
    ]
    for limit, label, divisor in thresholds:
        if seconds < limit:
            value = round(seconds / divisor)
            return f"{value} {label}"
    return "billions of years (practically impossible)"


def run_checks(password: str) -> dict[str, bool]:
    return {
        "min_8_chars":   len(password) >= 8,
        "has_uppercase": bool(re.search(r"[A-Z]", password)),
        "has_lowercase": bool(re.search(r"[a-z]", password)),
        "has_digit":     bool(re.search(r"[0-9]", password)),
        "has_symbol":    bool(re.search(r"[^a-zA-Z0-9]", password)),
        "min_16_chars":  len(password) >= 16,
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


def _extract_base_word(password: str, dict_result: DictionaryCheckResult | None) -> str | None:
    """
    Returns the most likely base word found in the password, or None.
    Prefers the longest alphabetic match from the dictionary check.
    """
    if dict_result and dict_result.matches:
        alpha = [m for m in dict_result.matches if m.isalpha()]
        if alpha:
            return max(alpha, key=len)
    stripped = re.sub(r"^[^a-zA-Z]+|[^a-zA-Z]+$", "", password.lower())
    return stripped if len(stripped) >= 3 else None


def analyze(
    password: str,
    skip_dictionary: bool = False,
    skip_variant_scan: bool = False,
) -> AnalysisResult:
    """
    Analyze a password and return an AnalysisResult.

    Entropy reflects pure brute-force difficulty and is never penalized.
    Dictionary risk is reported separately as a 0-4 index.

    Args:
        password: The password string to analyze.
        skip_dictionary: Skip the local dictionary/pattern check.
        skip_variant_scan: Skip the HIBP variant scan (no network call).
    """
    checks = run_checks(password)
    score = sum(checks.values())
    entropy = calc_entropy(password)
    charset = get_charset_size(password)

    avg_guesses = (2 ** entropy) / 2
    seconds = avg_guesses / GUESSES_PER_SECOND

    # --- Local dictionary check ---
    dict_result = None if skip_dictionary else check_dictionary(password)
    if dict_result and dict_result.is_weak:
        score = max(0, score - 2)

    # --- HIBP variant scan ---
    variant_scan: WordScanResult | None = None
    if not skip_variant_scan:
        base_word = _extract_base_word(password, dict_result)
        if base_word:
            variant_scan = scan_word(base_word)

    # --- Dictionary risk index (independent of entropy) ---
    found_count = variant_scan.found_count if variant_scan else 0
    risk_level, risk_label = get_dictionary_risk(found_count)

    return AnalysisResult(
        password=password,
        length=len(password),
        score=score,
        strength_label=get_strength(score),
        entropy_bits=round(entropy, 2),
        charset_size=charset,
        crack_time_seconds=seconds,
        crack_time_human=crack_time_human(seconds),
        dictionary_risk_level=risk_level,
        dictionary_risk_label=risk_label,
        checks=checks,
        suggestions=build_suggestions(checks),
        dictionary=dict_result,
        variant_scan=variant_scan,
    )