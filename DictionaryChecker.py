"""
DictionaryChecker.py
Detects passwords that are based on dictionary words or weak patterns,
making them vulnerable to dictionary and rule-based attacks.

Detection layers:
    1. Direct match against a built-in list of the most common passwords
    2. Leet-speak normalization (e.g. "p@ssw0rd" → "password") before matching
    3. Substring match: checks if any known word is contained in the password
    4. Keyboard walk patterns (e.g. "qwerty", "123456", "zxcvbn")
    5. Repeated character sequences (e.g. "aaaa", "1111")
    6. Sequential character runs (e.g. "abcd", "1234", "wxyz")

None of these checks require network access — everything runs locally.
"""

import re
import unicodedata
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Built-in word lists
# ---------------------------------------------------------------------------

# Top common passwords (subset — extend as needed)
COMMON_PASSWORDS: frozenset[str] = frozenset({
    "password", "123456", "123456789", "12345678", "12345", "1234567",
    "qwerty", "abc123", "password1", "iloveyou", "admin", "letmein",
    "monkey", "1234567890", "000000", "111111", "password123", "dragon",
    "master", "sunshine", "princess", "welcome", "shadow", "superman",
    "michael", "football", "baseball", "soccer", "batman", "trustno1",
    "starwars", "hello", "charlie", "donald", "password2", "qwerty123",
    "access", "login", "passw0rd", "p@ssword", "p@ssw0rd", "pa$$word",
    "pass", "guest", "test", "root", "toor", "admin123", "user",
    "senha", "123mudar", "mudar123", "brasil", "brazil", "senhadificil",
})

# Common dictionary words often used as passwords (English + Portuguese)
DICTIONARY_WORDS: frozenset[str] = frozenset({
    # English
    "love", "baby", "angel", "girl", "boy", "kiss", "sex", "god",
    "hell", "devil", "fire", "water", "earth", "sky", "moon", "sun",
    "star", "flower", "rose", "blue", "red", "black", "white", "green",
    "happy", "lucky", "magic", "tiger", "lion", "eagle", "shark",
    "killer", "winner", "loser", "secret", "private", "family",
    "summer", "winter", "spring", "autumn", "monday", "friday",
    "nintendo", "pokemon", "google", "apple", "microsoft", "amazon",
    "facebook", "twitter", "instagram", "youtube", "netflix",
    # Portuguese
    "amor", "casa", "gato", "cachorro", "carro", "azul", "verde",
    "vermelho", "amarelo", "feliz", "triste", "bonita", "bonito",
    "forte", "fraco", "deus", "vida", "morte", "tempo", "mundo",
    "poder", "chave", "coelho", "teclado", "computador", "celular",
})

# Keyboard walk patterns (rows and common diagonals)
KEYBOARD_PATTERNS: tuple[str, ...] = (
    "qwertyuiop", "asdfghjkl", "zxcvbnm",   # QWERTY rows
    "qwerty", "asdfgh", "zxcvbn",            # short row prefixes
    "qweasd", "wasdfg",                       # diagonal walks
    "1234567890", "0987654321",               # digit rows
    "!@#$%^&*()",                             # shift+digits
)

# Leet-speak substitution map (char → plain)
LEET_MAP: dict[str, str] = {
    "@": "a", "4": "a",
    "8": "b",
    "(": "c", "<": "c",
    "3": "e",
    "6": "g",
    "#": "h", "|-|": "h",
    "!": "i", "1": "i",
    "|": "l",
    "0": "o",
    "$": "s", "5": "s",
    "+": "t", "7": "t",
    "v": "v", "\\/": "v",
    "2": "z",
}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class DictionaryCheckResult:
    is_weak: bool                          # True if any weakness was found
    matches: list[str] = field(default_factory=list)    # matched words/patterns
    warnings: list[str] = field(default_factory=list)   # human-readable warnings
    normalized: str = ""                   # password after leet normalization (for transparency)


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def normalize_leet(password: str) -> str:
    """
    Converts leet-speak substitutions back to plain letters.
    Works left-to-right, longest match first (for multi-char sequences like '|-|').
    Example: "p@ssw0rd" → "password", "p455w0rd" → "password"
    """
    result = password.lower()

    # Multi-character substitutions first (order matters)
    multi = {k: v for k, v in LEET_MAP.items() if len(k) > 1}
    for leet, plain in multi.items():
        result = result.replace(leet, plain)

    # Single-character substitutions
    single = {k: v for k, v in LEET_MAP.items() if len(k) == 1}
    result = "".join(single.get(ch, ch) for ch in result)

    return result


def remove_accents(text: str) -> str:
    """Strips diacritics: 'café' → 'cafe'."""
    normalized = unicodedata.normalize("NFD", text)
    return "".join(ch for ch in normalized if unicodedata.category(ch) != "Mn")


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_common_passwords(password: str, normalized: str) -> tuple[list[str], list[str]]:
    """Checks direct match against the common passwords list."""
    matches, warnings = [], []
    lower = password.lower()
    for variant in (lower, normalized, remove_accents(normalized)):
        if variant in COMMON_PASSWORDS:
            matches.append(variant)
            warnings.append(
                f"'{password}' is one of the most commonly used passwords and is "
                f"instantly cracked by any dictionary attack."
            )
            break
    return matches, warnings


def _check_dictionary_words(password: str, normalized: str) -> tuple[list[str], list[str]]:
    """
    Checks if the password IS or CONTAINS a known dictionary word.
    Strips leading/trailing digits and symbols before matching (common pattern: word+year).
    """
    matches, warnings = [], []
    lower = password.lower()

    # Strip surrounding digits/symbols (e.g. "!password1" → "password")
    stripped = re.sub(r"^[^a-zA-Z]+|[^a-zA-Z]+$", "", lower)
    stripped_norm = re.sub(r"^[^a-zA-Z]+|[^a-zA-Z]+$", "", normalized)

    all_words = COMMON_PASSWORDS | DICTIONARY_WORDS
    for word in all_words:
        if len(word) < 3:
            continue
        # Exact match on stripped version
        if stripped == word or stripped_norm == word:
            if word not in matches:
                matches.append(word)
                warnings.append(
                    f"Password is based on the word '{word}', which is trivially "
                    f"guessed even with added numbers or symbols."
                )
        # Substring check on full password
        elif word in lower or word in normalized:
            if word not in matches:
                matches.append(word)
                warnings.append(
                    f"Password contains the word '{word}', which weakens it against "
                    f"rule-based dictionary attacks."
                )
    return matches, warnings


def _check_keyboard_walks(password: str) -> tuple[list[str], list[str]]:
    """Detects keyboard walk patterns of 4 or more consecutive characters."""
    matches, warnings = [], []
    lower = password.lower()

    for pattern in KEYBOARD_PATTERNS:
        # Check forward and reverse
        for direction, seq in (("forward", pattern), ("reverse", pattern[::-1])):
            for length in range(min(len(pattern), len(lower)), 3, -1):
                for start in range(len(seq) - length + 1):
                    chunk = seq[start: start + length]
                    if chunk in lower and chunk not in matches:
                        matches.append(chunk)
                        warnings.append(
                            f"Password contains the keyboard pattern '{chunk}' "
                            f"({direction}), which is commonly targeted in attacks."
                        )
    return matches, warnings


def _check_repeated_chars(password: str) -> tuple[list[str], list[str]]:
    """Detects runs of the same character repeated 3+ times (e.g. 'aaa', '111')."""
    matches, warnings = [], []
    found = re.findall(r"(.)\1{2,}", password)
    for repeat in found:
        if repeat not in matches:
            matches.append(repeat * 3)
            warnings.append(
                f"Password contains repeated characters ('{repeat * 3}...'), "
                f"which reduces entropy significantly."
            )
    return matches, warnings


def _check_sequential_runs(password: str) -> tuple[list[str], list[str]]:
    """
    Detects sequential character runs of 3 or more characters,
    ascending or descending (e.g. 'abc', '321', 'xyz').
    """
    matches, warnings = [], []
    if len(password) < 3:
        return matches, warnings

    def find_runs(s: str, step: int) -> list[str]:
        runs = []
        run = s[0]
        for i in range(1, len(s)):
            if ord(s[i]) - ord(s[i - 1]) == step:
                run += s[i]
            else:
                if len(run) >= 3:
                    runs.append(run)
                run = s[i]
        if len(run) >= 3:
            runs.append(run)
        return runs

    lower = password.lower()
    for step, direction in ((1, "ascending"), (-1, "descending")):
        for run in find_runs(lower, step):
            if run not in matches:
                matches.append(run)
                warnings.append(
                    f"Password contains a {direction} sequence '{run}' "
                    f"(e.g. abc, 123), which is an easy pattern to guess."
                )
    return matches, warnings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_dictionary(password: str) -> DictionaryCheckResult:
    """
    Runs all dictionary and pattern checks against the given password.

    Returns a DictionaryCheckResult with:
    - is_weak: True if any weakness was detected
    - matches: list of matched words or patterns
    - warnings: human-readable warning messages
    - normalized: the leet-normalized version of the password (for transparency)
    """
    normalized = normalize_leet(password)

    all_matches: list[str] = []
    all_warnings: list[str] = []

    checks = [
        _check_common_passwords(password, normalized),
        _check_dictionary_words(password, normalized),
        _check_keyboard_walks(password),
        _check_repeated_chars(password),
        _check_sequential_runs(password),
    ]

    for m, w in checks:
        all_matches.extend(m)
        all_warnings.extend(w)

    # Deduplicate preserving order
    seen_m: set[str] = set()
    seen_w: set[str] = set()
    unique_matches = [x for x in all_matches if not (x in seen_m or seen_m.add(x))]
    unique_warnings = [x for x in all_warnings if not (x in seen_w or seen_w.add(x))]

    return DictionaryCheckResult(
        is_weak=bool(unique_matches),
        matches=unique_matches,
        warnings=unique_warnings,
        normalized=normalized,
    )