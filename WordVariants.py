"""
WordVariants.py
Generates common password variations from a base word and checks each one
against the Have I Been Pwned (HIBP) API.

Variation layers (applied in order, deduplicated, capped at MAX_VARIANTS):
    1. Casing          — lowercase, UPPERCASE, Capitalized, tItLeCaSe, aLtErNaTiNg
    2. Leet-speak      — single-char substitutions (a→@/4, e→3, i→1/!, o→0, s→$/5, t→7)
    3. Common suffixes — popular numbers, years, and symbols appended/prepended
    4. Combinations    — casing × suffix (most impactful cross-product)

All checks use k-Anonymity (only the first 5 SHA-1 chars leave the machine).
"""

from __future__ import annotations

import itertools
import time
from dataclasses import dataclass, field

from Pwned import check_pwned, PwnedResult

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_VARIANTS: int = 50          # hard cap on variants checked per word
REQUEST_DELAY: float = 0.1      # seconds between API calls (HIBP rate limit)

# Common suffixes used in password mutation attacks
NUMBER_SUFFIXES: tuple[str, ...] = (
    "1", "12", "123", "1234", "12345",
    "0", "01", "007",
    "2020", "2021", "2022", "2023", "2024", "2025",
    "99", "100",
)

SYMBOL_SUFFIXES: tuple[str, ...] = (
    "!", "!!", "@", "#", "123!", "1!", "!1", "!123",
)

PREPEND_TOKENS: tuple[str, ...] = (
    "my", "the", "super", "mega", "1",
)

# Leet-speak substitution table — one plain char → possible leet chars
LEET_TABLE: dict[str, list[str]] = {
    "a": ["@", "4"],
    "e": ["3"],
    "i": ["1", "!"],
    "o": ["0"],
    "s": ["$", "5"],
    "t": ["7"],
    "l": ["1"],
    "g": ["9"],
    "b": ["8"],
}


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class VariantResult:
    variant: str
    pwned: PwnedResult
    error: str = ""          # non-empty if the API call failed


@dataclass
class WordScanResult:
    word: str
    total_checked: int
    found_count: int                              # variants actually seen in breaches
    total_breach_appearances: int                 # sum of all counts
    results: list[VariantResult] = field(default_factory=list)

    @property
    def found_results(self) -> list[VariantResult]:
        return [r for r in self.results if r.pwned.found]

    @property
    def not_found_results(self) -> list[VariantResult]:
        return [r for r in self.results if not r.pwned.found and not r.error]

    @property
    def error_results(self) -> list[VariantResult]:
        return [r for r in self.results if r.error]


# ---------------------------------------------------------------------------
# Variant generation
# ---------------------------------------------------------------------------

def _casing_variants(word: str) -> list[str]:
    """Returns casing mutations of the word."""
    lower = word.lower()
    variants = [
        lower,
        word.upper(),
        word.capitalize(),
        lower.title(),
        "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(lower)),  # aLtErNaTe
        "".join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(lower)),  # AlTeRnAtE
    ]
    return variants


def _leet_variants(word: str) -> list[str]:
    """
    Generates leet-speak variants by substituting one character at a time.
    Avoids combinatorial explosion by substituting only one position per variant.
    """
    lower = word.lower()
    variants: list[str] = []
    for i, ch in enumerate(lower):
        if ch in LEET_TABLE:
            for sub in LEET_TABLE[ch]:
                variant = lower[:i] + sub + lower[i + 1:]
                variants.append(variant)
                # Also capitalized version: Passw0rd
                variants.append(variant.capitalize())
    return variants


def _suffix_variants(base_variants: list[str]) -> list[str]:
    """Appends and prepends common tokens to a set of base variants."""
    results: list[str] = []
    for base in base_variants:
        for suffix in NUMBER_SUFFIXES + SYMBOL_SUFFIXES:
            results.append(base + suffix)          # word123
            results.append(base + suffix.upper())  # word123 (suffix already str, no-op for nums)
        for prefix in PREPEND_TOKENS:
            results.append(prefix + base)          # myword
    return results


def generate_variants(word: str, max_variants: int = MAX_VARIANTS) -> list[str]:
    """
    Generates up to `max_variants` unique password variants from `word`.

    Order of generation (priority reflects real-world attack lists):
      1. Casing mutations
      2. Leet-speak (single substitution)
      3. Casing + common suffixes/prefixes
      4. Leet + suffixes
    """
    seen: set[str] = set()
    ordered: list[str] = []

    def add(v: str) -> None:
        if v and v not in seen:
            seen.add(v)
            ordered.append(v)

    casing = _casing_variants(word)
    leet   = _leet_variants(word)

    # Layer 1 — casing
    for v in casing:
        add(v)

    # Layer 2 — leet
    for v in leet:
        add(v)

    # Layer 3 — casing × suffixes (most impactful combos)
    for v in _suffix_variants(casing):
        add(v)
        if len(ordered) >= max_variants:
            break

    # Layer 4 — leet × suffixes
    if len(ordered) < max_variants:
        for v in _suffix_variants(leet):
            add(v)
            if len(ordered) >= max_variants:
                break

    return ordered[:max_variants]


# ---------------------------------------------------------------------------
# Batch HIBP check
# ---------------------------------------------------------------------------

def scan_word(
    word: str,
    max_variants: int = MAX_VARIANTS,
    delay: float = REQUEST_DELAY,
    progress_callback=None,
) -> WordScanResult:
    """
    Generates variants of `word` and checks each against the HIBP API.

    Args:
        word: Base word to scan (e.g. "alface").
        max_variants: Maximum number of variants to check.
        delay: Seconds to wait between API requests.
        progress_callback: Optional callable(current, total, variant) for progress reporting.

    Returns:
        WordScanResult with all findings.
    """
    variants = generate_variants(word, max_variants)
    results: list[VariantResult] = []

    for i, variant in enumerate(variants):
        if progress_callback:
            progress_callback(i + 1, len(variants), variant)

        try:
            pwned = check_pwned(variant)
            results.append(VariantResult(variant=variant, pwned=pwned))
        except ConnectionError as exc:
            results.append(VariantResult(
                variant=variant,
                pwned=PwnedResult(
                    password_hash="", hash_prefix="", hash_suffix="",
                    found=False, count=0, message="",
                ),
                error=str(exc),
            ))

        if i < len(variants) - 1:
            time.sleep(delay)

    found_results = [r for r in results if r.pwned.found]
    total_appearances = sum(r.pwned.count for r in found_results)

    return WordScanResult(
        word=word,
        total_checked=len(results),
        found_count=len(found_results),
        total_breach_appearances=total_appearances,
        results=results,
    )