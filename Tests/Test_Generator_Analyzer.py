"""
tests/test_Generator_Analyzer.py
Unitarian test for Analyzer and Generator.

Execute:
    python -m pytest tests/ -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import re
import pytest

from Analyzer import (
    analyze,
    calc_entropy,
    crack_time_human,
    get_charset_size,
    run_checks,
)
from Generator import GeneratorConfig, generate


# ─────────────────────────────────────────────
# Analyzer
# ─────────────────────────────────────────────

class TestCharsetSize:
    def test_only_lowercase(self):
        assert get_charset_size("abc") == 26

    def test_lower_and_upper(self):
        assert get_charset_size("abcABC") == 52

    def test_all_types(self):
        assert get_charset_size("aA1!") == 94

    def test_empty(self):
        assert get_charset_size("") == 0


class TestEntropy:
    def test_empty_password(self):
        assert calc_entropy("") == 0.0

    def test_increases_with_length(self):
        e1 = calc_entropy("aaaa")
        e2 = calc_entropy("aaaaaaaa")
        assert e2 > e1

    def test_increases_with_charset(self):
        e1 = calc_entropy("aaaaaaaa")   # only lowercase
        e2 = calc_entropy("aA1!aA1!")   # all types
        assert e2 > e1


class TestCrackTime:
    def test_instant(self):
        assert crack_time_human(0.0001) == "instantaneous"

    def test_seconds(self):
        result = crack_time_human(30)
        assert "second" in result

    def test_very_long(self):
        result = crack_time_human(1e20)
        assert "billions" in result or "years" in result


class TestRunChecks:
    def test_all_fail_on_short_simple(self):
        checks = run_checks("abc")
        assert checks["min_8_chars"] is False
        assert checks["has_uppercase"] is False
        assert checks["has_digit"] is False
        assert checks["has_symbol"] is False

    def test_all_pass_on_strong(self):
        checks = run_checks("Tr0ub4dor&3_SecurePass!")
        assert all(checks.values())

    def test_digit_check(self):
        assert run_checks("Abcdefgh1")["has_digit"] is True
        assert run_checks("Abcdefghi")["has_digit"] is False


class TestAnalyze:
    def test_returns_result(self):
        result = analyze("Hello123!")
        assert result.length == 9
        assert result.entropy_bits > 0
        assert result.strength_label in [
            "very weak", "weak", "reasonable", "good", "strong", "very strong"
        ]

    def test_weak_password(self):
        result = analyze("abc")
        assert result.score <= 2
        assert result.strength_label in ("very weak", "weak")

    def test_strong_password(self):
        result = analyze("xK#9mPqL!2vRn$Wd")
        assert result.score >= 5
        assert result.strength_label in ("strong", "very strong")

    def test_suggestions_for_weak(self):
        result = analyze("abc")
        assert len(result.suggestions) > 0

    def test_no_suggestions_for_strong(self):
        result = analyze("xK#9mPqL!2vRn$Wd")
        assert len(result.suggestions) == 0


# ─────────────────────────────────────────────
# Generator
# ─────────────────────────────────────────────

class TestGeneratorConfig:
    def test_default_config(self):
        config = GeneratorConfig()
        assert config.length == 20
        assert config.uppercase is True

    def test_length_too_short(self):
        with pytest.raises(ValueError, match="minimum"):
            GeneratorConfig(length=2)

    def test_length_too_long(self):
        with pytest.raises(ValueError, match="maximum"):
            GeneratorConfig(length=300)

    def test_no_charset_selected(self):
        with pytest.raises(ValueError, match="at least"):
            GeneratorConfig(uppercase=False, lowercase=False,
                            digits=False, symbols=False)


class TestGenerate:
    def test_correct_length(self):
        for length in [8, 16, 32, 64]:
            pwd = generate(GeneratorConfig(length=length))
            assert len(pwd) == length

    def test_contains_uppercase_when_required(self):
        config = GeneratorConfig(length=20, uppercase=True,
                                 lowercase=False, digits=False, symbols=False)
        pwd = generate(config)
        assert re.search(r"[A-Z]", pwd)

    def test_contains_digit_when_required(self):
        config = GeneratorConfig(length=20, uppercase=False,
                                 lowercase=False, digits=True, symbols=False)
        pwd = generate(config)
        assert re.search(r"[0-9]", pwd)

    def test_no_symbol_when_disabled(self):
        config = GeneratorConfig(length=30, symbols=False)
        pwd = generate(config)
        assert not re.search(r"[^a-zA-Z0-9]", pwd)

    def test_uniqueness(self):
        # Two runs should produce different passwords (very low probability of collision)
        passwords = {generate() for _ in range(20)}
        assert len(passwords) == 20

    def test_all_types_present(self):
        # With all types enabled, each should appear at least once
        config = GeneratorConfig(length=40)
        pwd = generate(config)
        assert re.search(r"[A-Z]", pwd)
        assert re.search(r"[a-z]", pwd)
        assert re.search(r"[0-9]", pwd)
        assert re.search(r"[^a-zA-Z0-9]", pwd)