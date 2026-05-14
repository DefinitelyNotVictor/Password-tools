"""
tests/test_pwned.py
Unit tests for the pwned.py module.

The hashing and parsing tests run offline (without actual API calls).
The integration test is separated and marked to be skipped by default.

Execute with:
    python -m pytest tests/test_pwned.py -v
    python -m pytest tests/test_pwned.py -v -m integration  # test the real API
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from unittest.mock import patch

from Pwned import (
    sha1_hash,
    split_hash,
    parse_response,
    check_pwned,
    PwnedResult,
)


# ─────────────────────────────────────────────
# sha1_hash
# ─────────────────────────────────────────────

class TestSha1Hash:
    def test_known_hash(self):
        # The SHA-1 hash for "password" is well-known and widely documented.
        result = sha1_hash("password")
        assert result == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"

    def test_returns_uppercase(self):
        result = sha1_hash("abc")
        assert result == result.upper()

    def test_length_is_40(self):
        assert len(sha1_hash("anything")) == 40

    def test_empty_string(self):
        # The SHA-1 value of an empty string is a fixed and well-defined value.
        result = sha1_hash("")
        assert len(result) == 40
        assert result == result.upper()

    def test_different_passwords_different_hashes(self):
        assert sha1_hash("password1") != sha1_hash("password2")

    def test_case_sensitive(self):
        # SHA-1 differs for "Password" vs "password" due to case sensitivity
        assert sha1_hash("Password") != sha1_hash("password")


# ─────────────────────────────────────────────
# split_hash
# ─────────────────────────────────────────────

class TestSplitHash:
    def test_prefix_length(self):
        prefix, _ = split_hash("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")
        assert len(prefix) == 5

    def test_suffix_length(self):
        _, suffix = split_hash("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")
        assert len(suffix) == 35

    def test_correct_split(self):
        prefix, suffix = split_hash("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")
        assert prefix == "5BAA6"
        assert suffix == "1E4C9B93F3F0682250B6CF8331B7EE68FD8"

    def test_prefix_plus_suffix_equals_original(self):
        original = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        prefix, suffix = split_hash(original)
        assert prefix + suffix == original


# ─────────────────────────────────────────────
# parse_response
# ─────────────────────────────────────────────

class TestParseResponse:
    MOCK_RESPONSE = (
        "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n"  # "password" suffix
        "AABBCCDDEE112233445566778899001122334:3\r\n"
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFAF:1\r\n"
    )

    def test_finds_existing_suffix(self):
        count = parse_response(self.MOCK_RESPONSE, "1E4C9B93F3F0682250B6CF8331B7EE68FD8")
        assert count == 9545824

    def test_returns_zero_for_missing_suffix(self):
        count = parse_response(self.MOCK_RESPONSE, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        assert count == 0

    def test_case_insensitive_suffix(self):
        count = parse_response(self.MOCK_RESPONSE, "1e4c9b93f3f0682250b6cf8331b7ee68fd8")
        assert count == 9545824

    def test_empty_response(self):
        assert parse_response("", "1E4C9B93F3F0682250B6CF8331B7EE68FD8") == 0

    def test_malformed_lines_ignored(self):
        response = "LINHA_SEM_DOIS_PONTOS\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\n"
        assert parse_response(response, "1E4C9B93F3F0682250B6CF8331B7EE68FD8") == 42


# ─────────────────────────────────────────────
# check_pwned (com mock da API)
# ─────────────────────────────────────────────

class TestCheckPwned:
    SUFFIX_OF_PASSWORD = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"

    def _mock_response_with_password(self):
        """Simula resposta da API que contém o hash de 'password'."""
        return f"{self.SUFFIX_OF_PASSWORD}:9545824\nOUTROSUFIXO123456789012345678901234:1\n"

    def _mock_response_without_password(self):
        """Simulates an API response containing the hash of 'password'."""
        return "OUTROSUFIXO123456789012345678901234:1\n"

    def test_found_password(self):
        with patch("pwned.fetch_hash_range", return_value=self._mock_response_with_password()):
            result = check_pwned("password")
        assert result.found is True
        assert result.count == 9545824
        assert "9,545,824" in result.message or "9545824" in result.message

    def test_not_found_password(self):
        with patch("pwned.fetch_hash_range", return_value=self._mock_response_without_password()):
            result = check_pwned("very_unic_password_xyz987")
        assert result.found is False
        assert result.count == 0

    def test_result_contains_correct_hash(self):
        with patch("pwned.fetch_hash_range", return_value=self._mock_response_with_password()):
            result = check_pwned("password")
        assert result.password_hash == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
        assert result.hash_prefix == "5BAA6"
        assert result.hash_suffix == self.SUFFIX_OF_PASSWORD

    def test_connection_error_propagates(self):
        with patch("pwned.fetch_hash_range", side_effect=ConnectionError("No conection")):
            with pytest.raises(ConnectionError):
                check_pwned("any password")

    def test_returns_pwned_result_instance(self):
        with patch("pwned.fetch_hash_range", return_value=self._mock_response_without_password()):
            result = check_pwned("test_password")
        assert isinstance(result, PwnedResult)


# ─────────────────────────────────────────────
# Real integration test (disabled by default)
# Execute: pytest -m integration
# ─────────────────────────────────────────────

@pytest.mark.integration
class TestCheckPwnedIntegration:
    def test_known_pwned_password(self):
        """'password' deve estar em milhões de vazamentos."""
        result = check_pwned("password")
        assert result.found is True
        assert result.count > 1_000_000

    def test_random_safe_password(self):
        """Uma senha gerada aleatoriamente não deve estar em vazamentos."""
        from Generator import GeneratorConfig, generate
        import secrets, string
        # Generates something very unlikely to exist on leaks, e.g. "Zx!9a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"
        random_suffix = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(30))
        safe_password = f"Zx!9{random_suffix}"
        result = check_pwned(safe_password)
        assert result.found is False