"""
pwned.py
Verifies if a password has been exposed in known data breaches
using the API from "Have I Been Pwned" (HIBP) and the k-Anonymity model.

How does k-Anonymity work in this context?
    1. Generates the SHA-1 hash of the password (in uppercase)
    2. Sends only the first 5 characters of the hash (prefix) to the HIBP API
    3. The API returns a list of hash suffixes (the remaining 35 characters) and their breach counts for all hashes that match the prefix
    4. The verification is done locally by comparing the suffix of the password's hash with the returned suffixes to see if it exists and how many times it was found in breaches.
    → The password itself is never sent to the API, ensuring user privacy while still allowing for effective breach checking.

Reference: https://haveibeenpwned.com/API/v3#PwnedPasswords
"""

import hashlib
import urllib.request
import urllib.error
from dataclasses import dataclass


HIBP_API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
REQUEST_TIMEOUT = 10  # seconds


@dataclass
class PwnedResult:
    password_hash: str        # full SHA-1 hash of the password (in uppercase)
    hash_prefix: str          # first 5 characters of the hash (sent to API)
    hash_suffix: str          # rest of the hash (compared locally)
    found: bool               # True if the password was found in breaches, False otherwise
    count: int                # how many times the password was found in breaches (0 if not found)
    message: str              # legible message summarizing the result for the user


def sha1_hash(password: str) -> str:
    """Returns the SHA-1 hash of the password in uppercase hexadecimal format."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def split_hash(full_hash: str) -> tuple[str, str]:
    """Divides the full hash into a prefix (first 5 characters) and suffix (remaining characters)."""
    return full_hash[:5], full_hash[5:]


def fetch_hash_range(prefix: str) -> str:
    """
    Checks the HIBP API for hashes that start with the given prefix.
    Returns the raw response text containing suffixes and counts.
    Launches ConnectionError if there was an issue connecting to the API.
    """
    url = HIBP_API_URL.format(prefix=prefix)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "password-tool-educational/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as response:
            return response.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        raise ConnectionError(f"Error HTTP {e.code} when consulting the HIBP API .") from e
    except urllib.error.URLError as e:
        raise ConnectionError(
            f"HIBP API connection failed. Check your network.\n"
            f"Detail: {e.reason}"
        ) from e


def parse_response(response_text: str, suffix: str) -> int:
    """
    Procura o sufixo do hash na resposta da API.
    Retorna a contagem de vazamentos, ou 0 se não encontrado.

    Formato da resposta (uma linha por hash):
        SUFFIX1:COUNT
        SUFFIX2:COUNT
        ...
    """
    for line in response_text.splitlines():
        parts = line.split(":")
        if len(parts) != 2:
            continue
        api_suffix, count = parts
        if api_suffix.strip().upper() == suffix.upper():
            return int(count.strip())
    return 0


def check_pwned(password: str) -> PwnedResult:
    """
    Verify if the given password has been exposed in known data breaches using the HIBP API.

    Returns a PwnedResult dataclass containing:
    - password_hash: the full SHA-1 hash of the password
    - found: True if the password was found in any breach, False otherwise
    - count: number of times the password was found in breaches (0 if not found)
    - message: a user-friendly message summarizing the result

    Launches ConnectionError if there was an issue connecting to the HIBP API.
    """
    full_hash = sha1_hash(password)
    prefix, suffix = split_hash(full_hash)

    response_text = fetch_hash_range(prefix)
    count = parse_response(response_text, suffix)
    found = count > 0

    if found:
        message = (
            f"This password was found in {count:,} data leaks. "
            f"Consider changing it immediately."
        )
    else:
        message = "This password wasn't found on any known data leak."

    return PwnedResult(
        password_hash=full_hash,
        hash_prefix=prefix,
        hash_suffix=suffix,
        found=found,
        count=count,
        message=message,
    )

def cmd_pwned(args) -> None:
    password = args.password
    result = check_pwned(password)
    print(f"Checking password: {password}")
    print(f"Result: {result.message}")