import secrets
import string
from dataclasses import dataclass


CHARSETS = {
    "uppercase": string.ascii_uppercase,       # A-Z
    "lowercase": string.ascii_lowercase,       # a-z
    "digits":    string.digits,                # 0-9
    "symbols":   "!@#$%^&*()_+-=[]{}|;:,.<>?",
}


@dataclass
class GeneratorConfig:
    length: int = 20
    uppercase: bool = True
    lowercase: bool = True
    digits: bool = True
    symbols: bool = True

    def __post_init__(self):
        if self.length < 4:
            raise ValueError("Minimum length is 4 characters.")
        if self.length > 256:
            raise ValueError("Maximum length is 256 characters.")
        if not any([self.uppercase, self.lowercase, self.digits, self.symbols]):
            raise ValueError("Select at least one character type.")

def generate(config: GeneratorConfig | None = None) -> str:
    """
    Generates a random password based on the provided configuration.

    Grants the presence of at least one character from each selected type and fills the rest randomly.
    """
    if config is None:
        config = GeneratorConfig()

    # Create a pool of characters based on the selected options and ensure at least one of each type is included
    pool = ""
    mandatory: list[str] = []

    for key, chars in CHARSETS.items():
        if getattr(config, key):
            pool += chars
            mandatory.append(secrets.choice(chars))  # grant at least one character from this set

    # Fill the rest of the password length with random choices from the pool
    remaining_len = config.length - len(mandatory)
    rest = [secrets.choice(pool) for _ in range(remaining_len)]

    # Shuffle to not reveal the position of the mandatory characters
    combined = mandatory + rest
    secrets.SystemRandom().shuffle(combined)

    return "".join(combined)