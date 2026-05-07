"""
cli.py
Command-line interface for the password_tool.

Use:
    python cli.py analyze "mypassword123"
    python cli.py generate --length 24 --no-symbols
"""

import argparse
import sys

from Analyzer import analyze
from Generator import GeneratorConfig, generate

# ANSI colors (only works if output is a terminal)
USE_COLOR = sys.stdout.isatty()

RESET  = "\033[0m"  if USE_COLOR else ""
BOLD   = "\033[1m"  if USE_COLOR else ""
RED    = "\033[91m" if USE_COLOR else ""
YELLOW = "\033[93m" if USE_COLOR else ""
GREEN  = "\033[92m" if USE_COLOR else ""
CYAN   = "\033[96m" if USE_COLOR else ""
DIM    = "\033[2m"  if USE_COLOR else ""

STRENGTH_COLORS = {
    "very weak":     RED,
    "weak":          RED,
    "reasonable":    YELLOW,
    "good":          GREEN,
    "strong":        GREEN,
    "very strong":   GREEN,
}


def check_icon(ok: bool) -> str:
    return f"{GREEN}✔️{RESET}" if ok else f"{RED}X{RESET}"


def print_analysis(result) -> None:
    color = STRENGTH_COLORS.get(result.strength_label, "")
    print()
    print(f"  {BOLD}Strength:{RESET}{color}{result.strength_label.upper()}{RESET}  "
          f"({result.score}/6 criteria)")
    print(f"  {BOLD}Length:{RESET}{result.length} characters")
    print(f"  {BOLD}Charset:{RESET}{result.charset_size} possible characters")
    print(f"  {BOLD}Entropy:{RESET}{result.entropy_bits} bits")
    print(f"  {BOLD}Time to crack:{RESET} {CYAN}{result.crack_time_human}{RESET}")

    print(f"\n  {BOLD}Criteria:{RESET}")
    labels = {
        "min_8_chars":   "Use at least 8 characters.",
        "has_uppercase": "Add uppercase letters (A-Z).",
        "has_lowercase": "Add lowercase letters (a-z).",
        "has_digit":     "Add numbers (0-9).",
        "has_symbol":    "Add symbols (!@#$%...).",
        "min_16_chars":  "Prefer 16 or more characters for greater security.",
    }
    for key, label in labels.items():
        icon = check_icon(result.checks[key])
        print(f"    {icon}  {label}")

    if result.suggestions:
        print(f"\n  {BOLD}Suggestions:{RESET}")
        for s in result.suggestions:
            print(f"    {DIM}→ {s}{RESET}")
    print()


def cmd_analyze(args) -> None:
    password = args.password
    if not password:
        print(f"{RED}Error: Please provide a password to analyze.{RESET}")
        sys.exit(1)
    result = analyze(password)
    print_analysis(result)


def cmd_generate(args) -> None:
    try:
        config = GeneratorConfig(
            length=args.length,
            uppercase=not args.no_uppercase,
            lowercase=not args.no_lowercase,
            digits=not args.no_digits,
            symbols=not args.no_symbols,
        )
        password = generate(config)
    except ValueError as e:
        print(f"{RED}Error: {e}{RESET}")
        sys.exit(1)

    print(f"\n  {BOLD}Generated password:{RESET}")
    print(f"  {CYAN}{password}{RESET}")

    if args.analyze:
        result = analyze(password)
        print_analysis(result)
    else:
        print()



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password_tool",
        description="Analyzer and generator of secure passwords",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- analyze ---
    p_analyze = sub.add_parser("analyze", help="Analyze the strength of a password")
    p_analyze.add_argument("password", help="Password to analyze")
    p_analyze.set_defaults(func=cmd_analyze)

    # --- generate ---
    p_gen = sub.add_parser("generate", help="Generate a secure random password")
    p_gen.add_argument("--length", "-l", type=int, default=20,
                       help="Password length (default: 20)")
    p_gen.add_argument("--no-uppercase", action="store_true")
    p_gen.add_argument("--no-lowercase", action="store_true")
    p_gen.add_argument("--no-digits",    action="store_true")
    p_gen.add_argument("--no-symbols",   action="store_true")
    p_gen.add_argument("--analyze", "-a", action="store_true",
                       help="Show analysis of the generated password")
    p_gen.set_defaults(func=cmd_generate)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()