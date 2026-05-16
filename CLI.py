"""
cli.py
Command-line interface for the password_tool.

Use:
    python cli.py analyze "mypassword123"
    python cli.py generate --length 24 --no-symbols
    python cli.py word "password" --limit 50 --show-safe
    python cli.py pwned "password123"
"""

import argparse
import sys

from Analyzer import analyze
from Generator import GeneratorConfig, generate
from Pwned import cmd_pwned
from WordVariants import MAX_VARIANTS, scan_word

# ANSI colors (only works if output is a terminal)
USE_COLOR = sys.stdout.isatty()

RESET  = "\033[0m"  if USE_COLOR else ""
BOLD   = "\033[1m"  if USE_COLOR else ""
RED    = "\033[91m" if USE_COLOR else ""
YELLOW = "\033[93m" if USE_COLOR else ""
GREEN  = "\033[92m" if USE_COLOR else ""
CYAN   = "\033[96m" if USE_COLOR else ""
DIM    = "\033[2m"  if USE_COLOR else ""
ORANGE = "\033[38;5;208m" if USE_COLOR else ""

STRENGTH_COLORS = {
    "very weak":   RED + BOLD,
    "weak":        ORANGE,
    "reasonable":  YELLOW,
    "good":        GREEN,
    "strong":      GREEN,
    "very strong": CYAN + BOLD,
}

RISK_COLORS = {
    "none":     GREEN,
    "low":      YELLOW,
    "moderate": ORANGE,
    "high":     RED,
    "critical": RED,
}

# Visual risk bar: 5 blocks, one filled per level
def risk_bar(level: int) -> str:
    filled = "█" * level
    empty  = "░" * (4 - level)
    return filled + empty


def check_icon(ok: bool) -> str:
    return f"{GREEN}✔{RESET}" if ok else f"{RED}✘{RESET}"


# ---------------------------------------------------------------------------
# Analysis print helpers
# ---------------------------------------------------------------------------

def print_dictionary_results(result) -> None:
    if result.dictionary is None:
        return
    print(f"\n  {BOLD}Dictionary & Pattern Check:{RESET}")
    if not result.dictionary.is_weak:
        print(f"    {GREEN}✔{RESET}  No known words or weak patterns detected.")
        return
    for warning in result.dictionary.warnings:
        print(f"    {ORANGE}⚠{RESET}  {warning}")
    if result.dictionary.normalized.lower() != result.password.lower():
        print(
            f"\n    {DIM}Leet-speak normalized form: "
            f"'{result.password}' → '{result.dictionary.normalized}'{RESET}"
        )


def print_variant_scan(result) -> None:
    scan = result.variant_scan
    if scan is None:
        return

    risk_color = RISK_COLORS.get(result.dictionary_risk_label, "")
    bar = risk_bar(result.dictionary_risk_level)

    print(f"\n  {BOLD}Dictionary Attack Risk:{RESET}  "
          f"{risk_color}{result.dictionary_risk_label.upper()}{RESET}  "
          f"{DIM}[{bar}]{RESET}")
    print(f"    Base word        : '{scan.word}'")
    print(f"    Variants checked : {scan.total_checked}")

    if scan.found_count == 0:
        print(f"    {GREEN}✔  No compromised variants found.{RESET}")
        print(
            f"\n    {DIM}Note: this measures targeted dictionary attack risk, "
            f"independent of brute-force entropy.{RESET}"
        )
        return

    found_color = RISK_COLORS.get(result.dictionary_risk_label, "")
    print(f"    Compromised      : {found_color}{scan.found_count}{RESET} variant(s)")
    print(f"    Total appearances: {found_color}{scan.total_breach_appearances:,}{RESET}")

    top = sorted(scan.found_results, key=lambda r: r.pwned.count, reverse=True)[:5]
    print(f"\n    {BOLD}Most exposed variants:{RESET}")
    for r in top:
        print(f"      {RED}✘{RESET}  {r.variant:<26s}  {r.pwned.count:>10,} breaches")

    print(
        f"\n    {DIM}Note: these are similar passwords in breach databases, not your "
        f"password itself. High risk means rule-based attacks will try these "
        f"patterns — your brute-force entropy ({result.entropy_bits} bits) is unaffected.{RESET}"
    )


def print_analysis(result) -> None:
    color = STRENGTH_COLORS.get(result.strength_label, "")
    print()
    print(f"  {BOLD}Strength:{RESET} {color}{result.strength_label.upper()}{RESET}  "
          f"({result.score}/6 criteria)")
    print(f"  {BOLD}Length:{RESET} {result.length} characters")
    print(f"  {BOLD}Charset:{RESET} {result.charset_size} possible characters")
    print(f"  {BOLD}Entropy:{RESET} {result.entropy_bits} bits")
    print(f"  {BOLD}Time to crack:{RESET} {CYAN}{result.crack_time_human}{RESET}  "
          f"{DIM}(brute-force, 10M guesses/sec){RESET}")

    print(f"\n  {BOLD}Criteria:{RESET}")
    labels = {
        "min_8_chars":   "At least 8 characters",
        "has_uppercase": "Uppercase letters (A-Z)",
        "has_lowercase": "Lowercase letters (a-z)",
        "has_digit":     "Numbers (0-9)",
        "has_symbol":    "Symbols (!@#$%...)",
        "min_16_chars":  "At least 16 characters (recommended)",
    }
    for key, label in labels.items():
        icon = check_icon(result.checks[key])
        print(f"    {icon}  {label}")

    print_dictionary_results(result)
    print_variant_scan(result)

    if result.suggestions:
        print(f"\n  {BOLD}Suggestions:{RESET}")
        for s in result.suggestions:
            print(f"    {DIM}→ {s}{RESET}")
    print()


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def cmd_analyze(args) -> None:
    password = args.password
    if not password:
        print(f"{RED}Error: Please provide a password to analyze.{RESET}")
        sys.exit(1)
    result = analyze(password, skip_variant_scan=getattr(args, "no_scan", False))
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
        result = analyze(password, skip_variant_scan=True)
        print_analysis(result)
    else:
        print()


def cmd_word_scan(args) -> None:
    word = args.word
    limit = args.limit

    print(f"\n  {BOLD}Word scan:{RESET} '{word}'  (up to {limit} variants)\n")

    def progress(current: int, total: int, variant: str) -> None:
        bar_len = 30
        filled = int(bar_len * current / total)
        bar = "█" * filled + "░" * (bar_len - filled)
        display = variant[:24].ljust(24)
        print(f"\r  [{bar}] {current:>3}/{total}  {DIM}{display}{RESET}", end="", flush=True)

    scan = scan_word(word, max_variants=limit, progress_callback=progress)
    print()

    print(f"\n  {BOLD}Results for '{word}':{RESET}")
    print(f"  Variants checked : {scan.total_checked}")

    found_color = RED if scan.found_count > 0 else GREEN
    print(f"  Variants pwned   : {found_color}{scan.found_count}{RESET}")
    print(f"  Total appearances: {found_color}{scan.total_breach_appearances:,}{RESET}")

    if scan.error_results:
        print(f"  {YELLOW}API errors        : {len(scan.error_results)}{RESET}")

    if scan.found_results:
        print(f"\n  {BOLD}{RED}⚠  Compromised variants:{RESET}")
        for r in sorted(scan.found_results, key=lambda x: x.pwned.count, reverse=True):
            bar_count = min(r.pwned.count // 1000, 40)
            bar = "▓" * bar_count
            print(
                f"    {RED}✘{RESET}  {r.variant:<28s}"
                f"  {r.pwned.count:>10,} breaches  {DIM}{bar}{RESET}"
            )
    else:
        print(f"\n  {GREEN}✔  No variants found in known breaches.{RESET}")

    if args.show_safe and scan.not_found_results:
        print(f"\n  {BOLD}Safe variants (not found):{RESET}")
        for r in scan.not_found_results:
            print(f"    {GREEN}✔{RESET}  {r.variant}")

    if scan.error_results:
        print(f"\n  {YELLOW}Variants with API errors:{RESET}")
        for r in scan.error_results:
            print(f"    {YELLOW}?{RESET}  {r.variant}  — {r.error}")

    print()


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="password_tool",
        description="Analyzer and generator of secure passwords",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- analyze ---
    p_analyze = sub.add_parser("analyze", help="Analyze the strength of a password")
    p_analyze.add_argument("password", help="Password to analyze")
    p_analyze.add_argument(
        "--no-scan", action="store_true",
        help="Skip the HIBP variant scan (faster, offline-only analysis)",
    )
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

    # --- pwned ---
    p_pwned = sub.add_parser("pwned", help="Check if a password appeared in data breaches (HIBP)")
    p_pwned.add_argument("password", help="Password to check")
    p_pwned.set_defaults(func=cmd_pwned)

    # --- word ---
    p_word = sub.add_parser(
        "word",
        help="Scan all common variants of a word against HIBP (casing, leet, suffixes...)",
    )
    p_word.add_argument("word", help="Base word to scan (e.g. alface)")
    p_word.add_argument(
        "--limit", "-l", type=int, default=MAX_VARIANTS,
        help=f"Max variants to check (default: {MAX_VARIANTS})",
    )
    p_word.add_argument(
        "--show-safe", action="store_true",
        help="Also list variants that were NOT found in any breach",
    )
    p_word.set_defaults(func=cmd_word_scan)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()