#!/usr/bin/env python3
"""
Password Strength Analyzer

This script analyzes the strength of a password (or a list of passwords from a file)
and prints:
- A strength rating: Weak / Moderate / Strong
- A human-friendly crack-time estimate (very rough; assumes offline brute-force)
- Actionable feedback to improve the password

USAGE EXAMPLES
--------------
# Analyze a single password (quote or escape special chars like $):
python password_analyzer.py -p 'MyStr0ngP@ss!'

# Analyze passwords from a file (one password per line):
python password_analyzer.py -f passwords.txt

# Assume a faster attacker (e.g., 1e12 guesses/second):
python password_analyzer.py -p 'MyStr0ngP@ss!' --gps 1e12
"""

import re
import argparse
from pathlib import Path


# ---------- Core logic ----------

def check_password_strength(password: str):
    """
    Evaluate a password and return a (rating, feedback_list) tuple.

    Parameters
    ----------
    password : str
        The password string to evaluate.

    Returns
    -------
    tuple[str, list[str]]
        rating : 'Weak' | 'Moderate' | 'Strong'
        feedback_list : list of actionable suggestions (may be empty)

    Evaluation criteria (simple heuristic):
    - Length >= 8 contributes to score.
    - Presence of uppercase, lowercase, digits, symbols each contribute to score.
    - Warns if the password contains very common/easy patterns (e.g., 'password').
    - Adds targeted improvement tips (e.g., "Add numbers.", "Increase length...").

    Notes
    -----
    This is a heuristic—NOT a guarantee of security. Do not reuse passwords.
    Use a reputable password manager and enable multi-factor authentication.
    """
    score = 0
    feedback = []

    # Length check (minimum baseline)
    if len(password) < 8:
        feedback.append("Password too short (<8).")
    else:
        score += 1

    # Character class checks (breadth increases search space)
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"[a-z]", password): score += 1
    if re.search(r"\d", password): score += 1
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password): score += 1

    # Common patterns (flag even if other criteria look good)
    common = {"password", "123456", "qwerty", "admin"}
    if any(word in password.lower() for word in common):
        feedback.append("Contains a common/easy-to-guess word.")

    # Map score to rating (coarse)
    if score <= 2:
        rating = "Weak"
    elif score == 3:
        rating = "Moderate"
    else:
        rating = "Strong"

    # Targeted suggestions for improvement
    if not re.search(r"[A-Z]", password): feedback.append("Add uppercase letters.")
    if not re.search(r"[a-z]", password): feedback.append("Add lowercase letters.")
    if not re.search(r"\d", password): feedback.append("Add numbers.")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password): feedback.append("Add symbols.")
    if len(password) < 12: feedback.append("Increase length to 12+ characters.")

    return rating, feedback


def estimate_crack_time_seconds(password: str, guesses_per_second: float = 1e9):
    """
    Estimate brute-force time in seconds for a single password.

    Parameters
    ----------
    password : str
        Password to estimate against.
    guesses_per_second : float, optional
        Assumed attacker speed (default: 1e9 guesses/sec). Adjust with --gps.

    Returns
    -------
    float
        Estimated seconds to brute-force (very rough upper bound).

    Method
    ------
    - Approximate character set size from the classes present in the password.
    - Compute charset_size ** len(password) / guesses_per_second.

    Caution
    -------
    This is an oversimplification:
    - Real attacks don’t brute-force uniformly; they prioritize likely patterns.
    - Online attacks have rate limits; offline attacks can be much faster.
    - Use this only for relative comparison, not absolute security guarantees.
    """
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"\d", password): charset += 10
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password): charset += 33  # approx. common symbols

    if charset == 0:
        return 0.0

    total_combinations = charset ** len(password)
    return total_combinations / guesses_per_second


def human_time(seconds: float) -> str:
    """
    Convert a number of seconds into a short, friendly string.

    Parameters
    ----------
    seconds : float
        Duration in seconds.

    Returns
    -------
    str
        Human-readable duration (e.g., '3 hours, 12 minutes').

    Notes
    -----
    - Caps output to two units to keep it concise.
    - Returns 'less than 1 second' if under 1.0.
    """
    if seconds < 1:
        return "less than 1 second"
    units = [
        ("year", 60*60*24*365),
        ("day", 60*60*24),
        ("hour", 60*60),
        ("minute", 60),
        ("second", 1),
    ]
    parts = []
    for name, size in units:
        if seconds >= size:
            qty = int(seconds // size)
            seconds -= qty * size
            parts.append(f"{qty} {name}{'' if qty==1 else 's'}")
        if len(parts) == 2:  # keep it short
            break
    return ", ".join(parts)


def analyze_password(password: str, gps: float = 1e9) -> str:
    """
    Produce a single-line summary for one password.

    Parameters
    ----------
    password : str
        Password to analyze.
    gps : float, optional
        Guesses per second assumption (default: 1e9).

    Returns
    -------
    str
        Formatted result string with rating, crack-time, and feedback.

    Example
    -------
    >>> analyze_password('MyStr0ngP@ss!')
    "'MyStr0ngP@ss!': Strong | crack-time≈ 84 years, 3 months | No obvious issues."
    """
    rating, feedback = check_password_strength(password)
    secs = estimate_crack_time_seconds(password, guesses_per_second=gps)
    tips = " | ".join(feedback) if feedback else "No obvious issues."
    return f"{password!r}: {rating} | crack-time≈ {human_time(secs)} | {tips}"


def analyze_password_file(path: Path, gps: float = 1e9):
    """
    Analyze multiple passwords from a UTF-8 text file (one per line).

    Parameters
    ----------
    path : pathlib.Path
        Path to the text file containing passwords (one per line).
    gps : float, optional
        Guesses per second assumption (default: 1e9).

    Returns
    -------
    list[str]
        A list of formatted result lines (same format as analyze_password).

    Raises
    ------
    FileNotFoundError
        If the provided path does not exist.

    Notes
    -----
    Blank lines are ignored. Lines are stripped of surrounding whitespace.
    """
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    results = []
    for raw in lines:
        pwd = raw.strip()
        if not pwd:
            continue
        results.append(analyze_password(pwd, gps=gps))
    return results


# ---------- CLI entry point ----------

def parse_args():
    """
    Define and parse command-line arguments.

    Returns
    -------
    argparse.Namespace
        Parsed arguments with attributes:
        - password (str|None): a single password to analyze
        - file (Path|None): path to a file of passwords (one per line)
        - gps (float): guesses per second assumption
    """
    p = argparse.ArgumentParser(
        description="Password Strength Analyzer (single password or file)."
    )
    # Require exactly one of -p/--password or -f/--file
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-p", "--password", help="Password string to analyze. "
                   "Tip: use single quotes to avoid shell interpretation of $ and !.")
    g.add_argument("-f", "--file", type=Path,
                   help="Path to a UTF-8 text file with one password per line.")
    p.add_argument("--gps", type=float, default=1e9,
                   help="Guesses per second assumption (default: 1e9).")
    return p.parse_args()


def main():
    """
    Program entry point.
    - Parses CLI arguments.
    - Runs single-password analysis OR file-based analysis.
    - Prints results to stdout.
    """
    args = parse_args()

    if args.password:
        # Single password mode
        print(analyze_password(args.password, gps=args.gps))
    else:
        # File mode
        if not args.file.exists():
            raise SystemExit(f"File not found: {args.file}")
        for line in analyze_password_file(args.file, gps=args.gps):
            print(line)


if __name__ == "__main__":
    main()
