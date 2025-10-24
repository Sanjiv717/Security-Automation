import re
import argparse
from pathlib import Path

# ---------- Core logic ----------

def check_password_strength(password: str):
    """Return (rating, feedback_list) for a given password."""
    score = 0
    feedback = []

    # Length check
    if len(password) < 8:
        feedback.append("Password too short (<8).")
    else:
        score += 1

    # Uppercase, lowercase, numbers, symbols
    if re.search(r"[A-Z]", password): score += 1
    if re.search(r"[a-z]", password): score += 1
    if re.search(r"\d", password): score += 1
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password): score += 1

    # Common words check
    common = {"password", "123456", "qwerty", "admin"}
    if any(word in password.lower() for word in common):
        feedback.append("Contains a common/easy-to-guess word.")

    # Strength rating
    if score <= 2:
        rating = "Weak"
    elif score == 3:
        rating = "Moderate"
    else:
        rating = "Strong"

    # Actionable hints
    if not re.search(r"[A-Z]", password): feedback.append("Add uppercase letters.")
    if not re.search(r"[a-z]", password): feedback.append("Add lowercase letters.")
    if not re.search(r"\d", password): feedback.append("Add numbers.")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password): feedback.append("Add symbols.")
    if len(password) < 12: feedback.append("Increase length to 12+ characters.")

    return rating, feedback


def estimate_crack_time_seconds(password: str, guesses_per_second: float = 1e9):
    """Very rough brute-force time estimate in seconds, assuming offline attack."""
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"\d", password): charset += 10
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password): charset += 33  # ~common symbol set

    if charset == 0:
        return 0.0

    total_combinations = charset ** len(password)
    return total_combinations / guesses_per_second


def human_time(seconds: float) -> str:
    """Convert seconds to a friendly string."""
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
    rating, feedback = check_password_strength(password)
    secs = estimate_crack_time_seconds(password, guesses_per_second=gps)
    tips = " | ".join(feedback) if feedback else "No obvious issues."
    return f"{password!r}: {rating} | crack-time≈ {human_time(secs)} | {tips}"


def analyze_password_file(path: Path, gps: float = 1e9):
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
    p = argparse.ArgumentParser(
        description="Password Strength Analyzer (single password or file)."
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-p", "--password", help="Password string to analyze.")
    g.add_argument("-f", "--file", type=Path, help="Path to a file with one password per line.")
    p.add_argument("--gps", type=float, default=1e9,
                   help="Guesses per second assumption (default: 1e9).")
    return p.parse_args()


def main():
    args = parse_args()
    if args.password:
        print(analyze_password(args.password, gps=args.gps))
    else:
        if not args.file.exists():
            raise SystemExit(f"File not found: {args.file}")
        for line in analyze_password_file(args.file, gps=args.gps):
            print(line)


if __name__ == "__main__":
    main()
