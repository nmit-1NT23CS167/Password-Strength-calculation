"""
password_strength.py

A small, dependency-free password strength checker.

It scores a password using two complementary signals:

1. Composition checks   — length, character-class variety, common patterns
                           (repeats, sequences, keyboard walks, dictionary words).
2. Entropy estimate      — bits of entropy based on the effective character
                           set size and length, used as a rough crack-time
                           estimate.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field


# A small built-in list of very common passwords / words worth flagging.
# In a real project you'd load a much larger list from a file or database, but this is enough to illustrate the idea.
COMMON_PASSWORDS = {
    "password","password123","abcdefg", "123456", "123456789", "qwerty", "abc123", "password1",
    "111111", "12345678", "letmein", "password@123", "admin", "welcome",
    "monkey", "dragon", "football", "starwars", "sunshine", "master","asdf", "qazwsx", "iloveyou", "princess", "passw0rd",
    "shadow", "superman", "trustno1","1234", "12345", "1234567", "1q2w3e4r", "1qaz2wsx", "zaq12wsx", "qwertyuiop", "asdfghjkl", "zxcvbnm","zxcvbnm"
}

KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]


@dataclass
class StrengthResult:
    score: int                     # 0-4 (very weak .. very strong)
    label: str                     # human-readable label for `score`
    entropy_bits: float            # estimated entropy in bits
    crack_time_display: str        # human-readable offline crack-time estimate
    reasons: list[str] = field(default_factory=list)   # weaknesses found
    suggestions: list[str] = field(default_factory=list)  # how to improve


def _character_pool_size(password: str) -> int:
    """Estimate the effective character-set size used by the password."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32  # rough count of common symbols
    return pool or 1


def _estimate_entropy_bits(password: str) -> float:
    """log2(pool_size ** length) = length * log2(pool_size)."""
    pool = _character_pool_size(password)
    return len(password) * math.log2(pool)


def _has_sequential_run(password: str, run_length: int = 4) -> bool:
    """Detect ascending/descending runs like 'abcd' or '4321'."""
    lowered = password.lower()
    for i in range(len(lowered) - run_length + 1):
        window = lowered[i:i + run_length]
        codes = [ord(c) for c in window]
        ascending = all(b - a == 1 for a, b in zip(codes, codes[1:]))
        descending = all(a - b == 1 for a, b in zip(codes, codes[1:]))
        if ascending or descending:
            return True
    return False


def _has_keyboard_walk(password: str, run_length: int = 4) -> bool:
    """Detect keyboard-adjacent runs like 'qwerty' or 'asdf'."""
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - run_length + 1):
            chunk = row[i:i + run_length]
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def _has_repeated_chars(password: str, repeat_threshold: int = 3) -> bool:
    """Detect a character repeated `repeat_threshold`+ times in a row."""
    return re.search(r"(.)\1{" + str(repeat_threshold - 1) + r",}", password) is not None


def _crack_time_display(entropy_bits: float, guesses_per_second: float = 1e10) -> str:
    """
    Rough offline crack-time estimate assuming a fast offline attack
    (guesses_per_second defaults to 10 billion/sec, a plausible GPU-cluster
    rate against a weakly-hashed password). This is illustrative, not exact.
    """
    seconds = (2 ** entropy_bits) / guesses_per_second / 2  # /2 for average case
    if seconds < 1:
        return "instantly"

    units = [
        ("century", "centuries", 60 * 60 * 24 * 365 * 100),
        ("year", "years", 60 * 60 * 24 * 365),
        ("day", "days", 60 * 60 * 24),
        ("hour", "hours", 60 * 60),
        ("minute", "minutes", 60),
        ("second", "seconds", 1),
    ]
    for singular, plural, unit_seconds in units:
        if seconds >= unit_seconds:
            value = seconds / unit_seconds
            word = singular if value == 1 else plural
            if value > 1000:
                return f"over 1000 {plural}"
            return f"about {value:.1f} {word}"
    return "instantly"


def check_password_strength(password: str) -> StrengthResult:
    """
    Analyze a password and return a StrengthResult with a 0-4 score,
    an entropy estimate, a crack-time estimate, and concrete feedback.
    """
    reasons: list[str] = []
    suggestions: list[str] = []

    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    class_count = sum([has_lower, has_upper, has_digit, has_symbol])

    # --- Length checks ---
    if length == 0:
        return StrengthResult(
            score=0,
            label="Very weak",
            entropy_bits=0.0,
            crack_time_display="instantly",
            reasons=["Password is empty."],
            suggestions=["Enter a password."],
        )
    if length < 8:
        reasons.append("Shorter than 8 characters.")
        suggestions.append("Use at least 12 characters — length matters more than complexity.")
    elif length < 12:
        suggestions.append("Consider using 12+ characters for stronger protection.")

    # --- Character variety ---
    if class_count <= 1:
        reasons.append("Uses only one character type (e.g. all lowercase letters).")
        suggestions.append("Mix uppercase, lowercase, digits, and symbols.")
    elif class_count == 2:
        suggestions.append("Add another character type (digits or symbols) for more variety.")

    # --- Common password / dictionary check ---
    if password.lower() in COMMON_PASSWORDS:
        reasons.append("This is one of the most commonly used passwords.")
        suggestions.append("Avoid common words and known leaked passwords entirely.")

    # --- Pattern checks ---
    if _has_sequential_run(password):
        reasons.append("Contains a sequential run (e.g. 'abcd' or '1234').")
        suggestions.append("Avoid sequential characters.")
    if _has_keyboard_walk(password):
        reasons.append("Contains a keyboard-adjacent pattern (e.g. 'qwerty', 'asdf').")
        suggestions.append("Avoid keyboard-walk patterns.")
    if _has_repeated_chars(password):
        reasons.append("Contains a character repeated 3+ times in a row (e.g. 'aaa').")
        suggestions.append("Avoid repeating the same character multiple times in a row.")

    # --- Entropy & crack-time estimate ---
    entropy_bits = _estimate_entropy_bits(password)
    crack_time = _crack_time_display(entropy_bits)

    # --- Scoring ---
    # Start from entropy-driven baseline, then penalize for red flags found above.
    if entropy_bits < 28:
        score = 0
    elif entropy_bits < 36:
        score = 1
    elif entropy_bits < 60:
        score = 2
    elif entropy_bits < 80:
        score = 3
    else:
        score = 4

    penalty = 0
    if password.lower() in COMMON_PASSWORDS:
        penalty += 4  # common passwords are crackable in milliseconds regardless of entropy math
    if _has_sequential_run(password):
        penalty += 1
    if _has_keyboard_walk(password):
        penalty += 1
    if _has_repeated_chars(password):
        penalty += 1

    score = max(0, score - penalty)
    score = min(score, 4)

    labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
    label = labels[score]

    if not suggestions and score == 4:
        suggestions.append("Good password. Consider a password manager so you never reuse it.")

    return StrengthResult(
        score=score,
        label=label,
        entropy_bits=round(entropy_bits, 1),
        crack_time_display=crack_time,
        reasons=reasons,
        suggestions=suggestions,
    )


def print_report(password: str) -> None:
    """Pretty-print a strength report for a single password to stdout."""
    result = check_password_strength(password)
    bar = "#" * (result.score * 5) + "-" * ((4 - result.score) * 5)

    print(f"Password:        {'*' * len(password)}")
    print(f"Strength:        [{bar}] {result.label} ({result.score}/4)")
    print(f"Estimated entropy: {result.entropy_bits} bits")
    print(f"Estimated offline crack time: {result.crack_time_display}")

    if result.reasons:
        print("\nWeaknesses found:")
        for r in result.reasons:
            print(f"  - {r}")

    if result.suggestions:
        print("\nSuggestions:")
        for s in result.suggestions:
            print(f"  - {s}")


if __name__ == "__main__":
    import getpass
    import sys

    if len(sys.argv) > 1:
        pw = sys.argv[1]
    else:
        pw = getpass.getpass("Enter a password to check (input hidden): ")

    print()
    print_report(pw)