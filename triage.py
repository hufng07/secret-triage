import argparse
import math
import random
import re
import string
import sys
from collections import Counter

HEX_CHARS = set(string.hexdigits)

# Từ thường xuất hiện trong giá trị giả / mẫu
PLACEHOLDER_WORDS = [
    "example", "sample", "your", "test", "mock", "dummy", "fake",
    "invalid", "placeholder", "changeme", "xxx", "here", "password",
]

# (tên loại key, regex, mức độ): secret / review / public
KEY_PATTERNS = [
    ("GitHub personal access token", r"^ghp_[A-Za-z0-9]{36}$", "secret"),
    ("AWS access key ID", r"^(AKIA|ASIA)[A-Z0-9]{16}$", "secret"),
    ("Stripe secret key (live)", r"^sk_live_[A-Za-z0-9]{24,}$", "secret"),
    ("Stripe secret key (test)", r"^sk_test_[A-Za-z0-9]{24,}$", "review"),
    ("Stripe publishable key", r"^pk_(live|test)_[A-Za-z0-9]{24,}$", "public"),
    ("Google API key", r"^AIza[0-9A-Za-z_\-]{35}$", "review"),
]


def shannon_entropy(s: str) -> float:
    """Đo độ 'lộn xộn' của chuỗi. Càng cao càng giống chuỗi ngẫu nhiên."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_hex(s: str) -> bool:
    return all(c in HEX_CHARS for c in s)


def looks_like_placeholder(s: str) -> bool:
    low = s.lower()
    return any(word in low for word in PLACEHOLDER_WORDS)


def detect_key_type(s: str):
    for name, pattern, level in KEY_PATTERNS:
        if re.match(pattern, s):
            return name, level
    return None, None


def classify(s: str) -> str:
    if looks_like_placeholder(s):
        return "🟢 FP (placeholder)"

    name, level = detect_key_type(s)
    if level == "public":
        return f"🟢 FP (public by design: {name})"
    if level == "review":
        return f"🟡 REVIEW ({name})"
    if level == "secret":
        return f"🔴 SUSPICIOUS ({name})"

    entropy = shannon_entropy(s)
    threshold = 3.0 if is_hex(s) else 4.5
    if len(s) >= 20 and entropy >= threshold:
        return "🔴 SUSPICIOUS (high entropy)"
    return "🟡 REVIEW"


def fake(prefix: str, n: int, chars: str = string.ascii_letters + string.digits) -> str:
    """Tạo key GIẢ đúng format để test."""
    return prefix + "".join(random.choices(chars, k=n))


def extract_value(line: str) -> str:
    """Lấy phần giá trị: 'TOKEN="abc"' -> 'abc'. Không có '=' thì giữ nguyên."""
    line = line.strip()
    if "=" in line:
        line = line.split("=", 1)[1]
    return line.strip().strip("\"'")


def demo_samples() -> list:
    random.seed(7)
    return [
        "password123",
        "invalid-e2e-world-suite-key",
        "a3f9c2e17b8d4056f1e2c9a7b3d8e4f0",
        "hello-world-config-value",
        fake("gh" + "p_", 36),
        fake("AK" + "IA", 16, string.ascii_uppercase + string.digits),
        fake("sk_" + "live_", 24),
        fake("pk_" + "live_", 24),
        fake("AI" + "za", 35),
    ]


def main():
    parser = argparse.ArgumentParser(
        description="Triage suspected secrets: placeholder filter, key-type detection, entropy."
    )
    parser.add_argument("strings", nargs="*", help="one or more strings to score")
    parser.add_argument("-f", "--file", help="read and score each line of a file (e.g. .env)")
    parser.add_argument("--demo", action="store_true", help="run with built-in fake samples")
    args = parser.parse_args()

    if args.demo:
        lines = demo_samples()
    elif args.file:
        with open(args.file, encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    elif args.strings:
        lines = args.strings
    elif not sys.stdin.isatty():      # có dữ liệu được "bơm" qua pipe
        lines = sys.stdin.readlines()
    else:
        parser.print_help()
        return

    for line in lines:
        if not line.strip() or line.strip().startswith("#"):
            continue                  # bỏ dòng trống và dòng comment
        s = extract_value(line)
        print(f"{shannon_entropy(s):.2f}  {s:<45} {classify(s)}")


if __name__ == "__main__":
    main()