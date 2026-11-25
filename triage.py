import math
import random
import re
import string
from collections import Counter

HEX_CHARS = set(string.hexdigits)

# Từ thường xuất hiện trong giá trị giả / mẫu
PLACEHOLDER_WORDS = [
    "example", "sample", "your", "test", "mock", "dummy", "fake",
    "invalid", "placeholder", "changeme", "xxx", "here", "password",
]

# (tên loại key, regex, mức độ)
#   secret = bí mật thật, lộ là nguy hiểm
#   review = tùy ngữ cảnh, cần người xem
#   public = thiết kế để công khai
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
    """Chuỗi chỉ gồm 0-9, a-f?"""
    return all(c in HEX_CHARS for c in s)


def looks_like_placeholder(s: str) -> bool:
    """Có chứa từ kiểu 'your', 'example', 'invalid'... không?"""
    low = s.lower()
    return any(word in low for word in PLACEHOLDER_WORDS)


def detect_key_type(s: str):
    """Trả về (tên loại key, mức độ), hoặc (None, None) nếu không nhận ra."""
    for name, pattern, level in KEY_PATTERNS:
        if re.match(pattern, s):
            return name, level
    return None, None


def classify(s: str) -> str:
    """Chấm điểm: FP / cần xem / đáng nghi."""
    if looks_like_placeholder(s):
        return "🟢 FP (placeholder)"

    name, level = detect_key_type(s)
    if level == "public":
        return f"🟢 FP (public by design: {name})"
    if level == "review":
        return f"🟡 REVIEW ({name})"
    if level == "secret":
        return f"🔴 SUSPICIOUS ({name})"

    # Không nhận ra loại key -> dùng entropy như v0.2
    entropy = shannon_entropy(s)
    threshold = 3.0 if is_hex(s) else 4.5
    if len(s) >= 20 and entropy >= threshold:
        return "🔴 SUSPICIOUS (high entropy)"
    return "🟡 REVIEW"


def fake(prefix: str, n: int, chars: str = string.ascii_letters + string.digits) -> str:
    """Tạo key GIẢ đúng format để test."""
    return prefix + "".join(random.choices(chars, k=n))


if __name__ == "__main__":
    random.seed(7)  # cố định seed để mỗi lần chạy ra cùng kết quả
    samples = [
        "password123",
        "invalid-e2e-world-suite-key",
        "a3f9c2e17b8d4056f1e2c9a7b3d8e4f0",
        "hello-world-config-value",
        # Tiền tố được tách đôi có chủ đích, đọc giải thích bên dưới
        fake("gh" + "p_", 36),
        fake("AK" + "IA", 16, string.ascii_uppercase + string.digits),
        fake("sk_" + "live_", 24),
        fake("pk_" + "live_", 24),
        fake("AI" + "za", 35),
    ]
    for s in samples:
        print(f"{shannon_entropy(s):.2f}  {s:<45} {classify(s)}")