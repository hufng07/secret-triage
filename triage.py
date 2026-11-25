import math
import string
from collections import Counter

HEX_CHARS = set(string.hexdigits)

# Từ thường xuất hiện trong giá trị giả / mẫu
PLACEHOLDER_WORDS = [
    "example", "sample", "your", "test", "mock", "dummy", "fake",
    "invalid", "placeholder", "changeme", "xxx", "here", "password",
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


def classify(s: str) -> str:
    """Chấm điểm: FP / cần xem / đáng nghi."""
    if looks_like_placeholder(s):
        return "🟢 FP (placeholder)"

    entropy = shannon_entropy(s)
    threshold = 3.0 if is_hex(s) else 4.5   # hex có trần 4.0 nên ngưỡng thấp hơn

    if len(s) >= 20 and entropy >= threshold:
        return "🔴 SUSPICIOUS"
    return "🟡 REVIEW"


if __name__ == "__main__":
    samples = [
        "password123",
        "YOUR-PROJECT-API-KEY",
        "invalid-e2e-world-suite-key",
        "a3f9c2e17b8d4056f1e2c9a7b3d8e4f0",
        "Xk9mQ2vL8pR4tW7nB3jH6sD1fG5zC0yA",
        "hello-world-config-value",
    ]
    for s in samples:
        print(f"{shannon_entropy(s):.2f}  {classify(s):<22} {s}")