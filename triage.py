import argparse
import json
import math
import os
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
    ("GitHub personal access token", r"^(ghp_)[A-Za-z0-9]{36}$", "secret"),
    ("GitLab personal access token", r"^(glpat-)[A-Za-z0-9_\-]{20,}$", "secret"),
    ("AWS access key ID", r"^(AKIA|ASIA)[A-Z0-9]{16}$", "secret"),
    ("Stripe secret key (live)", r"^(sk_live_)[A-Za-z0-9]{24,}$", "secret"),
    ("Stripe secret key (test)", r"^(sk_test_)[A-Za-z0-9]{24,}$", "review"),
    ("Stripe publishable key", r"^(pk_(?:live|test)_)[A-Za-z0-9]{24,}$", "public"),
    ("Slack token", r"^(xox[abposr]-)[A-Za-z0-9\-]{10,}$", "secret"),
    ("Slack webhook URL", r"^(https://hooks\.slack\.com/services/)[A-Za-z0-9/]+$", "review"),
    ("Anthropic API key", r"^(sk-ant-)[A-Za-z0-9_\-]{20,}$", "secret"),   # phải đứng trước OpenAI
    ("OpenAI API key", r"^(sk-(?:proj-|svcacct-|admin-)?)[A-Za-z0-9_\-]{20,}$", "secret"),
    ("Google API key", r"^(AIza)[0-9A-Za-z_\-]{35}$", "review"),
]

PRIVATE_KEY_RE = re.compile(r"^-----BEGIN ([A-Z]+ )*PRIVATE KEY-----")
AWS_SECRET_RE = re.compile(r"^[A-Za-z0-9/+]{40}$")
# Đường dẫn "ít rủi ro": test, dữ liệu mẫu, tài liệu
LOW_RISK_PATH_RE = re.compile(
    r"(^|/)(tests?|testdata|fixtures?|mocks?|examples?|samples?|docs?)/"
    r"|_test\.|(^|/)test_[^/]*$|\.md$",
    re.IGNORECASE,
)
# Tên file "nguy hiểm": file tạm, file sao lưu, file cũ
HIGH_RISK_PATH_RE = re.compile(r"(^|/)(temp|tmp|backup|old)([._-][^/]*)?$|\.bak$", re.IGNORECASE)


def adjust_for_path(label: str, path: str) -> str:
    """Checklist câu 1: hạ hoặc tăng một mức tùy theo đường dẫn file."""
    if LOW_RISK_PATH_RE.search(path):
        down = {"🔴": "🟡", "🟡": "🟢"}
        return down.get(label[0], label[0]) + label[1:] + " [test/docs path]"
    if HIGH_RISK_PATH_RE.search(path):
        up = {"🟡": "🔴", "🟢": "🟡"}
        return up.get(label[0], label[0]) + label[1:] + " [risky filename]"
    return label

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
    """Trả về (tên, mức độ, phần thân sau tiền tố), hoặc (None, None, s)."""
    for name, pattern, level in KEY_PATTERNS:
        m = re.match(pattern, s)
        if m:
            return name, level, s[m.end(1):]
    return None, None, s


def classify(s: str) -> str:
    if PRIVATE_KEY_RE.match(s):
        return "🔴 SUSPICIOUS (private key)"
    name, level, body = detect_key_type(s)

    # Soi placeholder trên PHẦN THÂN, không tính tiền tố như sk_test_
    if looks_like_placeholder(body):
        return "🟢 FP (placeholder)"
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
        fake("sk_" + "test_", 24),     
        fake("pk_" + "live_", 24),
        fake("AI" + "za", 35),
        fake("gl" + "pat-", 20),
        fake("xo" + "xb-", 40, string.ascii_letters + string.digits + "-"),
        fake("sk-" + "proj-", 40),
        fake("-----BEGIN " + "RSA PRIVATE KEY-----", 64),
    ]

def mask(s: str) -> str:
    """Che secret: chỉ hiện 6 ký tự đầu và độ dài."""
    if len(s) <= 6:
        return "*" * len(s)
    return f"{s[:6]}… ({len(s)} chars)"


def report_gitleaks(path: str, unmask: bool = False) -> None:
    """Đọc báo cáo JSON của gitleaks, chấm điểm và in theo mức độ."""
    with open(path, encoding="utf-8") as fh:
        findings = json.load(fh)

    # Vòng 1: ghi lại vị trí (file, commit, dòng) của mọi AWS access key ID
    aws_id_spots = set()
    for f in findings:
        name, _, _ = detect_key_type(f.get("Secret", ""))
        if name == "AWS access key ID":
            aws_id_spots.add((f.get("File", "?"), f.get("Commit", ""), f.get("StartLine", 0)))

    # Vòng 2: chấm điểm; chuỗi 40 ký tự nằm sát một access key ID là secret key AWS
    rows = []
    for f in findings:
        secret = f.get("Secret", "")
        file, commit, line = f.get("File", "?"), f.get("Commit", ""), f.get("StartLine", 0)
        label = classify(secret)
        near_id = any((file, commit, line + d) in aws_id_spots for d in (-1, 1))
        if AWS_SECRET_RE.match(secret) and near_id:
            label = "🔴 SUSPICIOUS (AWS secret key, paired)"
        label = adjust_for_path(label, file)
        rows.append((label, f"{file}:{line}", commit[:7], secret))

    order = {"🔴": 0, "🟡": 1, "🟢": 2}
    rows.sort(key=lambda r: order.get(r[0][0], 3))   # 🔴 lên đầu

    counts = {e: sum(1 for r in rows if r[0][0] == e) for e in "🔴🟡🟢"}
    print(f"{len(rows)} findings:  🔴 {counts['🔴']}  🟡 {counts['🟡']}  🟢 {counts['🟢']}\n")
    for label, where, commit, secret in rows:
        shown = secret if unmask else mask(secret)
        print(f"{label:<65} {where:<10} {commit:<8} {shown}")

def main():
    parser = argparse.ArgumentParser(
        description="Triage suspected secrets: placeholder filter, key-type detection, entropy."
    )
    parser.add_argument("strings", nargs="*", help="one or more strings to score")
    parser.add_argument("-f", "--file", help="read and score each line of a file (e.g. .env)")
    parser.add_argument("--demo", action="store_true", help="run with built-in fake samples")
    parser.add_argument("--gitleaks", metavar="REPORT", help="score findings from a gitleaks JSON report")
    parser.add_argument("--unmask", action="store_true", help="show full secrets (masked by default)")
    args = parser.parse_args()
    if args.gitleaks:
        report_gitleaks(args.gitleaks, args.unmask)
        return

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
    try:
        main()
    except BrokenPipeError:
        # head/less đóng ống sớm: không phải lỗi, thoát êm
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(0)