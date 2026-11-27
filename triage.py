"""secret-triage: triage suspected secrets found during GitHub recon."""
import argparse
import base64
import datetime
import json
import math
import os
import random
import re
import string
import sys
import time
from collections import Counter

HEX_CHARS = set(string.hexdigits)

# Từ thường xuất hiện trong giá trị giả / mẫu
PLACEHOLDER_WORDS = [
    "example", "sample", "your", "test", "mock", "dummy", "fake",
    "invalid", "placeholder", "changeme", "xxx", "here", "password",
]

# (tên loại key, regex có tiền tố trong nhóm 1, mức độ): secret / review / public
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
JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")

# Đường dẫn "ít rủi ro": test, mẫu, tài liệu, Storybook, code vendored, lockfile, file dự án Xcode
LOW_RISK_PATH_RE = re.compile(
    r"(^|/)(tests?|testing|testdata|__tests__|spec|e2e|fixtures?|mocks?"
    r"|examples?|example-[^/]*|samples?|docs?"
    r"|vendor|node_modules|Pods|contrib|vs)/"
    r"|_test\.|(^|/)test_[^/]*$|\.stories\.|\.md$"
    r"|\.(pbxproj|xcscmblueprint)$"
    r"|(^|/)(Podfile|Gemfile|Cargo|poetry|composer)\.lock$",
    re.IGNORECASE)

# Tên file "nguy hiểm": file tạm, sao lưu, file cũ, file log (crash dump, derby.log...)
HIGH_RISK_PATH_RE = re.compile(
    r"(^|/)(temp|tmp|backup|old)([._-][^/]*)?$|\.bak$|\.log$",
    re.IGNORECASE,
)
# Repo có tên kiểu "mender-testkit", "mender-test-containers" (nhưng không bắt "latest")
TEST_REPO_RE = re.compile(r"(^|[-_.])test", re.IGNORECASE)

# Tên biến được thiết kế để công khai: bị nhúng vào JS gửi xuống trình duyệt
PUBLIC_NAME_RE = re.compile(
    r"\b(REACT_APP|NEXT_PUBLIC|VITE|EXPO_PUBLIC|GATSBY)_\w+"
    r"|\w*(SITE_KEY|CLIENT_KEY|PUBLISHABLE_KEY)\b",
    re.IGNORECASE)
LEVELS = ["🟢", "🟡", "🔴"]
LEVEL_WORDS = {"🟢": "LOW", "🟡": "REVIEW", "🔴": "SUSPICIOUS"}


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


def jwt_payload(token: str):
    """Giải mã payload của JWT. Chỉ ĐỌC: không kiểm tra chữ ký, không gửi đi đâu."""
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except (ValueError, IndexError):
        return None


def classify_jwt(s: str) -> str:
    """JWT tự khai ngày hết hạn (exp): hết hạn rồi thì vô hại."""
    payload = jwt_payload(s)
    if not isinstance(payload, dict):
        return "🟡 REVIEW (JWT-like, cannot decode)"
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        return "🔴 SUSPICIOUS (JWT, no expiry)"
    try:
        when = datetime.datetime.fromtimestamp(exp, datetime.timezone.utc).date()
    except (OverflowError, OSError, ValueError):
        when = "?"
    if exp < time.time():
        return f"🟢 FP (expired JWT, exp {when})"
    return f"🔴 SUSPICIOUS (JWT, valid until {when})"


def classify(s: str) -> str:
    if PRIVATE_KEY_RE.match(s):
        return "🔴 SUSPICIOUS (private key)"
    if JWT_RE.match(s):
        return classify_jwt(s)

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


def shift_level(label: str, step: int, reason: str) -> str:
    """Move a label down (-1) or up (+1) one level, keeping what it was before."""
    emoji, _, rest = label.partition(" ")
    if emoji not in LEVELS:
        return f"{label} [{reason}]"
    i = LEVELS.index(emoji)
    j = min(max(i + step, 0), len(LEVELS) - 1)
    if j == i:
        return f"{label} [{reason}]"
    new = LEVELS[j]
    return f"{new} {LEVEL_WORDS[new]} (was {rest}) [{reason}]"


def adjust_for_path(label: str, path: str, test_repo: bool = False) -> str:
    """Checklist câu 1: hạ hoặc tăng một mức tùy đường dẫn file và tên repo."""
    if LOW_RISK_PATH_RE.search(path) or test_repo:
        reason = "low-risk path" if LOW_RISK_PATH_RE.search(path) else "test repo"
        return shift_level(label, -1, reason)
    if HIGH_RISK_PATH_RE.search(path):
        return shift_level(label, +1, "risky filename")
    return label


def fake(prefix: str, n: int, chars: str = string.ascii_letters + string.digits) -> str:
    """Tạo key GIẢ đúng format để test."""
    return prefix + "".join(random.choices(chars, k=n))


def fake_jwt(exp: int) -> str:
    """Tạo JWT GIẢ (chữ ký ngẫu nhiên) để test logic đọc ngày hết hạn."""
    def enc(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return enc({"alg": "RS256"}) + "." + enc({"sub": "demo", "exp": exp}) + "." + fake("", 43)


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
        fake_jwt(1731706274),   # hết hạn 2024-11-15 (giống vụ Cognito)
        fake_jwt(4102444800),   # còn hạn tới 2100-01-01
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

    # Tên repo lấy từ tên file báo cáo (org_recon.py đặt tên <repo>.json)
    repo = os.path.splitext(os.path.basename(path))[0]
    test_repo = bool(TEST_REPO_RE.search(repo))

    # Vòng 1: ghi lại vị trí (file, commit, dòng) của mọi AWS access key ID
    aws_id_spots = set()
    for f in findings:
        name, _, _ = detect_key_type(f.get("Secret", ""))
        if name == "AWS access key ID":
            aws_id_spots.add((f.get("File", "?"), f.get("Commit", ""), f.get("StartLine", 0)))

    # Vòng 2: chấm điểm, ghép cặp AWS, rồi xét đường dẫn, tên repo, tên biến
    rows = []
    for f in findings:
        secret = f.get("Secret", "")
        file, commit, line = f.get("File", "?"), f.get("Commit", ""), f.get("StartLine", 0)
        label = classify(secret)
        near_id = any((file, commit, line + d) in aws_id_spots for d in (-1, 1))
        if AWS_SECRET_RE.match(secret) and near_id:
            label = "🔴 SUSPICIOUS (AWS secret key, paired)"
        label = adjust_for_path(label, file, test_repo)
        if PUBLIC_NAME_RE.search(f.get("Match", "")):
            label = shift_level(label, -1, "public-by-design name")
        rows.append((label, f"{file}:{line}", commit[:7], secret))

    # Vòng 3: cùng một secret ở nhiều file/commit gộp thành 1 dòng, giữ dòng nặng nhất
    order = {"🔴": 0, "🟡": 1, "🟢": 2}
    total = len(rows)
    best, times = {}, Counter()
    for r in rows:
        times[r[3]] += 1
        old = best.get(r[3])
        if old is None or order.get(r[0][0], 3) < order.get(old[0][0], 3):
            best[r[3]] = r
    rows = sorted(best.values(), key=lambda r: order.get(r[0][0], 3))  # 🔴 lên đầu

    counts = {e: sum(1 for r in rows if r[0][0] == e) for e in "🔴🟡🟢"}
    print(f"{total} findings, {len(rows)} unique:  🔴 {counts['🔴']}  🟡 {counts['🟡']}  🟢 {counts['🟢']}\n")
    for label, where, commit, secret in rows:
        shown = secret if unmask else mask(secret)
        extra = f"  (x{times[secret]})" if times[secret] > 1 else ""
        print(f"{label:<65} {where:<10} {commit:<8} {shown}{extra}")


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
            continue
        s = extract_value(line)
        print(f"{shannon_entropy(s):.2f}  {s:<45} {classify(s)}")


if __name__ == "__main__":
    try:
        main()
        sys.stdout.flush()      # đẩy hết dữ liệu ra ngay trong vùng try
    except BrokenPipeError:
        # head/less đóng ống sớm: không phải lỗi, thoát êm
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(0)