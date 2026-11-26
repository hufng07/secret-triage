"""org_recon.py: list a GitHub org's repos, clone full history, scan with gitleaks.

Only use on orgs that are in scope of a bug bounty program, or on repos made for
practice. Never use any secret you find.
"""
import argparse
import json
import os
import subprocess


def list_repos(org: str, limit: int) -> list:
    """Dùng gh để lấy danh sách repo (bỏ fork, bỏ archived), trả về JSON."""
    out = subprocess.run(
        ["gh", "repo", "list", org, "--limit", str(limit),
         "--source", "--no-archived", "--json", "name,url"],
        capture_output=True, text=True, check=True,
    ).stdout
    return json.loads(out)


def clone(url: str, dest: str) -> None:
    """Clone ĐẦY ĐỦ lịch sử (không dùng --depth). Đã có rồi thì bỏ qua."""
    if os.path.isdir(dest):
        print("   already cloned, skipping")
        return
    subprocess.run(["git", "clone", "--quiet", url, dest], check=True)


def scan(repo_dir: str, reports_dir: str, name: str) -> int:
    """Chạy gitleaks trên toàn bộ lịch sử, trả về số phát hiện."""
    subprocess.run(
        ["docker", "run", "--rm",
         "-v", f"{repo_dir}:/repo",
         "-v", f"{reports_dir}:/reports",
         "zricethezav/gitleaks:latest", "git", "/repo", "--no-banner",
         "--report-format", "json", "--report-path", f"/reports/{name}.json"],
        capture_output=True,   # giấu output dài của gitleaks
    )                          # không check=True: tìm thấy leak thì gitleaks trả mã 1
    report = os.path.join(reports_dir, f"{name}.json")
    if not os.path.exists(report):
        print("   ⚠️  no report produced (scan failed?)")
        return 0
    with open(report, encoding="utf-8") as fh:
        return len(json.load(fh))


def main():
    parser = argparse.ArgumentParser(description="Clone an org's repos and scan them with gitleaks.")
    parser.add_argument("org", help="GitHub organization (must be in scope!)")
    parser.add_argument("--limit", type=int, default=5, help="max number of repos (default 5)")
    parser.add_argument("--workdir", default="/tmp/recon", help="where to put clones and reports")
    args = parser.parse_args()

    repos_dir = os.path.join(args.workdir, args.org, "repos")
    reports_dir = os.path.join(args.workdir, args.org, "reports")
    os.makedirs(repos_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)

    repos = list_repos(args.org, args.limit)
    print(f"{len(repos)} repos in {args.org} (no forks, no archived)\n")

    summary = []
    for r in repos:
        name = r["name"]
        print(f"== {name}")
        repo_dir = os.path.join(repos_dir, name)
        clone(r["url"], repo_dir)
        count = scan(repo_dir, reports_dir, name)
        print(f"   {count} findings")
        summary.append((count, name))

    print("\n== SUMMARY (most findings first)")
    for count, name in sorted(summary, reverse=True):
        print(f"{count:>5}  {name}")
    print(f"\nTriage a repo with:  python3 triage.py --gitleaks {reports_dir}/<name>.json")


if __name__ == "__main__":
    main()