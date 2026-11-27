"""org_recon.py: list a GitHub org's repos, clone full history, scan with gitleaks.

Only use on orgs that are in scope of a bug bounty program, or on repos made for
practice. Never use any secret you find.
"""
import argparse
import json
import os
import subprocess


def list_repos(org, limit, include_archived=False):
    cmd = ["gh", "repo", "list", org, "--limit", str(limit),
           "--source", "--json", "name,url"]
    if not include_archived:
        cmd.append("--no-archived")
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
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
    parser.add_argument("--workdir", default="/workspaces/recon", help="where to put clones and reports")
    parser.add_argument("--suffix", default="", help="only repos whose name ends with this, e.g. -sdk")
    parser.add_argument("--include-archived", action="store_true", help="also scan archived repos")
    parser.add_argument("--skip", default="", help="comma-separated repo names to skip")
    args = parser.parse_args()

    repos_dir = os.path.join(args.workdir, args.org, "repos")
    reports_dir = os.path.join(args.workdir, args.org, "reports")
    os.makedirs(repos_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)

    skip = set(args.skip.split(",")) if args.skip else set()
    repos = [r for r in list_repos(args.org, args.limit, args.include_archived)
             if r["name"].endswith(args.suffix) and r["name"] not in skip]
    note = "incl. archived" if args.include_archived else "no archived"
    print(f"{len(repos)} repos in {args.org} (no forks, {note}, suffix '{args.suffix}', skipped {len(skip)})\n")

    summary = []
    for r in repos:
        name = r["name"]
        print(f"== {name}")
        report = os.path.join(reports_dir, f"{name}.json")
        if os.path.exists(report):                 # resume: đã quét rồi thì bỏ qua
            with open(report, encoding="utf-8") as fh:
                count = len(json.load(fh))
            print(f"   already scanned, skipping")
        else:
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