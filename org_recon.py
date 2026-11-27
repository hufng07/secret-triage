"""org_recon.py: list a GitHub org's repos, clone full history, scan with gitleaks.

Only use on orgs that are in scope of a bug bounty program, or on repos made for
practice. Never use any secret you find.
"""
import argparse
import json
import os
import shutil
import subprocess


def list_repos(org, limit, include_archived=False):
    cmd = ["gh", "repo", "list", org, "--limit", str(limit),
           "--source", "--json", "name,url"]
    if not include_archived:
        cmd.append("--no-archived")
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def clone(url, dest):
    """Clone FULL history into dest.partial, then rename, so dest always means 'complete'."""
    if os.path.isdir(dest):
        print("   already cloned, skipping")
        return
    tmp = dest + ".partial"
    if os.path.isdir(tmp):
        print("   found an interrupted clone, starting over")
        shutil.rmtree(tmp)
    subprocess.run(["git", "clone", "--quiet", url, tmp], check=True)
    os.rename(tmp, dest)


def run_gitleaks(repo_dir: str, reports_dir: str, config_name: str, out_name: str):
    """One gitleaks pass with the given config. Returns the findings list, or None on failure."""
    config = os.path.join(os.path.dirname(os.path.abspath(__file__)), config_name)
    subprocess.run(
        ["docker", "run", "--rm",
         "-v", f"{os.path.abspath(repo_dir)}:/repo",
         "-v", f"{os.path.abspath(reports_dir)}:/reports",
         "-v", f"{config}:/config.toml:ro",
         "zricethezav/gitleaks:latest",
         "git", "/repo", "--no-banner",
         "--config", "/config.toml",
         "--report-format", "json",
         "--report-path", f"/reports/{out_name}"],
        capture_output=True,
    )
    path = os.path.join(reports_dir, out_name)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        findings = json.load(fh)
    os.remove(path)
    return findings


def scan(repo_dir: str, reports_dir: str, name: str) -> int:
    """Pass 1: default rules + noise filters. Pass 2: URL creds, lockfiles included."""
    main = run_gitleaks(repo_dir, reports_dir, "gitleaks-recon.toml", f"{name}.pass1.tmp")
    urls = run_gitleaks(repo_dir, reports_dir, "gitleaks-urls.toml", f"{name}.pass2.tmp")
    if main is None or urls is None:
        print("   warning: gitleaks wrote no report (check docker / config)")
        return 0
    findings = main + urls
    with open(os.path.join(reports_dir, f"{name}.json"), "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=1)
    return len(findings)


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