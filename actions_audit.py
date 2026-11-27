"""actions_audit.py: find risky patterns in GitHub Actions workflows (static, read-only).

Checks:
  1. Script injection: untrusted ${{ github.event... }} pasted into run: / script:
  2. Pwn request: pull_request_target / workflow_run that fetches PR code

Only reads YAML files. Never open PRs or issues against a target to "test" a finding.
"""
import argparse
import glob
import os
import re

# Contexts an outsider controls (GitHub Security Lab list)
UNTRUSTED_RE = re.compile(
    r"\$\{\{\s*(github\.head_ref|github\.event\.[\w.\-\[\]*]*?"
    r"(body|title|head_ref|label|message|name|email|default_branch|page_name|ref))\s*\}\}")
RUN_KEY_RE = re.compile(r"^(\s*)(-\s+)?(run|script):")
TRIGGER_RE = re.compile(
    r"\b(pull_request_target|workflow_run|issue_comment|issues|pull_request_review_comment"
    r"|pull_request_review|discussion_comment|discussion|pull_request)\b")
OUTSIDER_EVENTS = {"pull_request_target", "workflow_run", "issue_comment", "issues",
                   "pull_request_review_comment", "pull_request_review",
                   "discussion_comment", "discussion"}
PR_CODE_RE = re.compile(
    r"github\.event\.pull_request\.head\.(sha|ref)|github\.event\.workflow_run\.head_(sha|branch)"
    r"|gh pr checkout|git fetch\b.*pull/|refs/pull/|allow-unsafe-pr-checkout")
BYPASS_RE = re.compile(r"gh pr checkout|git fetch\b|refs/pull/|allow-unsafe-pr-checkout")


def triggers_of(lines):
    """Events in the on: section (everything before the top-level jobs: key)."""
    events = set()
    for line in lines:
        if line.startswith("jobs:"):
            break
        events.update(m.group(1) for m in TRIGGER_RE.finditer(line))
    return events


def audit_file(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()
    events = triggers_of(lines)
    outsider = bool(events & OUTSIDER_EVENTS)
    privileged = bool(events & {"pull_request_target", "workflow_run"})
    findings = []
    run_indent = None  # column of the current run:/script: key, None when outside one
    for no, line in enumerate(lines, 1):
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if run_indent is not None and stripped and indent <= run_indent:
            run_indent = None
        m = RUN_KEY_RE.match(line)
        if m:
            run_indent = len(m.group(1)) + len(m.group(2) or "")
        if run_indent is not None:
            for u in UNTRUSTED_RE.finditer(line):
                if outsider:
                    label = "🔴 INJECTION (outsider-controlled input in a shell/script)"
                elif "pull_request" in events:
                    label = "🟡 INJECTION (fork PRs get a read-only token, no secrets)"
                else:
                    label = "🟡 INJECTION (trigger not outsider-controlled, verify)"
                findings.append((label, no, u.group(0)))
        if privileged and PR_CODE_RE.search(line):
            if BYPASS_RE.search(line):
                label = "🔴 PWN REQUEST (fetches PR code outside actions/checkout)"
            else:
                label = "🟡 PWN REQUEST (PR head checkout, may be blocked by checkout v7)"
            findings.append((label, no, stripped[:80]))
    return events, findings


def workflow_files(target):
    """A .yml file, a repo dir (.github/workflows), or a plain dir of .yml files."""
    if os.path.isfile(target):
        return [target]
    found = glob.glob(os.path.join(target, ".github", "workflows", "*.y*ml"))
    return sorted(found or glob.glob(os.path.join(target, "*.y*ml")))


def main():
    parser = argparse.ArgumentParser(description="Static audit of GitHub Actions workflows.")
    parser.add_argument("targets", nargs="+", help="repo dirs, workflow dirs or .yml files")
    args = parser.parse_args()
    total = 0
    for target in args.targets:
        paths = workflow_files(target)
        if not paths:
            print(f"!! {target}: no workflow files found (wrong path?)")
        for path in paths:
            events, findings = audit_file(path)
            if not findings:
                continue
            print(f"== {path}  (on: {', '.join(sorted(events)) or '?'})")
            for label, no, what in findings:
                print(f"   {label:<72} line {no:<4} {what}")
            total += len(findings)
    print(f"\n{total} findings")


if __name__ == "__main__":
    main()