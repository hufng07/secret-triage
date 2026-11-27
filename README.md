# secret-triage

A small Python tool to triage suspected secrets found during GitHub recon.
It scores each string and labels it as a likely false positive, needs review, or suspicious.

## How it works
0. **Private key detection**: `-----BEGIN ... PRIVATE KEY-----` blocks are always flagged first,
   so long random bodies cannot be dropped by the placeholder filter.
1. **Placeholder filter**: drops values containing words like `example`, `your`, `invalid`, `test`.
2. **Key-type detection**: recognizes known formats by prefix (GitHub PAT, AWS access key ID,
   Stripe secret/publishable keys, Google API key) and rates them as secret, review, or public by design.
3. **Shannon entropy** for unknown formats, with charset-aware thresholds:
   - hex strings (max entropy 4.0): threshold 3.0
   - mixed alphanumeric: threshold 4.5
4. **AWS key pairing** (gitleaks mode): a 40-character string on the line right above or below
   an AWS access key ID, in the same file and commit, is labeled as the paired AWS secret key.
5. **Path-aware ranking** (gitleaks mode): findings in test, fixture, example, docs or Storybook
   (`.stories.`) paths, or in repos named like `*-test*`, are lowered one level; temp, backup,
   old and `.log` files (e.g. Java crash dumps) are raised one level.
6. **JWT expiry check**: JWTs are decoded locally (never sent anywhere) and their `exp` claim
   is compared to the current time. Expired tokens are marked as false positives;
   tokens with no expiry are flagged as suspicious.
## Usage

```bash
python3 triage.py "string1" "string2"   # score strings directly
python3 triage.py -f path/to/.env        # score each line of a file
cat .env | python3 triage.py             # read from a pipe
python3 triage.py --demo                 # run with built-in fake samples
python3 triage.py --help
python3 triage.py --gitleaks report.json            # score a gitleaks JSON report (secrets masked)
python3 triage.py --gitleaks report.json --unmask   # same, with full secrets
```

Lines starting with `#` are skipped. For `KEY=value` lines, only the value is scored.

## Example output

```
3.84  🟢 FP (placeholder)     invalid-e2e-world-suite-key
3.95  🔴 SUSPICIOUS           a3f9c2e17b8d4056f1e2c9a7b3d8e4f0
3.77  🟡 REVIEW               hello-world-config-value
```

## Known limitations

- Placeholder matching uses substrings, so `here` also matches `where` and `test` matches `latest`.
- Entropy alone cannot separate long placeholders from short real keys.
- Path rules lower findings in test folders but never drop them: real keys are sometimes copied into tests.

## org_recon.py: scan a whole org

Lists an org's repos, clones full history, scans each one with gitleaks,
then prints a summary sorted by number of findings.

Needs: `gh` (logged in), Docker.

```bash
python3 org_recon.py ORG --limit 50
python3 org_recon.py ORG --limit 500 --suffix=-sdk          # only repos ending in -sdk
python3 org_recon.py ORG --include-archived --skip big-repo  # archived too, skip one
python3 triage.py --gitleaks /workspaces/recon/ORG/reports/REPO.json
python3 org_recon.py ORG --osv                    # + dependency CVEs (osv-scanner)
```

- **Resume:** a repo that already has a report is skipped, so you can re-run after an interruption.
- **Safe clone:** clones go to `NAME.partial` and are renamed when complete.
- **Noise filters:** `gitleaks-recon.toml` keeps the default rules and drops known false
  positives (vendored builds, media, KiCad DigiKey part names, JS `metaKey`).
- **Two passes:** gitleaks' default config skips lockfiles (`package-lock.json`, `yarn.lock`,
- **`--osv`:** runs osv-scanner (Docker) on the current checkout and counts known CVEs per lockfile,
  split into test/example paths vs the rest. A vulnerable dependency is not a bug by itself: show the
  vulnerable code is actually reachable (e.g. `govulncheck` for Go) before reporting. SDKs often ship
  no lockfile, so "no package sources" is normal there.
  `poetry.lock`...). A second pass with `gitleaks-urls.toml` (no defaults) looks only for
  credentials in URLs, so private registry tokens in lockfiles are not missed.
- Clones and reports live in `/workspaces/recon` (outside the repo). Never commit them.

## actions_audit.py: GitHub Actions audit

Static, read-only check of workflow files. It never runs or triggers anything.

```bash
python3 actions_audit.py path/to/repo          # reads .github/workflows/*.yml
python3 actions_audit.py tests/fixtures/workflows
python3 org_recon.py ORG --actions              # audit every repo in an org
```

- **Script injection:** outsider-controlled input (`github.event.issue.title`, `...pull_request.body`,
  `github.head_ref`...) pasted into `run:` or `script:`. Red when outsiders can trigger the workflow.
- **Pwn request:** `pull_request_target` / `workflow_run` that fetches PR code. Red when it bypasses
  `actions/checkout` (`gh pr checkout`, `git fetch ... pull/`), yellow for a plain head checkout,
  which `actions/checkout` v7+ blocks by default.
- Says so when it finds no workflow files, so "0 findings" never means "nothing was read".
- For hardening checks (token permissions, pinned actions) use [zizmor](https://docs.zizmor.sh/) as a second opinion.
- **Never** open issues or PRs against a target to "test" a finding. Report from the YAML alone.

## Ethics

Built for authorized security testing and bug bounty programs only.
Never use any secret you find. Report it, redacted, through the program's official channel.