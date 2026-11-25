# secret-triage

A small Python tool to triage suspected secrets found during GitHub recon.
It scores each string and labels it as a likely false positive, needs review, or suspicious.

## How it works

1. **Placeholder filter**: drops values containing words like `example`, `your`, `invalid`, `test`.
2. **Length check**: only strings of 20+ characters can be marked suspicious.
3. **Shannon entropy** with charset-aware thresholds:
   - hex strings (max entropy 4.0): threshold 3.0
   - mixed alphanumeric: threshold 4.5

## Usage

```bash
python3 triage.py
```

## Example output

```
3.84  🟢 FP (placeholder)     invalid-e2e-world-suite-key
3.95  🔴 SUSPICIOUS           a3f9c2e17b8d4056f1e2c9a7b3d8e4f0
3.77  🟡 REVIEW               hello-world-config-value
```

## Known limitations

- Placeholder matching uses substrings, so `here` also matches `where` and `test` matches `latest`.
- Entropy alone cannot separate long placeholders from short real keys.

## Ethics

Built for authorized security testing and bug bounty programs only.
Never use any secret you find. Report it, redacted, through the program's official channel.