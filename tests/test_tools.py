"""Regression tests: every case here came from a real hunt or a real bug."""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import actions_audit  # noqa: E402
import triage  # noqa: E402

FIXTURES = os.path.join(ROOT, "tests", "fixtures", "workflows")


class TriageTests(unittest.TestCase):
    def assertLevel(self, value, emoji):
        label = triage.classify(value)
        self.assertTrue(label.startswith(emoji), f"{value!r} -> {label}")

    # Credentials in URLs (v1.4)
    def test_url_creds_real_host_is_red(self):
        self.assertLevel("postgres://admin:S3cr3tP4ss9x@db.prod.acme.io:5432/app", "🔴")

    def test_url_creds_short_password_is_green(self):
        # DoD anet: Selenium sample test, password "pw". Also guards the dead-code indent bug.
        self.assertLevel("http://arthur:pw@anet-dev.dds.mil", "🟢")

    def test_url_creds_weak_password_is_green(self):
        self.assertLevel("postgres://user:password@localhost/db", "🟢")

    def test_url_creds_template_is_green(self):
        self.assertLevel("mongodb://app:${MONGO_PASS}@mongo:27017", "🟢")

    def test_url_creds_docker_service_is_yellow(self):
        self.assertLevel("redis://default:Xk9mQ2pL7vR4@redis:6379", "🟡")

    # JWT expiry (v1.0, PagerDuty rundeck)
    def test_expired_jwt_is_green(self):
        self.assertLevel(triage.fake_jwt(1731706274), "🟢")

    def test_future_jwt_is_red(self):
        self.assertLevel(triage.fake_jwt(4102444800), "🔴")

    # Level labels (v1.3: green dot used to say REVIEW)
    def test_shift_level_keeps_history(self):
        self.assertEqual(triage.shift_level("🟡 REVIEW", -1, "low-risk path"),
                         "🟢 LOW (was REVIEW) [low-risk path]")

    def test_shift_level_clamps_at_bottom(self):
        self.assertEqual(triage.shift_level("🟢 FP (placeholder)", -1, "x"),
                         "🟢 FP (placeholder) [x]")

    # Path rules (v1.3, LaunchDarkly + DoD eMCM)
    def test_low_risk_paths(self):
        for path in ["vs/language/typescript/lib/typescriptServices.js", "e2e/go/go.mod",
                     "Pods/Pods.xcodeproj/project.pbxproj", "src/__tests__/auth.spec.tsx",
                     "example-legacy/Podfile.lock"]:
            self.assertTrue(triage.LOW_RISK_PATH_RE.search(path), path)

    def test_real_paths_are_not_low_risk(self):
        for path in ["config/secrets.yml", ".env", "dev.env.example", "package-lock.json"]:
            self.assertFalse(triage.LOW_RISK_PATH_RE.search(path), path)

    # Public-by-design names (v1.3, DoD Crossfeed reCAPTCHA)
    def test_public_names(self):
        self.assertTrue(triage.PUBLIC_NAME_RE.search("REACT_APP_RECAPTCHA_CLIENT_KEY: 6LdE76"))
        self.assertFalse(triage.PUBLIC_NAME_RE.search("JWT_KEY=-----BEGIN RSA PRIVATE KEY-----"))


class ActionsAuditTests(unittest.TestCase):
    def audit(self, name):
        _, findings = actions_audit.audit_file(os.path.join(FIXTURES, name))
        return [(label[0], line) for label, line, _ in findings]

    def test_injection_is_red(self):
        self.assertEqual(self.audit("bad_injection.yml"), [("🔴", 9)])

    def test_env_var_fix_is_clean(self):
        self.assertEqual(self.audit("safe_env.yml"), [])

    def test_pwn_request(self):
        self.assertEqual(self.audit("pwn_request.yml"), [("🟡", 8), ("🔴", 10)])

    def test_missing_path_finds_no_files(self):
        self.assertEqual(actions_audit.workflow_files("/no/such/dir"), [])


if __name__ == "__main__":
    unittest.main()