import os
import tempfile
import unittest
from pathlib import Path

from zero_trust_guard.scanner import SecretScanner


class SecretScannerTests(unittest.TestCase):
    def test_scan_file_reports_counts_and_lines_without_values(self):
        scanner = SecretScanner()
        secret = "sk-" + ("a" * 48)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.txt"
            path.write_text(
                "public=true\n"
                f"OPENAI_API_KEY={secret}\n",
                encoding="utf-8",
            )

            findings = scanner.scan_file(path)

        self.assertEqual(findings[0]["type"], "OpenAI API Key")
        self.assertEqual(findings[0]["count"], 1)
        self.assertEqual(findings[0]["lines"], [2])
        self.assertNotIn("sk-", str(findings[0].get("value", "")))

    def test_redact_content_replaces_matching_secret(self):
        scanner = SecretScanner()
        secret = "sk-" + ("a" * 48)
        content = f"token={secret}\n"
        findings = [{"type": "OpenAI API Key", "count": 1, "lines": [1]}]

        redacted = scanner.redact_content(content, findings)

        self.assertEqual(redacted, "token=[REDACTED]\n")

    def test_scan_directory_skips_git_directory(self):
        scanner = SecretScanner()
        secret = "ghp_" + ("a" * 36)

        with tempfile.TemporaryDirectory() as tmpdir:
            git_dir = Path(tmpdir) / ".git"
            git_dir.mkdir()
            (git_dir / "config").write_text(
                f"token={secret}\n",
                encoding="utf-8",
            )

            report = scanner.scan_directory(tmpdir)

        self.assertEqual(report, {})

    def test_scan_file_skips_symlink(self):
        scanner = SecretScanner()
        secret = "ghp_" + ("a" * 36)

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.txt"
            link = Path(tmpdir) / "link.txt"
            target.write_text(
                f"token={secret}\n",
                encoding="utf-8",
            )
            os.symlink(target, link)

            self.assertEqual(scanner.scan_file(link), [])


if __name__ == "__main__":
    unittest.main()
