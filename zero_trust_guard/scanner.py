import os
import re
from pathlib import Path


class SecretScanner:
    def __init__(self, max_file_size=1024 * 1024):
        self.max_file_size = max_file_size
        self.patterns = {
            "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
            "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24}",
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "GitHub Personal Access Token": r"ghp_[0-9a-zA-Z]{36}",
            "GitHub Fine-Grained Token": r"github_pat_[0-9A-Za-z_]{82}",
            "Slack Webhook": r"https://hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[0-9a-zA-Z]{24}",
            "OpenAI API Key": r"sk-[a-zA-Z0-9]{48}",
            "Anthropic API Key": r"sk-ant-api03-[a-zA-Z0-9-_]{90,120}",
        }
        self.compiled_patterns = {
            name: re.compile(pattern) for name, pattern in self.patterns.items()
        }
        self.skip_dirs = {
            ".git",
            ".hg",
            ".svn",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            ".venv",
            "__pycache__",
            "build",
            "dist",
            "env",
            "node_modules",
            "venv",
        }

    def should_scan_file(self, file_path):
        path = Path(file_path)
        if path.is_symlink() or not path.is_file():
            return False
        return path.stat().st_size <= self.max_file_size

    def redact_content(self, content, findings):
        redacted = content
        for finding in findings:
            pattern = self.compiled_patterns.get(finding["type"])
            if pattern:
                redacted = pattern.sub("[REDACTED]", redacted)
        return redacted

    def scan_file(self, file_path):
        findings = []
        try:
            if not self.should_scan_file(file_path):
                return []

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            for name, pattern in self.compiled_patterns.items():
                matches = list(pattern.finditer(content))
                if matches:
                    lines = sorted({content.count("\n", 0, match.start()) + 1 for match in matches})
                    findings.append({"type": name, "count": len(matches), "lines": lines})
        except (OSError, UnicodeError):
            return []
        return findings

    def scan_directory(self, directory):
        report = {}
        for root, dirs, files in os.walk(directory):
            dirs[:] = sorted(d for d in dirs if d not in self.skip_dirs)

            for file in sorted(files):
                path = os.path.join(root, file)
                findings = self.scan_file(path)
                if findings:
                    report[path] = findings
        return report
