import re
import os

class SecretScanner:
    def __init__(self):
        self.patterns = {
            "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
            "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24}",
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "GitHub Personal Access Token": r"ghp_[0-9a-zA-Z]{36}",
            "Slack Webhook": r"https://hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[0-9a-zA-Z]{24}",
            "OpenAI API Key": r"sk-[a-zA-Z0-9]{48}",
            "Anthropic API Key": r"sk-ant-api03-[a-zA-Z0-9-_]{93}ak-ant-api03-[a-zA-Z0-9-_]{93}",
        }
        self.skip_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'env', 'venv', 'dist', 'build'}

    def scan_file(self, file_path):
        findings = []
        try:
            # Only scan text-based files and limit size to 1MB for speed
            if os.path.getsize(file_path) > 1024 * 1024:
                return []
                
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                for name, pattern in self.patterns.items():
                    matches = re.findall(pattern, content)
                    if matches:
                        findings.append({"type": name, "count": len(matches)})
        except Exception:
            pass
        return findings

    def scan_directory(self, directory):
        report = {}
        for root, dirs, files in os.walk(directory):
            # Efficiently skip blacklisted directories
            dirs[:] = [d for d in dirs if d not in self.skip_dirs]
            
            for file in files:
                path = os.path.join(root, file)
                findings = self.scan_file(path)
                if findings:
                    report[path] = findings
        return report
