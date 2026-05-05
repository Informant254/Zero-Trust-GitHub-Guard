import sys
import argparse
import os
import shutil
import re
from rich.console import Console
from rich.table import Table
from .scanner import SecretScanner

console = Console()

def main():
    parser = argparse.ArgumentParser(description="Zero-Trust GitHub Guard")
    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser("init", help="Initialize security scan")
    scan_parser = subparsers.add_parser("scan", help="Scan current directory for secrets")
    fix_parser = subparsers.add_parser("fix", help="Interactively fix discovered leaks")

    args = parser.parse_args()

    if args.command == "init":
        console.print("[bold green]🛡️ Initializing Zero-Trust GitHub Guard...[/bold green]")
        console.print("System check complete. Ready to protect your repositories.")
    elif args.command == "scan":
        scanner = SecretScanner()
        console.print("[bold blue]🔍 Scanning for exposed secrets...[/bold blue]")
        report = scanner.scan_directory(".")
        
        if not report:
            console.print("[bold green]✅ No secrets found. Your repository is clean![/bold green]")
        else:
            table = Table(title="Exposed Secrets Found")
            table.add_column("File Path", style="cyan")
            table.add_column("Secret Type", style="magenta")
            table.add_column("Count", style="red")

            for path, findings in report.items():
                for f in findings:
                    table.add_row(path, f["type"], str(f["count"]))
            
            console.print(table)
            console.print("\n[bold yellow]💡 Tip: Run 'zero-trust-guard fix' to secure these leaks.[/bold yellow]")
            
    elif args.command == "fix":
        scanner = SecretScanner()
        report = scanner.scan_directory(".")
        if not report:
            console.print("[bold green]✅ Nothing to fix! Your repository is clean.[/bold green]")
            return

        for path, findings in report.items():
            console.print(f"\n[bold red]Leak detected in: {path}[/bold red]")
            for f in findings:
                console.print(f" - Found {f['count']} {f['type']}")
            
            choice = console.input("\nChoose action: [r]edact, [d]elete, [q]uarantine, [s]kip: ").lower()
            
            if choice == 'r':
                # Simple redaction logic
                with open(path, 'r') as file:
                    content = file.read()
                for f in findings:
                    # Replace patterns with [REDACTED]
                    pattern = scanner.patterns.get(f['type'])
                    if pattern:
                        content = re.sub(pattern, "[REDACTED]", content)
                with open(path, 'w') as file:
                    file.write(content)
                console.print(f"[green]✓ {path} redacted.[/green]")
                
            elif choice == 'd':
                os.remove(path)
                console.print(f"[green]✓ {path} deleted.[/green]")
                
            elif choice == 'q':
                q_dir = ".quarantine"
                if not os.path.exists(q_dir):
                    os.makedirs(q_dir)
                shutil.move(path, os.path.join(q_dir, os.path.basename(path)))
                console.print(f"[green]✓ {path} moved to {q_dir}.[/green]")
            else:
                console.print("[yellow]Skipped.[/yellow]")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
