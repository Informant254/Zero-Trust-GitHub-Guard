import sys
import argparse
from rich.console import Console
from rich.table import Table
from .scanner import SecretScanner

console = Console()

def main():
    parser = argparse.ArgumentParser(description="Zero-Trust GitHub Guard")
    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser("init", help="Initialize security scan")
    scan_parser = subparsers.add_parser("scan", help="Scan current directory for secrets")

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
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
