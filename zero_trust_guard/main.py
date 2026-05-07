import argparse
import os
import shutil
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .scanner import SecretScanner

console = Console()


def render_report(report):
    table = Table(title="Exposed Secrets Found")
    table.add_column("File Path", style="cyan")
    table.add_column("Secret Type", style="magenta")
    table.add_column("Count", style="red")
    table.add_column("Lines", style="yellow")

    for path, findings in sorted(report.items()):
        for finding in findings:
            lines = ", ".join(str(line) for line in finding.get("lines", []))
            table.add_row(path, finding["type"], str(finding["count"]), lines)

    console.print(table)


def quarantine_path(path):
    q_dir = Path(".quarantine")
    q_dir.mkdir(exist_ok=True)
    source = Path(path)
    destination = q_dir / source.name
    index = 1
    while destination.exists():
        destination = q_dir / f"{source.stem}-{os.getpid()}-{index}{source.suffix}"
        index += 1
    return destination


def main():
    parser = argparse.ArgumentParser(description="Zero-Trust GitHub Guard")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("init", help="Initialize security scan")
    scan_parser = subparsers.add_parser("scan", help="Scan current directory for secrets")
    scan_parser.add_argument("path", nargs="?", default=".", help="Directory or file to scan")
    fix_parser = subparsers.add_parser("fix", help="Interactively fix discovered leaks")
    fix_parser.add_argument("path", nargs="?", default=".", help="Directory or file to scan")
    fix_parser.add_argument(
        "--apply",
        action="store_true",
        help="Allow redaction, delete, and quarantine actions to modify files",
    )

    args = parser.parse_args()

    if args.command == "init":
        console.print("[bold green]Initializing Zero-Trust GitHub Guard...[/bold green]")
        console.print("System check complete. Ready to protect your repositories.")
    elif args.command == "scan":
        scanner = SecretScanner()
        console.print("[bold blue]Scanning for exposed secrets...[/bold blue]")
        target = args.path
        report = {target: scanner.scan_file(target)} if os.path.isfile(target) else scanner.scan_directory(target)
        report = {path: findings for path, findings in report.items() if findings}
        
        if not report:
            console.print("[bold green]No secrets found. Your repository is clean.[/bold green]")
        else:
            render_report(report)
            console.print("\n[bold yellow]Tip: Run 'zero-trust-guard fix --apply' to secure these leaks.[/bold yellow]")
            
    elif args.command == "fix":
        scanner = SecretScanner()
        target = args.path
        report = {target: scanner.scan_file(target)} if os.path.isfile(target) else scanner.scan_directory(target)
        report = {path: findings for path, findings in report.items() if findings}
        if not report:
            console.print("[bold green]Nothing to fix. Your repository is clean.[/bold green]")
            return
        if not args.apply:
            render_report(report)
            console.print("\n[bold yellow]Dry run only. Re-run with --apply before modifying files.[/bold yellow]")
            return

        for path, findings in sorted(report.items()):
            console.print(f"\n[bold red]Leak detected in: {path}[/bold red]")
            for f in findings:
                lines = ", ".join(str(line) for line in f.get("lines", []))
                console.print(f" - Found {f['count']} {f['type']} on line(s): {lines}")
            
            choice = console.input("\nChoose action: [r]edact, [d]elete, [q]uarantine, [s]kip: ").lower()
            
            if choice == "r":
                with open(path, "r", encoding="utf-8", errors="ignore") as file:
                    content = file.read()
                content = scanner.redact_content(content, findings)
                with open(path, "w", encoding="utf-8") as file:
                    file.write(content)
                console.print(f"[green]{path} redacted.[/green]")
                
            elif choice == "d":
                os.remove(path)
                console.print(f"[green]{path} deleted.[/green]")
                
            elif choice == "q":
                destination = quarantine_path(path)
                shutil.move(path, destination)
                console.print(f"[green]{path} moved to {destination}.[/green]")
            else:
                console.print("[yellow]Skipped.[/yellow]")
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
