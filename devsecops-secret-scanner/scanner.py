#!/usr/bin/env python3
"""
Automated SAST & Secret Scanner
Author: Your Name
Description: Scans source code files for hardcoded credentials, API keys, and unsafe code patterns.
"""

import argparse
import json
import os
import re
import sys
from rich.console import Console
from rich.table import Table

console = Console()

# Regular Expression Rules for Secret & SAST Scanning
RULES = {
    "AWS Access Key": re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
    "Generic API Key / Secret": re.compile(r"(?i)(api_key|secret_key|password|token)\s*=\s*['\"][A-Za-z0-9%_.-]{8,}['\"]"),
    "Stripe Live API Key": re.compile(r"sk_live_[0-9a-zA-Z]{24}"),
    "Command Injection (os.system)": re.compile(r"os\.system\([^)]*\+"),
    "Insecure Exec/Eval Usage": re.compile(r"\b(exec|eval)\s*\(")
}

def scan_file(file_path: str) -> list:
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        for line_num, line in enumerate(lines, 1):
            for rule_name, pattern in RULES.items():
                if pattern.search(line):
                    findings.append({
                        "file": file_path,
                        "line": line_num,
                        "rule": rule_name,
                        "code": line.strip()
                    })
    except Exception as e:
        console.print(f"[bold red][-] Error reading {file_path}: {e}[/]")
    return findings

def scan_directory(target_dir: str) -> list:
    all_findings = []
    for root, _, files in os.walk(target_dir):
        if any(ignored in root for ignored in [".git", "__pycache__", ".venv"]):
            continue
        for file in files:
            if file.endswith((".py", ".js", ".json", ".env", ".yaml", ".yml", ".txt")):
                full_path = os.path.join(root, file)
                all_findings.extend(scan_file(full_path))
    return all_findings

def main():
    parser = argparse.ArgumentParser(description="Static Application Security Testing (SAST) & Secret Scanner")
    parser.add_argument("path", help="Path to file or directory to scan")
    parser.add_argument("-oJ", "--json", help="Export findings to JSON file")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        console.print(f"[bold red][-] Error:[/] Path '{args.path}' does not exist.")
        sys.exit(1)

    console.print(f"\n[bold blue][*] Starting Security Scan on:[/] {args.path}\n")

    if os.path.isfile(args.path):
        findings = scan_file(args.path)
    else:
        findings = scan_directory(args.path)

    # Display Findings in Rich Table
    table = Table(title=f"Security Scan Results ({len(findings)} Issues Found)")
    table.add_column("File", style="cyan")
    table.add_column("Line", style="magenta", justify="right")
    table.add_column("Issue Type", style="bold red")
    table.add_column("Detected Code Snippet", style="white")

    for f in findings:
        table.add_row(f["file"], str(f["line"]), f["rule"], f["code"])

    console.print(table)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as out:
            json.dump({"findings": findings}, out, indent=4)
        console.print(f"\n[bold green][+] Results successfully exported to {args.json}[/]")

    # Return exit code 1 if issues found (useful for CI/CD pipelines)
    if findings:
        sys.exit(1)

if __name__ == "__main__":
    main()