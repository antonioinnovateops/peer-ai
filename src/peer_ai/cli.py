#!/usr/bin/env python3
"""Peer-AI CLI - AI-powered code review from the command line."""

import argparse
import json
import sys
import subprocess
import requests
from typing import Optional

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "peer-ai-raw"

def review_code(code: str, language: str = "unknown") -> dict:
    """Send code to Peer-AI for review."""
    # Add line numbers
    lines = code.strip().split('\n')
    numbered = '\n'.join(f"  {i+1} | {line}" for i, line in enumerate(lines))
    
    prompt = f"""Review the following {language} code for security vulnerabilities, bugs, and quality issues:

```{language}
{numbered}
```

Analyze carefully and report any issues found."""

    try:
        resp = requests.post(OLLAMA_URL, json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False
        }, timeout=120)
        resp.raise_for_status()
        return json.loads(resp.json().get("response", "{}"))
    except Exception as e:
        return {"error": str(e)}

def detect_language(filename: str) -> str:
    """Detect language from filename."""
    ext_map = {
        '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
        '.go': 'go', '.rs': 'rust', '.c': 'c', '.cpp': 'cpp',
        '.h': 'c', '.hpp': 'cpp', '.java': 'java', '.rb': 'ruby',
        '.php': 'php', '.sh': 'bash', '.sql': 'sql'
    }
    for ext, lang in ext_map.items():
        if filename.endswith(ext):
            return lang
    return 'unknown'

def parse_diff(diff: str) -> list:
    """Parse unified diff into file chunks."""
    chunks = []
    current_file = None
    current_code = []
    current_lang = 'unknown'
    
    for line in diff.split('\n'):
        if line.startswith('+++ b/'):
            if current_file and current_code:
                chunks.append({
                    'file': current_file,
                    'language': current_lang,
                    'code': '\n'.join(current_code)
                })
            current_file = line[6:]
            current_lang = detect_language(current_file)
            current_code = []
        elif line.startswith('+') and not line.startswith('+++'):
            current_code.append(line[1:])
    
    if current_file and current_code:
        chunks.append({
            'file': current_file,
            'language': current_lang,
            'code': '\n'.join(current_code)
        })
    
    return chunks

def format_finding(finding: dict, filename: str = None) -> str:
    """Format a finding for terminal output."""
    severity = finding.get('severity', 'unknown').upper()
    colors = {'CRITICAL': '\033[91m', 'HIGH': '\033[91m', 'MEDIUM': '\033[93m', 'LOW': '\033[94m'}
    reset = '\033[0m'
    color = colors.get(severity, '')
    
    parts = []
    if filename:
        parts.append(f"\033[1m{filename}\033[0m")
    line = finding.get('line', '?')
    parts.append(f":{line}")
    parts.append(f" {color}[{severity}]{reset}")
    
    rule = finding.get('rule')
    if rule:
        parts.append(f" {rule}")
    
    title = finding.get('title', finding.get('message', 'Issue found'))
    parts.append(f" - {title}")
    
    output = ''.join(parts)
    
    suggestion = finding.get('suggestion')
    if suggestion:
        output += f"\n  💡 {suggestion}"
    
    return output

def main():
    parser = argparse.ArgumentParser(
        description='Peer-AI: AI-powered code review',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  git diff | peer-ai review -
  peer-ai review src/main.py
  peer-ai review --diff HEAD~1
        """
    )
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Review command
    review_parser = subparsers.add_parser('review', help='Review code for issues')
    review_parser.add_argument('target', nargs='?', default='-',
                              help='File to review, - for stdin, or --diff for git diff')
    review_parser.add_argument('--diff', '-d', metavar='REF',
                              help='Review git diff against REF (e.g., HEAD~1, main)')
    review_parser.add_argument('--json', '-j', action='store_true',
                              help='Output raw JSON')
    review_parser.add_argument('--language', '-l',
                              help='Override language detection')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'review':
        findings = []
        
        if args.diff:
            # Git diff mode
            result = subprocess.run(
                ['git', 'diff', args.diff],
                capture_output=True, text=True
            )
            if result.returncode != 0:
                print(f"Error: git diff failed: {result.stderr}", file=sys.stderr)
                sys.exit(1)
            
            chunks = parse_diff(result.stdout)
            for chunk in chunks:
                finding = review_code(chunk['code'], chunk['language'])
                if finding and 'error' not in finding:
                    finding['_file'] = chunk['file']
                    findings.append(finding)
        
        elif args.target == '-':
            # Stdin mode (could be diff or raw code)
            content = sys.stdin.read()
            if content.startswith('diff --git') or content.startswith('--- '):
                chunks = parse_diff(content)
                for chunk in chunks:
                    finding = review_code(chunk['code'], chunk['language'])
                    if finding and 'error' not in finding:
                        finding['_file'] = chunk['file']
                        findings.append(finding)
            else:
                lang = args.language or 'unknown'
                finding = review_code(content, lang)
                if finding and 'error' not in finding:
                    findings.append(finding)
        
        else:
            # File mode
            try:
                with open(args.target) as f:
                    content = f.read()
                lang = args.language or detect_language(args.target)
                finding = review_code(content, lang)
                if finding and 'error' not in finding:
                    finding['_file'] = args.target
                    findings.append(finding)
            except FileNotFoundError:
                print(f"Error: File not found: {args.target}", file=sys.stderr)
                sys.exit(1)
        
        # Output
        if args.json:
            print(json.dumps(findings, indent=2))
        else:
            if not findings:
                print("✅ No issues found")
            else:
                for f in findings:
                    filename = f.pop('_file', None)
                    print(format_finding(f, filename))
                print(f"\n🔍 Found {len(findings)} issue(s)")
        
        sys.exit(1 if findings else 0)

if __name__ == '__main__':
    main()
