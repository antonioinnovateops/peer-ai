"""Peer-AI command line interface."""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table

from peer_ai import __version__
from peer_ai.model.reviewer import CodeReviewer
from peer_ai.analyzers.diff import parse_diff


console = Console()


@click.group()
@click.version_option(__version__)
def main():
    """Peer-AI: AI-powered code review for git workflows."""
    pass


@main.command()
@click.argument("target", required=False)
@click.option("--model", "-m", default="peer-ai/reviewer-1.5b", help="Model to use")
@click.option("--language", "-l", multiple=True, help="Languages to analyze")
@click.option("--severity", "-s", default="low", help="Minimum severity threshold")
@click.option("--format", "-f", "output_format", default="rich", 
              type=click.Choice(["rich", "json", "sarif", "github"]))
@click.option("--diff/--no-diff", default=True, help="Treat input as diff")
def review(
    target: Optional[str],
    model: str,
    language: tuple[str, ...],
    severity: str,
    output_format: str,
    diff: bool,
):
    """Review code for issues.
    
    TARGET can be a file path or '-' for stdin (pipe a diff).
    
    Examples:
    
        # Review a diff from git
        git diff main..feature | peer-ai review -
        
        # Review staged changes
        git diff --cached | peer-ai review -
        
        # Review a file directly
        peer-ai review src/main.c
    """
    # Read input
    if target == "-" or target is None:
        if sys.stdin.isatty():
            console.print("[yellow]Reading from stdin... (pipe a diff or Ctrl+D to finish)[/]")
        content = sys.stdin.read()
    else:
        path = Path(target)
        if not path.exists():
            console.print(f"[red]Error: File not found: {target}[/]")
            raise SystemExit(1)
        content = path.read_text()
    
    if not content.strip():
        console.print("[yellow]No input provided.[/]")
        return
    
    # Initialize reviewer
    console.print(f"[dim]Loading model: {model}[/]")
    reviewer = CodeReviewer(model_name=model)
    
    # Parse and review
    if diff:
        files = parse_diff(content)
        findings = []
        for file_path, hunks in files.items():
            console.print(f"[dim]Reviewing: {file_path}[/]")
            for hunk in hunks:
                results = reviewer.review(hunk["content"], file_path=file_path, line_offset=hunk["start_line"])
                findings.extend(results)
    else:
        findings = reviewer.review(content, file_path=target or "stdin")
    
    # Filter by severity
    severity_order = ["low", "medium", "high", "critical"]
    min_severity = severity_order.index(severity)
    findings = [f for f in findings if severity_order.index(f.severity) >= min_severity]
    
    # Output
    if output_format == "rich":
        _print_rich(findings)
    elif output_format == "json":
        _print_json(findings)
    elif output_format == "sarif":
        _print_sarif(findings)
    elif output_format == "github":
        _print_github(findings)
    
    # Exit code based on findings
    if any(f.severity in ("high", "critical") for f in findings):
        raise SystemExit(1)


def _print_rich(findings):
    """Print findings in rich table format."""
    if not findings:
        console.print("[green]✓ No issues found![/]")
        return
    
    table = Table(title=f"Found {len(findings)} issue(s)")
    table.add_column("Severity", style="bold")
    table.add_column("Location")
    table.add_column("Issue")
    table.add_column("Rule")
    
    severity_colors = {
        "critical": "red bold",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
    }
    
    for f in findings:
        table.add_row(
            f"[{severity_colors[f.severity]}]{f.severity.upper()}[/]",
            f"{f.file}:{f.line}",
            f.message[:60] + "..." if len(f.message) > 60 else f.message,
            f.rule or "-",
        )
    
    console.print(table)
    
    # Print details
    console.print("\n[bold]Details:[/]\n")
    for i, f in enumerate(findings, 1):
        console.print(f"[bold]{i}. {f.title}[/]")
        console.print(f"   [dim]{f.file}:{f.line}[/]")
        console.print(f"   {f.message}")
        if f.suggestion:
            console.print(f"   [green]Suggestion:[/] {f.suggestion}")
        console.print()


def _print_json(findings):
    """Print findings as JSON."""
    import json
    data = [f.model_dump() for f in findings]
    console.print_json(json.dumps(data, indent=2))


def _print_sarif(findings):
    """Print findings in SARIF format for GitHub code scanning."""
    import json
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "peer-ai",
                    "version": __version__,
                    "informationUri": "https://github.com/antonioinnovateops/peer-ai",
                }
            },
            "results": [
                {
                    "ruleId": f.rule or "peer-ai/generic",
                    "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note"}[f.severity],
                    "message": {"text": f.message},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": {"startLine": f.line}
                        }
                    }]
                }
                for f in findings
            ]
        }]
    }
    console.print_json(json.dumps(sarif, indent=2))


def _print_github(findings):
    """Print findings as GitHub Actions workflow commands."""
    for f in findings:
        level = {"critical": "error", "high": "error", "medium": "warning", "low": "notice"}[f.severity]
        message = f.message.replace("\n", "%0A")
        print(f"::{level} file={f.file},line={f.line},title={f.title}::{message}")


@main.command()
@click.option("--host", "-h", default="0.0.0.0", help="Host to bind to")
@click.option("--port", "-p", default=8080, help="Port to listen on")
@click.option("--config", "-c", type=click.Path(exists=True), help="Config file")
def serve(host: str, port: int, config: Optional[str]):
    """Start the webhook server."""
    import uvicorn
    from peer_ai.server.app import create_app
    
    app = create_app(config_path=config)
    console.print(f"[green]Starting Peer-AI server on {host}:{port}[/]")
    uvicorn.run(app, host=host, port=port)


@main.group()
def data():
    """Training data management."""
    pass


@data.command("generate")
@click.option("--output", "-o", default="data/train.jsonl", help="Output file")
@click.option("--sources", "-s", multiple=True, 
              default=["cve", "github-advisories", "cwe"],
              help="Data sources to use")
@click.option("--limit", "-n", default=10000, help="Max samples per source")
def data_generate(output: str, sources: tuple[str, ...], limit: int):
    """Generate training data from security databases."""
    from peer_ai.model.data import generate_training_data
    
    console.print(f"[bold]Generating training data from: {', '.join(sources)}[/]")
    generate_training_data(output_path=output, sources=list(sources), limit=limit)
    console.print(f"[green]✓ Saved to {output}[/]")


@main.command()
@click.option("--config", "-c", default="configs/training.yaml", help="Training config")
@click.option("--resume", "-r", type=click.Path(exists=True), help="Resume from checkpoint")
def train(config: str, resume: Optional[str]):
    """Fine-tune the code review model."""
    from peer_ai.model.train import train_model
    
    console.print(f"[bold]Starting training with config: {config}[/]")
    train_model(config_path=config, resume_from=resume)


if __name__ == "__main__":
    main()
