import typer
from .core.reporter import Reporter
from rich.console import Console
from rich.table import Table
from pathlib import Path

from .core.scope import Scope
from .core.datastore import Datastore
from .core.engine import Engine
from .core.plugin_loader import discover_modules

app = typer.Typer(help="UMANI — web security testing framework")
console = Console()


@app.command()
def modules():
    """List available modules."""
    mods = discover_modules()
    t = Table("Name", "Severity", "Description")
    for name, cls in sorted(mods.items()):
        t.add_row(name, cls.severity, cls.description)
    console.print(t)

@app.command()
def scan(
    target: str,
    scope_file: Path = typer.Option("scope.yaml", "--scope"),
    module: list[str] = typer.Option(None, "--module", "-m"),
    db: Path = typer.Option("umani.db", "--db"),
    spider: bool = typer.Option(False, "--spider",
                                 help="Crawl first, then scan discovered URLs"),
):
    """Scan a target URL."""
    scope = Scope(scope_file)
    store = Datastore(str(db))
    scan_id = store.new_scan(target, {"modules": module})
    engine = Engine(scope, store)

    console.print(f"[bold]Scanning[/bold] {target} (scan #{scan_id})")

    # Optionally crawl first
    urls_to_scan = [target]
    if spider:
        console.print("[dim]Crawling…[/dim]")
        crawl_findings = engine.scan(target, modules=["spider"],
                                      scan_id=scan_id)
        discovered = [f.url for f in crawl_findings
                      if "Link found" in f.name]
        urls_to_scan = sorted(set(urls_to_scan + discovered))
        console.print(f"[dim]Discovered {len(urls_to_scan)} URLs[/dim]")

    # Parse --module-option key=value pairs into a dict
    options = {}
    for kv in (module_option or []):
        if "=" in kv:
            k, v = kv.split("=", 1)
            options[k] = v
    # merge options into the module config
    if options:
        engine.options = {m: options for m in (module or engine.modules.keys())}

    findings = []
    for url in urls_to_scan:
        findings.extend(engine.scan(url, modules=module, scan_id=scan_id))
    if not findings:
        console.print("[green]No findings.[/green]")
        return

    module_option: list[str] = typer.Option(
        None, "--module-option", "-o",
        help="key=value passed to module (e.g. param=name)"),

    t = Table("Severity", "Module", "Finding", "URL")
    for f in findings:
        color = {"critical": "red", "high": "red", "medium": "yellow",
                 "low": "cyan", "info": "white"}.get(f.severity, "white")
        t.add_row(f"[{color}]{f.severity}[/{color}]", f.module, f.name, f.url)
    console.print(t)

@app.command()
def report(
    scan_id: int = typer.Argument(..., help="Scan ID to report on"),
    db: Path = typer.Option("umani.db", "--db"),
    output: Path = typer.Option("report.html", "--output", "-o"),
):
    """Generate an HTML report for a scan."""
    store = Datastore(str(db))
    reporter = Reporter(store)
    path = reporter.write_html(scan_id, output)
    console.print(f"[green]Report written to[/green] {path}")
    console.print(f"Open it with: [bold]xdg-open {path}[/bold]")


if __name__ == "__main__":
    app()
