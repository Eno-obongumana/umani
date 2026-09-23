import typer
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
):
    """Scan a target URL."""
    scope = Scope(scope_file)
    store = Datastore(str(db))
    scan_id = store.new_scan(target, {"modules": module})
    engine = Engine(scope, store)

    console.print(f"[bold]Scanning[/bold] {target} (scan #{scan_id})")
    findings = engine.scan(target, modules=module, scan_id=scan_id)

    if not findings:
        console.print("[green]No findings.[/green]")
        return

    t = Table("Severity", "Module", "Finding", "URL")
    for f in findings:
        color = {"critical": "red", "high": "red", "medium": "yellow",
                 "low": "cyan", "info": "white"}.get(f.severity, "white")
        t.add_row(f"[{color}]{f.severity}[/{color}]", f.module, f.name, f.url)
    console.print(t)


if __name__ == "__main__":
    app()
