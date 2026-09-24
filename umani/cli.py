import time
from pathlib import Path
import typer
from rich.console import Console
from rich.table import Table

from .core.scope import Scope
from .core.datastore import Datastore
from .core.engine import Engine
from .core.plugin_loader import discover_modules
from .core.reporter import Reporter
from .core.repeater import Repeater
from .core.proxy import Proxy
from .core.intercept import QUEUE


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
    module_option: list[str] = typer.Option(
        None, "--module-option", "-o",
        help="key=value passed to module (e.g. param=name)"),
):
    """Scan a target URL."""
    scope = Scope(scope_file)
    store = Datastore(str(db))
    scan_id = store.new_scan(target, {"modules": module})
    engine = Engine(scope, store)

    console.print(f"[bold]Scanning[/bold] {target} (scan #{scan_id})")

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
    if options:
        engine.options = {m: options for m in (module or engine.modules.keys())}

    findings = []
    for url in urls_to_scan:
        findings.extend(engine.scan(url, modules=module, scan_id=scan_id))

    if not findings:
        console.print("[green]No findings.[/green]")
        return

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


@app.command()
def findings(
    scan_id: int = typer.Argument(..., help="Scan ID"),
    db: Path = typer.Option("umani.db", "--db"),
):
    """List findings for a scan."""
    store = Datastore(str(db))
    rows = store.list_findings(scan_id)
    if not rows:
        console.print("[yellow]No findings for that scan.[/yellow]")
        return

    t = Table("ID", "Severity", "Module", "Finding", "URL")
    for r in rows:
        color = {"critical": "red", "high": "red", "medium": "yellow",
                 "low": "cyan", "info": "white"}.get(r["severity"], "white")
        t.add_row(str(r["id"]), f"[{color}]{r['severity']}[/{color}]",
                  r["module"], r["name"], r["url"])
    console.print(t)


@app.command()
def repeater(
    finding_id: int = typer.Argument(...,
                                      help="Finding ID from `umani findings`"),
    scope_file: Path = typer.Option("scope.yaml", "--scope"),
    db: Path = typer.Option("umani.db", "--db"),
    url: str = typer.Option(None, "--url", help="Override URL"),
    method: str = typer.Option(None, "--method", "-X", help="Override method"),
    body: str = typer.Option(None, "--body", help="Override body"),
    param: list[str] = typer.Option(None, "--param", "-p",
                                     help="Override query param key=value"),
    header: list[str] = typer.Option(None, "--header", "-H",
                                      help="Add header key:value"),
):
    """Replay and modify a stored request."""
    scope = Scope(scope_file)
    store = Datastore(str(db))
    rep = Repeater(store, scope)

    set_params = {}
    for p in (param or []):
        if "=" in p:
            k, v = p.split("=", 1)
            set_params[k] = v

    add_headers = {}
    for h in (header or []):
        if ":" in h:
            k, v = h.split(":", 1)
            add_headers[k.strip()] = v.strip()

    result = rep.replay(
        finding_id,
        override_url=url,
        override_method=method,
        override_body=body.encode() if body else None,
        add_headers=add_headers or None,
        set_params=set_params or None,
    )

    console.print(f"[bold]Finding:[/bold] {result['finding']['name']}")
    console.print(f"[bold]Module:[/bold] {result['finding']['module']}")
    console.print()

    orig = result["original_response"]
    new = result["new_response"]
    orig_req = result["original_request"]

    t = Table("", "Original", "New")
    t.add_row("URL",
              orig_req["url"] if orig_req else "—",
              result["new_request"]["url"])
    t.add_row("Method",
              orig_req["method"] if orig_req else "—",
              result["new_request"]["method"])
    t.add_row("Status",
              str(orig["status"]) if orig else "—",
              str(new["status"]))
    t.add_row("Length",
              str(len(orig["body"])) if orig else "—",
              str(new["length"]))
    t.add_row("Time (ms)",
              str(orig["elapsed_ms"]) if orig else "—",
              str(new["elapsed_ms"]))
    console.print(t)

    console.print()
    console.print("[bold]New response preview:[/bold]")
    console.print(new["body_preview"])


@app.command()
def proxy(
    port: int = typer.Option(8080, "--port", "-p"),
    db: Path = typer.Option("umani.db", "--db"),
    intercept: bool = typer.Option(False, "--intercept", "-i",
                                    help="Pause requests until forward/drop"),
):
    """Start an HTTP forward proxy that logs all traffic."""
    store = Datastore(str(db))
    scope = Scope()
    p = Proxy(store, scope, host="127.0.0.1", port=port,
              intercept=intercept)
    p.start()

    console.print(f"[green]Proxy listening on[/green] http://127.0.0.1:{port}")
    if intercept:
        console.print("[yellow]INTERCEPT MODE ON[/yellow] — "
                      "requests pause until `umani queue` / `umani forward`")
    console.print()
    console.print("Configure your browser to use this proxy:")
    console.print(f"  HTTP  proxy: [bold]127.0.0.1:{port}[/bold]")
    console.print(f"  HTTPS proxy: [bold]127.0.0.1:{port}[/bold]")
    console.print()
    console.print("Or use curl:")
    console.print(f"  [bold]curl -x http://127.0.0.1:{port} http://example.com/[/bold]")
    console.print()
    console.print("[dim]Press Ctrl+C to stop.[/dim]")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping proxy…[/yellow]")
        QUEUE.clear()
        p.stop()


@app.command()
def queue():
    """List requests paused by intercept mode."""
    items = QUEUE.list_pending()
    if not items:
        console.print("[dim]No intercepted requests.[/dim]")
        return
    t = Table("ID", "Method", "URL", "Age (s)")
    for i in items:
        t.add_row(str(i.id), i.method, i.url,
                  f"{time.time() - i.created_at:.1f}")
    console.print(t)
    console.print()
    console.print("Forward: [bold]umani forward <id>[/bold]")
    console.print("Drop:    [bold]umani drop <id>[/bold]")


@app.command()
def forward(
    item_id: int = typer.Argument(...),
    method: str = typer.Option(None, "--method", "-X"),
    url: str = typer.Option(None, "--url"),
    header: list[str] = typer.Option(None, "--header", "-H",
                                      help="Replace header key:value"),
    body: str = typer.Option(None, "--body"),
):
    """Forward a paused request, optionally with edits."""
    item = QUEUE.get(item_id)
    if not item:
        console.print(f"[red]No pending request with id {item_id}.[/red]")
        return

    console.print(f"[bold]Original:[/bold] {item.method} {item.url}")
    if item.headers:
        for k, v in list(item.headers.items())[:10]:
            console.print(f"  {k}: {v}")
    if item.body:
        console.print(f"  Body: {item.body[:200]!r}")
    console.print()

    edited_headers = None
    if header:
        edited_headers = dict(item.headers)
        for h in header:
            if ":" in h:
                k, v = h.split(":", 1)
                edited_headers[k.strip()] = v.strip()

    ok = QUEUE.forward(item_id, method=method, url=url,
                       headers=edited_headers,
                       body=body.encode() if body else None)
    if ok:
        console.print(f"[green]Forwarded request {item_id}.[/green]")
    else:
        console.print(f"[red]Failed — request {item_id} already released.[/red]")


@app.command()
def drop(item_id: int = typer.Argument(...)):
    """Drop a paused request."""
    if QUEUE.drop(item_id):
        console.print(f"[green]Dropped request {item_id}.[/green]")
    else:
        console.print(f"[red]No pending request with id {item_id}.[/red]")


if __name__ == "__main__":
    app()
