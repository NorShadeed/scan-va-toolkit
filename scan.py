#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║              S C A N  —  VA CLI Toolkit  v1.0                   ║
║        Subdomain Finder  ·  API Endpoint Discovery               ║
╚══════════════════════════════════════════════════════════════════╝

Commands:
  scan subs      -d example.com
  scan endpoints -u https://api.example.com
  scan full      -d example.com

Run `scan <command> --help` for full options.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import json
import os
import sys
import time
import traceback

# Some Windows terminals still default to cp1252, which cannot encode the
# Unicode symbols used by the CLI help and status output. Preserve the active
# encoding but replace unsupported glyphs instead of crashing before a scan.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(errors="replace")
        except (AttributeError, OSError):
            pass

# ── Make lib/ importable whether the script is called from any cwd ──────────
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from lib.subfinder import SubfinderRecon, check_live, LiveSubdomain
from lib.api_discovery import APIDiscovery
from lib.crawler import WebCrawler, CrawlResult, CrawledURL

# ── Rich terminal output ─────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.table import Table
    from rich.text import Text
    _RICH = True
    console = Console(highlight=False)
except ImportError:
    _RICH = False

    class _FallbackConsole:
        def print(self, *args, **kwargs):
            # Strip any rich markup tags before printing
            import re
            text = " ".join(str(a) for a in args)
            text = re.sub(r"\[/?[^\]]*\]", "", text)
            print(text)
        def rule(self, title="", **kwargs):
            print(f"\n{'─' * 60}  {title}")

    console = _FallbackConsole()

# ── Colour helpers ───────────────────────────────────────────────────────────
def _m(tag: str, text: str) -> str:
    return f"[{tag}]{text}[/{tag}]" if _RICH else str(text)

ok   = lambda t: _m("bold green",   t)
warn = lambda t: _m("bold yellow",  t)
err  = lambda t: _m("bold red",     t)
info = lambda t: _m("bold cyan",    t)
hi   = lambda t: _m("bold magenta", t)
dim  = lambda t: _m("dim",          t)
bold = lambda t: _m("bold",         t)

# ── Priority helpers ─────────────────────────────────────────────────────────
def _priority_label(p: int) -> str:
    if p >= 80: return "HIGH"
    if p >= 60: return "MED"
    return "LOW"

def _priority_style(p: int) -> str:
    if p >= 80: return "bold red"
    if p >= 60: return "bold yellow"
    return "green"

# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────
_BANNER_TEXT = r"""
  ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ███████╗██║     ███████║██╔██╗ ██║
  ╚════██║██║     ██╔══██║██║╚████║
  ███████║╚██████╗██║  ██║██║ ╚███║
  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝"""

def print_banner() -> None:
    if _RICH:
        console.print(Panel(
            Text(_BANNER_TEXT, style="bold cyan") +
            Text("\n  VA CLI Toolkit — Subdomain Finder · API Discovery", style="dim"),
            border_style="cyan",
            padding=(0, 2),
        ))
    else:
        print(_BANNER_TEXT)
        print("  VA CLI Toolkit — Subdomain Finder · API Discovery")
        print("─" * 60)


# ─────────────────────────────────────────────────────────────────────────────
# Output / save helpers
# ─────────────────────────────────────────────────────────────────────────────
def _save(data: list, path: str, fmt: str) -> None:
    """Save *data* to *path* in the requested format."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    if fmt == "json":
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)

    elif fmt == "txt":
        with open(path, "w", encoding="utf-8") as fh:
            for item in data:
                if isinstance(item, dict):
                    line = item.get("url") or item.get("subdomain") or json.dumps(item)
                else:
                    line = str(item)
                fh.write(line + "\n")

    elif fmt == "csv":
        if not data:
            return
        with open(path, "w", newline="", encoding="utf-8") as fh:
            if isinstance(data[0], dict):
                writer = csv.DictWriter(fh, fieldnames=list(data[0].keys()))
                writer.writeheader()
                writer.writerows(data)
            else:
                writer = csv.writer(fh)
                for item in data:
                    writer.writerow([item])

    console.print(ok(f"✔ Saved → {path}"))


def _filter_endpoints(endpoints: list, args: argparse.Namespace) -> list:
    """Apply --min-priority and --methods filters."""
    min_p = getattr(args, "min_priority", 0) or 0
    methods_raw = getattr(args, "methods", None)

    if min_p:
        endpoints = [e for e in endpoints if e.get("priority", 0) >= min_p]

    if methods_raw:
        wanted = {m.strip().upper() for m in methods_raw.split(",")}
        endpoints = [e for e in endpoints if e.get("method", "").upper() in wanted]

    return endpoints


# ─────────────────────────────────────────────────────────────────────────────
# Command: subs
# ─────────────────────────────────────────────────────────────────────────────
def cmd_subs(args: argparse.Namespace) -> list[str]:
    domain    = args.domain.lower().strip()
    live_only = getattr(args, "live_only", False)
    lc_timeout= getattr(args, "live_timeout", 4)
    lc_threads= getattr(args, "live_threads", 100)
    source_threads = getattr(args, "source_threads", 6)
    subfinder_timeout = getattr(args, "subfinder_timeout", 120)
    all_sources = getattr(args, "all_sources", False)

    console.print(info(f"\n🌐  Subdomain enumeration  →  {domain}"))
    console.print(dim(f"   discovery sources running in parallel  (workers={source_threads})"))
    if live_only:
        console.print(dim(f"   live-check enabled  (timeout={lc_timeout}s  threads={lc_threads})"))
    console.rule(style="cyan") if _RICH else console.rule()

    recon = SubfinderRecon(
        timeout=getattr(args, "timeout", 30),
        source_workers=source_threads,
        binary_timeout=subfinder_timeout,
        all_sources=all_sources,
    )

    # ── Phase 1: discover ────────────────────────────────────────────────────
    t0 = time.monotonic()

    if _RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as prog:
            task = prog.add_task("[cyan]Hunting subdomains…", total=None)
            subdomains = recon.run(domain)
            prog.update(task, completed=True)
    else:
        console.print(dim("  Hunting subdomains…"))
        subdomains = recon.run(domain)

    # Always show provider health. A small result set is actionable only when
    # the user can see whether a source returned zero, was rate-limited, or was
    # not configured at all.
    console.print(info("\n  Source coverage"))
    for report in recon.last_report:
        if report.status == "ok":
            console.print(ok(
                f"    ✔ {report.name:<16} {report.count:>5} host(s)  {report.duration:.1f}s"
            ))
        elif report.status == "empty":
            console.print(dim(
                f"    · {report.name:<16}     0 host(s)  {report.duration:.1f}s"
            ))
        elif report.status == "skipped":
            console.print(warn(f"    ○ {report.name:<16} skipped — {report.error}"))
        else:
            console.print(err(
                f"    ✘ {report.name:<16} failed in {report.duration:.1f}s — {report.error}"
            ))

    if not recon.binary:
        console.print(warn(
            "\n  Coverage warning: Subfinder is not installed. "
            "Run install-subfinder.ps1 on Windows for substantially broader enumeration."
        ))

    if not subdomains:
        console.print(warn("⚠  No subdomains found."))
        return []

    console.print(dim(f"  Found {len(subdomains)} total (including possibly dead ones)…"))

    # ── Phase 2: optional liveness check ────────────────────────────────────
    if live_only:
        console.print(info(f"\n🔴  Live check — probing {len(subdomains)} subdomain(s)…"))

        _checked = {"n": 0}

        def _cb(sub: str, result):
            _checked["n"] += 1
            n = _checked["n"]
            if result is not None:
                s = result.status
                style = "bold red" if s >= 500 else "bold yellow" if s >= 400 else "bold green"
                console.print(
                    dim(f"  [{n:>4}/{len(subdomains)}] ") +
                    (f"[{style}]{s}[/{style}]" if _RICH else str(s)) +
                    dim(f"  {sub}")
                )
            elif n % 20 == 0:
                console.print(dim(f"  [{n:>4}/{len(subdomains)}] dead…"))

        live_results: list[LiveSubdomain] = check_live(
            subdomains,
            timeout=lc_timeout,
            threads=lc_threads,
            callback=_cb,
        )

        elapsed = round(time.monotonic() - t0, 1)

        if not live_results:
            console.print(warn("⚠  No live subdomains found."))
            return []

        dead_count = len(subdomains) - len(live_results)
        console.print(ok(
            f"\n✔  {len(live_results)} live  |  {dead_count} dead  |  {elapsed}s total"
        ))

        # ── Rich live-subdomain table ────────────────────────────────────────
        if _RICH:
            tbl = Table(
                title=f"[bold cyan]Live Subdomains of {domain}  ({len(live_results)})[/]",
                header_style="bold magenta",
                border_style="dim",
                show_lines=False,
            )
            tbl.add_column("#",          style="dim",  width=6,  justify="right")
            tbl.add_column("Status",     width=8,  justify="center")
            tbl.add_column("Scheme",     width=7,  style="bold blue")
            tbl.add_column("Subdomain",  style="bold green")
            tbl.add_column("Title",      style="dim")

            for i, lr in enumerate(live_results, 1):
                s = lr.status
                st_style = (
                    "bold red"    if s >= 500 else
                    "bold yellow" if s >= 400 else
                    "bold green"  if s == 200 else
                    "dim"
                )
                tbl.add_row(
                    str(i),
                    f"[{st_style}]{s}[/]",
                    lr.scheme,
                    lr.subdomain,
                    lr.title or "—",
                )
            console.print(tbl)
        else:
            print(f"\nLive Subdomains ({len(live_results)}):")
            print(f"  {'#':<5} {'Status':<8} {'Scheme':<7} Subdomain")
            print("─" * 80)
            for i, lr in enumerate(live_results, 1):
                print(f"  {i:<5} {lr.status:<8} {lr.scheme:<7} {lr.subdomain}")

        # Save / return just the live ones
        if args.output:
            data = [
                {
                    "subdomain": lr.subdomain,
                    "url":       lr.url,
                    "scheme":    lr.scheme,
                    "status":    lr.status,
                    "title":     lr.title,
                }
                for lr in live_results
            ]
            _save(data, args.output, args.format)

        return [lr.subdomain for lr in live_results]

    # ── No live check — standard table ──────────────────────────────────────
    elapsed = round(time.monotonic() - t0, 1)

    if _RICH:
        tbl = Table(
            title=f"[bold cyan]Subdomains of {domain}  ({len(subdomains)})[/]",
            header_style="bold magenta",
            border_style="dim",
            show_lines=False,
        )
        tbl.add_column("#",         style="dim",       width=6,  justify="right")
        tbl.add_column("Subdomain", style="bold green")
        for i, sub in enumerate(subdomains, 1):
            tbl.add_row(str(i), sub)
        console.print(tbl)
    else:
        print(f"\nSubdomains ({len(subdomains)}):")
        for i, sub in enumerate(subdomains, 1):
            print(f"  {i:>4}. {sub}")

    console.print(ok(f"\n✔  {len(subdomains)} subdomain(s) found in {elapsed}s"))

    if args.output:
        _save(subdomains, args.output, args.format)

    return subdomains




# ─────────────────────────────────────────────────────────────────────────────
# Command: endpoints
# ─────────────────────────────────────────────────────────────────────────────
def cmd_endpoints(args: argparse.Namespace) -> list[dict]:
    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    console.print(info(f"\n🔍  API endpoint discovery  →  {url}"))
    console.rule(style="cyan") if _RICH else console.rule()

    timeout = getattr(args, "timeout", 10)
    engine = APIDiscovery(url, timeout=timeout)

    t0 = time.monotonic()

    if _RICH:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as prog:
            task = prog.add_task("[cyan]Running discovery phases…", total=None)
            endpoints = engine.discover_all()
            prog.update(task, completed=True)
    else:
        console.print(dim("  Running discovery phases…"))
        endpoints = engine.discover_all()

    elapsed = round(time.monotonic() - t0, 1)

    endpoints = _filter_endpoints(endpoints, args)

    if not endpoints:
        console.print(warn("⚠  No endpoints discovered (try lowering --min-priority)."))
        return []

    # ── Table ───────────────────────────────────────────────────────────────
    if _RICH:
        tbl = Table(
            title=f"[bold cyan]Endpoints ({len(endpoints)})[/]",
            header_style="bold magenta",
            border_style="dim",
            show_lines=False,
        )
        tbl.add_column("PRI",    width=5,  justify="center")
        tbl.add_column("METHOD", width=8,  style="bold blue")
        tbl.add_column("URL",              style="cyan")
        tbl.add_column("SOURCE", width=12, style="dim")
        tbl.add_column("NOTES",  width=40, style="dim")

        for ep in endpoints:
            p = ep.get("priority", 50)
            tbl.add_row(
                f"[{_priority_style(p)}]{_priority_label(p)}[/]",
                ep.get("method", "GET"),
                ep.get("url", ""),
                ep.get("source", ""),
                (ep.get("description") or "")[:40],
            )
        console.print(tbl)
    else:
        print(f"\nEndpoints ({len(endpoints)}):")
        print(f"{'PRI':<5}  {'METHOD':<8}  URL")
        print("─" * 80)
        for ep in endpoints:
            p = ep.get("priority", 50)
            print(f"{_priority_label(p):<5}  {ep.get('method','GET'):<8}  {ep.get('url','')}")

    console.print(ok(f"\n✔  {len(endpoints)} endpoint(s) found in {elapsed}s"))

    if args.output:
        _save(endpoints, args.output, args.format)

    return endpoints


# ─────────────────────────────────────────────────────────────────────────────
# Command: full  (subs → endpoints on each)
# ─────────────────────────────────────────────────────────────────────────────
def cmd_full(args: argparse.Namespace) -> None:
    console.print(hi(f"\n🚀  Full recon mode  →  {args.domain}"))
    console.rule(style="magenta") if _RICH else console.rule()

    # Phase A — subdomains. Full mode owns the aggregate output file, so do
    # not briefly write subdomain-only data to that same path.
    sub_args = argparse.Namespace(**vars(args))
    sub_args.output = None
    subdomains = cmd_subs(sub_args)
    if not subdomains:
        console.print(warn("No subdomains found — aborting endpoint phase."))
        return

    # Phase B — endpoint discovery on each subdomain
    max_hosts: int = getattr(args, "max_hosts", 10)
    targets = subdomains[:max_hosts]

    console.print(info(
        f"\n🔍  Running endpoint discovery on {len(targets)} host(s) "
        f"(limit: {max_hosts})"
    ))
    console.rule(style="cyan") if _RICH else console.rule()

    all_endpoints: list[dict] = []

    for idx, sub in enumerate(targets, 1):
        target_url = f"https://{sub}" if not sub.startswith("http") else sub
        console.print(dim(f"  [{idx}/{len(targets)}] → {target_url}"))

        # Build a scoped args namespace for this subdomain
        ep_args = argparse.Namespace(**vars(args))
        ep_args.url    = target_url
        ep_args.output = None  # Aggregate output; don't write per-host

        try:
            eps = cmd_endpoints(ep_args)
            for ep in eps:
                ep.setdefault("subdomain", sub)
            all_endpoints.extend(eps)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            console.print(warn(f"  ⚠  Skipped {sub}: {exc}"))

        # Polite delay between hosts
        if idx < len(targets):
            time.sleep(1)

    # Summary
    console.print(ok(f"\n✔  Full recon done.  Total endpoints: {len(all_endpoints)}"))

    if args.output and all_endpoints:
        _save(all_endpoints, args.output, args.format)


# ─────────────────────────────────────────────────────────────────────────────
# Command: crawl  — spider every URL on a site by following real links
# ─────────────────────────────────────────────────────────────────────────────
def cmd_crawl(args: argparse.Namespace) -> None:
    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    max_pages  = getattr(args, "max_pages",   300)
    max_depth  = getattr(args, "max_depth",   6)
    timeout    = getattr(args, "timeout",     10)
    delay      = getattr(args, "delay",       0.05)
    no_assets  = getattr(args, "no_assets",   False)
    params_only= getattr(args, "params_only", False)

    console.print(info(f"\n🕷  Web Crawler  →  {url}"))
    console.print(dim(f"   max-pages={max_pages}  max-depth={max_depth}  timeout={timeout}s"))
    if _RICH:
        console.rule(style="cyan")
    else:
        console.rule()

    # ── Live progress counter ──────────────────────────────────────────────
    _progress_ref: dict = {"n": 0}

    def _on_visit(visited_url: str, status: int):
        _progress_ref["n"] += 1
        n = _progress_ref["n"]
        if n % 10 == 0 or status >= 400:
            s_style = "bold red" if status >= 400 else "dim"
            console.print(
                dim(f"  [{n:>4}] ") +
                (f"[{s_style}]{status}[/{s_style}]" if _RICH else str(status)) +
                dim(f"  {visited_url[:90]}")
            )

    # ── Run crawler ────────────────────────────────────────────────────────
    t0 = time.monotonic()
    crawler = WebCrawler(
        base_url=url,
        timeout=timeout,
        max_pages=max_pages,
        max_depth=max_depth,
        delay=delay,
        callback=_on_visit,
    )
    result: CrawlResult = crawler.crawl()
    elapsed = round(time.monotonic() - t0, 1)

    console.print(ok(f"\n✔  Crawl finished in {elapsed}s  —  {result.total} URLs found"))
    if _RICH:
        console.rule(style="cyan")
    else:
        console.rule()

    # ── Build display sections ─────────────────────────────────────────────
    sections = []

    if result.pages and not params_only:
        sections.append(("🗄  Pages", result.pages, "bold green"))

    if result.params:
        sections.append(("🎯  URLs with Parameters  (injection targets)", result.params, "bold yellow"))

    if result.forms and not params_only:
        sections.append(("📝  Forms", result.forms, "bold magenta"))

    if result.endpoints and not params_only:
        sections.append(("⚡  API Endpoints  (JSON/XML responses)", result.endpoints, "bold cyan"))

    if result.errors and not params_only:
        sections.append(("🚫  Errors  (4xx/5xx)", result.errors, "bold red"))

    if result.assets and not no_assets and not params_only:
        sections.append(("📦  Assets  (JS/CSS/images)", result.assets, "dim"))

    # ── Render tables ──────────────────────────────────────────────────────
    if _RICH:
        for title, items, style in sections:
            if not items:
                continue
            tbl = Table(
                title=f"[{style}]{title}  ({len(items)})[/]",
                header_style="bold magenta",
                border_style="dim",
                show_lines=False,
                min_width=80,
            )
            tbl.add_column("Status", width=8,  justify="center")
            tbl.add_column("Method", width=8,  style="bold blue")
            tbl.add_column("URL",               style=style)

            for item in items:
                status_str = str(item.status) if item.status else "—"
                status_style = (
                    "bold red"    if item.status >= 500 else
                    "bold yellow" if item.status >= 400 else
                    "bold green"  if item.status == 200 else
                    "dim"
                )
                tbl.add_row(
                    f"[{status_style}]{status_str}[/]",
                    item.method or "GET",
                    item.url,
                )
            console.print(tbl)
            console.print()
    else:
        for title, items, _style in sections:
            if not items:
                continue
            print(f"\n{title} ({len(items)})")
            print("─" * 80)
            for item in items:
                print(f"  {item.status or '?':>3}  {item.method or 'GET':<6}  {item.url}")

    # ── Summary ────────────────────────────────────────────────────────────
    console.print(dim(
        f"  Summary: "
        f"{len(result.pages)} pages  |  "
        f"{len(result.params)} param-URLs  |  "
        f"{len(result.forms)} forms  |  "
        f"{len(result.endpoints)} API endpoints  |  "
        f"{len(result.assets)} assets  |  "
        f"{len(result.errors)} errors"
    ))

    # ── Save output ────────────────────────────────────────────────────────
    if args.output:
        all_data = [
            {
                "url":          item.url,
                "status":       item.status,
                "method":       item.method or "GET",
                "category":     item.category,
                "content_type": item.content_type,
                "note":         item.note,
            }
            for item in result.all_urls
            if not (no_assets   and item.category == "asset")
            if not (params_only and item.category != "params")
        ]
        _save(all_data, args.output, args.format)


# ─────────────────────────────────────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────────────────────────────────────
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scan",
        description="VA CLI Toolkit — Subdomain Finder + API Endpoint Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  scan subs -d example.com
  scan subs -d example.com -o subs.txt

  scan endpoints -u https://api.example.com
  scan endpoints -u https://api.example.com --min-priority 60 -o out.json --format json
  scan endpoints -u https://api.example.com --methods GET,POST,DELETE

  scan full -d example.com --max-hosts 5 -o full.json --format json
        """,
    )
    parser.add_argument("--no-banner", action="store_true", help="Suppress the banner")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # ── subs ─────────────────────────────────────────────────────────────────
    p_subs = sub.add_parser("subs", help="Enumerate subdomains")
    p_subs.add_argument("-d", "--domain",  required=True, help="Target domain  e.g. example.com")
    p_subs.add_argument("-o", "--output",  default=None,  help="Output file path")
    p_subs.add_argument("--format", choices=["txt", "json", "csv"], default="txt",
                        help="Output format (default: txt)")
    p_subs.add_argument("--timeout", type=int, default=30,
                        help="HTTP timeout in seconds for enumeration (default: 30)")
    p_subs.add_argument("--source-threads", type=int, default=6, dest="source_threads",
                        help="Concurrent passive discovery sources (default: 6, max: 8)")
    p_subs.add_argument("--subfinder-timeout", type=int, default=120, dest="subfinder_timeout",
                        help="Maximum seconds for the optional subfinder binary (default: 120)")
    p_subs.add_argument("--all-sources", action="store_true", dest="all_sources",
                        help="Ask subfinder to use every provider (slower, potentially more results)")
    p_subs.add_argument("--live-only", action="store_true", dest="live_only",
                        help="Only show subdomains that respond to HTTP/HTTPS probes")
    p_subs.add_argument("--live-timeout", type=int, default=4, dest="live_timeout",
                        help="Timeout per live-check probe in seconds (default: 4)")
    p_subs.add_argument("--live-threads", "--workers", type=int, default=100, dest="live_threads",
                        help="Concurrent live-check workers (default: 100, max: 200)")
    p_subs.set_defaults(func=cmd_subs)

    # ── endpoints ────────────────────────────────────────────────────────────
    p_eps = sub.add_parser("endpoints", help="Discover API endpoints")
    p_eps.add_argument("-u", "--url",      required=True, help="Target URL  e.g. https://api.example.com")
    p_eps.add_argument("-o", "--output",   default=None,  help="Output file path")
    p_eps.add_argument("--format", choices=["txt", "json", "csv"], default="json",
                       help="Output format (default: json)")
    p_eps.add_argument("--timeout", type=int, default=10,
                       help="HTTP timeout in seconds (default: 10)")
    p_eps.add_argument("--min-priority", type=int, default=0, dest="min_priority",
                       help="Only show endpoints with priority >= N  (0–100, default: 0)")
    p_eps.add_argument("--methods", default=None,
                       help="Filter HTTP methods, comma-separated  e.g. GET,POST")
    p_eps.set_defaults(func=cmd_endpoints)

    # ── full ─────────────────────────────────────────────────────────────────
    p_full = sub.add_parser("full", help="Full recon: subs → endpoints on each")
    p_full.add_argument("-d", "--domain",  required=True, help="Target domain  e.g. example.com")
    p_full.add_argument("-o", "--output",  default=None,  help="Output file path")
    p_full.add_argument("--format", choices=["txt", "json", "csv"], default="json",
                        help="Output format (default: json)")
    p_full.add_argument("--max-hosts", type=int, default=10, dest="max_hosts",
                        help="Max subdomains to scan (default: 10)")
    p_full.add_argument("--timeout", type=int, default=10,
                        help="HTTP timeout in seconds (default: 10)")
    p_full.add_argument("--source-threads", type=int, default=6, dest="source_threads",
                        help="Concurrent passive discovery sources (default: 6, max: 8)")
    p_full.add_argument("--subfinder-timeout", type=int, default=120, dest="subfinder_timeout",
                        help="Maximum seconds for the optional subfinder binary (default: 120)")
    p_full.add_argument("--all-sources", action="store_true", dest="all_sources",
                        help="Ask subfinder to use every provider (slower, potentially more results)")
    p_full.add_argument("--min-priority", type=int, default=0, dest="min_priority",
                        help="Endpoint priority filter (default: 0)")
    p_full.add_argument("--methods", default=None,
                        help="Filter HTTP methods, comma-separated")
    p_full.add_argument("--live-only", action="store_true", dest="live_only",
                        help="Only run endpoint discovery on live subdomains")
    p_full.add_argument("--live-timeout", type=int, default=4, dest="live_timeout",
                        help="Timeout per live-check probe in seconds (default: 4)")
    p_full.add_argument("--live-threads", "--workers", type=int, default=100, dest="live_threads",
                        help="Concurrent live-check workers (default: 100, max: 200)")
    p_full.set_defaults(func=cmd_full)

    # ── crawl ─────────────────────────────────────────────────────────────────
    p_crawl = sub.add_parser(
        "crawl",
        help="Spider every URL on a site by following real links (finds .aspx, query params, etc.)",
        description=(
            "BFS web crawler — follows every <a href>, <form action>, and JS fetch call "
            "found on the target site. Finds URLs that fuzzing never could."
        ),
    )
    p_crawl.add_argument("-u", "--url", required=True, help="Target URL  e.g. http://10.5.2.10")
    p_crawl.add_argument("-o", "--output", default=None, help="Save results to file")
    p_crawl.add_argument("--format", choices=["txt", "json", "csv"], default="json",
                         help="Output format (default: json)")
    p_crawl.add_argument("--max-pages", type=int, default=300, dest="max_pages",
                         help="Max pages to crawl (default: 300)")
    p_crawl.add_argument("--max-depth", type=int, default=6, dest="max_depth",
                         help="Max link-follow depth (default: 6)")
    p_crawl.add_argument("--timeout", type=int, default=10,
                         help="HTTP timeout per request in seconds (default: 10)")
    p_crawl.add_argument("--delay", type=float, default=0.05,
                         help="Delay between requests in seconds (default: 0.05)")
    p_crawl.add_argument("--no-assets", action="store_true", dest="no_assets",
                         help="Hide JS/CSS/image URLs from output")
    p_crawl.add_argument("--params-only", action="store_true", dest="params_only",
                         help="Only show URLs that have query parameters")
    p_crawl.set_defaults(func=cmd_crawl)

    return parser


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    if not getattr(args, "no_banner", False):
        print_banner()

    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    console.print(dim(f"  Started: {ts}\n"))

    try:
        args.func(args)
    except KeyboardInterrupt:
        console.print(warn("\n\n⚡  Interrupted (Ctrl+C)"))
        sys.exit(130)
    except Exception as exc:
        console.print(err(f"\n✘  Fatal error: {exc}"))
        if os.getenv("SCAN_DEBUG"):
            traceback.print_exc()
        else:
            console.print(dim("  (set SCAN_DEBUG=1 for full traceback)"))
        sys.exit(1)


if __name__ == "__main__":
    main()
