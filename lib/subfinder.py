"""
Subdomain discovery module.

Discovery sources (run concurrently):
  1. subfinder binary  — fastest, most sources
  2. crt.sh            — certificate transparency logs
  3. Cert Spotter      — certificate transparency search
  4. URLScan           — historical public scan index
  5. HackerTarget      — free passive DNS API
  6. AlienVault OTX    — passive DNS when OTX_API_KEY is configured

Optional liveness check:
  check_live(subdomains) — concurrent HTTP/HTTPS probes, returns only
  subdomains that actually respond. Uses a thread pool so even 200+
  subdomains are checked in seconds instead of minutes.
"""

import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Common local and Go install locations.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_GO_BIN_CANDIDATES = [
    os.path.join(_PROJECT_ROOT, "tools", "subfinder.exe"),
    os.path.join(_PROJECT_ROOT, "tools", "subfinder"),
    os.path.join(_PROJECT_ROOT, "bin", "subfinder.exe"),
    os.path.expanduser("~/go/bin/subfinder"),
    os.path.expanduser("~/go/bin/subfinder.exe"),
    "/usr/local/bin/subfinder",
    "/usr/bin/subfinder",
    "/snap/bin/subfinder",
]

# Fast defaults, with a hard ceiling to avoid exhausting sockets/file handles.
_LIVE_CHECK_THREADS = 100
_MAX_LIVE_CHECK_THREADS = 200
_SOURCE_WORKERS = 6
_MAX_SOURCE_WORKERS = 8


def _new_session(retries: bool = True) -> requests.Session:
    """Build an isolated HTTP session safe for use by one worker thread."""
    session = requests.Session()
    session.verify = False
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; scan-cli/1.1)"})
    if retries:
        retry = Retry(
            total=2,
            connect=1,
            read=1,
            status=2,
            backoff_factor=0.25,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(("GET",)),
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=4, pool_maxsize=4)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
    return session


def _locate_subfinder() -> str | None:
    """
    Return the path to the subfinder binary, or None if not found.
    Avoids accidentally picking up this .py file itself.
    """
    candidate = shutil.which("subfinder")
    if candidate:
        if os.path.abspath(candidate) != os.path.abspath(__file__):
            return candidate

    for path in _GO_BIN_CANDIDATES:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path

    return None


# ── Liveness result ──────────────────────────────────────────────────────────

@dataclass
class LiveSubdomain:
    """A subdomain that responded to an HTTP/HTTPS probe."""
    subdomain: str          # e.g. api.example.com
    url:       str          # the URL that worked, e.g. https://api.example.com
    scheme:    str          # "https" or "http"
    status:    int          # HTTP status code (200, 301, 403, etc.)
    title:     str = ""     # <title> tag if available (helps identify what it is)


@dataclass
class SourceReport:
    """Outcome from one passive discovery provider."""
    name:     str
    status:   str            # ok / empty / error / skipped
    count:    int = 0
    duration: float = 0.0
    error:    str = ""


def check_live(
    subdomains: List[str],
    timeout:    int = 4,
    threads:    int = _LIVE_CHECK_THREADS,
    callback=None,           # optional fn(subdomain, result_or_none) for progress
) -> List[LiveSubdomain]:
    """
    Probe every subdomain concurrently over HTTPS then HTTP.
    Returns only those that actually respond (any HTTP status counts as live).

    Args:
        subdomains: list of hostname strings
        timeout:    seconds to wait for response data (default 4)
        threads:    how many concurrent probes (default 100, capped at 200)
        callback:   called after each probe with (subdomain, LiveSubdomain|None)

    Returns:
        Sorted list of LiveSubdomain, ordered by subdomain name.
    """
    # requests.Session is not guaranteed to be thread-safe. Give each pool
    # thread its own connection pool while still reusing connections handled
    # by that worker.
    worker_state = threading.local()
    timeout = max(1, int(timeout))
    worker_count = max(1, min(int(threads), _MAX_LIVE_CHECK_THREADS))

    def _worker_session() -> requests.Session:
        session = getattr(worker_state, "session", None)
        if session is None:
            session = _new_session(retries=False)
            worker_state.session = session
        return session

    def _probe(subdomain: str) -> Optional[LiveSubdomain]:
        """Try HTTPS first, fall back to HTTP. Return LiveSubdomain or None."""
        session = _worker_session()
        for scheme in ("https", "http"):
            url = f"{scheme}://{subdomain}"
            try:
                resp = session.get(
                    url,
                    # Fail fast when a host cannot be connected to, while
                    # still allowing the configured time for response data.
                    timeout=(min(timeout, 3), timeout),
                    allow_redirects=True,
                    stream=True,        # don't load full body
                )
                # Read only first 4 KB to grab the <title>
                chunk = b""
                for c in resp.iter_content(chunk_size=4096):
                    chunk = c
                    break
                resp.close()

                # Extract <title> if present
                title = ""
                try:
                    text = chunk.decode("utf-8", errors="replace")
                    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
                    if m:
                        title = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
                except Exception:
                    pass

                result = LiveSubdomain(
                    subdomain=subdomain,
                    url=resp.url,       # final URL after redirects
                    scheme=scheme,
                    status=resp.status_code,
                    title=title,
                )
                return result

            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout,
                    requests.exceptions.TooManyRedirects):
                # This scheme didn't work — try the next one
                continue
            except Exception:
                continue

        # Both HTTP and HTTPS failed — subdomain is dead / unreachable
        return None

    live: List[LiveSubdomain] = []
    # Avoid scheduling duplicate hosts and normalize input before creating the
    # worker pool. This matters with merged passive sources.
    targets = sorted({sub.strip().lower() for sub in subdomains if sub and sub.strip()})

    with ThreadPoolExecutor(max_workers=min(worker_count, len(targets) or 1)) as pool:
        futures = {pool.submit(_probe, sub): sub for sub in targets}
        for future in as_completed(futures):
            subdomain = futures[future]
            try:
                result = future.result()
            except Exception:
                result = None

            # Run UI callbacks on the caller thread, not worker threads. Rich
            # console rendering and simple counters are then deterministic.
            if callback:
                try:
                    callback(subdomain, result)
                except Exception:
                    pass

            if result is not None:
                live.append(result)

    return sorted(live, key=lambda x: x.subdomain)


# ── Main recon class ─────────────────────────────────────────────────────────

class SubfinderRecon:
    """
    Enumerate subdomains for a given domain using multiple sources.

    Usage:
        recon = SubfinderRecon(timeout=30)
        subs  = recon.run("example.com")          # List[str]
    """

    def __init__(
        self,
        timeout: int = 30,
        source_workers: int = _SOURCE_WORKERS,
        binary_timeout: int = 120,
        all_sources: bool = False,
    ):
        self.timeout = max(1, int(timeout))
        self.source_workers = max(1, min(int(source_workers), _MAX_SOURCE_WORKERS))
        self.binary_timeout = max(1, int(binary_timeout))
        self.all_sources = bool(all_sources)
        self.binary = _locate_subfinder()
        self.last_report: List[SourceReport] = []
        self.source_results: dict[str, set[str]] = {}

    # ──────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────

    def run(self, domain: str) -> List[str]:
        """
        Discover subdomains for *domain*.
        Returns a deduplicated, sorted list of subdomain strings.
        """
        domain = domain.lower().strip()
        results: set[str] = set()
        self.last_report = []
        self.source_results = {}

        # These sources are independent and network-bound, so run all of them
        # together. Total discovery time is now roughly the slowest source,
        # rather than the sum of every source's runtime.
        sources = [
            ("crt.sh", self._query_crtsh),
            ("Cert Spotter", self._query_certspotter),
            ("URLScan", self._query_urlscan),
            ("HackerTarget", self._query_hackertarget),
        ]
        if self.binary:
            sources.insert(0, ("Subfinder", self._run_binary))
        else:
            self.last_report.append(SourceReport(
                name="Subfinder",
                status="skipped",
                error="not installed (run install-subfinder.ps1 for broad coverage)",
            ))

        if os.getenv("OTX_API_KEY"):
            sources.append(("AlienVault OTX", self._query_otx))
        else:
            self.last_report.append(SourceReport(
                name="AlienVault OTX",
                status="skipped",
                error="OTX_API_KEY not configured",
            ))

        source_order = {
            name: index
            for index, name in enumerate((
                "Subfinder", "crt.sh", "Cert Spotter", "URLScan",
                "HackerTarget", "AlienVault OTX",
            ))
        }

        def _invoke(name, source):
            started = time.monotonic()
            try:
                found = self._clean_candidates(domain, source(domain))
                return found, SourceReport(
                    name=name,
                    status="ok" if found else "empty",
                    count=len(found),
                    duration=time.monotonic() - started,
                )
            except Exception as exc:
                return set(), SourceReport(
                    name=name,
                    status="error",
                    duration=time.monotonic() - started,
                    error=f"{type(exc).__name__}: {exc}"[:180],
                )

        with ThreadPoolExecutor(max_workers=min(self.source_workers, len(sources))) as pool:
            futures = [pool.submit(_invoke, name, source) for name, source in sources]
            for future in as_completed(futures):
                found, report = future.result()
                self.source_results[report.name] = found
                self.last_report.append(report)
                results.update(found)

        self.last_report.sort(key=lambda item: source_order.get(item.name, 999))
        return sorted(results)

    # ──────────────────────────────────────────────────────────────────────
    # Private sources
    # ──────────────────────────────────────────────────────────────────────

    def _run_binary(self, domain: str) -> List[str]:
        """Run the subfinder binary and return discovered subdomains."""
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, prefix="subfinder_"
        )
        tmp.close()

        try:
            cmd = [
                self.binary,
                "-d", domain,
                "-silent",
                "-o", tmp.name,
            ]
            # Subfinder's default provider set is optimized for speed and
            # reliability. The slower exhaustive provider set is opt-in.
            if self.all_sources:
                cmd.insert(-2, "-all")
            completed = subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=self.binary_timeout,
                check=False,
                text=True,
                errors="replace",
            )

            if os.path.exists(tmp.name):
                with open(tmp.name, "r", errors="ignore") as fh:
                    lines = [ln.strip() for ln in fh if ln.strip()]
                if lines:
                    return lines

            if completed.returncode != 0:
                detail = (completed.stderr or "").strip().splitlines()
                raise RuntimeError(detail[-1] if detail else f"exit code {completed.returncode}")

        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"timed out after {self.binary_timeout}s") from exc
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass

        return []

    def _query_crtsh(self, domain: str) -> List[str]:
        """Query crt.sh certificate transparency logs."""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        with _new_session() as session:
            resp = session.get(url, timeout=(min(self.timeout, 5), self.timeout))
        resp.raise_for_status()

        subs: set[str] = set()
        data = resp.json()
        if not isinstance(data, list):
            raise RuntimeError("unexpected response format")
        for entry in data:
            name_value = entry.get("name_value", "")
            for line in name_value.splitlines():
                line = line.strip().lower()
                if line and domain in line:
                    subs.add(line)

        return list(subs)

    def _query_certspotter(self, domain: str) -> List[str]:
        """Query SSLMate Cert Spotter with bounded cursor pagination."""
        url = "https://api.certspotter.com/v1/issuances"
        headers = {}
        api_key = os.getenv("CERTSPOTTER_API_KEY")
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        subs: set[str] = set()
        after = ""
        max_pages = 10 if (api_key or self.all_sources) else 3
        with _new_session() as session:
            session.headers.update(headers)
            for _page in range(max_pages):
                params = {
                    "domain": domain,
                    "include_subdomains": "true",
                    "expand": "dns_names",
                }
                if after:
                    params["after"] = after
                resp = session.get(
                    url,
                    params=params,
                    timeout=(min(self.timeout, 5), self.timeout),
                )
                resp.raise_for_status()
                data = resp.json()
                if not isinstance(data, list):
                    raise RuntimeError("unexpected response format")
                if not data:
                    break
                for issuance in data:
                    for hostname in issuance.get("dns_names", []):
                        if isinstance(hostname, str):
                            subs.add(hostname.lower())
                next_after = str(data[-1].get("id", ""))
                if not next_after or next_after == after:
                    break
                after = next_after

        return list(subs)

    def _query_urlscan(self, domain: str) -> List[str]:
        """Query URLScan's public search index and extract in-scope hosts."""
        url = "https://urlscan.io/api/v1/search/"
        size = 5000 if self.all_sources else 1000
        params = {
            "q": f"domain:{domain}",
            "size": str(size),
            "collapse": "page.domain.keyword",
        }
        with _new_session() as session:
            api_key = os.getenv("URLSCAN_API_KEY")
            if api_key:
                session.headers["api-key"] = api_key
            resp = session.get(
                url,
                params=params,
                timeout=(min(self.timeout, 5), self.timeout),
            )
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise RuntimeError("unexpected response format")

        subs: set[str] = set()
        for item in data.get("results", []):
            if not isinstance(item, dict):
                continue
            for section in (item.get("page", {}), item.get("task", {})):
                if not isinstance(section, dict):
                    continue
                hostname = section.get("domain")
                if isinstance(hostname, str):
                    subs.add(hostname.lower())
                raw_url = section.get("url")
                if isinstance(raw_url, str):
                    parsed_host = urlparse(raw_url).hostname
                    if parsed_host:
                        subs.add(parsed_host.lower())

        return list(subs)

    def _query_hackertarget(self, domain: str) -> List[str]:
        """Query HackerTarget passive DNS API (free tier)."""
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        with _new_session() as session:
            resp = session.get(url, timeout=(min(self.timeout, 5), self.timeout))
        resp.raise_for_status()

        if resp.text.lstrip().lower().startswith(("error", "api count exceeded")):
            raise RuntimeError(resp.text.strip()[:160])

        subs: set[str] = set()
        for line in resp.text.splitlines():
            parts = line.split(",")
            if parts and domain in parts[0]:
                subs.add(parts[0].strip().lower())

        return list(subs)

    def _query_otx(self, domain: str) -> List[str]:
        """Query AlienVault OTX passive DNS when an API key is configured."""
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        with _new_session() as session:
            session.headers["X-OTX-API-KEY"] = os.environ["OTX_API_KEY"]
            resp = session.get(url, timeout=(min(self.timeout, 5), self.timeout))
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise RuntimeError("unexpected response format")

        subs: set[str] = set()
        for record in data.get("passive_dns", []):
            if not isinstance(record, dict):
                continue
            for field in ("hostname", "host", "domain"):
                value = record.get(field)
                if isinstance(value, str):
                    subs.add(value.lower())
        return list(subs)

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _clean_candidates(domain: str, candidates) -> set[str]:
        """Normalize candidates and enforce an exact DNS-name boundary."""
        clean: set[str] = set()
        for candidate in candidates or []:
            if not isinstance(candidate, str):
                continue
            hostname = candidate.strip().lower().rstrip(".")
            if (
                hostname
                and (hostname == domain or hostname.endswith("." + domain))
                and "*" not in hostname
                and SubfinderRecon._is_valid_hostname(hostname)
            ):
                clean.add(hostname)
        return clean

    @staticmethod
    def _is_valid_hostname(hostname: str) -> bool:
        """Basic hostname sanity check."""
        if len(hostname) > 253:
            return False
        return bool(re.match(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$", hostname))
