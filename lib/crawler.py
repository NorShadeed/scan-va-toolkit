"""
Web Crawler — discovers every URL on a target web application by following links.

Why this beats fuzzing for internal apps:
  Fuzzing guesses paths from a wordlist — it misses anything not on the list.
  Crawling READS the actual HTML/JS and follows every real link — nothing is missed.

Crawl strategy (BFS):
  1. Start from the base URL
  2. Fetch the page, extract ALL links (a, form, script, iframe, link, meta tags)
  3. Extract URLs from inline JavaScript patterns
  4. Queue any new same-origin URLs found
  5. Repeat until max_pages reached or no new URLs left

Results are categorised into:
  - pages      — HTML pages (200 responses)
  - endpoints  — API-like responses (JSON/XML, or path-only with no extension)
  - forms      — <form> actions with their HTTP method
  - params     — URLs containing query strings (prime injection targets)
  - assets     — JS / CSS / images / fonts
  - errors     — 4xx / 5xx responses
"""

from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlunparse, parse_qs

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Constants ────────────────────────────────────────────────────────────────

# Maximum response body to read per page (4 MB — enough for any HTML)
_MAX_BODY_BYTES = 4 * 1024 * 1024

# File extensions that are pure assets — we record but don't crawl into them
_ASSET_EXTENSIONS = {
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".pdf", ".zip",
    ".mp4", ".mp3", ".webp", ".map", ".xml", ".txt",
}

# Extensions that are pages we should crawl into
_PAGE_EXTENSIONS = {
    ".html", ".htm", ".aspx", ".asp", ".php", ".jsp", ".jspx",
    ".cfm", ".cshtml", ".erb", ".do", ".action", "",
}

# Inline JS patterns for extracting API calls / links
_JS_URL_PATTERNS = [
    r"""fetch\(['"]([^'"]+)['"]""",
    r"""axios\.[a-z]+\(['"]([^'"]+)['"]""",
    r"""\.get\(['"]([/][^'"]+)['"]""",
    r"""\.post\(['"]([/][^'"]+)['"]""",
    r"""\.put\(['"]([/][^'"]+)['"]""",
    r"""\.delete\(['"]([/][^'"]+)['"]""",
    r"""['"]url['"]\s*:\s*['"]([/][^'"]+)['"]""",
    r"""['"]href['"]\s*:\s*['"]([/][^'"]+)['"]""",
    r"""window\.location\s*=\s*['"]([^'"]+)['"]""",
    r"""window\.location\.href\s*=\s*['"]([^'"]+)['"]""",
    r"""location\.replace\(['"]([^'"]+)['"]""",
]

# ── Data model ───────────────────────────────────────────────────────────────

@dataclass
class CrawledURL:
    url:         str
    status:      int  = 0
    content_type:str  = ""
    method:      str  = "GET"   # for forms
    source:      str  = ""      # which page linked here
    category:    str  = ""      # page / endpoint / form / asset / error
    note:        str  = ""


@dataclass
class CrawlResult:
    base_url:   str
    pages:      List[CrawledURL] = field(default_factory=list)
    endpoints:  List[CrawledURL] = field(default_factory=list)
    forms:      List[CrawledURL] = field(default_factory=list)
    params:     List[CrawledURL] = field(default_factory=list)   # URLs with ?query=
    assets:     List[CrawledURL] = field(default_factory=list)
    errors:     List[CrawledURL] = field(default_factory=list)

    @property
    def all_urls(self) -> List[CrawledURL]:
        return self.pages + self.endpoints + self.forms + self.params + self.assets + self.errors

    @property
    def total(self) -> int:
        return len(self.all_urls)


# ── HTML parser ──────────────────────────────────────────────────────────────

class _LinkExtractor(HTMLParser):
    """
    Lightweight stdlib HTML parser that extracts:
      - <a href="…">
      - <form action="…" method="…">
      - <script src="…">
      - <link href="…">
      - <iframe src="…">
      - <img src="…">
      - <meta http-equiv="refresh" content="…url=…">
    """

    def __init__(self):
        super().__init__()
        self.links:  List[str]             = []   # plain href/src links
        self.forms:  List[Tuple[str, str]] = []   # (action, method)

    def handle_starttag(self, tag: str, attrs):
        attrs_d = dict(attrs)
        tag = tag.lower()

        if tag == "a":
            href = attrs_d.get("href", "").strip()
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                self.links.append(href)

        elif tag == "form":
            action = attrs_d.get("action", "").strip() or "."
            method = (attrs_d.get("method", "GET") or "GET").upper()
            if not action.startswith(("javascript:", "#")):
                self.forms.append((action, method))

        elif tag in ("script", "iframe", "frame"):
            src = attrs_d.get("src", "").strip()
            if src:
                self.links.append(src)

        elif tag == "link":
            href = attrs_d.get("href", "").strip()
            if href:
                self.links.append(href)

        elif tag in ("img", "source", "embed", "object"):
            for attr in ("src", "data"):
                val = attrs_d.get(attr, "").strip()
                if val:
                    self.links.append(val)

        elif tag == "meta":
            # <meta http-equiv="refresh" content="5; url=…">
            http_equiv = (attrs_d.get("http-equiv") or "").lower()
            if http_equiv == "refresh":
                content = attrs_d.get("content", "")
                m = re.search(r"url=([^\s;]+)", content, re.IGNORECASE)
                if m:
                    self.links.append(m.group(1).strip('"\''))


# ── Main crawler ─────────────────────────────────────────────────────────────

class WebCrawler:
    """
    BFS web crawler — follows every link it finds within the same origin.

    Usage:
        crawler = WebCrawler("http://10.5.2.10", max_pages=300, max_depth=6)
        result  = crawler.crawl()   # CrawlResult
    """

    def __init__(
        self,
        base_url:  str,
        timeout:   int = 10,
        max_pages: int = 300,
        max_depth: int = 6,
        delay:     float = 0.05,      # polite delay between requests (seconds)
        callback=None,                # optional fn(url, status) called per request
    ):
        parsed = urlparse(base_url)
        # Normalise: strip trailing slash, strip fragment
        self.base_url   = parsed.scheme + "://" + parsed.netloc
        self.base_path  = parsed.path.rstrip("/")
        self.origin     = parsed.netloc    # host[:port] — stay-in-scope check
        self.timeout    = timeout
        self.max_pages  = max_pages
        self.max_depth  = max_depth
        self.delay      = delay
        self.callback   = callback

        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0 Safari/537.36"
            ),
        })

        # State
        self._visited:  Set[str] = set()   # normalised URLs already fetched
        self._queued:   Set[str] = set()   # normalised URLs already enqueued
        self._forms_seen: Set[Tuple[str, str]] = set()

    # ── Public API ──────────────────────────────────────────────────────────

    def crawl(self) -> CrawlResult:
        result = CrawlResult(base_url=self.base_url)

        start_url = self._normalise(self.base_url + self.base_path + "/")
        queue: deque[Tuple[str, int]] = deque()   # (url, depth)
        queue.append((start_url, 0))
        self._queued.add(start_url)

        while queue and len(self._visited) < self.max_pages:
            url, depth = queue.popleft()

            if url in self._visited:
                continue

            self._visited.add(url)

            # ── Fetch ──────────────────────────────────────────────────────
            crawled, body, content_type = self._fetch(url)

            if self.callback:
                try:
                    self.callback(url, crawled.status)
                except Exception:
                    pass

            # ── Categorise ────────────────────────────────────────────────
            self._categorise(crawled, result)

            # ── Extract new links (only if this is an HTML page) ──────────
            if depth < self.max_depth and body and self._is_html(content_type, body):
                new_urls, new_forms = self._extract_links(url, body)
                result.forms.extend(new_forms)
                for new_url in new_urls:
                    if new_url not in self._queued and new_url not in self._visited:
                        self._queued.add(new_url)
                        queue.append((new_url, depth + 1))

            if self.delay:
                time.sleep(self.delay)

        return result

    # ── Fetch ───────────────────────────────────────────────────────────────

    def _fetch(self, url: str) -> Tuple[CrawledURL, Optional[bytes], str]:
        """
        Fetch *url* with a body cap.  Returns (CrawledURL, body_bytes, content_type).
        Body is None if fetch failed or response was too large to be useful.
        """
        crawled = CrawledURL(url=url)
        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                stream=True,
            )
            crawled.status = resp.status_code
            content_type   = resp.headers.get("Content-Type", "")
            crawled.content_type = content_type.split(";")[0].strip()

            # Read body up to cap
            chunks, total = [], 0
            for chunk in resp.iter_content(chunk_size=8192):
                chunks.append(chunk)
                total += len(chunk)
                if total > _MAX_BODY_BYTES:
                    break
            resp.close()

            body = b"".join(chunks)
            return crawled, body, content_type

        except requests.exceptions.ConnectionError:
            crawled.note = "Connection refused"
            return crawled, None, ""
        except requests.exceptions.Timeout:
            crawled.note = "Timeout"
            return crawled, None, ""
        except Exception as e:
            crawled.note = str(e)[:80]
            return crawled, None, ""

    # ── Link extraction ─────────────────────────────────────────────────────

    def _extract_links(self, page_url: str, body: bytes) -> Tuple[List[str], List[CrawledURL]]:
        """
        Extract and normalise all links from an HTML page body.
        Stays within the same origin.
        """
        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            return [], []

        found: Set[str] = set()
        forms: List[CrawledURL] = []

        # ── HTML tag extraction ────────────────────────────────────────────
        parser = _LinkExtractor()
        try:
            parser.feed(text)
        except Exception:
            pass

        for raw in parser.links:
            norm = self._resolve_and_normalise(page_url, raw)
            if norm:
                found.add(norm)

        for action, method in parser.forms:
            norm = self._resolve_and_normalise(page_url, action)
            if norm:
                found.add(norm)
                key = (norm, method)
                if key not in self._forms_seen:
                    self._forms_seen.add(key)
                    forms.append(CrawledURL(
                        url=norm,
                        method=method,
                        source=page_url,
                        category="form",
                        note="Form action",
                    ))

        # ── Inline JS extraction ──────────────────────────────────────────
        for pattern in _JS_URL_PATTERNS:
            try:
                for match in re.findall(pattern, text):
                    norm = self._resolve_and_normalise(page_url, match)
                    if norm:
                        found.add(norm)
            except Exception:
                continue

        # ── Bare URL regex (catches anything missed above) ────────────────
        # Look for quoted strings that look like paths: "/something/page.aspx?x=1"
        for raw in re.findall(r"""['"]([/][^'"<>\s]{2,200})['"]""", text):
            if " " in raw or "\n" in raw:
                continue
            norm = self._resolve_and_normalise(page_url, raw)
            if norm:
                found.add(norm)

        return list(found), forms

    # ── Categorisation ──────────────────────────────────────────────────────

    def _categorise(self, crawled: CrawledURL, result: CrawlResult) -> None:
        """Put a crawled URL into the right bucket in CrawlResult."""
        url = crawled.url
        status = crawled.status
        ct = crawled.content_type.lower()
        ext = self._extension(url).lower()
        has_params = "?" in url

        if status == 0:
            # Failed to connect / timeout — skip silently
            return

        if status >= 400:
            crawled.category = "error"
            result.errors.append(crawled)
            return

        if ext in _ASSET_EXTENSIONS:
            crawled.category = "asset"
            result.assets.append(crawled)
            return

        if "json" in ct or "xml" in ct:
            crawled.category = "endpoint"
            result.endpoints.append(crawled)
            return

        if has_params:
            crawled.category = "params"
            result.params.append(crawled)
            return

        crawled.category = "page"
        result.pages.append(crawled)

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _resolve_and_normalise(self, page_url: str, raw: str) -> Optional[str]:
        """
        Resolve *raw* relative to *page_url*, check it's same-origin,
        strip fragment, and return a normalised URL string — or None.
        """
        if not raw or raw.startswith(("data:", "javascript:", "mailto:", "tel:", "#")):
            return None
        try:
            full = urljoin(page_url, raw.strip())
            return self._normalise(full)
        except Exception:
            return None

    def _normalise(self, url: str) -> Optional[str]:
        """
        Normalise a URL: lowercase scheme+host, strip fragment.
        Returns None if not same-origin.
        """
        try:
            p = urlparse(url)
            if p.scheme not in ("http", "https"):
                return None
            if p.netloc.lower() != self.origin.lower():
                return None
            # Strip fragment, keep query string
            clean = urlunparse((p.scheme, p.netloc, p.path, "", p.query, ""))
            return clean
        except Exception:
            return None

    @staticmethod
    def _extension(url: str) -> str:
        path = urlparse(url).path
        dot = path.rfind(".")
        slash = path.rfind("/")
        if dot > slash:
            return path[dot:]
        return ""

    @staticmethod
    def _is_html(content_type: str, body: bytes) -> bool:
        ct = content_type.lower()
        if "html" in ct:
            return True
        # Sniff: most HTML starts with <!DOCTYPE or <html
        sniff = body[:512].lower()
        return b"<!doctype" in sniff or b"<html" in sniff
