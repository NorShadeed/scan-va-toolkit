"""
API Endpoint Discovery Engine.

Discovers endpoints using five methods in order:
  1. Swagger / OpenAPI spec  — parse documented endpoints
  2. Directory fuzzing        — probe common path wordlist
  3. Pattern generation       — infer variations from discovered paths
  4. Response analysis        — extract URLs embedded in JSON responses
  5. JavaScript parsing       — grep API calls from <script> tags
"""

import re
import time
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

import requests
import urllib3

# Suppress SSL warnings — normal in VA/pentest contexts
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Hard cap on how many bytes we will read from any single response.
# Prevents OOM on sites with massive JS bundles (Next.js, Webpack, etc.)
_MAX_RESPONSE_BYTES = 1 * 1024 * 1024   # 1 MB per file
_MAX_HTML_BYTES     = 2 * 1024 * 1024   # 2 MB for the homepage HTML

_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH"]

_SWAGGER_PATHS = [
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/docs",
    "/documentation",
    "/swagger",
    "/swagger-ui",
    "/redoc",
    "/api/docs",
    "/__swagger__",
    "/api/__swagger__",
]

# Curated wordlist — common REST API paths worth probing
_API_WORDLIST = [
    # Auth
    "auth", "login", "logout", "register", "signup", "token", "refresh",
    "oauth", "oauth2", "sso", "forgot-password", "reset-password",
    # Users
    "users", "user", "me", "profile", "account", "accounts",
    "admin", "admins", "staff",
    # Data
    "customers", "customer", "orders", "order", "products", "product",
    "items", "item", "posts", "post", "comments", "comment",
    "files", "file", "uploads", "upload", "download", "downloads",
    "media", "images", "attachments",
    # Settings
    "settings", "config", "configuration", "preferences",
    # Admin paths
    "admin/users", "admin/settings", "admin/logs", "admin/stats",
    "admin/dashboard",
    # Internal / debug (high value)
    "internal", "internal/api", "internal/debug", "internal/config",
    "debug", "debug/info", "debug/status", "debug/logs",
    "test", "dev", "staging",
    # Versioned APIs
    "v1", "v2", "v3", "api/v1", "api/v2", "api/v3",
    # Meta
    "status", "health", "healthz", "ping", "version", "info",
    # Operations
    "search", "query", "filter", "export", "import",
    "notifications", "messages", "inbox",
    "permissions", "roles", "groups", "teams",
    # Business
    "dashboard", "analytics", "reports", "statistics",
    "billing", "payments", "invoices", "subscriptions",
    "webhooks", "events", "logs", "audit",
    # CRUD shortcuts
    "create", "delete", "remove", "update", "edit", "list", "all",
]

# Priority scoring keywords
_HIGH_KEYWORDS  = ["admin", "internal", "debug", "test", "dev", "secret", "private"]
_DESTR_KEYWORDS = ["delete", "remove", "drop", "destroy", "reset"]
_MED_KEYWORDS   = ["/v1/", "/v2/", "/v3/", "auth", "login", "register", "token"]
_LOW_KEYWORDS   = ["public", "info", "health", "ping", "status", "docs"]

# JS regex patterns to find API calls in bundled JavaScript
_JS_PATTERNS = [
    r"""fetch\(['"]([^'"]+)['"]""",
    r"""axios\.[a-z]+\(['"]([^'"]+)['"]""",
    r"""\.get\(['"]([/][^'"]+)['"]""",
    r"""\.post\(['"]([/][^'"]+)['"]""",
    r"""\.put\(['"]([/][^'"]+)['"]""",
    r"""\.delete\(['"]([/][^'"]+)['"]""",
    r"""['"]api['"]:\s*['"]([^'"]+)['"]""",
    r"""['"]endpoint['"]:\s*['"]([^'"]+)['"]""",
    r"""['"]baseURL['"]:\s*['"]([^'"]+)['"]""",
    r"""['"]baseUrl['"]:\s*['"]([^'"]+)['"]""",
]

_URL_JSON_KEYS = {
    "url", "href", "link", "uri", "endpoint",
    "path", "_links", "next", "previous", "self", "related",
}


def _calculate_priority(url: str, method: str) -> int:
    """
    Score an endpoint 0–100.  Higher = more interesting to investigate.
    """
    u = url.lower()

    if any(k in u for k in _HIGH_KEYWORDS):
        return 90
    if any(k in u for k in _DESTR_KEYWORDS):
        return 85
    if method in ("DELETE", "PUT", "PATCH"):
        return 70
    if any(k in u for k in _MED_KEYWORDS):
        return 65
    if any(k in u for k in ["user", "account", "profile", "setting"]):
        return 60
    if any(k in u for k in _LOW_KEYWORDS):
        return 30
    return 50


class APIDiscovery:
    """
    Multi-method API endpoint discovery.

    Usage:
        engine    = APIDiscovery("https://api.example.com", timeout=10)
        endpoints = engine.discover_all()   # List[Dict]

    Each endpoint dict contains:
        url         str   — full URL
        method      str   — HTTP method
        source      str   — discovery method
        priority    int   — 0-100 (higher = more interesting)
        description str   — human-readable note
    """

    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

        self.session = requests.Session()
        self.session.verify = False          # common in VA environments
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0 Safari/537.36"
            ),
        })

        # Endpoints found so far — used by later phases
        self._found: List[Dict] = []

    # ──────────────────────────────────────────────────────────────────────
    # Safe fetch helpers
    # ──────────────────────────────────────────────────────────────────────

    def _safe_get(self, url: str, max_bytes: int = _MAX_RESPONSE_BYTES) -> requests.Response | None:
        """
        GET *url* but abort if the response body exceeds *max_bytes*.
        Returns the Response (with .text populated) or None if skipped/failed.

        Strategy:
          1. Send request with stream=True so we control how much we read.
          2. Check Content-Length header first — if it's already over the cap
             we skip without reading a single byte.
          3. Read the body in chunks, stopping at max_bytes.
        """
        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                stream=True,
                allow_redirects=True,
            )

            # Fast path: Content-Length header tells us it's too big
            content_length = resp.headers.get("Content-Length")
            if content_length and int(content_length) > max_bytes:
                resp.close()
                return None

            # Read up to max_bytes
            chunks: list[bytes] = []
            total = 0
            for chunk in resp.iter_content(chunk_size=8192):
                chunks.append(chunk)
                total += len(chunk)
                if total > max_bytes:
                    resp.close()
                    return None   # Too large — bail out

            # Stitch it back together and let requests decode it normally
            resp._content = b"".join(chunks)   # type: ignore[attr-defined]
            resp.encoding  = resp.apparent_encoding or "utf-8"
            return resp

        except Exception:
            return None

    # ──────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────

    def discover_all(self) -> List[Dict]:
        """
        Run all five discovery phases.
        Returns deduplicated, priority-sorted endpoint list.
        """
        phases = [
            ("Swagger / OpenAPI",           self._phase_swagger),
            ("Directory fuzzing",           self._phase_fuzzing),
            ("Pattern generation",          self._phase_patterns),
            ("Response analysis",           self._phase_responses),
            ("JavaScript parsing",          self._phase_javascript),
        ]

        for _name, fn in phases:
            try:
                new = fn()
                self._found.extend(new)
            except Exception:
                pass

        return self._deduplicate_and_sort(self._found)

    # ──────────────────────────────────────────────────────────────────────
    # Phase 1 — Swagger / OpenAPI
    # ──────────────────────────────────────────────────────────────────────

    def _phase_swagger(self) -> List[Dict]:
        """Probe known Swagger/OpenAPI paths and parse the spec."""
        for swagger_path in _SWAGGER_PATHS:
            try:
                url = self.base_url + swagger_path
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if resp.status_code == 200:
                    spec = resp.json()
                    endpoints = self._parse_openapi_spec(spec)
                    if endpoints:
                        return endpoints
            except Exception:
                continue
        return []

    def _parse_openapi_spec(self, spec: Dict) -> List[Dict]:
        """Extract all paths × methods from an OpenAPI 2.x / 3.x spec."""
        endpoints: List[Dict] = []
        paths = spec.get("paths", {})

        # Swagger 2.0 base path
        base_path = spec.get("basePath", "") if "swagger" in spec else ""

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, operation in methods.items():
                method = method.upper()
                if method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                    continue

                full_url = urljoin(self.base_url, base_path + path)
                desc = ""
                if isinstance(operation, dict):
                    desc = operation.get("summary", operation.get("description", ""))

                endpoints.append({
                    "url": full_url,
                    "method": method,
                    "source": "swagger",
                    "priority": _calculate_priority(full_url, method),
                    "description": (desc or "")[:120],
                })

        return endpoints

    # ──────────────────────────────────────────────────────────────────────
    # Phase 2 — Directory fuzzing
    # ──────────────────────────────────────────────────────────────────────

    def _phase_fuzzing(self) -> List[Dict]:
        """Probe every word in the wordlist with a GET request."""
        endpoints: List[Dict] = []
        interesting_codes = {200, 201, 204, 301, 302, 401, 403, 405}

        for word in _API_WORDLIST:
            url = f"{self.base_url}/{word}"
            try:
                resp = self.session.get(
                    url, timeout=self.timeout, allow_redirects=False
                )
                if resp.status_code in interesting_codes:
                    # Record all methods for this discovered path
                    for method in _HTTP_METHODS:
                        endpoints.append({
                            "url": url,
                            "method": method,
                            "source": "fuzzing",
                            "priority": _calculate_priority(url, method),
                            "description": f"HTTP {resp.status_code} on GET probe",
                        })
                    time.sleep(0.05)   # gentle rate limiting
            except Exception:
                continue

        return endpoints

    # ──────────────────────────────────────────────────────────────────────
    # Phase 3 — Pattern generation
    # ──────────────────────────────────────────────────────────────────────

    def _phase_patterns(self) -> List[Dict]:
        """
        Derive new candidate paths from what fuzzing already found:
        plural ↔ singular, common prefix/suffix combos.
        """
        found_urls = [e["url"] for e in self._found if e.get("source") == "fuzzing"]
        if not found_urls:
            return []

        # Extract path segments from found URLs
        segments: set[str] = set()
        for url in found_urls:
            path = urlparse(url).path
            segments.update(p for p in path.split("/") if p)

        # Build candidate variations
        candidates: set[str] = set()
        prefixes = ["admin", "internal", "api", "v1", "v2"]
        suffixes = ["list", "all", "search", "create", "update", "delete"]

        for seg in segments:
            # plural ↔ singular
            if seg.endswith("s") and len(seg) > 2:
                candidates.add(seg[:-1])
            else:
                candidates.add(seg + "s")
            # combos (limit to avoid explosion)
            for pre in prefixes:
                candidates.add(f"{pre}/{seg}")
            for suf in suffixes:
                candidates.add(f"{seg}/{suf}")

        # Probe candidates
        endpoints: List[Dict] = []
        interesting_codes = {200, 201, 401, 403}

        for candidate in list(candidates)[:60]:   # cap at 60 probes
            url = f"{self.base_url}/{candidate}"
            try:
                resp = self.session.get(
                    url, timeout=self.timeout, allow_redirects=False
                )
                if resp.status_code in interesting_codes:
                    endpoints.append({
                        "url": url,
                        "method": "GET",
                        "source": "pattern",
                        "priority": _calculate_priority(url, "GET"),
                        "description": f"Pattern-derived (HTTP {resp.status_code})",
                    })
                    time.sleep(0.05)
            except Exception:
                continue

        return endpoints

    # ──────────────────────────────────────────────────────────────────────
    # Phase 4 — Response analysis
    # ──────────────────────────────────────────────────────────────────────

    def _phase_responses(self) -> List[Dict]:
        """
        Fetch previously discovered endpoints and mine their JSON responses
        for embedded URLs.
        """
        endpoints: List[Dict] = []
        visited: set[str] = set()

        # Sample up to 30 already-found URLs
        probe_urls = list({e["url"] for e in self._found})[:30]

        for url in probe_urls:
            if url in visited:
                continue
            visited.add(url)

            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                for extracted in self._extract_urls_from_json(data):
                    full_url = urljoin(self.base_url, extracted)
                    if full_url.startswith(self.base_url):
                        endpoints.append({
                            "url": full_url,
                            "method": "GET",
                            "source": "response",
                            "priority": _calculate_priority(full_url, "GET"),
                            "description": f"Extracted from JSON at {url}",
                        })
            except Exception:
                continue

        return endpoints

    def _extract_urls_from_json(self, data, _depth: int = 0) -> Set[str]:
        """Recursively walk JSON looking for URL-like values."""
        urls: set[str] = set()
        if _depth > 4:
            return urls

        if isinstance(data, dict):
            for key, value in data.items():
                if key in _URL_JSON_KEYS and isinstance(value, str):
                    urls.add(value)
                elif isinstance(value, (dict, list)):
                    urls |= self._extract_urls_from_json(value, _depth + 1)
        elif isinstance(data, list):
            for item in data[:15]:
                if isinstance(item, (dict, list)):
                    urls |= self._extract_urls_from_json(item, _depth + 1)

        return urls

    # ──────────────────────────────────────────────────────────────────────
    # Phase 5 — JavaScript parsing
    # ──────────────────────────────────────────────────────────────────────

    def _phase_javascript(self) -> List[Dict]:
        """
        Fetch the homepage, find every <script src="…">, download each JS
        file, and regex-grep for API calls.

        Safety:
          - Homepage HTML capped at _MAX_HTML_BYTES (2 MB)
          - Each JS file capped at _MAX_RESPONSE_BYTES (1 MB)
          - Files exceeding the cap are silently skipped — no OOM risk
        """
        endpoints: List[Dict] = []

        # Fetch homepage with size cap
        home_resp = self._safe_get(self.base_url, max_bytes=_MAX_HTML_BYTES)
        if home_resp is None or home_resp.status_code != 200:
            return []

        # Find all external JS script sources
        js_sources = re.findall(
            r"""<script[^>]+src=['"]([^'"]+)['"]""",
            home_resp.text,
            re.IGNORECASE,
        )

        for js_path in js_sources[:15]:
            js_url = urljoin(self.base_url, js_path)

            # Download JS with strict 1 MB cap — skips huge webpack/Next.js bundles
            js_resp = self._safe_get(js_url, max_bytes=_MAX_RESPONSE_BYTES)
            if js_resp is None or js_resp.status_code != 200:
                continue

            try:
                js_text = js_resp.text
            except Exception:
                continue

            for pattern in _JS_PATTERNS:
                try:
                    for match in re.findall(pattern, js_text):
                        if not match.startswith(("/", "http")):
                            continue
                        full_url = urljoin(self.base_url, match)
                        if full_url.startswith(self.base_url):
                            endpoints.append({
                                "url": full_url,
                                "method": "GET",
                                "source": "javascript",
                                "priority": _calculate_priority(full_url, "GET"),
                                "description": f"Found in {js_path}",
                            })
                except Exception:
                    continue

        return endpoints

    # ──────────────────────────────────────────────────────────────────────
    # Deduplication
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _deduplicate_and_sort(endpoints: List[Dict]) -> List[Dict]:
        """Keep the first occurrence of each (url, method) pair, sort by priority."""
        seen: set[tuple] = set()
        unique: List[Dict] = []
        for ep in endpoints:
            key = (ep.get("url", ""), ep.get("method", "GET"))
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        unique.sort(key=lambda x: x.get("priority", 50), reverse=True)
        return unique
