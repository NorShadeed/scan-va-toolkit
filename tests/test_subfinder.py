import threading
import time
import unittest
from unittest.mock import patch

from lib.subfinder import SubfinderRecon, check_live


class _FakeResponse:
    status_code = 200

    def __init__(self, url):
        self.url = url

    def iter_content(self, chunk_size=4096):
        yield b"<html><title>Test host</title></html>"

    def close(self):
        pass


class _ConcurrentFakeSession:
    active = 0
    max_active = 0
    lock = threading.Lock()

    def get(self, url, **kwargs):
        with self.lock:
            type(self).active += 1
            type(self).max_active = max(type(self).max_active, type(self).active)
        try:
            time.sleep(0.02)
            return _FakeResponse(url)
        finally:
            with self.lock:
                type(self).active -= 1


class SubfinderConcurrencyTests(unittest.TestCase):
    def test_discovery_sources_run_concurrently_and_filter_domain_boundary(self):
        recon = SubfinderRecon(source_workers=5)
        recon.binary = "fake-subfinder"
        barrier = threading.Barrier(5)

        def crt_source(domain):
            barrier.wait(timeout=1)
            return [f"crt.{domain}", f"not-{domain}"]

        def hacker_source(domain):
            barrier.wait(timeout=1)
            return [f"dns.{domain}"]

        def certspotter_source(domain):
            barrier.wait(timeout=1)
            return [f"cert.{domain}"]

        def urlscan_source(domain):
            barrier.wait(timeout=1)
            return [f"archive.{domain}"]

        def binary_source(domain):
            barrier.wait(timeout=1)
            return [f"bin.{domain}", f"crt.{domain}"]

        recon._query_crtsh = crt_source
        recon._query_hackertarget = hacker_source
        recon._query_certspotter = certspotter_source
        recon._query_urlscan = urlscan_source
        recon._run_binary = binary_source

        with patch.dict("os.environ", {"OTX_API_KEY": ""}):
            self.assertEqual(
                recon.run("example.com"),
                [
                    "archive.example.com",
                    "bin.example.com",
                    "cert.example.com",
                    "crt.example.com",
                    "dns.example.com",
                ],
            )
        self.assertEqual(
            [report.name for report in recon.last_report],
            ["Subfinder", "crt.sh", "Cert Spotter", "URLScan", "HackerTarget", "AlienVault OTX"],
        )

    def test_provider_failures_are_reported_instead_of_silently_disappearing(self):
        recon = SubfinderRecon(source_workers=4)
        recon.binary = None
        recon._query_crtsh = lambda _domain: (_ for _ in ()).throw(RuntimeError("upstream unavailable"))
        recon._query_certspotter = lambda _domain: []
        recon._query_urlscan = lambda domain: [f"archive.{domain}"]
        recon._query_hackertarget = lambda _domain: (_ for _ in ()).throw(RuntimeError("rate limited"))

        with patch.dict("os.environ", {"OTX_API_KEY": ""}):
            results = recon.run("example.com")

        self.assertEqual(results, ["archive.example.com"])
        statuses = {report.name: report.status for report in recon.last_report}
        self.assertEqual(statuses["Subfinder"], "skipped")
        self.assertEqual(statuses["crt.sh"], "error")
        self.assertEqual(statuses["Cert Spotter"], "empty")
        self.assertEqual(statuses["URLScan"], "ok")
        self.assertEqual(statuses["HackerTarget"], "error")

    def test_live_checks_use_multiple_workers_and_callback_on_caller_thread(self):
        _ConcurrentFakeSession.active = 0
        _ConcurrentFakeSession.max_active = 0
        caller_thread = threading.get_ident()
        callback_threads = []
        targets = [f"host{i}.example.com" for i in range(24)]

        with patch("lib.subfinder._new_session", side_effect=lambda **_kwargs: _ConcurrentFakeSession()):
            results = check_live(
                targets,
                timeout=1,
                threads=8,
                callback=lambda _subdomain, _result: callback_threads.append(threading.get_ident()),
            )

        self.assertEqual(len(results), len(targets))
        self.assertGreater(_ConcurrentFakeSession.max_active, 1)
        self.assertEqual(set(callback_threads), {caller_thread})

    @patch("lib.subfinder.subprocess.run")
    def test_exhaustive_subfinder_providers_are_opt_in(self, run_mock):
        run_mock.return_value.returncode = 0
        run_mock.return_value.stderr = ""
        fast = SubfinderRecon(all_sources=False)
        fast.binary = "subfinder"
        fast._run_binary("example.com")
        self.assertNotIn("-all", run_mock.call_args.args[0])

        exhaustive = SubfinderRecon(all_sources=True)
        exhaustive.binary = "subfinder"
        exhaustive._run_binary("example.com")
        self.assertIn("-all", run_mock.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
