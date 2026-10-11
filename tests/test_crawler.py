import unittest

from lib.crawler import WebCrawler


class CrawlerExtractionTests(unittest.TestCase):
    def test_form_actions_are_recorded_with_method_and_source(self):
        crawler = WebCrawler("https://example.com")
        body = b"""
            <html><body>
              <form action="/account/login" method="post"></form>
              <a href="/help">Help</a>
            </body></html>
        """

        urls, forms = crawler._extract_links("https://example.com/start", body)

        self.assertIn("https://example.com/account/login", urls)
        self.assertIn("https://example.com/help", urls)
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0].method, "POST")
        self.assertEqual(forms[0].source, "https://example.com/start")
        self.assertEqual(forms[0].category, "form")

    def test_duplicate_forms_are_only_recorded_once(self):
        crawler = WebCrawler("https://example.com")
        body = b'<form action="/search" method="get"></form>'

        _urls, first = crawler._extract_links("https://example.com/one", body)
        _urls, second = crawler._extract_links("https://example.com/two", body)

        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])


if __name__ == "__main__":
    unittest.main()
