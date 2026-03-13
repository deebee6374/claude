"""
Search engine dorking module for email harvesting.

Constructs site-specific search queries to find exposed email addresses
indexed by search engines. Uses multiple search engines to maximize coverage.

Supported engines:
  - DuckDuckGo HTML (no API key needed, rate-limited)
  - Bing (no API key for basic scraping)
  - Google (via programmatic search — note ToS; use with own key or carefully)
  - Startpage
"""

import logging
import time
import random
import re
from typing import Dict, Optional, Set
from urllib.parse import quote_plus, urljoin

from bs4 import BeautifulSoup

from emailharvest.utils.extractor import extract_emails_from_html, _is_valid
from emailharvest.utils.http import build_session, safe_get

logger = logging.getLogger(__name__)

# Google Custom Search API endpoint (requires API key)
GOOGLE_CSE_URL = "https://www.googleapis.com/customsearch/v1"

# Dorks to run per domain
EMAIL_DORKS = [
    'site:{domain} "@{domain}"',
    'site:{domain} "email" filetype:html',
    'site:{domain} "contact" "@{domain}"',
    '"{domain}" email',
    '"{domain}" filetype:pdf email',
    '"@{domain}" -site:{domain}',         # Emails on OTHER sites mentioning the domain
    'site:{domain} inurl:contact',
    'site:{domain} inurl:about',
    'site:{domain} inurl:staff',
    'site:{domain} inurl:team',
    'site:{domain} inurl:people',
    'site:{domain} inurl:directory',
]


class SearchDorkHarvester:
    def __init__(
        self,
        domain: str,
        engines: Optional[list] = None,
        max_results_per_dork: int = 30,
        delay: float = 2.0,
        proxy: Optional[str] = None,
        google_api_key: Optional[str] = None,
        google_cx: Optional[str] = None,
    ):
        """
        Args:
            domain: Target domain (e.g. "example.com")
            engines: List of engines to use: ["duckduckgo", "bing", "google"]
            max_results_per_dork: Max search results to scrape per dork query
            delay: Seconds between search requests (be polite)
            proxy: Optional proxy URL
            google_api_key: Google Custom Search API key
            google_cx: Google Custom Search Engine ID
        """
        self.domain = domain.lower().lstrip("www.")
        self.engines = engines or ["duckduckgo", "bing"]
        self.max_results = max_results_per_dork
        self.delay = delay
        self.google_api_key = google_api_key
        self.google_cx = google_cx
        self.session = build_session(proxy=proxy)
        self.found_emails: Dict[str, Set[str]] = {}

    def harvest(self) -> Dict[str, Set[str]]:
        """Run all configured dorks across all configured engines."""
        dorks = [d.format(domain=self.domain) for d in EMAIL_DORKS]

        for engine in self.engines:
            for dork in dorks:
                logger.info("[SearchDork:%s] Query: %s", engine, dork)
                try:
                    if engine == "duckduckgo":
                        self._duckduckgo(dork)
                    elif engine == "bing":
                        self._bing(dork)
                    elif engine == "google" and self.google_api_key:
                        self._google_cse(dork)
                    time.sleep(self.delay + random.uniform(0, 1.0))
                except Exception as e:
                    logger.debug("[SearchDork:%s] Error on dork '%s': %s", engine, dork, e)

        return self.found_emails

    # ------------------------------------------------------------------

    def _add_from_text(self, text: str, source: str) -> None:
        for email in extract_emails_from_html(text):
            if self.domain in email.split("@")[-1] or f"@{self.domain}" in email:
                self._add(email, source)
            # Also add cross-domain references if the domain appears in surrounding text
            if _is_valid(email):
                self._add(email, source)

    def _add(self, email: str, source: str) -> None:
        email = email.lower().strip(".")
        if _is_valid(email):
            if email not in self.found_emails:
                self.found_emails[email] = set()
                logger.info("[SearchDork] Found: %s (via %s)", email, source)
            self.found_emails[email].add(source)

    def _duckduckgo(self, query: str) -> None:
        """
        DuckDuckGo HTML search (non-JS endpoint).
        """
        url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
        source = f"duckduckgo:{query}"
        resp = safe_get(self.session, url, delay=self.delay)
        if not resp:
            return

        soup = BeautifulSoup(resp.text, "lxml")

        # Extract from result snippets and URLs
        for result in soup.select(".result__body, .result__snippet, .result__url"):
            self._add_from_text(result.get_text(" ", strip=True), source)
            self._add_from_text(str(result), source)

        # Also scan the entire page text
        self._add_from_text(resp.text, source)

        # Follow result links for deeper extraction (first page only)
        result_links = []
        for a in soup.select(".result__a"):
            href = a.get("href", "")
            if href.startswith("http") and self.domain in href:
                result_links.append(href)

        for link in result_links[:5]:  # Limit follow-throughs
            time.sleep(self.delay / 2)
            page_resp = safe_get(self.session, link, delay=0)
            if page_resp:
                self._add_from_text(page_resp.text, f"duckduckgo-follow:{link}")

    def _bing(self, query: str) -> None:
        """Bing web search (HTML scraping)."""
        url = f"https://www.bing.com/search?q={quote_plus(query)}&count=50"
        source = f"bing:{query}"
        resp = safe_get(self.session, url, delay=self.delay)
        if not resp:
            return

        soup = BeautifulSoup(resp.text, "lxml")

        for result in soup.select(".b_caption, .b_algoSlug, .b_snippet"):
            self._add_from_text(result.get_text(" ", strip=True), source)

        # Bing sometimes shows cached contact pages
        self._add_from_text(resp.text, source)

        # Paginate up to max_results (10 per page by default on Bing)
        pages_to_fetch = min(self.max_results // 10, 3)
        for page in range(1, pages_to_fetch):
            time.sleep(self.delay + random.uniform(0.5, 1.5))
            paged_url = f"{url}&first={page * 10 + 1}"
            paged_resp = safe_get(self.session, paged_url, delay=0)
            if paged_resp:
                self._add_from_text(paged_resp.text, f"bing-p{page+1}:{query}")

    def _google_cse(self, query: str) -> None:
        """Google Custom Search Engine API (requires API key + CX)."""
        if not self.google_api_key or not self.google_cx:
            return
        source = f"google-cse:{query}"
        start = 1
        while start <= self.max_results:
            params = {
                "key": self.google_api_key,
                "cx": self.google_cx,
                "q": query,
                "start": start,
                "num": 10,
            }
            resp = safe_get(self.session, GOOGLE_CSE_URL + "?" + "&".join(f"{k}={quote_plus(str(v))}" for k, v in params.items()), delay=0)
            if not resp:
                break
            try:
                data = resp.json()
                items = data.get("items", [])
                if not items:
                    break
                for item in items:
                    self._add_from_text(item.get("snippet", ""), source)
                    self._add_from_text(item.get("htmlSnippet", ""), source)
                    self._add_from_text(item.get("link", ""), source)
                start += 10
                time.sleep(self.delay)
            except Exception as e:
                logger.debug("Google CSE parse error: %s", e)
                break


def harvest_domain(domain: str, **kwargs) -> Dict[str, Set[str]]:
    """Convenience wrapper."""
    h = SearchDorkHarvester(domain, **kwargs)
    return h.harvest()
