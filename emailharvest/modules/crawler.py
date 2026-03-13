"""
Web crawler module — BFS crawler that harvests emails from web pages.

Features:
  - Respects robots.txt (optional)
  - Stays within target domain/subdomains by default
  - Configurable crawl depth and page limit
  - Extracts emails from HTML, inline JS, and linked JS files
  - Discovers and queues linked documents (PDF, DOCX, XLSX, etc.)
"""

import logging
import time
from collections import deque
from typing import Callable, Dict, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin
from urllib.robotparser import RobotFileParser

from bs4 import BeautifulSoup

from emailharvest.utils.extractor import extract_emails_from_html, extract_emails_from_js
from emailharvest.utils.http import build_session, safe_get, normalize_url, same_domain

logger = logging.getLogger(__name__)

# File extensions to hand off to the document parser instead of crawling
DOCUMENT_EXTENSIONS = {".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".odt", ".ods"}

# Extensions to skip entirely (binary, media, etc.)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".ico", ".webp",
    ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".mkv",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dmg", ".pkg", ".deb", ".rpm",
    ".woff", ".woff2", ".ttf", ".eot",
    ".css",
}


class Crawler:
    def __init__(
        self,
        target: str,
        depth: int = 3,
        max_pages: int = 200,
        stay_on_domain: bool = True,
        respect_robots: bool = True,
        delay: float = 0.8,
        timeout: int = 15,
        proxy: Optional[str] = None,
        on_email_found: Optional[Callable[[str, str], None]] = None,
        on_page_crawled: Optional[Callable[[str, int], None]] = None,
    ):
        """
        Args:
            target: Starting URL (e.g. https://example.com)
            depth: Maximum link depth from starting URL
            max_pages: Maximum number of pages to crawl
            stay_on_domain: Only follow links on the same domain/subdomains
            respect_robots: Honor robots.txt directives
            delay: Seconds to wait between requests (polite crawling)
            timeout: HTTP timeout per request
            proxy: Optional HTTP/SOCKS proxy URL
            on_email_found: Callback(email, source_url) called when a new email is found
            on_page_crawled: Callback(url, page_num) called after each page is crawled
        """
        self.target = target.rstrip("/")
        self.depth = depth
        self.max_pages = max_pages
        self.stay_on_domain = stay_on_domain
        self.respect_robots = respect_robots
        self.delay = delay
        self.timeout = timeout
        self.on_email_found = on_email_found
        self.on_page_crawled = on_page_crawled

        parsed = urlparse(target)
        self.base_domain = parsed.netloc.lower().lstrip("www.")
        self.scheme = parsed.scheme

        self.session = build_session(timeout=timeout, proxy=proxy)
        self.visited: Set[str] = set()
        self.found_emails: Dict[str, Set[str]] = {}  # email -> set of source URLs
        self.document_queue: Set[str] = set()  # docs handed off to doc parser
        self._robots: Optional[RobotFileParser] = None

        if respect_robots:
            self._load_robots(target)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def crawl(self) -> Dict[str, Set[str]]:
        """
        Run the BFS crawl.
        Returns: dict mapping email -> set of URLs where it was found.
        """
        # Queue entries: (url, current_depth)
        queue: deque[Tuple[str, int]] = deque()
        queue.append((self.target, 0))
        self.visited.add(self.target)
        pages_crawled = 0

        # Also check sitemap and robots for extra URLs
        for seed_url in self._discover_seeds():
            if seed_url not in self.visited:
                self.visited.add(seed_url)
                queue.append((seed_url, 1))

        while queue and pages_crawled < self.max_pages:
            url, current_depth = queue.popleft()

            if not self._is_allowed(url):
                logger.debug("robots.txt blocked: %s", url)
                continue

            ext = self._url_extension(url)
            if ext in SKIP_EXTENSIONS:
                continue
            if ext in DOCUMENT_EXTENSIONS:
                self.document_queue.add(url)
                continue

            logger.info("[%d/%d] Crawling (depth=%d): %s", pages_crawled + 1, self.max_pages, current_depth, url)
            resp = safe_get(self.session, url, timeout=self.timeout, delay=self.delay)

            if resp is None:
                continue

            pages_crawled += 1
            if self.on_page_crawled:
                self.on_page_crawled(url, pages_crawled)

            content_type = resp.headers.get("Content-Type", "")
            body = resp.text

            # Extract emails
            if "javascript" in content_type:
                new_emails = extract_emails_from_js(body)
            else:
                new_emails = extract_emails_from_html(body)

            for email in new_emails:
                if email not in self.found_emails:
                    self.found_emails[email] = set()
                    if self.on_email_found:
                        self.on_email_found(email, url)
                self.found_emails[email].add(url)

            # Discover linked JS files for email scanning
            if "html" in content_type or not content_type:
                soup = BeautifulSoup(body, "lxml")
                for script in soup.find_all("script", src=True):
                    js_url = normalize_url(script["src"], url)
                    if js_url and js_url not in self.visited:
                        self.visited.add(js_url)
                        js_resp = safe_get(self.session, js_url, timeout=self.timeout, delay=self.delay / 2)
                        if js_resp:
                            js_emails = extract_emails_from_js(js_resp.text)
                            for email in js_emails:
                                if email not in self.found_emails:
                                    self.found_emails[email] = set()
                                    if self.on_email_found:
                                        self.on_email_found(email, js_url)
                                self.found_emails[email].add(js_url)

                # Queue new links if within depth
                if current_depth < self.depth:
                    for link in self._extract_links(soup, url):
                        if link not in self.visited:
                            if self.stay_on_domain and not same_domain(link, self.base_domain):
                                continue
                            self.visited.add(link)
                            queue.append((link, current_depth + 1))

        logger.info("Crawl complete. Pages: %d, Emails: %d, Docs queued: %d",
                    pages_crawled, len(self.found_emails), len(self.document_queue))
        return self.found_emails

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> list:
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if href.startswith("mailto:") or href.startswith("tel:") or href.startswith("#"):
                continue
            normalized = normalize_url(href, base_url)
            if normalized:
                links.append(normalized)
        return links

    def _discover_seeds(self) -> list:
        """Parse sitemap.xml and robots.txt for additional starting URLs."""
        seeds = []
        for path in ["/sitemap.xml", "/sitemap_index.xml"]:
            url = f"{self.scheme}://{self.base_domain}{path}"
            resp = safe_get(self.session, url, timeout=self.timeout, delay=0)
            if resp and resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "lxml-xml")
                for loc in soup.find_all("loc"):
                    link = loc.get_text(strip=True)
                    if link and link not in self.visited:
                        seeds.append(link)
                logger.debug("Found %d URLs in sitemap: %s", len(seeds), url)
        return seeds

    def _load_robots(self, target: str) -> None:
        parsed = urlparse(target)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            rp = RobotFileParser()
            rp.set_url(robots_url)
            rp.read()
            self._robots = rp
        except Exception as e:
            logger.debug("Could not load robots.txt: %s", e)

    def _is_allowed(self, url: str) -> bool:
        if self._robots is None:
            return True
        try:
            return self._robots.can_fetch("*", url)
        except Exception:
            return True

    @staticmethod
    def _url_extension(url: str) -> str:
        path = urlparse(url).path.lower()
        if "." in path.split("/")[-1]:
            return "." + path.rsplit(".", 1)[-1]
        return ""
