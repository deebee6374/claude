"""
HTTP utilities: session management, rate limiting, user-agent rotation.
"""

import time
import random
import logging
from typing import Optional, Dict
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

# Rotating user-agents to avoid trivial bot detection
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]


def build_session(
    timeout: int = 15,
    max_retries: int = 3,
    proxy: Optional[str] = None,
    verify_ssl: bool = True,
) -> requests.Session:
    """Build a requests Session with retry logic and sensible defaults."""
    session = requests.Session()

    retry = Retry(
        total=max_retries,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    session.headers.update(
        {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
    )

    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    session.verify = verify_ssl
    session.timeout = timeout

    return session


def safe_get(
    session: requests.Session,
    url: str,
    timeout: int = 15,
    delay: float = 0.5,
    rotate_ua: bool = True,
) -> Optional[requests.Response]:
    """GET a URL with error handling, optional UA rotation, and polite delay."""
    if delay > 0:
        time.sleep(delay + random.uniform(0, delay * 0.5))

    if rotate_ua:
        session.headers["User-Agent"] = random.choice(USER_AGENTS)

    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True)
        resp.raise_for_status()
        return resp
    except requests.exceptions.SSLError:
        logger.warning("SSL error for %s, retrying without verify", url)
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True, verify=False)
            return resp
        except Exception as e:
            logger.debug("Failed (no-verify) %s: %s", url, e)
            return None
    except requests.exceptions.TooManyRedirects:
        logger.debug("Too many redirects: %s", url)
        return None
    except requests.exceptions.ConnectionError as e:
        logger.debug("Connection error %s: %s", url, e)
        return None
    except requests.exceptions.Timeout:
        logger.debug("Timeout: %s", url)
        return None
    except requests.exceptions.HTTPError as e:
        logger.debug("HTTP error %s: %s", url, e)
        return None
    except Exception as e:
        logger.debug("Unexpected error %s: %s", url, e)
        return None


def normalize_url(url: str, base: str) -> Optional[str]:
    """Resolve a potentially relative URL against a base."""
    from urllib.parse import urljoin, urlparse
    try:
        full = urljoin(base, url)
        parsed = urlparse(full)
        if parsed.scheme not in ("http", "https"):
            return None
        # Drop fragment
        return parsed._replace(fragment="").geturl()
    except Exception:
        return None


def same_domain(url: str, base_domain: str) -> bool:
    """Check if URL belongs to the same domain (or subdomain) as base."""
    try:
        host = urlparse(url).netloc.lower().lstrip("www.")
        base = base_domain.lower().lstrip("www.")
        return host == base or host.endswith("." + base)
    except Exception:
        return False
