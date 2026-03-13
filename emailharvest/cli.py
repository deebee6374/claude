"""
EmailHarvest CLI — OSINT email harvesting tool.

Usage examples:

  # Basic web crawl
  python -m emailharvest https://example.com

  # Full OSINT sweep (crawl + DNS/WHOIS + search dorking)
  python -m emailharvest example.com --all

  # Deep crawl with proxy
  python -m emailharvest https://example.com --depth 5 --max-pages 500 --proxy socks5://127.0.0.1:9050

  # DNS/WHOIS only
  python -m emailharvest example.com --module dns

  # Save results
  python -m emailharvest example.com --all -o results.json --format json
  python -m emailharvest example.com --all -o results.csv  --format csv

  # Parse a local document
  python -m emailharvest --doc /path/to/report.pdf

  # Use Google CSE for dorking
  python -m emailharvest example.com --module search --google-key YOUR_KEY --google-cx YOUR_CX
"""

import argparse
import logging
import os
import sys
from typing import Dict, Optional, Set
from urllib.parse import urlparse

from emailharvest import __version__
from emailharvest.output.formatters import to_plain, to_json, to_csv, save, print_rich_table


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _merge(base: Dict[str, Set[str]], new: Dict[str, Set[str]]) -> None:
    """Merge new results into base in-place."""
    for email, sources in new.items():
        if email not in base:
            base[email] = set()
        base[email] |= sources


def _domain_from_target(target: str) -> str:
    """Extract bare domain from a URL or plain domain string."""
    if "://" not in target:
        target = "https://" + target
    return urlparse(target).netloc.lower().lstrip("www.")


def _ensure_scheme(target: str) -> str:
    if "://" not in target:
        return "https://" + target
    return target


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
        level=level,
    )
    # Silence noisy third-party loggers unless verbose
    if not verbose:
        for noisy in ("urllib3", "requests", "chardet", "bs4", "pdfminer"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


# ──────────────────────────────────────────────────────────────────────────────
# Banner
# ──────────────────────────────────────────────────────────────────────────────

BANNER = r"""
  _____ __  __       _ _ _   _   _                           _
 | ____|  \/  | __ _(_) | | | | | | __ _ _ ____   _____  __| |_
 |  _| | |\/| |/ _` | | | |_| |/ _` | '__\ \ / / / _ \/ __|  _|
 | |___| |  | | (_| | | |  _  | (_| | |   \ V /  |  __/\__ \ |
 |_____|_|  |_|\__,_|_|_|_| |_|\__,_|_|    \_/    \___||___/\__|

  OSINT Email Harvesting Tool  v{version}
  For authorized security research and penetration testing only.
"""


# ──────────────────────────────────────────────────────────────────────────────
# Argument parser
# ──────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="emailharvest",
        description="OSINT email harvesting toolkit — crawl, dork, and DNS-mine email addresses.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    p.add_argument("target", nargs="?", help="Target URL or domain (e.g. https://example.com or example.com)")
    p.add_argument("--version", action="version", version=f"EmailHarvest {__version__}")

    # Module selection
    mod = p.add_argument_group("Module selection")
    mod.add_argument(
        "--module", "-m",
        choices=["crawl", "dns", "search", "docs", "all"],
        default="crawl",
        help="Module(s) to run (default: crawl). Use 'all' for everything.",
    )
    mod.add_argument("--all", "-a", action="store_true", help="Enable all modules (shorthand for --module all)")

    # Crawler options
    cr = p.add_argument_group("Crawler options")
    cr.add_argument("--depth", "-d", type=int, default=3, metavar="N", help="Maximum crawl depth (default: 3)")
    cr.add_argument("--max-pages", "-p", type=int, default=200, metavar="N", help="Maximum pages to crawl (default: 200)")
    cr.add_argument("--no-robots", action="store_true", help="Ignore robots.txt")
    cr.add_argument("--external-links", action="store_true", help="Follow links outside target domain")
    cr.add_argument("--delay", type=float, default=0.8, metavar="SEC", help="Delay between requests in seconds (default: 0.8)")

    # DNS/WHOIS options
    dns_grp = p.add_argument_group("DNS/WHOIS options")
    dns_grp.add_argument("--no-zone-transfer", action="store_true", help="Skip DNS zone transfer attempts")
    dns_grp.add_argument("--no-crtsh", action="store_true", help="Skip crt.sh certificate transparency lookup")

    # Search dorking options
    srch = p.add_argument_group("Search dorking options")
    srch.add_argument(
        "--engines", nargs="+",
        choices=["duckduckgo", "bing", "google"],
        default=["duckduckgo", "bing"],
        help="Search engines to use for dorking (default: duckduckgo bing)",
    )
    srch.add_argument("--google-key", metavar="KEY", help="Google Custom Search API key")
    srch.add_argument("--google-cx", metavar="CX", help="Google Custom Search Engine ID")
    srch.add_argument("--dork-delay", type=float, default=2.5, metavar="SEC", help="Delay between dork queries (default: 2.5)")

    # Document parsing
    doc_grp = p.add_argument_group("Document parsing")
    doc_grp.add_argument("--doc", metavar="PATH", help="Parse a single local document for emails")
    doc_grp.add_argument("--doc-dir", metavar="DIR", help="Recursively parse all documents in a directory")

    # Networking
    net = p.add_argument_group("Networking")
    net.add_argument("--proxy", metavar="URL", help="Proxy URL (e.g. socks5://127.0.0.1:9050)")
    net.add_argument("--timeout", type=int, default=15, metavar="SEC", help="HTTP timeout in seconds (default: 15)")
    net.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL certificate verification")

    # Output
    out = p.add_argument_group("Output")
    out.add_argument("--output", "-o", metavar="FILE", help="Save results to file")
    out.add_argument(
        "--format", "-f",
        choices=["plain", "json", "csv"],
        default="plain",
        help="Output format (default: plain)",
    )
    out.add_argument("--no-banner", action="store_true", help="Suppress ASCII banner")
    out.add_argument("--verbose", "-v", action="store_true", help="Verbose/debug output")
    out.add_argument("--quiet", "-q", action="store_true", help="Suppress all output except results")

    return p


# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────

def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.all:
        args.module = "all"

    # Require target unless in doc-only mode
    if not args.target and not args.doc and not args.doc_dir:
        parser.print_help()
        return 1

    _setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    if not args.no_banner and not args.quiet:
        print(BANNER.format(version=__version__))

    all_emails: Dict[str, Set[str]] = {}
    modules_used: list = []
    domain = _domain_from_target(args.target) if args.target else ""

    # ── Document-only mode ──────────────────────────────────────────────────
    if args.doc or args.doc_dir:
        from emailharvest.modules.doc_parser import DocumentParser
        parser_inst = DocumentParser()
        if args.doc:
            if not args.quiet:
                print(f"[*] Parsing document: {args.doc}")
            _merge(all_emails, parser_inst.parse_file(args.doc))
            modules_used.append("docs")
        if args.doc_dir:
            if not args.quiet:
                print(f"[*] Scanning directory: {args.doc_dir}")
            for root, _, files in os.walk(args.doc_dir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    _merge(all_emails, parser_inst.parse_file(fpath))
            modules_used.append("docs")
        if not args.target:
            _output_results(all_emails, domain, modules_used, args)
            return 0

    # ── Crawler module ───────────────────────────────────────────────────────
    if args.module in ("crawl", "all"):
        from emailharvest.modules.crawler import Crawler
        modules_used.append("crawl")
        url = _ensure_scheme(args.target)

        if not args.quiet:
            print(f"[*] Starting web crawl: {url} (depth={args.depth}, max_pages={args.max_pages})")

        def on_email(email: str, source: str) -> None:
            if not args.quiet:
                print(f"  [+] {email}  ← {source[:80]}")

        crawler = Crawler(
            target=url,
            depth=args.depth,
            max_pages=args.max_pages,
            stay_on_domain=not args.external_links,
            respect_robots=not args.no_robots,
            delay=args.delay,
            timeout=args.timeout,
            proxy=args.proxy,
            on_email_found=on_email,
        )
        crawl_results = crawler.crawl()
        _merge(all_emails, crawl_results)

        # Parse any documents the crawler found
        if crawler.document_queue and args.module == "all":
            if not args.quiet:
                print(f"[*] Fetching {len(crawler.document_queue)} document(s) discovered during crawl…")
            from emailharvest.modules.doc_parser import parse_remote_documents
            doc_emails = parse_remote_documents(crawler.document_queue, crawler.session, delay=args.delay)
            _merge(all_emails, doc_emails)
            if "docs" not in modules_used:
                modules_used.append("docs")

    # ── DNS / WHOIS module ───────────────────────────────────────────────────
    if args.module in ("dns", "all"):
        from emailharvest.modules.dns_whois import DNSWhoisHarvester
        modules_used.append("dns")
        if not args.quiet:
            print(f"[*] Running DNS/WHOIS harvest on: {domain}")
        dns_harvester = DNSWhoisHarvester(
            domain=domain,
            timeout=args.timeout,
            try_zone_transfer=not args.no_zone_transfer,
            check_crtsh=not args.no_crtsh,
        )
        _merge(all_emails, dns_harvester.harvest())

    # ── Search dorking module ─────────────────────────────────────────────────
    if args.module in ("search", "all"):
        from emailharvest.modules.search_dork import SearchDorkHarvester
        modules_used.append("search")
        if not args.quiet:
            print(f"[*] Running search dorks on: {domain} (engines: {', '.join(args.engines)})")
        dork_harvester = SearchDorkHarvester(
            domain=domain,
            engines=args.engines,
            delay=args.dork_delay,
            proxy=args.proxy,
            google_api_key=args.google_key,
            google_cx=args.google_cx,
        )
        _merge(all_emails, dork_harvester.harvest())

    # ── Output ────────────────────────────────────────────────────────────────
    _output_results(all_emails, domain, modules_used, args)
    return 0


def _output_results(
    all_emails: Dict[str, Set[str]],
    domain: str,
    modules_used: list,
    args,
) -> None:
    if not args.quiet:
        print_rich_table(all_emails, domain=domain, modules_used=modules_used)

    fmt = args.format
    if fmt == "json":
        content = to_json(all_emails, domain=domain, modules_used=modules_used)
    elif fmt == "csv":
        content = to_csv(all_emails, domain=domain, modules_used=modules_used)
    else:
        content = to_plain(all_emails)

    if args.output:
        save(content, args.output)
    elif args.quiet:
        # In quiet mode, only print the raw results
        print(content)


if __name__ == "__main__":
    sys.exit(main())
