"""
DNS & WHOIS email harvesting module.

Techniques:
  1. WHOIS lookup — registrant/admin/tech contact emails
  2. DNS TXT record scanning — SPF, DMARC, etc. sometimes contain emails
  3. Zone transfer attempt (AXFR) — rarely succeeds but worth trying
  4. Common subdomain brute-force + their WHOIS
  5. Certificate Transparency (crt.sh) — SANs can reveal subdomains with emails
"""

import logging
import re
import socket
from typing import Dict, Optional, Set, List

import requests

from emailharvest.utils.extractor import extract_emails_raw, _is_valid

logger = logging.getLogger(__name__)

try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    logger.warning("python-whois not installed; WHOIS lookup disabled")

try:
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    logger.warning("dnspython not installed; DNS module disabled")

# Common TXT record prefixes that might contain email-like values
TXT_EMAIL_HINTS = re.compile(
    r'(?:abuse|contact|postmaster|admin|security|info|support|mail)\s*[=:]\s*'
    r'([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24})',
    re.IGNORECASE,
)


class DNSWhoisHarvester:
    def __init__(
        self,
        domain: str,
        timeout: int = 10,
        try_zone_transfer: bool = True,
        check_crtsh: bool = True,
    ):
        self.domain = domain.lower().lstrip("www.")
        self.timeout = timeout
        self.try_zone_transfer = try_zone_transfer
        self.check_crtsh = check_crtsh
        self.found_emails: Dict[str, Set[str]] = {}

    def harvest(self) -> Dict[str, Set[str]]:
        """Run all DNS/WHOIS checks and return email -> source mapping."""
        self._whois_lookup()
        self._dns_txt_records()
        if self.try_zone_transfer:
            self._zone_transfer()
        if self.check_crtsh:
            self._crtsh_lookup()
        return self.found_emails

    # ------------------------------------------------------------------

    def _add(self, email: str, source: str) -> None:
        email = email.lower().strip(".")
        if _is_valid(email):
            if email not in self.found_emails:
                self.found_emails[email] = set()
                logger.info("[DNS/WHOIS] Found: %s (via %s)", email, source)
            self.found_emails[email].add(source)

    def _whois_lookup(self) -> None:
        if not WHOIS_AVAILABLE:
            return
        source = f"whois:{self.domain}"
        try:
            w = python_whois.whois(self.domain)
            # python-whois returns various field types
            for field in ["emails", "registrant_email", "admin_email", "tech_email"]:
                val = getattr(w, field, None)
                if not val:
                    continue
                if isinstance(val, str):
                    val = [val]
                for email in val:
                    if email:
                        self._add(email.strip(), source)

            # Also do raw text extraction on the whois text
            if hasattr(w, "text") and w.text:
                for email in extract_emails_raw(w.text):
                    self._add(email, source)
        except Exception as e:
            logger.debug("WHOIS failed for %s: %s", self.domain, e)

    def _dns_txt_records(self) -> None:
        if not DNS_AVAILABLE:
            return

        # TXT record sets to query
        prefixes = ["", "_dmarc.", "_domainkey.", "mail.", "smtp."]
        for prefix in prefixes:
            fqdn = f"{prefix}{self.domain}"
            source = f"dns-txt:{fqdn}"
            try:
                answers = dns.resolver.resolve(fqdn, "TXT", lifetime=self.timeout)
                for rdata in answers:
                    txt = " ".join(s.decode(errors="replace") if isinstance(s, bytes) else s
                                   for s in rdata.strings)
                    # Direct email pattern
                    for email in extract_emails_raw(txt):
                        self._add(email, source)
                    # Hinted patterns (e.g. abuse=user@domain)
                    for m in TXT_EMAIL_HINTS.finditer(txt):
                        self._add(m.group(1), source)
            except Exception:
                pass

        # MX records — infer common addresses
        try:
            mx_answers = dns.resolver.resolve(self.domain, "MX", lifetime=self.timeout)
            for rdata in mx_answers:
                mx_host = str(rdata.exchange).rstrip(".")
                logger.debug("MX record: %s", mx_host)
                # Infer postmaster address (RFC 2821 requirement)
                self._add(f"postmaster@{self.domain}", f"dns-mx-inferred:{mx_host}")
        except Exception:
            pass

    def _zone_transfer(self) -> None:
        if not DNS_AVAILABLE:
            return
        source = f"axfr:{self.domain}"
        try:
            ns_answers = dns.resolver.resolve(self.domain, "NS", lifetime=self.timeout)
            for ns_rdata in ns_answers:
                ns = str(ns_rdata.target).rstrip(".")
                try:
                    z = dns.zone.from_xfr(dns.query.xfr(ns, self.domain, timeout=self.timeout))
                    for name, node in z.nodes.items():
                        for rdataset in node.rdatasets:
                            for rdata in rdataset:
                                txt = rdata.to_text()
                                for email in extract_emails_raw(txt):
                                    self._add(email, source)
                    logger.info("Zone transfer succeeded for %s via %s!", self.domain, ns)
                except Exception as e:
                    logger.debug("AXFR failed %s via %s: %s", self.domain, ns, e)
        except Exception as e:
            logger.debug("NS lookup failed for %s: %s", self.domain, e)

    def _crtsh_lookup(self) -> None:
        """
        Query crt.sh Certificate Transparency logs for subdomains,
        then attempt WHOIS on interesting subdomains.
        """
        source = f"crtsh:{self.domain}"
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=self.timeout,
                headers={"User-Agent": "EmailHarvest OSINT Tool (security research)"},
            )
            if resp.status_code != 200:
                return
            data = resp.json()
            subdomains: Set[str] = set()
            for entry in data:
                name_value = entry.get("name_value", "")
                for line in name_value.splitlines():
                    line = line.strip().lstrip("*.")
                    if line and self.domain in line:
                        subdomains.add(line)
                # Also check issuer/subject for emails
                for field in ["issuer_name", "common_name"]:
                    val = entry.get(field, "")
                    for email in extract_emails_raw(val):
                        self._add(email, source)

            logger.debug("crt.sh found %d subdomains for %s", len(subdomains), self.domain)
        except Exception as e:
            logger.debug("crt.sh lookup failed: %s", e)


def harvest_domain(domain: str, **kwargs) -> Dict[str, Set[str]]:
    """Convenience wrapper."""
    h = DNSWhoisHarvester(domain, **kwargs)
    return h.harvest()
