"""
Core email extraction utilities.
Regex-based and heuristic email detection from raw text/HTML.
"""

import re
import html
from typing import Set, List
from urllib.parse import unquote


# RFC 5321 compliant-ish email regex (practical variant)
EMAIL_PATTERN = re.compile(
    r"""
    (?<![a-zA-Z0-9._%+\-])          # no prefix chars (negative lookbehind)
    (
        [a-zA-Z0-9._%+\-]{1,64}      # local part
        @
        (?:[a-zA-Z0-9\-]{1,63}\.)+   # domain labels
        [a-zA-Z]{2,24}               # TLD
    )
    (?![a-zA-Z0-9._%+\-@])           # no suffix chars (negative lookahead)
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Obfuscation patterns commonly used on websites
OBFUSCATION_PATTERNS = [
    # user [at] domain [dot] com
    (re.compile(r'([a-zA-Z0-9._%+\-]+)\s*[\[\(]at[\]\)]\s*([a-zA-Z0-9.\-]+)\s*[\[\(]dot[\]\)]\s*([a-zA-Z]{2,24})', re.IGNORECASE), lambda m: f"{m.group(1)}@{m.group(2)}.{m.group(3)}"),
    # user AT domain DOT com
    (re.compile(r'([a-zA-Z0-9._%+\-]+)\s+AT\s+([a-zA-Z0-9.\-]+)\s+DOT\s+([a-zA-Z]{2,24})'), lambda m: f"{m.group(1)}@{m.group(2)}.{m.group(3)}"),
    # user(at)domain.com
    (re.compile(r'([a-zA-Z0-9._%+\-]+)\(at\)([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24})', re.IGNORECASE), lambda m: f"{m.group(1)}@{m.group(2)}"),
    # mailto:user@domain
    (re.compile(r'mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24})', re.IGNORECASE), lambda m: m.group(1)),
    # HTML entity encoded @  (&#64; or &#x40;)
    (re.compile(r'([a-zA-Z0-9._%+\-]+)(?:&#64;|&#x40;|%40)([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24})', re.IGNORECASE), lambda m: f"{m.group(1)}@{m.group(2)}"),
]

# Commonly invalid/noise emails to filter out
BLACKLIST_PATTERNS = re.compile(
    r'^(.*\.(png|jpg|jpeg|gif|svg|css|js|woff|woff2|ttf|eot|ico|webp)@|'
    r'noreply@|no-reply@|donotreply@|'
    r'example\.|test\.|localhost@|'
    r'.*@.*\.example\.com$|'
    r'[^@]{65,}@)',  # local part > 64 chars
    re.IGNORECASE,
)

# Valid TLDs check (very broad — allows anything 2–24 chars, but filters obvious junk)
INVALID_TLD = re.compile(r'\.(png|jpg|jpeg|gif|bmp|svg|css|js|min|map|gz|zip|tar|exe|dll|so|dylib|woff2?|ttf|eot|ico|webp|json|xml|html?|php|asp|aspx|jsp|ts|tsx|jsx|vue|scss|sass|less|coffee|md|txt|log|csv|sql|db|sqlite|lock|env|cfg|conf|ini|yaml|yml|toml)$', re.IGNORECASE)


def extract_emails_raw(text: str) -> Set[str]:
    """Extract email addresses from raw text using regex."""
    emails: Set[str] = set()

    # Decode common encodings first
    text = html.unescape(text)
    text = unquote(text)

    # Standard extraction
    for match in EMAIL_PATTERN.finditer(text):
        email = match.group(1).lower().strip(".")
        if _is_valid(email):
            emails.add(email)

    # Obfuscation patterns
    for pattern, resolver in OBFUSCATION_PATTERNS:
        for match in pattern.finditer(text):
            try:
                email = resolver(match).lower().strip(".")
                if _is_valid(email):
                    emails.add(email)
            except (IndexError, AttributeError):
                pass

    return emails


def extract_emails_from_js(js_text: str) -> Set[str]:
    """Extract emails embedded in JavaScript (string literals, template strings)."""
    emails: Set[str] = set()

    # Look for string-encoded emails in JS
    js_string_pattern = re.compile(
        r"""['"`]([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24})['"`]"""
    )
    for match in js_string_pattern.finditer(js_text):
        email = match.group(1).lower()
        if _is_valid(email):
            emails.add(email)

    # Also run standard extraction
    emails |= extract_emails_raw(js_text)
    return emails


def extract_emails_from_html(html_text: str) -> Set[str]:
    """
    Extract emails from HTML source, including:
    - Visible text
    - href="mailto:..." attributes
    - data-* attributes
    - Comments
    """
    emails: Set[str] = set()

    # mailto: links
    mailto_pattern = re.compile(
        r'mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24})',
        re.IGNORECASE,
    )
    for match in mailto_pattern.finditer(html_text):
        email = match.group(1).lower().strip(".")
        if _is_valid(email):
            emails.add(email)

    # data-email attributes
    data_email_pattern = re.compile(
        r'data-[a-z\-]*email[a-z\-]*\s*=\s*["\']([^"\']+)["\']',
        re.IGNORECASE,
    )
    for match in data_email_pattern.finditer(html_text):
        email = match.group(1).lower().strip()
        if _is_valid(email):
            emails.add(email)

    # General extraction from the whole HTML
    emails |= extract_emails_raw(html_text)
    return emails


def _is_valid(email: str) -> bool:
    """Basic validation to filter garbage."""
    if not email or "@" not in email:
        return False
    local, _, domain = email.partition("@")
    if not local or not domain:
        return False
    if len(local) > 64 or len(domain) > 253:
        return False
    if BLACKLIST_PATTERNS.search(email):
        return False
    if INVALID_TLD.search(email):
        return False
    if domain.count(".") == 0:
        return False
    return True


def deduplicate(emails: List[str]) -> List[str]:
    """Remove duplicates, preserve insertion order."""
    seen: Set[str] = set()
    result = []
    for e in emails:
        if e not in seen:
            seen.add(e)
            result.append(e)
    return result
