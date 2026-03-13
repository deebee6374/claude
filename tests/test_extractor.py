"""
Unit tests for the email extractor module.
"""

import pytest
from emailharvest.utils.extractor import (
    extract_emails_raw,
    extract_emails_from_html,
    extract_emails_from_js,
    _is_valid,
    deduplicate,
)


class TestExtractEmailsRaw:
    def test_simple_email(self):
        assert "user@example.com" in extract_emails_raw("Contact user@example.com for help")

    def test_multiple_emails(self):
        text = "a@foo.com and b@bar.org and c@baz.co.uk"
        result = extract_emails_raw(text)
        assert "a@foo.com" in result
        assert "b@bar.org" in result
        assert "c@baz.co.uk" in result

    def test_obfuscation_at_brackets(self):
        text = "user [at] example [dot] com"
        result = extract_emails_raw(text)
        assert "user@example.com" in result

    def test_obfuscation_at_parens(self):
        text = "user (at) example (dot) com"
        result = extract_emails_raw(text)
        assert "user@example.com" in result

    def test_obfuscation_AT_DOT_uppercase(self):
        text = "user AT example DOT com"
        result = extract_emails_raw(text)
        assert "user@example.com" in result

    def test_obfuscation_paren_at(self):
        text = "user(at)example.com"
        result = extract_emails_raw(text)
        assert "user@example.com" in result

    def test_html_entity_at(self):
        text = "user&#64;example.com"
        result = extract_emails_raw(text)
        assert "user@example.com" in result

    def test_mailto_prefix(self):
        text = "Send to mailto:contact@example.com now"
        result = extract_emails_raw(text)
        assert "contact@example.com" in result

    def test_filters_image_extension(self):
        text = "icon@2x.png@example.com is noise"
        result = extract_emails_raw(text)
        # Should not contain a false positive from image filename
        assert "icon@2x.png" not in result

    def test_case_insensitive_normalisation(self):
        result = extract_emails_raw("ADMIN@EXAMPLE.COM")
        assert "admin@example.com" in result

    def test_no_emails_returns_empty(self):
        assert extract_emails_raw("no emails here, just text") == set()

    def test_subaddress_plus(self):
        result = extract_emails_raw("user+tag@example.com")
        assert "user+tag@example.com" in result


class TestExtractEmailsFromHtml:
    def test_mailto_href(self):
        html = '<a href="mailto:info@example.com">Contact us</a>'
        result = extract_emails_from_html(html)
        assert "info@example.com" in result

    def test_data_email_attribute(self):
        html = '<span data-email="hidden@example.com">click</span>'
        result = extract_emails_from_html(html)
        assert "hidden@example.com" in result

    def test_html_comment(self):
        html = "<!-- admin@example.com -->"
        result = extract_emails_from_html(html)
        assert "admin@example.com" in result

    def test_visible_text(self):
        html = "<p>Email us at support@company.org for assistance.</p>"
        result = extract_emails_from_html(html)
        assert "support@company.org" in result


class TestExtractEmailsFromJs:
    def test_string_literal(self):
        js = 'var contact = "dev@example.com";'
        result = extract_emails_from_js(js)
        assert "dev@example.com" in result

    def test_template_string(self):
        js = "const email = `noreply@service.io`;"
        result = extract_emails_from_js(js)
        # noreply is blacklisted
        assert "noreply@service.io" not in result

    def test_single_quoted(self):
        js = "sendTo('billing@shop.com');"
        result = extract_emails_from_js(js)
        assert "billing@shop.com" in result


class TestIsValid:
    def test_valid_email(self):
        assert _is_valid("user@example.com") is True

    def test_no_at(self):
        assert _is_valid("userexample.com") is False

    def test_no_domain(self):
        assert _is_valid("user@") is False

    def test_local_too_long(self):
        assert _is_valid("a" * 65 + "@example.com") is False

    def test_invalid_tld_png(self):
        assert _is_valid("user@example.png") is False

    def test_invalid_tld_js(self):
        assert _is_valid("user@bundle.js") is False

    def test_no_dot_in_domain(self):
        assert _is_valid("user@localhost") is False


class TestDeduplicate:
    def test_removes_duplicates(self):
        emails = ["a@x.com", "b@x.com", "a@x.com"]
        assert deduplicate(emails) == ["a@x.com", "b@x.com"]

    def test_preserves_order(self):
        emails = ["z@x.com", "a@x.com", "m@x.com"]
        assert deduplicate(emails) == ["z@x.com", "a@x.com", "m@x.com"]
