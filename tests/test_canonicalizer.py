import pytest
from phishwatch.app.services.canonicalizer import CanonicalizationError, URLCanonicalizer


def test_canonicalizes_url_and_etld():
    c = URLCanonicalizer().canonicalize("login.example.co.uk/portal?x=1")
    assert c.scheme == "https"
    assert c.hostname == "login.example.co.uk"
    assert c.apex_domain == "example.co.uk"
    assert c.subdomain == "login"
    assert c.tld == "co.uk"
    assert c.path == "/portal"


def test_punycode_idn():
    c = URLCanonicalizer().canonicalize("https://bücher.example/")
    assert c.hostname.startswith("xn--")
    assert c.unicode_hostname == "bücher.example"


def test_rejects_private_ip_and_localhost():
    with pytest.raises(CanonicalizationError):
        URLCanonicalizer().canonicalize("http://127.0.0.1")
    with pytest.raises(CanonicalizationError):
        URLCanonicalizer().canonicalize("http://localhost")
