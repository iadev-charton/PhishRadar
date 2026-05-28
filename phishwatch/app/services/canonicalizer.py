from dataclasses import dataclass
import ipaddress
from urllib.parse import urlsplit, urlunsplit
import idna
import tldextract


class CanonicalizationError(ValueError):
    pass


@dataclass(frozen=True)
class CanonicalURL:
    input_url: str
    normalized_url: str
    scheme: str
    hostname: str
    unicode_hostname: str
    port: int | None
    path: str
    query: str
    apex_domain: str
    subdomain: str
    tld: str
    labels: list[str]


class URLCanonicalizer:
    def __init__(self, allow_private_ips: bool = False) -> None:
        self.allow_private_ips = allow_private_ips

    def canonicalize(self, raw_url: str) -> CanonicalURL:
        if not raw_url or not raw_url.strip():
            raise CanonicalizationError("URL must not be empty")
        value = raw_url.strip()
        if "://" not in value:
            value = f"https://{value}"
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"}:
            raise CanonicalizationError("Only HTTP and HTTPS URLs are supported")
        if not parsed.hostname:
            raise CanonicalizationError("URL must include a hostname")
        host = parsed.hostname.strip(".").lower()
        if host in {"localhost", "localhost.localdomain"}:
            raise CanonicalizationError("localhost is not allowed")
        try:
            ip = ipaddress.ip_address(host)
            if not self.allow_private_ips and (ip.is_private or ip.is_loopback or ip.is_link_local):
                raise CanonicalizationError("Private or local IP addresses are not allowed")
            raise CanonicalizationError("IP addresses are not supported as seeds")
        except ValueError:
            pass
        try:
            unicode_host = idna.decode(host.encode("ascii")) if host.startswith("xn--") or ".xn--" in host else host
            puny_host = idna.encode(unicode_host, uts46=True).decode("ascii").lower()
        except idna.IDNAError as exc:
            raise CanonicalizationError(f"Malformed IDN hostname: {exc}") from exc
        extracted = tldextract.extract(puny_host)
        if not extracted.suffix or not extracted.domain:
            raise CanonicalizationError("Hostname must contain a registrable domain")
        apex = f"{extracted.domain}.{extracted.suffix}"
        labels = puny_host.split(".")
        path = parsed.path or ""
        normalized = urlunsplit((parsed.scheme, puny_host + (f":{parsed.port}" if parsed.port else ""), path, parsed.query, ""))
        return CanonicalURL(raw_url, normalized, parsed.scheme, puny_host, unicode_host, parsed.port, path, parsed.query, apex, extracted.subdomain, extracted.suffix, labels)
