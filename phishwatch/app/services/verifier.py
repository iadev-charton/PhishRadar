from dataclasses import dataclass
from datetime import UTC, datetime
import re
import socket
import ssl
from email.utils import parsedate_to_datetime
import dns.exception
import dns.resolver
import httpx
from phishwatch.app.core.config import get_settings


@dataclass(frozen=True)
class VerificationResult:
    dns_status: str
    dns_json: dict
    tls_status: str
    tls_json: dict
    http_status: str
    http_json: dict
    mx_status: str
    mx_json: dict


class TechnicalVerifier:
    def __init__(self, timeout: float | None = None, max_redirects: int | None = None) -> None:
        settings = get_settings()
        self.timeout = timeout or settings.http_timeout_seconds
        self.max_redirects = max_redirects or settings.max_redirects
        self.user_agent = settings.user_agent

    async def verify(self, fqdn: str, active: bool = True) -> VerificationResult:
        if not active:
            return VerificationResult("SKIPPED", {}, "SKIPPED", {}, "SKIPPED", {}, "SKIPPED", {})
        dns_status, dns_json, mx_status, mx_json = await self.check_dns(fqdn)
        tls_status, tls_json = self.check_tls(fqdn) if dns_status == "RESOLVES" else ("SKIPPED", {})
        http_status, http_json = await self.check_http(fqdn) if dns_status == "RESOLVES" else ("SKIPPED", {})
        return VerificationResult(dns_status, dns_json, tls_status, tls_json, http_status, http_json, mx_status, mx_json)

    async def check_dns(self, fqdn: str) -> tuple[str, dict, str, dict]:
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        records: dict[str, list[str]] = {}
        status = "NXDOMAIN"
        try:
            for rtype in ["A", "AAAA", "CNAME", "NS"]:
                try:
                    answers = resolver.resolve(fqdn, rtype)
                    records[rtype] = [a.to_text() for a in answers]
                    status = "RESOLVES"
                except dns.resolver.NoAnswer:
                    records[rtype] = []
            try:
                mx = resolver.resolve(fqdn, "MX")
                mx_records = [m.to_text() for m in mx]
                mx_status = "RESOLVES"
            except dns.resolver.NoAnswer:
                mx_records = []
                mx_status = "NXDOMAIN"
            return status, records, mx_status, {"MX": mx_records}
        except dns.resolver.NXDOMAIN:
            return "NXDOMAIN", records, "NXDOMAIN", {"MX": []}
        except dns.exception.Timeout:
            return "TIMEOUT", records, "TIMEOUT", {"MX": []}
        except Exception as exc:
            return "ERROR", {"error": str(exc), **records}, "ERROR", {"error": str(exc)}

    def check_tls(self, fqdn: str) -> tuple[str, dict]:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((fqdn, 443), timeout=self.timeout) as sock, ctx.wrap_socket(sock, server_hostname=fqdn) as ssock:
                cert = ssock.getpeercert()
            not_before = cert.get("notBefore")
            not_after = cert.get("notAfter")
            now = datetime.now(UTC)
            temporal_valid = True
            if not_before and parsedate_to_datetime(not_before) > now:
                temporal_valid = False
            if not_after and parsedate_to_datetime(not_after) < now:
                temporal_valid = False
            return "OK", {"issuer": cert.get("issuer"), "subject": cert.get("subject"), "sans": cert.get("subjectAltName", []), "not_before": not_before, "not_after": not_after, "temporal_valid": temporal_valid}
        except Exception as exc:
            return "ERROR", {"error": str(exc)}

    async def check_http(self, fqdn: str) -> tuple[str, dict]:
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True, max_redirects=self.max_redirects, headers={"User-Agent": self.user_agent}) as client:
            for method in ("HEAD", "GET"):
                try:
                    resp = await client.request(method, f"https://{fqdn}/")
                except Exception as exc:
                    if method == "GET":
                        return "ERROR", {"error": str(exc)}
                    continue
                if method == "HEAD" and resp.status_code in {405, 403}:
                    continue
                text = "" if method == "HEAD" else resp.text[:8192]
                title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
                return "RESPONDS", {"status_code": resp.status_code, "final_url": str(resp.url), "title": title_match.group(1).strip()[:200] if title_match else None, "content_type": resp.headers.get("content-type"), "content_length": resp.headers.get("content-length"), "redirect_chain": [str(r.url) for r in resp.history]}
        return "ERROR", {"error": "No HTTP method completed"}
