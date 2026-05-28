import pytest
import dns.resolver
from phishwatch.app.db.models import Verification
from phishwatch.app.services.scorer import RiskScorer
from phishwatch.app.services.verifier import TechnicalVerifier


def test_scoring_classifies_high_signal():
    verification = Verification(dns_status="RESOLVES", dns_json={}, tls_status="OK", tls_json={"temporal_valid": True}, http_status="RESPONDS", http_json={"status_code": 200, "final_url": "https://login-examp1e.com/"}, mx_status="RESOLVES", mx_json={})
    score = RiskScorer().score(seed_apex="example.com", variant_fqdn="login-examp1e.com", attack_family="homoglyph", edit_distance=1, skeleton="login-example.com", tld="com", verification=verification)
    assert score.score >= 85
    assert score.severity == "critical"


@pytest.mark.asyncio
async def test_dns_verifier_nxdomain_mock(monkeypatch):
    def fake_resolve(*args, **kwargs):
        raise dns.resolver.NXDOMAIN
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve)
    dns_status, _, mx_status, _ = await TechnicalVerifier(timeout=0.1).check_dns("missing.example")
    assert dns_status == "NXDOMAIN"
    assert mx_status == "NXDOMAIN"
