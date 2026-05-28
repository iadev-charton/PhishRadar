from dataclasses import dataclass
from phishwatch.app.db.models import Verification
from phishwatch.app.services.variant_engine import skeletonize

SUSPICIOUS_WORDS = {"login", "secure", "account", "verify", "support"}
COMMON_TLDS = {"com", "org", "net", "edu", "gov", "es"}


@dataclass(frozen=True)
class ScoreResult:
    score: int
    severity: str
    factors: dict
    explanation: str


def severity_for(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


class RiskScorer:
    def score(self, *, seed_apex: str, variant_fqdn: str, attack_family: str, edit_distance: int, skeleton: str, tld: str, verification: Verification | None = None, reputation: dict | None = None) -> ScoreResult:
        score = 0
        factors: dict[str, int | bool | list[str]] = {}
        reasons: list[str] = []
        if edit_distance <= 1:
            score += 20; factors["edit_distance_1"] = 20; reasons.append("distancia de edición baja")
        if skeletonize(seed_apex) in skeleton or skeleton == skeletonize(seed_apex):
            score += 25; factors["similar_skeleton"] = 25; reasons.append("skeleton visual similar")
        if attack_family == "homoglyph":
            score += 25; factors["homoglyph"] = 25; reasons.append("homoglyph detectado")
        if tld not in COMMON_TLDS:
            score += 10; factors["unusual_tld"] = 10
        hits = [w for w in SUSPICIOUS_WORDS if w in variant_fqdn]
        if hits:
            score += 10; factors["suspicious_words"] = hits; reasons.append("contiene términos sensibles")
        if verification:
            if verification.dns_status == "RESOLVES":
                score += 15; factors["dns_resolves"] = 15; reasons.append("DNS activo")
            elif verification.dns_status == "NXDOMAIN":
                score -= 20; factors["dns_nxdomain"] = -20
            http_code = verification.http_json.get("status_code") if verification.http_json else None
            if isinstance(http_code, int) and 200 <= http_code < 400:
                score += 20; factors["http_accessible"] = 20; reasons.append("HTTP accesible")
            if verification.tls_json.get("temporal_valid"):
                score += 10; factors["tls_valid"] = 10; reasons.append("TLS válido temporalmente")
            if verification.mx_status == "RESOLVES":
                score += 15; factors["mx_active"] = 15
            final_url = verification.http_json.get("final_url", "") if verification.http_json else ""
            if final_url and seed_apex not in final_url and variant_fqdn not in final_url:
                score += 5; factors["external_redirect"] = 5
            if final_url and seed_apex in final_url:
                score -= 20; factors["redirects_to_legitimate"] = -20
        reputation = reputation or {}
        for key, points in {"phishtank_hit": 40, "safebrowsing_hit": 50, "urlscan_suspicious": 30}.items():
            if reputation.get(key):
                score += points; factors[key] = points
        score = max(0, min(100, score))
        explanation = f"Dominio {variant_fqdn} con similitud respecto a {seed_apex}; " + (", ".join(reasons) if reasons else "sin señales técnicas fuertes en el MVP") + "."
        return ScoreResult(score, severity_for(score), factors, explanation)
