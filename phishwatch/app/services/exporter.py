import csv
import io
from phishwatch.app.db.models import Finding


def findings_to_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "seed_id", "variant_id", "fqdn", "risk_score", "severity", "status", "explanation", "created_at"])
    for f in findings:
        writer.writerow([f.id, f.seed_id, f.variant_id, f.variant.fqdn if f.variant else "", f.risk_score, f.severity, f.status, f.explanation, f.created_at.isoformat()])
    return buf.getvalue()


def findings_to_json(findings: list[Finding]) -> list[dict]:
    return [{"id": f.id, "seed_id": f.seed_id, "variant_id": f.variant_id, "fqdn": f.variant.fqdn if f.variant else None, "risk_score": f.risk_score, "severity": f.severity, "status": f.status, "factors": f.factors, "explanation": f.explanation, "created_at": f.created_at.isoformat()} for f in findings]
