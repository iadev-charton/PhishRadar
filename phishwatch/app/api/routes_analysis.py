from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from phishwatch.app.db.models import AnalysisJob, Finding, Variant, Verification
from phishwatch.app.db.session import get_db
from phishwatch.app.schemas.analysis import AnalyzeRequest, AnalyzeResponse, JobResponse
from phishwatch.app.schemas.variant import VariantResponse
from phishwatch.app.services.scorer import RiskScorer
from phishwatch.app.services.verifier import TechnicalVerifier
from phishwatch.app.workers.tasks import analyze_job

router = APIRouter(prefix="/v1", tags=["analysis"])


@router.post("/analyze", response_model=AnalyzeResponse, status_code=202)
def analyze(request: AnalyzeRequest, db: Session = Depends(get_db)) -> AnalyzeResponse:
    job = AnalysisJob(status="queued", message="Analysis queued", request=request.model_dump(mode="json"))
    db.add(job); db.commit(); db.refresh(job)
    analyze_job.delay(job.id)
    return AnalyzeResponse(job_id=job.id, status=job.status, message=job.message)


@router.get("/jobs/{job_id}", response_model=JobResponse)
def get_job(job_id: str, db: Session = Depends(get_db)) -> AnalysisJob:
    job = db.get(AnalysisJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@router.get("/seeds/{seed_id}/variants", response_model=list[VariantResponse])
def get_seed_variants(seed_id: str, db: Session = Depends(get_db)) -> list[Variant]:
    return db.query(Variant).filter(Variant.seed_id == seed_id).order_by(Variant.created_at.desc()).all()


@router.post("/reverify/{finding_id}")
async def reverify(finding_id: str, db: Session = Depends(get_db)) -> dict:
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    variant = db.get(Variant, finding.variant_id)
    result = await TechnicalVerifier().verify(variant.fqdn, active=True)
    verification = Verification(variant_id=variant.id, dns_status=result.dns_status, dns_json=result.dns_json, tls_status=result.tls_status, tls_json=result.tls_json, http_status=result.http_status, http_json=result.http_json, mx_status=result.mx_status, mx_json=result.mx_json)
    db.add(verification); db.flush()
    score = RiskScorer().score(seed_apex=finding.seed.apex_domain, variant_fqdn=variant.fqdn, attack_family=variant.attack_family, edit_distance=variant.edit_distance, skeleton=variant.skeleton, tld=variant.tld, verification=verification)
    finding.risk_score = score.score; finding.severity = score.severity; finding.factors = score.factors; finding.explanation = score.explanation
    db.commit()
    return {"finding_id": finding.id, "risk_score": score.score, "severity": score.severity}
