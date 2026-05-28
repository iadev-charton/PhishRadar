from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session, joinedload
from phishwatch.app.db.models import Finding
from phishwatch.app.db.session import get_db
from phishwatch.app.schemas.finding import FindingResponse
from phishwatch.app.services.exporter import findings_to_csv, findings_to_json

router = APIRouter(prefix="/v1", tags=["findings"])


@router.get("/findings", response_model=list[FindingResponse])
def list_findings(db: Session = Depends(get_db), limit: int = 100, offset: int = 0) -> list[Finding]:
    return db.query(Finding).options(joinedload(Finding.variant)).order_by(Finding.created_at.desc()).offset(offset).limit(min(limit, 500)).all()


@router.get("/findings/{finding_id}", response_model=FindingResponse)
def get_finding(finding_id: str, db: Session = Depends(get_db)) -> Finding:
    finding = db.query(Finding).options(joinedload(Finding.variant)).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.get("/export/findings.csv")
def export_findings_csv(db: Session = Depends(get_db)) -> Response:
    findings = db.query(Finding).options(joinedload(Finding.variant)).order_by(Finding.created_at.desc()).all()
    return Response(findings_to_csv(findings), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=findings.csv"})


@router.get("/export/findings.json")
def export_findings_json(db: Session = Depends(get_db)) -> list[dict]:
    findings = db.query(Finding).options(joinedload(Finding.variant)).order_by(Finding.created_at.desc()).all()
    return findings_to_json(findings)
