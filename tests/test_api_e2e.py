from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from phishwatch.app.db.base import Base
from phishwatch.app.db.session import get_db
from phishwatch.app.main import app

engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
Base.metadata.create_all(bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


def test_analyze_endpoint_and_mock_flow(monkeypatch):
    from phishwatch.app.workers import tasks
    # Force task execution against the same in-memory test DB dependency by running a tiny synchronous API smoke test.
    response = client.post("/v1/analyze", json={"url": "https://login.example.com/portal", "options": {"active_verification": False}, "sources": ["mock_feed"]})
    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "queued"
    job = client.get(f"/v1/jobs/{body['job_id']}")
    assert job.status_code == 200
    assert client.get("/v1/health").json() == {"status": "ok"}


def test_end_to_end_mock_feed_worker():
    import asyncio
    from phishwatch.app.db.models import AnalysisJob, Finding, Variant
    from phishwatch.app.db.session import SessionLocal
    from phishwatch.app.workers.tasks import run_analysis

    db = SessionLocal()
    job = AnalysisJob(request={"url": "https://login.example.com/portal", "options": {"active_verification": False, "tlds": ["com", "net"]}, "sources": ["mock_feed"]})
    db.add(job); db.commit(); job_id = job.id; db.close()
    asyncio.run(run_analysis(job_id))
    db = SessionLocal()
    done = db.get(AnalysisJob, job_id)
    assert done.status == "completed"
    assert db.query(Variant).filter(Variant.seed_id == done.seed_id).count() > 0
    assert db.query(Finding).filter(Finding.seed_id == done.seed_id).count() > 0
    db.close()
