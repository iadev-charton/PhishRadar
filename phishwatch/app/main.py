from fastapi import FastAPI
from phishwatch.app.api.routes_analysis import router as analysis_router
from phishwatch.app.api.routes_findings import router as findings_router
from phishwatch.app.api.routes_health import router as health_router
from phishwatch.app.core.logging import configure_logging
from phishwatch.app.db.base import Base
from phishwatch.app.db.session import engine

configure_logging()
Base.metadata.create_all(bind=engine)
app = FastAPI(title="PhishWatch", version="0.1.0", description="Defensive OSINT monitoring for phishing-like domains.")
app.include_router(health_router)
app.include_router(analysis_router)
app.include_router(findings_router)
