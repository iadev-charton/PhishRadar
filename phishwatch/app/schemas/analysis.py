from datetime import datetime
from pydantic import BaseModel, Field


class AnalyzeOptions(BaseModel):
    include_typosquatting: bool = True
    include_homoglyphs: bool = True
    include_bitsquatting: bool = True
    include_tld_swaps: bool = True
    include_subdomain_lookalikes: bool = True
    max_edit_distance: int = Field(default=1, ge=1, le=3)
    tlds: list[str] = Field(default_factory=lambda: ["com", "net", "org", "es", "co", "io"])
    active_verification: bool = True


class AnalyzeRequest(BaseModel):
    url: str
    options: AnalyzeOptions = Field(default_factory=AnalyzeOptions)
    sources: list[str] = Field(default_factory=lambda: ["mock_feed"])


class AnalyzeResponse(BaseModel):
    job_id: str
    status: str
    message: str


class JobResponse(BaseModel):
    id: str
    seed_id: str | None
    status: str
    message: str
    error: str | None = None
    created_at: datetime
    updated_at: datetime
