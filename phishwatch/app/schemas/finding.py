from datetime import datetime
from pydantic import BaseModel, ConfigDict
from phishwatch.app.schemas.variant import VariantResponse


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    seed_id: str
    variant_id: str
    risk_score: float
    severity: str
    status: str
    factors: dict
    explanation: str
    created_at: datetime
    updated_at: datetime
    variant: VariantResponse | None = None
