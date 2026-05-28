from datetime import datetime
from pydantic import BaseModel, ConfigDict


class ObservationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    variant_id: str
    source: str
    source_event: str
    first_seen: datetime | None
    last_seen: datetime | None
    raw_ref: str | None
    payload: dict
    created_at: datetime
