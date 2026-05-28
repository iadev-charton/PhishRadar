from datetime import datetime
from pydantic import BaseModel, ConfigDict


class VariantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    seed_id: str
    fqdn: str
    unicode_fqdn: str
    punycode_fqdn: str
    tld: str
    attack_family: str
    attack_rule: str
    edit_distance: int
    skeleton: str
    created_at: datetime
