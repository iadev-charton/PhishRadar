from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class CollectionContext:
    seed_id: str
    apex_domain: str
    hostname: str
    variants: list[str]
    sources: list[str]


@dataclass(frozen=True)
class ObservationCandidate:
    fqdn: str
    source: str
    source_event: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    raw_ref: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)


class BaseCollector:
    name: str = "base"

    async def is_enabled(self) -> bool:
        return True

    async def collect(self, context: CollectionContext) -> list[ObservationCandidate]:
        raise NotImplementedError
