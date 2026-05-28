from datetime import UTC, datetime
from phishwatch.app.collectors.base import BaseCollector, CollectionContext, ObservationCandidate


class MockFeedCollector(BaseCollector):
    name = "mock_feed"

    async def collect(self, context: CollectionContext) -> list[ObservationCandidate]:
        now = datetime.now(UTC)
        selected = context.variants[: min(8, len(context.variants))]
        return [ObservationCandidate(fqdn=fqdn, source=self.name, source_event="mock_newly_observed_domain", first_seen=now, last_seen=now, raw_ref=f"mock://{fqdn}", payload={"demo": True, "confidence": "simulated"}) for fqdn in selected]
