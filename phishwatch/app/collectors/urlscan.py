import logging
import httpx
from phishwatch.app.collectors.base import BaseCollector, CollectionContext, ObservationCandidate
from phishwatch.app.core.config import get_settings

log = logging.getLogger(__name__)


class UrlscanCollector(BaseCollector):
    name = "urlscan"

    async def is_enabled(self) -> bool:
        enabled = bool(get_settings().urlscan_api_key)
        if not enabled:
            log.warning("urlscan collector disabled: URLSCAN_API_KEY is not configured")
        return enabled

    async def collect(self, context: CollectionContext) -> list[ObservationCandidate]:
        if not await self.is_enabled():
            return []
        headers = {"API-Key": get_settings().urlscan_api_key or ""}
        async with httpx.AsyncClient(timeout=5, headers=headers) as client:
            resp = await client.get("https://urlscan.io/api/v1/search/", params={"q": f"domain:{context.apex_domain}"})
            resp.raise_for_status()
            data = resp.json()
        out = []
        for row in data.get("results", [])[:25]:
            page = row.get("page", {})
            domain = page.get("domain")
            if domain:
                out.append(ObservationCandidate(domain, self.name, "urlscan_result", raw_ref=row.get("result"), payload={"verdicts": row.get("verdicts", {})}))
        return out
