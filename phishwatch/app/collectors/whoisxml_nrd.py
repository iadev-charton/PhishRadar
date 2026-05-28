import logging
from phishwatch.app.collectors.base import BaseCollector, CollectionContext, ObservationCandidate
from phishwatch.app.core.config import get_settings

log = logging.getLogger(__name__)


class WhoisXmlNrdCollector(BaseCollector):
    name = "whoisxml_nrd"

    async def is_enabled(self) -> bool:
        key_map = {
            "phishtank": get_settings().phishtank_api_key,
            "safebrowsing": get_settings().safebrowsing_api_key or get_settings().webrisk_api_key,
            "whoisxml_nrd": get_settings().whoisxml_api_key,
            "czds": None,
            "certstream": None,
        }
        enabled = bool(key_map.get(self.name)) if self.name not in {"certstream", "czds"} else False
        if not enabled:
            log.warning("%s collector disabled: credentials/local feed not configured", self.name)
        return enabled

    async def collect(self, context: CollectionContext) -> list[ObservationCandidate]:
        if not await self.is_enabled():
            return []
        return []
