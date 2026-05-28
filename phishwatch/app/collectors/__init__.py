from phishwatch.app.collectors.base import BaseCollector
from phishwatch.app.collectors.mock_feed import MockFeedCollector
from phishwatch.app.collectors.urlscan import UrlscanCollector
from phishwatch.app.collectors.certstream import CertStreamCollector
from phishwatch.app.collectors.phishtank import PhishTankCollector
from phishwatch.app.collectors.safebrowsing import SafeBrowsingCollector
from phishwatch.app.collectors.whoisxml_nrd import WhoisXmlNrdCollector
from phishwatch.app.collectors.czds import CzdsCollector

COLLECTORS: dict[str, BaseCollector] = {c.name: c for c in [MockFeedCollector(), UrlscanCollector(), CertStreamCollector(), PhishTankCollector(), SafeBrowsingCollector(), WhoisXmlNrdCollector(), CzdsCollector()]}
