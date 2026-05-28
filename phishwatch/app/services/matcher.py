from dataclasses import dataclass
import idna
import tldextract
from rapidfuzz.distance import Levenshtein
from phishwatch.app.collectors.base import ObservationCandidate
from phishwatch.app.services.variant_engine import VariantCandidate, skeletonize


@dataclass(frozen=True)
class MatchCandidate:
    variant: VariantCandidate
    observation: ObservationCandidate
    match_type: str
    priority: int


class Matcher:
    def match(self, variants: list[VariantCandidate], observations: list[ObservationCandidate]) -> list[MatchCandidate]:
        by_fqdn = {v.fqdn: v for v in variants}
        by_puny = {v.punycode_fqdn: v for v in variants}
        by_skeleton = {v.skeleton: v for v in variants}
        matches: list[MatchCandidate] = []
        for obs in observations:
            fqdn = obs.fqdn.lower().strip(".")
            try:
                puny = idna.encode(fqdn, uts46=True).decode("ascii").lower()
            except idna.IDNAError:
                continue
            skel = skeletonize(fqdn)
            variant = by_fqdn.get(fqdn)
            if variant:
                matches.append(MatchCandidate(variant, obs, "exact_fqdn", 100)); continue
            variant = by_puny.get(puny)
            if variant:
                matches.append(MatchCandidate(variant, obs, "punycode", 95)); continue
            variant = by_skeleton.get(skel)
            if variant:
                matches.append(MatchCandidate(variant, obs, "skeleton", 85)); continue
            extracted = tldextract.extract(fqdn)
            for candidate in variants:
                if candidate.tld == extracted.suffix and abs(len(candidate.fqdn) - len(fqdn)) <= 3 and Levenshtein.distance(candidate.fqdn, fqdn) <= 2:
                    matches.append(MatchCandidate(candidate, obs, "levenshtein", 70)); break
        return sorted(matches, key=lambda m: m.priority, reverse=True)
