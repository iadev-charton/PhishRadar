import asyncio
from sqlalchemy import select
from phishwatch.app.collectors import COLLECTORS
from phishwatch.app.collectors.base import CollectionContext
from phishwatch.app.core.config import get_settings
from phishwatch.app.db.models import AnalysisJob, Finding, Observation, Seed, Variant, Verification
from phishwatch.app.db.session import SessionLocal
from phishwatch.app.services.canonicalizer import URLCanonicalizer
from phishwatch.app.services.matcher import Matcher
from phishwatch.app.services.scorer import RiskScorer
from phishwatch.app.services.variant_engine import VariantEngine
from phishwatch.app.services.verifier import TechnicalVerifier
from phishwatch.app.workers.celery_app import celery_app


async def run_analysis(job_id: str) -> None:
    settings = get_settings()
    db = SessionLocal()
    try:
        job = db.get(AnalysisJob, job_id)
        if not job:
            return
        job.status = "running"; job.message = "Analysis running"; db.commit()
        req = job.request
        canonical = URLCanonicalizer().canonicalize(req["url"])
        seed = Seed(input_url=canonical.input_url, normalized_url=canonical.normalized_url, apex_domain=canonical.apex_domain, hostname=canonical.hostname, path=canonical.path)
        db.add(seed); db.flush()
        job.seed_id = seed.id
        opts = req.get("options", {})
        engine = VariantEngine(max_variants=settings.max_variants_per_seed)
        candidates = engine.generate(canonical.apex_domain, opts.get("tlds", ["com", "net", "org", "es", "co", "io"]), include_typosquatting=opts.get("include_typosquatting", True), include_homoglyphs=opts.get("include_homoglyphs", True), include_bitsquatting=opts.get("include_bitsquatting", True), include_tld_swaps=opts.get("include_tld_swaps", True), include_subdomain_lookalikes=opts.get("include_subdomain_lookalikes", True))
        for c in candidates:
            db.add(Variant(seed_id=seed.id, fqdn=c.fqdn, unicode_fqdn=c.unicode_fqdn, punycode_fqdn=c.punycode_fqdn, tld=c.tld, attack_family=c.attack_family, attack_rule=c.attack_rule, edit_distance=c.edit_distance, skeleton=c.skeleton))
        db.flush()
        selected_sources = req.get("sources", ["mock_feed"])
        context = CollectionContext(seed.id, seed.apex_domain, seed.hostname, [c.fqdn for c in candidates], selected_sources)
        observations = []
        for name in selected_sources:
            collector = COLLECTORS.get(name)
            if collector and await collector.is_enabled():
                observations.extend(await collector.collect(context))
        matches = Matcher().match(candidates, observations)
        variant_by_key = {(v.fqdn, v.attack_family, v.attack_rule): v for v in db.scalars(select(Variant).where(Variant.seed_id == seed.id)).all()}
        verifier = TechnicalVerifier()
        scorer = RiskScorer()
        for match in matches:
            c = match.variant
            variant = variant_by_key.get((c.fqdn, c.attack_family, c.attack_rule))
            if not variant:
                continue
            db.add(Observation(variant_id=variant.id, source=match.observation.source, source_event=match.observation.source_event, first_seen=match.observation.first_seen, last_seen=match.observation.last_seen, raw_ref=match.observation.raw_ref, payload={**match.observation.payload, "match_type": match.match_type}))
            active = bool(opts.get("active_verification", True)) and settings.active_verification_enabled
            result = await verifier.verify(variant.fqdn, active=active)
            verification = Verification(variant_id=variant.id, dns_status=result.dns_status, dns_json=result.dns_json, tls_status=result.tls_status, tls_json=result.tls_json, http_status=result.http_status, http_json=result.http_json, mx_status=result.mx_status, mx_json=result.mx_json)
            db.add(verification); db.flush()
            reputation = {"urlscan_suspicious": match.observation.source == "urlscan" and match.observation.payload.get("verdicts", {}).get("overall", {}).get("malicious")}
            score = scorer.score(seed_apex=seed.apex_domain, variant_fqdn=variant.fqdn, attack_family=variant.attack_family, edit_distance=variant.edit_distance, skeleton=variant.skeleton, tld=variant.tld, verification=verification, reputation=reputation)
            db.add(Finding(seed_id=seed.id, variant_id=variant.id, risk_score=score.score, severity=score.severity, status="open", factors=score.factors, explanation=score.explanation))
        job.status = "completed"; job.message = "Analysis completed"; db.commit()
    except Exception as exc:
        db.rollback()
        job = db.get(AnalysisJob, job_id)
        if job:
            job.status = "failed"; job.message = "Analysis failed"; job.error = str(exc); db.commit()
        raise
    finally:
        db.close()


@celery_app.task(name="phishwatch.analyze")
def analyze_job(job_id: str) -> None:
    asyncio.run(run_analysis(job_id))
