from phishwatch.app.services.variant_engine import VariantEngine


def families(domain="example.com"):
    return VariantEngine(max_variants=1000).generate(domain, ["com", "net", "org", "co"])


def test_generates_typosquatting_families():
    variants = families()
    fqdns = {v.fqdn for v in variants}
    assert "exmaple.com" in fqdns
    assert "exampl.com" in fqdns
    assert any(v.attack_rule == "addition" for v in variants)


def test_generates_homoglyph_tld_bits_and_subdomain_lookalikes():
    variants = families()
    assert any(v.attack_family == "homoglyph" for v in variants)
    assert any(v.attack_family == "tld_swap" and v.fqdn == "example.net" for v in variants)
    assert any(v.attack_family == "bitsquatting" for v in variants)
    assert any(v.fqdn == "login-example.com" for v in variants)


def test_deduplicates_and_limits():
    variants = VariantEngine(max_variants=25).generate("example.com", ["com", "net"])
    keys = {(v.fqdn, v.attack_family, v.attack_rule) for v in variants}
    assert len(variants) == len(keys) <= 25
