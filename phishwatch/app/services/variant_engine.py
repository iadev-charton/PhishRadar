from dataclasses import dataclass
import idna
import tldextract
from rapidfuzz.distance import Levenshtein

HOMOGLYPHS = {"a": ["à", "á", "ɑ", "4"], "e": ["é", "è", "3"], "o": ["0", "ο"], "l": ["1", "I"], "i": ["1", "í"], "s": ["5"], "g": ["9"]}
KEYBOARD = {"a": "s", "s": "a", "e": "r", "r": "e", "o": "p", "p": "o", "l": "k", "m": "n", "n": "m"}
VOWELS = "aeiou"
BRAND_WORDS = ["login", "secure", "account", "verify", "support"]
ALLOWED = set("abcdefghijklmnopqrstuvwxyz0123456789-")
SKELETON_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "9": "g", "I": "l", "í": "i", "é": "e", "è": "e", "à": "a", "á": "a", "ɑ": "a", "ο": "o"})


@dataclass(frozen=True)
class VariantCandidate:
    fqdn: str
    unicode_fqdn: str
    punycode_fqdn: str
    tld: str
    attack_family: str
    attack_rule: str
    edit_distance: int
    skeleton: str


def skeletonize(value: str) -> str:
    return value.lower().translate(SKELETON_MAP)


class VariantEngine:
    def __init__(self, max_variants: int = 5000) -> None:
        self.max_variants = max_variants

    def generate(self, apex_domain: str, tlds: list[str], *, include_typosquatting: bool = True, include_homoglyphs: bool = True, include_bitsquatting: bool = True, include_tld_swaps: bool = True, include_subdomain_lookalikes: bool = True) -> list[VariantCandidate]:
        extracted = tldextract.extract(apex_domain)
        label, original_tld = extracted.domain, extracted.suffix
        seen: dict[tuple[str, str, str], VariantCandidate] = {}

        def add(mutated_label: str, tld: str, family: str, rule: str) -> None:
            if len(seen) >= self.max_variants:
                return
            mutated_label = mutated_label.strip("-").lower()
            if not mutated_label or len(mutated_label) > 63 or "--" in mutated_label:
                return
            if any(ch not in ALLOWED and ord(ch) < 128 for ch in mutated_label):
                return
            unicode_fqdn = f"{mutated_label}.{tld.lower().lstrip('.')}"
            try:
                puny = idna.encode(unicode_fqdn, uts46=True).decode("ascii").lower()
            except idna.IDNAError:
                return
            fqdn = puny
            key = (fqdn, family, rule)
            if key in seen or fqdn == apex_domain:
                return
            seen[key] = VariantCandidate(fqdn, unicode_fqdn, puny, tld.lower().lstrip('.'), family, rule, Levenshtein.distance(label, skeletonize(mutated_label)), skeletonize(unicode_fqdn))

        if include_typosquatting:
            for i in range(len(label)):
                add(label[:i] + label[i + 1 :], original_tld, "typosquatting", "omission")
                add(label[:i] + label[i] + label[i:], original_tld, "typosquatting", "repetition")
                if label[i] in KEYBOARD:
                    add(label[:i] + KEYBOARD[label[i]] + label[i + 1 :], original_tld, "typosquatting", "keyboard_replacement")
                if label[i] in VOWELS:
                    for v in VOWELS:
                        if v != label[i]:
                            add(label[:i] + v + label[i + 1 :], original_tld, "typosquatting", "vowel_swap")
                for ins in ("-", "s"):
                    add(label[:i] + ins + label[i:], original_tld, "typosquatting", "insertion")
            for i in range(len(label) - 1):
                add(label[:i] + label[i + 1] + label[i] + label[i + 2 :], original_tld, "typosquatting", "transposition")
            for suffix in BRAND_WORDS:
                add(f"{label}-{suffix}", original_tld, "typosquatting", "addition")
                add(f"{suffix}-{label}", original_tld, "typosquatting", "addition")
            if len(label) > 3:
                add(label[: len(label)//2] + "-" + label[len(label)//2 :], original_tld, "typosquatting", "hyphenation")
        if include_tld_swaps:
            for tld in tlds:
                if tld.lower().lstrip(".") != original_tld:
                    add(label, tld, "tld_swap", "configured_tld")
        if include_homoglyphs:
            produced = 0
            for i, ch in enumerate(label):
                for replacement in HOMOGLYPHS.get(ch, []):
                    add(label[:i] + replacement + label[i + 1 :], original_tld, "homoglyph", f"{ch}_to_{replacement}")
                    produced += 1
                    if produced >= 50:
                        break
        if include_bitsquatting:
            for i, ch in enumerate(label):
                code = ord(ch)
                for bit in range(7):
                    candidate = chr(code ^ (1 << bit))
                    if candidate in ALLOWED and candidate != "-":
                        add(label[:i] + candidate + label[i + 1 :], original_tld, "bitsquatting", "single_bit_flip")
        if include_subdomain_lookalikes:
            for word in BRAND_WORDS[:4]:
                add(f"{word}-{label}", original_tld, "subdomain_lookalike", "prefix_keyword")
                add(f"{label}-{word}", original_tld, "subdomain_lookalike", "suffix_keyword")
            add(f"www{label}", original_tld, "subdomain_lookalike", "www_concat")
        return list(seen.values())[: self.max_variants]
