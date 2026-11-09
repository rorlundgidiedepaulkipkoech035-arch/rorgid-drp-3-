"""Typosquat / brand-impersonation detection for domains seen in CT logs."""
import unicodedata
from typing import Iterable, Optional, Tuple

try:  # optional: better public-suffix handling when installed
    import tldextract

    _TLD = tldextract.TLDExtract(suffix_list_urls=())  # use bundled snapshot, no network
except Exception:  # pragma: no cover
    _TLD = None

# Fallback list of multi-part suffixes (used only if tldextract is unavailable)
_MULTI_SUFFIXES = {
    "co.ke", "or.ke", "ac.ke", "go.ke", "ne.ke", "sc.ke", "me.ke",
    "co.uk", "org.uk", "com.au", "co.za", "com.ng", "co.tz", "co.ug", "co.in",
}

# Visual look-alikes -> ASCII. Multi-character sequences are replaced first.
_MULTI_CHAR = (("rn", "m"), ("vv", "w"), ("cl", "d"))
_CHAR_MAP = {
    "0": "o", "1": "l", "!": "l", "|": "l", "3": "e", "5": "s", "$": "s", "@": "a",
    # common Cyrillic / Greek confusables (after punycode decoding)
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ӏ": "l", "ѕ": "s", "ј": "j", "ο": "o", "α": "a", "ν": "v",
}


def split_domain(domain: str) -> Tuple[str, str, str]:
    """Return (subdomain, label, suffix) for a hostname, e.g. 'a.b.brand.co.ke' ->
    ('a.b', 'brand', 'co.ke')."""
    domain = domain.strip().lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    if _TLD is not None:
        ext = _TLD(domain)
        if ext.suffix and ext.domain:
            return ext.subdomain, ext.domain, ext.suffix
    parts = domain.split(".")
    if len(parts) < 2:
        return "", domain, ""
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTI_SUFFIXES:
        return ".".join(parts[:-3]), parts[-3], ".".join(parts[-2:])
    return ".".join(parts[:-2]), parts[-2], parts[-1]


def decode_punycode(text: str) -> str:
    out = []
    for part in text.split("."):
        if part.startswith("xn--"):
            try:
                part = part.encode("ascii").decode("idna")
            except Exception:
                pass
        out.append(part)
    return ".".join(out)


def normalize(text: str) -> str:
    """Lowercase, strip accents and collapse look-alike characters to ASCII."""
    text = decode_punycode(text.lower())
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = "".join(_CHAR_MAP.get(c, c) for c in text)
    for src, dst in _MULTI_CHAR:
        text = text.replace(src, dst)
    return text


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def assess_domain(
    domain: str,
    brands: Iterable[str],
    legit_domains: Iterable[str] = (),
) -> Optional[str]:
    """Return a short reason string if the domain looks like an impersonation of a
    protected brand, otherwise None.

    brands:        brand labels without TLD, e.g. ["yourbrand"]
    legit_domains: registered domains you own, e.g. ["yourbrand.com", "yourbrand.co.ke"]
    """
    legit = {d.lower().rstrip(".") for d in legit_domains}
    domain = domain.strip().lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]

    sub, label, suffix = split_domain(domain)
    registered = f"{label}.{suffix}" if suffix else label
    if registered in legit:  # your own domain or one of its subdomains
        return None

    norm_label = normalize(label)
    norm_sub = normalize(sub)
    tokens = [t for t in norm_label.split("-") if t]

    for raw_brand in brands:
        brand = raw_brand.lower()
        if len(brand) < 4:
            continue  # too short to match safely

        if label == brand:
            return f"brand label on unowned domain/TLD ({brand})"
        if norm_label == brand:
            return f"homoglyph of brand ({brand})"
        if brand in norm_label:
            return f"brand embedded in domain ({brand})"
        if brand in norm_sub:
            return f"brand used as subdomain of unrelated domain ({brand})"

        max_dist = 1 if len(brand) <= 6 else 2
        for candidate in [norm_label, *tokens]:
            if abs(len(candidate) - len(brand)) <= max_dist and levenshtein(candidate, brand) <= max_dist:
                return f"typosquat of brand, edit distance <= {max_dist} ({brand})"
    return None
