"""M5 - rule-based URL analysis.

Each rule has a name, a strength (strong / weak / info), a weight and a human-readable reason.
Rules read the SAME parsed URL as the ML model (`src.features.analyze`), only inspect the
string, never fetch anything, and never log or store the URL.

    evaluate_rules(url) -> RuleReport(hits, score, strong, weak, info, parse_error)

Weights: strong = 3, weak = 1, info = 0 (shown to the user, adds nothing to the score).
How the hybrid uses strong/weak hits is defined in src/hybrid.py (M6), not here.

Thresholds below were FROZEN on 2026-11-19 (user decision) and are not tuned on the test set.

CLI (train split only):
    python -m src.rules firing-report     -> reports/rule_firing_train.csv
"""
from __future__ import annotations

import json
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qsl, unquote, unquote_plus

from src.features import _EXTRACT, SUSPICIOUS_KEYWORDS, URLParts, analyze

ROOT = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------- frozen thresholds
LONG_URL_CHARS = 100      # long_or_encoded: URL longer than this
MAX_PCT_ENCODED = 3       # long_or_encoded: more than this many %XX sequences
MIN_KEYWORDS = 2          # keywords: at least this many distinct suspicious keywords
DEEP_SUBDOMAINS = 3       # deep_subdomains: at least this many subdomain labels (www. excluded)
MANY_HYPHENS = 4          # deep_subdomains: at least this many hyphens in the host
STANDARD_PORTS = (80, 443)

WEIGHTS = {"strong": 3, "weak": 1, "info": 0}

# ---------------------------------------------------------------- reference lists
_BRAND_FILE = Path(__file__).with_name("brands.json")
BRANDS: dict[str, frozenset[str]] = {
    b: frozenset(d.lower() for d in doms)
    for b, doms in json.loads(_BRAND_FILE.read_text(encoding="utf-8"))["brands"].items()
}
SHORTENERS = frozenset({
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "shorte.st", "bl.ink",
})
# Archive / cache services whose normal URLs embed another site's full URL in the PATH
# (web.archive.org/web/2020/https://example.com). Narrow, documented exception: on these hosts
# embedded_url_in_path does not fire; the info rule archived_copy explains the URL instead.
ARCHIVE_DOMAINS = frozenset({
    "archive.org", "archive.today", "archive.ph", "archive.is", "archive.li", "archive.vn",
    "archive.md", "ghostarchive.org",
})
ARCHIVE_HOSTS = frozenset({"webcache.googleusercontent.com"})
RISKY_DOWNLOAD_EXTENSIONS = (
    ".exe", ".scr", ".msi", ".bat", ".cmd", ".pif", ".apk", ".jar", ".vbs", ".ps1",
    ".zip", ".rar", ".7z", ".iso", ".img", ".dll",
)

_TOKEN_SPLIT = re.compile(r"[^0-9a-z]+")
_EMBEDDED_RE = re.compile(
    r"(?:https?:/{1,2}|//)((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]{2,})", re.IGNORECASE)
_ABS_URL_RE = re.compile(r"^(?:https?:)?//[^/\s]", re.IGNORECASE)


# ---------------------------------------------------------------- helpers

def _tokens(text: str) -> list[str]:
    return [t for t in _TOKEN_SPLIT.split(text.lower()) if t]


def _match_brand(tokens: list[str], registered_domain: str) -> str | None:
    """First brand matching a token, unless the registered domain is official for it."""
    for tok in tokens:
        for brand, official in BRANDS.items():
            hit = (tok == brand
                   or (len(brand) >= 6 and tok.startswith(brand))
                   or (len(brand) >= 7 and tok.endswith(brand)))  # see brands.json _doc
            if hit and registered_domain not in official:
                return brand
    return None


def _script(ch: str) -> str:
    """Rough Unicode script of a letter from its name (LATIN, CYRILLIC, GREEK, CJK, ...)."""
    first = unicodedata.name(ch, "UNKNOWN").split(" ")[0]
    # Japanese legitimately mixes kana and kanji; Korean may mix Hangul and Hanja.
    return {"HIRAGANA": "CJK", "KATAKANA": "CJK", "IDEOGRAPHIC": "CJK", "HANGUL": "CJK"}.get(first, first)


def _decode_label(label: str) -> str | None:
    """Unicode form of a host label; punycode (xn--) is decoded. None if undecodable."""
    if label.startswith("xn--"):
        try:
            return label[4:].encode("ascii").decode("punycode")
        except (UnicodeError, ValueError):
            return None
    return label


def _idn_analysis(host: str) -> tuple[str, str] | None:
    """('mixed', label) for a mixed-script label, ('single', label) for other non-ASCII or
    punycode labels, None for plain-ASCII hosts."""
    single = None
    for label in host.split("."):
        u = _decode_label(label)
        if u is None or (label.startswith("xn--") and u.isascii()):
            single = single or label  # undecodable or invalid punycode: still an encoded host
            continue
        if u.isascii():
            continue
        scripts = {_script(c) for c in u if c.isalpha()}
        if len(scripts) > 1:
            return "mixed", u
        single = single or u
    return ("single", single) if single else None


def _embedded_host(p: URLParts) -> tuple[str, str] | None:
    """(host, registered_domain) of a URL embedded in the path pointing to a DIFFERENT site."""
    for m in _EMBEDDED_RE.finditer(unquote(p.path)):
        cand = m.group(1).lower()
        rd = (_EXTRACT(cand).top_domain_under_public_suffix or "").lower()
        if rd and rd != p.registered_domain:
            return cand, rd
    return None


def _is_archive(p: URLParts) -> bool:
    return p.registered_domain in ARCHIVE_DOMAINS or p.host in ARCHIVE_HOSTS


# ---------------------------------------------------------------- rule checks
# Each check returns a reason string when the rule fires, else None.

def _ip_host(p: URLParts, f: dict) -> str | None:
    if not p.is_ip:
        return None
    if p.is_obfuscated_ip:
        return "The host is an IP address written in a disguised form (decimal, hex or octal) instead of a domain name."
    return "The host is a bare IP address instead of a domain name. Legitimate sites rarely send users to one."


def _at_in_host(p: URLParts, f: dict) -> str | None:
    if "@" in p.netloc:
        return (f"The address contains '@' before the host. Browsers ignore everything before it, "
                f"so the real destination is {p.host or 'the part after the @'}.")
    return None


def _lookalike_host(p: URLParts, f: dict) -> str | None:
    r = _idn_analysis(p.host_nowww)
    if r and r[0] == "mixed":
        return (f"The host mixes letters from different alphabets ('{r[1]}'), a common trick to imitate "
                "a well-known name with look-alike characters.")
    return None


def _idn_host(p: URLParts, f: dict) -> str | None:
    r = _idn_analysis(p.host_nowww)
    if r and r[0] == "single":
        return (f"The host uses non-Latin or encoded (punycode) characters ('{r[1]}'). This is normal for "
                "many languages, but check that the name is the one you expect.")
    return None


def _brand_in_subdomain(p: URLParts, f: dict) -> str | None:
    if not p.subdomain:
        return None
    brand = _match_brand(_tokens(p.subdomain), p.registered_domain)
    if brand:
        return (f"'{brand}' appears in the subdomain, but the site's real domain is "
                f"{p.registered_domain or p.host}, which is not an official {brand} domain.")
    return None


def _brand_in_domain(p: URLParts, f: dict) -> str | None:
    # Deliberately WEAK, and not to be promoted on the train firing rate: legitimate training
    # URLs are bare homepages of popular sites, so a low legitimate rate there proves little
    # about real traffic (e.g. fan sites, resellers, "paypal-tips" blogs). User decision 2026-11-19.
    if not p.domain:
        return None
    brand = _match_brand(_tokens(p.domain), p.registered_domain)
    if brand:
        return (f"The domain name {p.registered_domain} contains '{brand}' but is not an official "
                f"{brand} domain.")
    return None


def _brand_in_path(p: URLParts, f: dict) -> str | None:
    # Weak: a brand in the path is common on legitimate sites (github.com/paypal/...).
    text = unquote_plus(f"{p.path} {p.query}")
    brand = _match_brand(_tokens(text), p.registered_domain)
    if brand:
        return (f"'{brand}' appears in the path, but the site is {p.registered_domain or p.host}. "
                "Common on legitimate pages too; on its own it means little.")
    return None


def _embedded_url_in_path(p: URLParts, f: dict) -> str | None:
    if _is_archive(p):
        return None  # see ARCHIVE_DOMAINS; archived_copy explains these URLs
    e = _embedded_host(p)
    if e:
        return (f"The path contains another full address ({e[0]}) on a different site. This can hide "
                "where the link really leads.")
    return None


def _archived_copy(p: URLParts, f: dict) -> str | None:
    if not _is_archive(p):
        return None
    e = _embedded_host(p)
    if e:
        return f"This is an archived copy of a page on {e[0]}, served by {p.registered_domain or p.host}."
    return None


def _url_in_query(p: URLParts, f: dict) -> str | None:
    # Weak by design: ?next=, ?url=, ?redirect= with a full address are normal on login pages,
    # but can also be open redirects. Relative values (?next=/dashboard) do not fire.
    try:
        pairs = parse_qsl(p.query, keep_blank_values=True)
    except ValueError:
        return None
    for key, val in pairs:
        v = val.strip()
        for _ in range(2):  # also catch one extra level of %-encoding
            if _ABS_URL_RE.match(v):
                return (f"The query parameter '{key[:30]}' contains a full web address, so the page may "
                        "forward you to another site.")
            v = unquote(v)
    return None


def _no_https(p: URLParts, f: dict) -> str | None:
    if p.has_scheme and p.scheme == "http":
        return "The link uses plain http, so the connection is not encrypted. Many phishing sites use https too, so this is a weak sign."
    return None


def _keywords(p: URLParts, f: dict) -> str | None:
    if f["url_suspicious_keyword_count"] < MIN_KEYWORDS:
        return None
    low = p.text.lower()
    found = [w for w in SUSPICIOUS_KEYWORDS if w in low][:4]
    return f"The address contains several words often used in phishing ({', '.join(found)})."


def _long_or_encoded(p: URLParts, f: dict) -> str | None:
    why = []
    if p.raw_length > LONG_URL_CHARS:
        why.append(f"it is very long ({p.raw_length} characters)")
    if f["url_num_pct_encoded"] > MAX_PCT_ENCODED:
        why.append(f"it has {f['url_num_pct_encoded']} percent-encoded characters")
    if f["url_has_hex_run"]:
        why.append("it contains a long hexadecimal string")
    if why:
        return "The address may be obfuscated: " + "; ".join(why) + "."
    return None


def _risky_extension(p: URLParts, f: dict) -> str | None:
    path = p.path.lower()
    for ext in RISKY_DOWNLOAD_EXTENSIONS:
        if path.endswith(ext):
            return f"The link points to a '{ext}' file, which can install software or hide malware."
    return None


def _deep_subdomains(p: URLParts, f: dict) -> str | None:
    why = []
    if f["host_num_subdomains"] >= DEEP_SUBDOMAINS:
        why.append(f"{f['host_num_subdomains']} subdomain levels")
    if f["host_num_hyphens"] >= MANY_HYPHENS:
        why.append(f"{f['host_num_hyphens']} hyphens")
    if p.port_invalid or (p.port is not None and p.port not in STANDARD_PORTS):
        why.append("a non-standard port")
    if why:
        return "The host has an unusual structure: " + ", ".join(why) + "."
    return None


def _shortener(p: URLParts, f: dict) -> str | None:
    if p.registered_domain in SHORTENERS:
        return (f"{p.registered_domain} is a link shortener. The real destination cannot be checked "
                "without visiting it, which PhishGuard never does.")
    return None


# ---------------------------------------------------------------- registry

@dataclass(frozen=True)
class Rule:
    name: str
    strength: str          # "strong" | "weak" | "info"
    description: str
    check: Callable[[URLParts, dict], str | None]

    @property
    def weight(self) -> int:
        return WEIGHTS[self.strength]


RULES: tuple[Rule, ...] = (
    Rule("ip_host", "strong", "Host is an IP address (IPv4, IPv6, or decimal/hex/octal IPv4)", _ip_host),
    Rule("at_in_host", "strong", "'@' before the host hides the real destination", _at_in_host),
    Rule("lookalike_host", "strong", "Host label mixes scripts (e.g. Latin + Cyrillic), also after punycode decoding", _lookalike_host),
    Rule("brand_in_subdomain", "strong", "Brand keyword in the subdomain of a non-official domain", _brand_in_subdomain),
    Rule("embedded_url_in_path", "strong", "Path embeds a URL to a different registered domain (archive services excepted)", _embedded_url_in_path),
    Rule("idn_host", "weak", "Single-script non-ASCII or punycode host", _idn_host),
    Rule("brand_in_domain", "weak", "Brand keyword inside a non-official registered domain name", _brand_in_domain),
    Rule("brand_in_path", "weak", "Brand keyword in the path/query of a non-official domain", _brand_in_path),
    Rule("url_in_query", "weak", "A query value is a full absolute URL", _url_in_query),
    Rule("no_https", "weak", "Scheme is plain http", _no_https),
    Rule("keywords", "weak", f">= {MIN_KEYWORDS} distinct suspicious keywords", _keywords),
    Rule("long_or_encoded", "weak", f"> {LONG_URL_CHARS} chars, > {MAX_PCT_ENCODED} %-encoded chars, or a long hex run", _long_or_encoded),
    Rule("risky_extension", "weak", "Path ends in an executable/archive extension", _risky_extension),
    Rule("deep_subdomains", "weak", f">= {DEEP_SUBDOMAINS} subdomains, >= {MANY_HYPHENS} hyphens, or non-standard port", _deep_subdomains),
    Rule("shortener", "info", "Known link shortener", _shortener),
    Rule("archived_copy", "info", "Archive/cache service showing a copy of another site", _archived_copy),
)
RULES_BY_NAME = {r.name: r for r in RULES}


@dataclass(frozen=True)
class RuleHit:
    name: str
    strength: str
    weight: int
    reason: str


@dataclass(frozen=True)
class RuleReport:
    hits: tuple[RuleHit, ...]
    parse_error: bool

    @property
    def score(self) -> int:
        return sum(h.weight for h in self.hits)

    def count(self, strength: str) -> int:
        return sum(1 for h in self.hits if h.strength == strength)

    @property
    def strong(self) -> int:
        return self.count("strong")

    @property
    def weak(self) -> int:
        return self.count("weak")

    @property
    def info(self) -> int:
        return self.count("info")


def evaluate_parts(p: URLParts, f: dict) -> RuleReport:
    hits = []
    for rule in RULES:
        try:
            reason = rule.check(p, f)
        except Exception:  # a rule bug must never crash the app (and must not echo the URL)
            reason = None
        if reason:
            hits.append(RuleHit(rule.name, rule.strength, rule.weight, reason))
    return RuleReport(tuple(hits), bool(p.parse_error))


def evaluate_rules(url: object) -> RuleReport:
    """Evaluate every rule on a URL string. Never raises; never fetches; never logs."""
    p, f = analyze(url)
    return evaluate_parts(p, f)


# ---------------------------------------------------------------- firing report (TRAIN only)

def firing_report() -> None:
    import pandas as pd

    df = pd.read_csv(ROOT / "data" / "processed" / "urls_clean.csv")
    tr = df[df["split"] == "train"].reset_index(drop=True)  # never the test split
    names = [r.name for r in RULES]
    fired = {n: [] for n in names}
    any_strong = []
    for url in tr["url"]:
        rep = evaluate_rules(url)
        hit = {h.name for h in rep.hits}
        for n in names:
            fired[n].append(n in hit)
        any_strong.append(rep.strong > 0)
    y = tr["is_phishing"].to_numpy()
    n_leg, n_phi = int((y == 0).sum()), int((y == 1).sum())
    rows = []
    for n, flags in list(fired.items()) + [("ANY_STRONG", any_strong)]:
        s = pd.Series(flags)
        lf, pf = int(s[y == 0].sum()), int(s[y == 1].sum())
        rows.append({
            "rule": n, "strength": RULES_BY_NAME[n].strength if n in RULES_BY_NAME else "-",
            "legit_fires": lf, "legit_rate": round(lf / n_leg, 5),
            "phish_fires": pf, "phish_rate": round(pf / n_phi, 5),
            "phishing_share_of_hits": round(pf / (lf + pf), 4) if lf + pf else None,
            "review_flag": "REVIEW" if lf / n_leg > 0.01 else "",
        })
    out = pd.DataFrame(rows)
    (ROOT / "reports").mkdir(exist_ok=True)
    out.to_csv(ROOT / "reports" / "rule_firing_train.csv", index=False)
    print(f"train: {n_leg} legitimate, {n_phi} phishing")
    print(out.to_string(index=False))


if __name__ == "__main__":
    if sys.argv[1:] == ["firing-report"]:
        firing_report()
    else:
        sys.exit("usage: python -m src.rules firing-report")
