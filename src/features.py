"""M3 - URL feature extraction.

One function, `extract_features(url) -> dict`, used by BOTH training and the app.
It only inspects the URL string: it never resolves, fetches or visits anything,
and it never logs or stores the input.

Feature groups (prefix = group):
    url_*   computed on the whole URL string
    host_*  computed on the hostname with a leading "www." removed (see PROGRESS.md:
            the training data's legitimate URLs are all https://www.<host>, so the
            ML model is restricted to host features and the "www." prefix is dropped
            to avoid that shortcut)
    path_*  computed on path / query / fragment
    tld     public suffix as a string (categorical; encoded later by the model)
    parse_error  1 if the string could not be parsed; all other features are then
                 best-effort (string-level counts still filled in)

Malformed input never raises.
"""
from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from urllib.parse import urlsplit

import tldextract

# Costly checks run on at most this many characters; url_length always reports the
# true length. Keeps a 1 MB pasted string from slowing the app down.
MAX_ANALYZE_LEN = 4096

# Offline: bundled Public Suffix List snapshot, never fetched (no network at all).
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

SUSPICIOUS_KEYWORDS = (
    "login", "log-in", "signin", "sign-in", "logon", "verify", "verification",
    "account", "update", "secure", "security", "banking", "confirm", "password",
    "passwd", "credential", "webscr", "wallet", "billing", "suspend", "unlock",
    "authenticate", "auth", "recover", "restore", "invoice", "support", "alert",
    "bonus", "free", "gift", "prize", "claim", "validation", "authorize",
)
BRAND_KEYWORDS = (
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook", "onedrive",
    "google", "gmail", "amazon", "netflix", "facebook", "instagram", "whatsapp",
    "linkedin", "dropbox", "docusign", "adobe", "chase", "wellsfargo", "bankofamerica",
    "dhl", "fedex", "usps", "ebay", "steam", "binance", "coinbase", "metamask",
)
RISKY_EXTENSIONS = (".php", ".html", ".htm", ".asp", ".aspx", ".jsp", ".cgi",
                    ".exe", ".zip", ".apk", ".scr", ".js")

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_PCT_RE = re.compile(r"%[0-9a-fA-F]{2}")
_HEX_RUN_RE = re.compile(r"(?:0x)?[0-9a-fA-F]{16,}")
_HEX_ESCAPE_RE = re.compile(r"\\x[0-9a-fA-F]{2}|&#x?[0-9a-fA-F]+;")

FEATURE_DEFAULTS: dict[str, float | int | str] = {
    # whole URL
    "url_length": 0, "url_has_scheme": 0, "url_is_https": 0,
    "url_num_dots": 0, "url_num_hyphens": 0, "url_num_underscores": 0,
    "url_num_slashes": 0, "url_num_question": 0, "url_num_equals": 0,
    "url_num_ampersand": 0, "url_num_at": 0, "url_num_percent": 0,
    "url_num_tilde": 0, "url_num_digits": 0, "url_digit_ratio": 0.0,
    "url_num_special": 0, "url_special_ratio": 0.0, "url_entropy": 0.0,
    "url_has_whitespace": 0, "url_has_at_in_netloc": 0, "url_num_pct_encoded": 0,
    "url_has_hex_run": 0, "url_has_hex_escape": 0, "url_has_double_slash_redirect": 0,
    "url_suspicious_keyword_count": 0, "url_brand_keyword_count": 0,
    "url_has_port": 0, "url_is_truncated": 0,
    # host (leading "www." removed)
    "host_length": 0, "host_num_dots": 0, "host_num_hyphens": 0, "host_num_digits": 0,
    "host_digit_ratio": 0.0, "host_entropy": 0.0, "host_num_subdomains": 0,
    "host_max_label_length": 0, "host_is_ip": 0, "host_is_ipv6": 0,
    "host_is_obfuscated_ip": 0, "host_has_punycode": 0, "host_non_ascii": 0,
    "host_domain_length": 0, "host_tld_length": 0, "host_tld_known": 0,
    "host_suspicious_keyword_count": 0, "host_brand_keyword_count": 0,
    # path / query / fragment
    "path_length": 0, "path_depth": 0, "path_query_length": 0, "path_num_params": 0,
    "path_fragment_length": 0, "path_has_risky_extension": 0,
    "path_suspicious_keyword_count": 0, "path_brand_keyword_count": 0,
    # categorical + status
    "tld": "", "parse_error": 0,
}
FEATURE_NAMES: tuple[str, ...] = tuple(FEATURE_DEFAULTS)
HOST_FEATURES: tuple[str, ...] = tuple(n for n in FEATURE_NAMES if n.startswith("host_")) + ("tld",)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _count_keywords(text: str, words: tuple[str, ...]) -> int:
    """Number of distinct keywords occurring in text (case-insensitive substring)."""
    t = text.lower()
    return sum(1 for w in words if w in t)


def _parse_obfuscated_ipv4(host: str) -> bool:
    """True for IPv4 written in non-dotted-decimal form: 3232235521, 0xC0A80001, 0300.0250.1.1, 127.1."""
    labels = host.split(".")
    if not 1 <= len(labels) <= 4 or not all(labels):
        return False
    vals = []
    for lab in labels:
        try:
            if lab.lower().startswith("0x"):
                vals.append(int(lab, 16))
            elif len(lab) > 1 and lab.startswith("0"):
                vals.append(int(lab, 8))
            else:
                vals.append(int(lab, 10))
        except ValueError:
            return False
    if any(v < 0 for v in vals) or vals[-1] >= 256 ** (5 - len(vals)) or any(v > 255 for v in vals[:-1]):
        return False
    # plain dotted-decimal (a.b.c.d with no leading zeros/hex) is a normal IP, not obfuscated
    return not (len(labels) == 4 and all(lab.isdigit() and (lab == "0" or not lab.startswith("0")) for lab in labels))


def _string_features(f: dict, s: str, raw_len: int) -> None:
    """Character-level features that need no parsing."""
    n = max(len(s), 1)
    f["url_length"] = raw_len
    f["url_is_truncated"] = int(raw_len > MAX_ANALYZE_LEN)
    f["url_has_scheme"] = int(bool(_SCHEME_RE.match(s)))
    f["url_is_https"] = int(s.lower().startswith("https://"))
    for key, ch in (("dots", "."), ("hyphens", "-"), ("underscores", "_"), ("slashes", "/"),
                    ("question", "?"), ("equals", "="), ("ampersand", "&"), ("at", "@"),
                    ("percent", "%"), ("tilde", "~")):
        f[f"url_num_{key}"] = s.count(ch)
    digits = sum(c.isdigit() for c in s)
    special = sum(not c.isalnum() for c in s)
    f["url_num_digits"] = digits
    f["url_digit_ratio"] = digits / n
    f["url_num_special"] = special
    f["url_special_ratio"] = special / n
    f["url_entropy"] = _entropy(s)
    f["url_has_whitespace"] = int(any(c.isspace() for c in s))
    f["url_num_pct_encoded"] = len(_PCT_RE.findall(s))
    f["url_has_hex_run"] = int(bool(_HEX_RUN_RE.search(s)))
    f["url_has_hex_escape"] = int(bool(_HEX_ESCAPE_RE.search(s)))
    f["url_suspicious_keyword_count"] = _count_keywords(s, SUSPICIOUS_KEYWORDS)
    f["url_brand_keyword_count"] = _count_keywords(s, BRAND_KEYWORDS)


def _host_features(f: dict, host: str) -> None:
    h = host[4:] if host.startswith("www.") else host
    f["host_length"] = len(h)
    f["host_num_dots"] = h.count(".")
    f["host_num_hyphens"] = h.count("-")
    digits = sum(c.isdigit() for c in h)
    f["host_num_digits"] = digits
    f["host_digit_ratio"] = digits / max(len(h), 1)
    f["host_entropy"] = _entropy(h)
    f["host_max_label_length"] = max((len(lab) for lab in h.split(".")), default=0)
    f["host_has_punycode"] = int("xn--" in h)
    f["host_non_ascii"] = int(not h.isascii())
    f["host_suspicious_keyword_count"] = _count_keywords(h, SUSPICIOUS_KEYWORDS)
    f["host_brand_keyword_count"] = _count_keywords(h, BRAND_KEYWORDS)

    try:
        ip = ipaddress.ip_address(h)
        f["host_is_ip"] = 1
        f["host_is_ipv6"] = int(ip.version == 6)
        return
    except ValueError:
        pass
    if _parse_obfuscated_ipv4(h):
        f["host_is_ip"] = 1
        f["host_is_obfuscated_ip"] = 1
        return

    ext = _EXTRACT(h)
    sub_labels = [lab for lab in ext.subdomain.split(".") if lab] if ext.subdomain else []
    f["host_num_subdomains"] = len(sub_labels)
    f["host_domain_length"] = len(ext.domain)
    f["tld"] = ext.suffix
    f["host_tld_length"] = len(ext.suffix)
    f["host_tld_known"] = int(bool(ext.suffix))


def _path_features(f: dict, path: str, query: str, fragment: str) -> None:
    f["path_length"] = len(path)
    f["path_depth"] = len([seg for seg in path.split("/") if seg])
    f["path_query_length"] = len(query)
    f["path_num_params"] = len([p for p in query.split("&") if p]) if query else 0
    f["path_fragment_length"] = len(fragment)
    f["path_has_risky_extension"] = int(path.lower().endswith(RISKY_EXTENSIONS))
    rest = f"{path}?{query}#{fragment}"
    f["path_suspicious_keyword_count"] = _count_keywords(rest, SUSPICIOUS_KEYWORDS)
    f["path_brand_keyword_count"] = _count_keywords(rest, BRAND_KEYWORDS)
    # "//" inside the path (not the scheme) is a classic open-redirect / obfuscation trick
    f["url_has_double_slash_redirect"] = int("//" in path)


def extract_features(url: object) -> dict:
    """Return a dict with exactly FEATURE_NAMES as keys, for any input. Never raises."""
    f = dict(FEATURE_DEFAULTS)
    if url is None:
        url = ""
    if not isinstance(url, str):
        f["parse_error"] = 1
        return f

    raw = url.strip()
    s = raw[:MAX_ANALYZE_LEN]
    _string_features(f, s, len(raw))
    if not s:
        f["parse_error"] = 1
        return f

    if s.startswith("//"):
        to_parse = "http:" + s
    elif f["url_has_scheme"]:
        to_parse = s
    else:
        to_parse = "http://" + s

    try:
        parts = urlsplit(to_parse)
        host = (parts.hostname or "").rstrip(".")
    except ValueError:  # e.g. unbalanced IPv6 brackets
        f["parse_error"] = 1
        return f

    f["url_has_at_in_netloc"] = int("@" in parts.netloc)
    try:
        f["url_has_port"] = int(parts.port is not None)
    except ValueError:  # non-numeric or out-of-range port
        f["url_has_port"] = 1
        f["parse_error"] = 1

    if not host:
        f["parse_error"] = 1
    else:
        _host_features(f, host)
    _path_features(f, parts.path, parts.query, parts.fragment)
    return f
