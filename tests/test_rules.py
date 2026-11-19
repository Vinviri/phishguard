"""Unit tests for the M5 rule engine.

The legitimate URLs below are hand-written real-world examples. None come from the
PhiUSIIL test split, and this list is separate from the M8 hand-made evaluation list.
"""
import pytest

from src.rules import (BRANDS, LONG_URL_CHARS, MAX_PCT_ENCODED, MIN_KEYWORDS, RULES,
                       RULES_BY_NAME, evaluate_rules)


def names(url):
    return {h.name for h in evaluate_rules(url).hits}


def strong(url):
    return {h.name for h in evaluate_rules(url).hits if h.strength == "strong"}


# ------------------------------------------------------------------ registry sanity

def test_every_rule_has_name_weight_reason_text():
    for r in RULES:
        assert r.name and r.description
        assert r.strength in ("strong", "weak", "info")
        assert r.weight == {"strong": 3, "weak": 1, "info": 0}[r.strength]


def test_frozen_thresholds():
    assert (LONG_URL_CHARS, MAX_PCT_ENCODED, MIN_KEYWORDS) == (100, 3, 2)


def test_rule_strengths_match_decisions():
    expected_strong = {"ip_host", "at_in_host", "lookalike_host", "brand_in_subdomain", "embedded_url_in_path"}
    assert {r.name for r in RULES if r.strength == "strong"} == expected_strong
    for weak in ("brand_in_domain", "brand_in_path", "url_in_query", "idn_host"):
        assert RULES_BY_NAME[weak].strength == "weak"


def test_brand_file_loaded():
    assert "paypal" in BRANDS and "paypal.com" in BRANDS["paypal"]


@pytest.mark.parametrize("url", ["", "   ", None, 123, "http://[::1", "http://a.com:99999", "%%%", "x" * 100_000])
def test_never_raises(url):
    rep = evaluate_rules(url)
    assert rep.score >= 0


def test_reasons_are_human_readable():
    for h in evaluate_rules("http://paypal.com.verify-login.ru/account/verify").hits:
        assert len(h.reason) > 20 and h.reason.endswith(".")


# ------------------------------------------------------------------ ip_host (all IPv4 forms)

@pytest.mark.parametrize("url", [
    "http://192.168.1.10/login",      # dotted decimal
    "http://3232235786/",             # decimal (single integer)
    "http://0xC0A8010A/",             # hex (single integer)
    "http://0xc0.0xa8.0x01.0x0a/",    # hex per octet
    "http://0300.0250.0001.0012/",    # octal per octet
    "http://127.1/",                  # short form
    "http://[2001:db8::1]/",          # IPv6
    "http://[::1]:8080/admin",        # IPv6 with port
])
def test_ip_host_fires(url):
    assert "ip_host" in strong(url)


def test_ip_host_reason_mentions_disguise_for_obfuscated():
    hit = next(h for h in evaluate_rules("http://3232235786/").hits if h.name == "ip_host")
    assert "disguised" in hit.reason


@pytest.mark.parametrize("url", ["https://www.36560022.com", "https://1password.com", "https://www.example.com"])
def test_ip_host_not_on_domains(url):
    assert "ip_host" not in names(url)


# ------------------------------------------------------------------ at_in_host

def test_at_in_host():
    assert "at_in_host" in strong("http://paypal.com@evil.example/")
    assert "at_in_host" not in names("https://example.com/user@mail")
    assert "at_in_host" not in names("mailto-free.com/contact")


# ------------------------------------------------------------------ lookalike / idn

def test_mixed_script_unicode_is_strong():
    assert "lookalike_host" in strong("http://pаypal.com/")  # Cyrillic 'а'


def test_mixed_script_punycode_is_strong():
    assert "xn--pypal-4ve".encode("ascii")[4:].decode("punycode") == "pаypal"
    assert "lookalike_host" in strong("http://xn--pypal-4ve.com/")


@pytest.mark.parametrize("url", [
    "https://münchen.de", "https://xn--mnchen-3ya.de",  # single-script Latin with umlaut
    "http://пример.рф",                                   # all Cyrillic
    "https://例え.jp",                                     # Japanese (kanji + kana counted as one script)
    "https://xn--undecodable--.com",                     # broken punycode: weak, never a crash
])
def test_single_script_idn_is_weak(url):
    n = names(url)
    assert "idn_host" in n and "lookalike_host" not in n


def test_plain_ascii_no_idn_rules():
    assert not names("https://www.example.com") & {"idn_host", "lookalike_host"}


# ------------------------------------------------------------------ brand rules

def test_brand_in_subdomain_is_strong():
    assert "brand_in_subdomain" in strong("http://paypal.com.secure-login.ru/")
    assert "brand_in_subdomain" in strong("https://login-microsoft.verify-now.top/")


def test_brand_in_domain_is_weak():
    n = names("https://paypal-verify.com/")
    assert "brand_in_domain" in n and not strong("https://paypal-verify.com/")


def test_brand_in_path_is_weak_only():
    url = "https://github.com/paypal/paypal-checkout-components"
    assert "brand_in_path" in names(url)
    assert strong(url) == set()


@pytest.mark.parametrize("url", [
    "https://www.paypal.com/signin", "https://accounts.google.com/", "https://www.amazon.co.uk/gp/cart",
    "https://outlook.office365.com/mail/", "https://www.apple.com.cn",
])
def test_brands_never_fire_on_official_domains(url):
    assert not names(url) & {"brand_in_subdomain", "brand_in_domain", "brand_in_path"}


@pytest.mark.parametrize("url", ["https://www.pineapple.com", "https://www.purchase.com", "https://www.steampunk.org",
                                 "https://www.applebees.com", "https://www.huaweicloud.com"])
def test_brand_token_matching_avoids_substrings(url):
    assert not names(url) & {"brand_in_subdomain", "brand_in_domain"}


def test_long_brand_prefix_and_suffix_match():
    assert "brand_in_domain" in names("https://paypalsecure.com")       # 6+ letters: prefix
    assert "brand_in_domain" in names("https://mymicrosoft.net")        # 7+ letters: suffix


# ------------------------------------------------------------------ embedded / query URLs

@pytest.mark.parametrize("url", ["https://site.com//evil.com/login", "https://site.com/r/https://evil.com/x",
                                 "https://site.com/go/http:/evil.com", "https://site.com/x/%2F%2Fevil.com/"])
def test_embedded_url_in_path_strong(url):
    assert "embedded_url_in_path" in strong(url)


@pytest.mark.parametrize("url", ["https://site.com//page.html", "https://site.com/a//b", "https://www.site.com/x/https://www.site.com/y"])
def test_embedded_url_not_for_same_site_or_non_hosts(url):
    assert "embedded_url_in_path" not in names(url)


def test_archive_exception_is_documented_behavior():
    url = "https://web.archive.org/web/2020/https://example.com"
    n = names(url)
    assert "embedded_url_in_path" not in n and "archived_copy" in n
    assert strong(url) == set()


@pytest.mark.parametrize("url", ["https://example.com/login?url=https://evil.com",
                                 "https://example.com/r?u=https%3A%2F%2Fevil.com",
                                 "https://example.com/r?u=https%253A%252F%252Fevil.com"])
def test_url_in_query_is_weak(url):
    assert "url_in_query" in names(url) and not strong(url)


def test_relative_redirect_param_does_not_fire():
    assert "url_in_query" not in names("https://example.com/login?next=/dashboard")


# ------------------------------------------------------------------ weak rules / thresholds

def test_no_https_only_with_explicit_http():
    assert "no_https" in names("http://example.com")
    assert "no_https" not in names("https://example.com")
    assert "no_https" not in names("example.com")  # unknown scheme: no claim


def test_keywords_threshold():
    assert "keywords" not in names("https://example.com/login")              # 1 keyword
    assert "keywords" in names("https://example.com/login/verify-account")   # >= 2


def test_long_url_threshold():
    base = "https://example.com/"
    assert "long_or_encoded" not in names(base + "z" * (LONG_URL_CHARS - len(base)))       # exactly 100 (non-hex filler)
    assert "long_or_encoded" in names(base + "z" * (LONG_URL_CHARS - len(base) + 1))       # 101


def test_pct_encoded_threshold():
    assert "long_or_encoded" not in names("https://e.com/%41%42%43")      # 3
    assert "long_or_encoded" in names("https://e.com/%41%42%43%44")       # 4


def test_risky_extension():
    assert "risky_extension" in names("http://example.com/invoice.exe")
    assert "risky_extension" not in names("https://example.com/index.php")
    assert "risky_extension" not in names("https://example.com/go/google.com")


def test_deep_subdomains():
    assert "deep_subdomains" in names("http://a.b.c.example.com/")
    assert "deep_subdomains" in names("http://example.com:8081/")
    assert "deep_subdomains" not in names("https://example.com:443/")
    assert "deep_subdomains" not in names("https://docs.python.org/3/")


def test_shortener_is_info_only():
    rep = evaluate_rules("https://bit.ly/3abcd")
    assert [h.name for h in rep.hits] == ["shortener"] and rep.score == 0


# ------------------------------------------------------------------ real-world legitimate URLs (hand-written)

LEGIT_NO_STRONG = [
    "https://github.com/paypal/paypal-checkout-components",
    "https://accounts.google.com/signin/v2/identifier?continue=https%3A%2F%2Fmail.google.com%2Fmail%2F",
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=abc",
    "https://example.com/login?next=/dashboard",
    "https://docs.python.org/3/library/urllib.parse.html",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://www.amazon.co.uk/gp/cart/view.html",
    "https://web.archive.org/web/2020/https://example.com",
    "https://stackoverflow.com/questions/12345/how-to-parse-a-url",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://mail.google.com/mail/u/0/#inbox",
    "https://münchen.de",
    "https://www.applebees.com/en/menu",
    "https://drive.google.com/file/d/1AbCdEfGhIjKlMnOp/view",
    "https://news.ycombinator.com/item?id=1",
]


@pytest.mark.parametrize("url", LEGIT_NO_STRONG)
def test_real_world_legit_has_no_strong_hit(url):
    assert strong(url) == set(), evaluate_rules(url).hits


# Documented known false positives: these legitimate URLs DO fire a strong rule. Kept as tests
# so a change in behavior is noticed; listed in PROGRESS.md / README limitations.
KNOWN_FALSE_POSITIVES = {
    "https://apple.stackexchange.com/questions/1": "brand_in_subdomain",
    "https://www.google.blognewschannel.com": "brand_in_subdomain",
}


@pytest.mark.parametrize("url,rule", KNOWN_FALSE_POSITIVES.items())
def test_known_false_positives_documented(url, rule):
    assert rule in strong(url)
