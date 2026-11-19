import pytest

from src.features import (FEATURE_NAMES, HOST_FEATURES, MAX_ANALYZE_LEN,
                          extract_features)


def feats(url):
    f = extract_features(url)
    assert tuple(f) == FEATURE_NAMES, "keys/order must be identical for every input"
    return f


# --- schema / robustness -------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "", "   ", None, 12345, b"http://x.com", "http://", "://", "http://[::1",
    "http://a.com:99999", "http://a.com:abc/", "\x00\x01", "ht!tp://???", "@@@",
    "http://" + "a." * 300 + "com", "%%%%", "http://xn--/", ".", "http://..",
])
def test_never_raises_and_same_keys(url):
    feats(url)


def test_host_features_are_host_prefixed_plus_tld():
    assert "tld" in HOST_FEATURES
    assert all(n.startswith("host_") or n == "tld" for n in HOST_FEATURES)
    assert not any(n.startswith(("url_", "path_")) for n in HOST_FEATURES)


def test_empty_string_and_none():
    for u in ("", None, "   "):
        f = feats(u)
        assert f["parse_error"] == 1
        assert f["url_length"] == 0


def test_non_string_is_parse_error():
    assert feats(12345)["parse_error"] == 1


# --- basics --------------------------------------------------------------------------

def test_simple_https_url():
    f = feats("https://www.example.com/login/index.php?user=a&x=1#top")
    assert f["parse_error"] == 0
    assert f["url_is_https"] == 1 and f["url_has_scheme"] == 1
    assert f["host_length"] == len("example.com")  # www. stripped
    assert f["host_num_subdomains"] == 0
    assert f["tld"] == "com" and f["host_tld_known"] == 1
    assert f["host_domain_length"] == len("example")
    assert f["path_depth"] == 2 and f["path_num_params"] == 2
    assert f["path_fragment_length"] == 3
    assert f["path_has_risky_extension"] == 1
    assert f["path_suspicious_keyword_count"] >= 1


def test_www_does_not_change_host_features():
    a = extract_features("https://www.example.com")
    b = extract_features("http://example.com")
    assert {k: a[k] for k in HOST_FEATURES} == {k: b[k] for k in HOST_FEATURES}


def test_no_scheme():
    f = feats("example.co.uk/path")
    assert f["url_has_scheme"] == 0 and f["url_is_https"] == 0
    assert f["parse_error"] == 0
    assert f["tld"] == "co.uk" and f["host_domain_length"] == len("example")
    assert f["path_depth"] == 1


def test_protocol_relative():
    f = feats("//cdn.example.com/a.js")
    assert f["parse_error"] == 0 and f["host_num_subdomains"] == 1


def test_subdomain_count():
    f = feats("http://a.b.c.paypal.com.evil-site.co.uk/")
    assert f["tld"] == "co.uk"
    assert f["host_num_subdomains"] == 5  # a b c paypal com
    assert f["host_brand_keyword_count"] >= 1
    assert f["host_num_hyphens"] == 1


def test_uppercase_host_normalized():
    assert feats("HTTP://WWW.EXAMPLE.COM")["host_length"] == len("example.com")


# --- IP hosts ------------------------------------------------------------------------

def test_ipv4_host():
    f = feats("http://192.168.10.5/login")
    assert f["host_is_ip"] == 1 and f["host_is_ipv6"] == 0 and f["host_is_obfuscated_ip"] == 0
    assert f["tld"] == ""


def test_ipv6_host():
    f = feats("http://[2001:db8::1]:8080/admin")
    assert f["host_is_ip"] == 1 and f["host_is_ipv6"] == 1
    assert f["url_has_port"] == 1 and f["parse_error"] == 0


def test_ipv6_unbalanced_bracket_is_parse_error():
    assert feats("http://[2001:db8::1/x")["parse_error"] == 1


@pytest.mark.parametrize("host", ["3232235521", "0xC0A80001", "0300.0250.0.1", "127.1"])
def test_obfuscated_ipv4(host):
    f = feats(f"http://{host}/")
    assert f["host_is_ip"] == 1 and f["host_is_obfuscated_ip"] == 1


def test_number_like_domain_is_not_ip():
    f = feats("https://www.36560022.com")
    assert f["host_is_ip"] == 0 and f["tld"] == "com"


# --- obfuscation ---------------------------------------------------------------------

def test_at_sign_in_netloc():
    f = feats("http://paypal.com@evil.example/")
    assert f["url_has_at_in_netloc"] == 1
    assert f["host_length"] == len("evil.example")  # real host is after the @


def test_at_sign_in_path_is_not_netloc():
    f = feats("https://example.com/user@mail")
    assert f["url_has_at_in_netloc"] == 0 and f["url_num_at"] == 1


def test_punycode():
    f = feats("http://xn--pypal-4ve.com/")
    assert f["host_has_punycode"] == 1


def test_unicode_host():
    f = feats("http://pаypal.com/")  # Cyrillic 'а'
    assert f["host_non_ascii"] == 1


def test_percent_encoding_and_hex():
    f = feats("http://example.com/%6c%6f%67%69%6e?id=deadbeefdeadbeefdeadbeef")
    assert f["url_num_pct_encoded"] == 5
    assert f["url_has_hex_run"] == 1


def test_double_slash_redirect():
    assert feats("http://example.com//evil.com/")["url_has_double_slash_redirect"] == 1
    assert feats("http://example.com/a/b")["url_has_double_slash_redirect"] == 0


def test_invalid_port_flagged():
    f = feats("http://example.com:99999/")
    assert f["parse_error"] == 1 and f["url_has_port"] == 1


# --- length / entropy ----------------------------------------------------------------

def test_very_long_url_is_capped_but_length_reported():
    url = "http://example.com/" + "a" * 100_000
    f = feats(url)
    assert f["url_length"] == len(url)
    assert f["url_is_truncated"] == 1
    assert f["path_length"] <= MAX_ANALYZE_LEN


def test_entropy_ordering():
    low = feats("http://aaaaaaaa.com")["host_entropy"]
    high = feats("http://x7k2q9zr.com")["host_entropy"]
    assert 0 <= low < high


def test_ratios_in_range():
    f = feats("http://1234.example.com/?a=1")
    for k in ("url_digit_ratio", "url_special_ratio", "host_digit_ratio"):
        assert 0.0 <= f[k] <= 1.0


def test_deterministic():
    u = "https://login.secure-bank.example.com/verify?acc=1"
    assert extract_features(u) == extract_features(u)
