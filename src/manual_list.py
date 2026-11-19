"""M8 - build the manual evaluation list (data/eval/manual_urls.csv).

No URL here is ever fetched, resolved or visited. URLs are stored DEFANGED
(hxxp(s)://, "[.]" in the host) and refanged only in memory.

Commands (from repo root):
    python -m src.manual_list sample-feed <file in data/eval/raw_feed/>
        Read the raw feed as text, draw a random sample of 25 (seed recorded), defang, dedupe,
        remove registered domains that appear in the train/test splits, and write
        data/eval/real_phishing_input.csv (needs >= 15 left).
    python -m src.manual_list assemble
        Hand-written legitimate URLs + synthetic phishing + real phishing -> overlap check ->
        data/eval/manual_urls.csv and data/eval/overlap_report.csv.
The overlap check reads only the registered-domain column of the splits (no labels, no predictions).
"""
from __future__ import annotations

import csv
import json
import random
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL = ROOT / "data" / "eval"
RAW_FEED_DIR = EVAL / "raw_feed"
REAL_INPUT = EVAL / "real_phishing_input.csv"
MANUAL = EVAL / "manual_urls.csv"            # committed: real phishing URLs withheld
MANUAL_FULL = EVAL / "manual_urls_full.csv"  # git-ignored: complete list used by src.manual_eval
REAL_SOURCE = "OpenPhish community feed (openphish.com/feed.txt)"
REAL_DATE = "2026-11-19"
WITHHELD = "[withheld: OpenPhish feed, redistribution not confirmed]"
OVERLAP_REPORT = EVAL / "overlap_report.csv"
SAMPLE_LOG = EVAL / "real_sample_log.json"
FEED_SEED = 20261119
FEED_SAMPLE = 25
FEED_MIN_KEEP = 15
PLATFORM_SAMPLE = 15
REAL_PLATFORM_INPUT = EVAL / "real_platform_input.csv"  # git-ignored
COLUMNS = ["id", "url_defanged", "label", "category", "source", "notes"]

HAND = "hand-written; real site; path not verified (never visited)"
SYN = "synthetic"
SYN_NOTE = "invented domain, never resolved or visited; built to use a rule trick"

# ------------------------------------------------------------------ legitimate candidates (hand-written)
# Real sites from general knowledge. Many will be dropped by the overlap check (more candidates than needed).
LEGIT_CANDIDATES: list[tuple[str, str, str]] = [
    # docs / subdomain sites
    ("https://docs.python.org/3/library/urllib.parse.html", "docs_subdomain", ""),
    ("https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/404", "docs_subdomain", ""),
    ("https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html", "docs_subdomain", "long path"),
    ("https://pandas.pydata.org/docs/reference/api/pandas.read_csv.html", "docs_subdomain", ""),
    ("https://docs.streamlit.io/develop/api-reference/widgets/st.text_input", "docs_subdomain", ""),
    ("https://en.wikipedia.org/wiki/Phishing", "docs_subdomain", ""),
    ("https://kubernetes.io/docs/concepts/overview/", "docs_subdomain", ""),
    ("https://www.postgresql.org/docs/16/sql-select.html", "docs_subdomain", ""),
    ("https://numpy.org/doc/stable/reference/generated/numpy.quantile.html", "docs_subdomain", ""),
    ("https://learn.microsoft.com/en-us/dotnet/csharp/tour-of-csharp/", "docs_subdomain", ""),
    ("https://cloud.google.com/storage/docs/introduction", "docs_subdomain", ""),
    ("https://docs.djangoproject.com/en/5.0/topics/http/urls/", "docs_subdomain", ""),
    ("https://fastapi.tiangolo.com/tutorial/first-steps/", "docs_subdomain", ""),
    # GitHub / code hosting repo paths
    ("https://github.com/scikit-learn/scikit-learn/blob/main/README.rst", "repo_path", ""),
    ("https://github.com/streamlit/streamlit/issues", "repo_path", ""),
    ("https://gitlab.com/gitlab-org/gitlab/-/issues", "repo_path", ""),
    ("https://bitbucket.org/atlassian/python-bitbucket/src/master/", "repo_path", ""),
    # OAuth / login redirects
    ("https://github.com/login?return_to=https%3A%2F%2Fgithub.com%2Fsettings%2Fprofile", "login_redirect", "full URL in query"),
    ("https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fmail.google.com%2Fmail%2F", "login_redirect", "?continue= with a full URL"),
    ("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=00000000-0000-0000-0000-000000000000&redirect_uri=https%3A%2F%2Fportal.azure.com", "login_redirect", "OAuth redirect_uri"),
    ("https://stackoverflow.com/users/login?ssrc=head&returnurl=https%3a%2f%2fstackoverflow.com%2f", "login_redirect", ""),
    ("https://www.reddit.com/login/?dest=https%3A%2F%2Fwww.reddit.com%2Fr%2Fpython%2F", "login_redirect", ""),
    ("https://news.ycombinator.com/login?goto=news", "login_redirect", "relative redirect"),
    ("https://discord.com/login?redirect_to=%2Fchannels%2F%40me", "login_redirect", "relative ?redirect_to="),
    ("https://app.example-saas.dev/login?next=/dashboard", "login_redirect", "SKIP"),  # placeholder, filtered below
    ("https://www.figma.com/login?next=%2Ffiles%2Frecent", "login_redirect", "relative ?next="),
    ("https://id.atlassian.com/login?continue=https%3A%2F%2Fwww.atlassian.com%2F", "login_redirect", "?continue= with a full URL"),
    # web archive
    ("https://web.archive.org/web/2020/https://www.python.org/", "archive", "archived copy of python.org"),
    # link shortener
    ("https://buff.ly/3Xk9PyDocs", "shortener", "Buffer link shortener; destination unknown by nature; label assumed legitimate (bit.ly was dropped: it overlaps the dataset)"),
    # IDN single script
    ("https://www.bücher.de/", "idn_single_script", "German umlaut (Latin script only)"),
    ("https://президент.рф/", "idn_single_script", "all Cyrillic"),
    # brand name in a legitimate path
    ("https://github.com/paypal/paypal-js", "brand_in_path", "brand in path on a code host"),
    ("https://www.npmjs.com/package/@paypal/react-paypal-js", "brand_in_path", ""),
    ("https://stackoverflow.com/questions/tagged/amazon-web-services", "brand_in_path", ""),
    ("https://pypi.org/project/google-cloud-storage/", "brand_in_path", ""),
    # ordinary long URLs
    ("https://www.nytimes.com/2024/05/01/technology/artificial-intelligence-regulation.html", "long_ordinary", ""),
    ("https://www.etsy.com/listing/1234567890/handmade-ceramic-coffee-mug-blue-glaze?ref=hp_rv-1&frs=1", "long_ordinary", ""),
    ("https://www.booking.com/hotel/nl/example-amsterdam.html?checkin=2025-06-01&checkout=2025-06-03&group_adults=2", "long_ordinary", ""),
    ("https://arxiv.org/abs/1706.03762", "long_ordinary", ""),
    ("https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLFgquLnL59alCl_2TQvOiD5Vgm1hCaGSI", "long_ordinary", ""),
    ("https://support.apple.com/en-us/102208", "long_ordinary", "brand's own support subdomain"),
    ("https://www.theguardian.com/technology/2024/jan/15/ai-chatbots-regulation-europe", "long_ordinary", ""),
    ("https://www.ikea.com/us/en/p/billy-bookcase-white-00263850/", "long_ordinary", ""),
]
LEGIT_CANDIDATES = [c for c in LEGIT_CANDIDATES if c[2] != "SKIP"]

# ------------------------------------------------------------------ synthetic phishing (rule tricks)
# Long invented names on real TLDs; IPs from documentation ranges (RFC 5737). Never resolved.
_LOOKALIKE_UNICODE = "аpple-id-support-q3n8xv.com"          # Cyrillic 'а' + Latin
_LOOKALIKE_PUNY = "рaypal-resolution-k7m2wq".encode("idna").decode("ascii") + ".com"  # Cyrillic 'р'
SYNTHETIC: list[tuple[str, str, str]] = [
    ("http://203.0.113.45/secure-login/paypal/verify.php", "syn_ip_host", "documentation IP range"),
    ("http://3405803821/account/update/login", "syn_ip_host", "decimal form of 203.0.113.45"),
    ("http://www.paypal.com@secure-verify-account-x7q2vn.top/login", "syn_at_trick", ""),
    ("https://paypal.com.resolution-center-k8m3vqz.xyz/signin?country=US", "syn_brand_subdomain", ""),
    ("http://secure.chase.com.online-banking-verify-t6r2pk.info/login/verify-account", "syn_brand_subdomain", ""),
    (f"https://{_LOOKALIKE_UNICODE}/signin", "syn_lookalike", "mixed Latin + Cyrillic, Unicode form"),
    (f"https://{_LOOKALIKE_PUNY}/webapps/signin", "syn_lookalike", "mixed Latin + Cyrillic, punycode form"),
    ("https://cdn-static-files-n2k7rq.site//secure-paypal-login-h5j9wd.top/verify", "syn_embedded_url", ""),
    ("https://redirect-gateway-z8p4qm.click/r/https://appleid-verify-w3k6tb.top/", "syn_embedded_url", ""),
    ("http://invoice-docs-share-m7v2xc.top/files/Invoice_2025_0193.zip", "syn_risky_extension", ""),
    ("https://update-player-q9w2jd.xyz/download/PlayerUpdate.exe", "syn_risky_extension", ""),
]


# ------------------------------------------------------------------ defang / refang

_SPLIT = re.compile(r"^(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)?(?P<host>[^/?#]*)(?P<rest>.*)$", re.S)


def defang(url: str) -> str:
    """hxxp(s):// and '[.]' in the host. URLs embedded in the path/query (http(s): and //host)
    are defanged the same way so no part of the stored text is clickable."""
    m = _SPLIT.match(url.strip())
    scheme, host, rest = m.group("scheme") or "", m.group("host"), m.group("rest")
    low = scheme.lower()
    if low.startswith("https"):
        scheme = "hxxps" + scheme[5:]
    elif low.startswith("http"):
        scheme = "hxxp" + scheme[4:]
    rest = re.sub(r"(?i)http(s?):", lambda mm: "hxxp" + mm.group(1) + ":", rest)
    rest = re.sub(r"//([^/?#\s]+)", lambda mm: "//" + mm.group(1).replace(".", "[.]"), rest)
    return scheme + host.replace(".", "[.]") + rest


def refang(url: str) -> str:
    """Exact inverse of defang (checked for every stored URL in assemble)."""
    return url.strip().replace("hxxp", "http").replace("HXXP", "HTTP").replace("[.]", ".")


# ------------------------------------------------------------------ overlap check

def _domain_forms(url: str) -> set[str]:
    from src.features import url_parts
    p = url_parts(url)
    rd = p.registered_domain
    if not rd:
        return set()
    forms = {rd}
    try:
        forms.add(rd.encode("idna").decode("ascii"))
    except UnicodeError:
        pass
    try:
        forms.add(".".join(lab[4:].encode("ascii").decode("punycode") if lab.startswith("xn--") else lab
                           for lab in rd.split(".")))
    except (UnicodeError, ValueError):
        pass
    return forms


def split_domains() -> set[str]:
    """Registered domains in the train AND test splits (domain column only)."""
    import pandas as pd
    df = pd.read_csv(ROOT / "data" / "processed" / "urls_clean.csv", usecols=["registered_domain"])
    return set(df["registered_domain"].astype(str).str.lower())


def overlap(url: str, domains: set[str]) -> str | None:
    hit = _domain_forms(url) & domains
    return sorted(hit)[0] if hit else None


# ------------------------------------------------------------------ real feed sampling

_URL_RE = re.compile(r"(?:https?|hxxps?)://[^\s,\"'<>]+", re.IGNORECASE)


def _write_real(path: Path, defanged: list[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["url_defanged", "source", "date_seen"])
        for d in defanged:
            w.writerow([d, REAL_SOURCE, REAL_DATE])


def sample_feed(path: Path) -> None:
    """User decision (option 1 + addition, made before any results):
    - independent sample: 25 URLs from the pool whose registered domain is NOT in the train/test splits;
    - platform sample: 15 URLs from the overlapping (known-platform) pool, descriptive only, never in headline counts.
    Both use random.Random(FEED_SEED). Only counts are logged (feed not redistributable)."""
    path = Path(path)
    if RAW_FEED_DIR.resolve() not in path.resolve().parents:
        sys.exit(f"The feed file must be inside {RAW_FEED_DIR}")
    text = path.read_text(encoding="utf-8", errors="replace")   # read as text only; nothing is fetched
    found = [refang(u.rstrip(").;")) for u in _URL_RE.findall(text)]
    unique = list(dict.fromkeys(defang(u) for u in found))       # dedupe on the defanged form
    domains = split_domains()
    independent_pool = [d for d in unique if overlap(refang(d), domains) is None]
    platform_pool = [d for d in unique if overlap(refang(d), domains) is not None]
    if len(independent_pool) < FEED_SAMPLE or len(platform_pool) < PLATFORM_SAMPLE:
        sys.exit("Not enough URLs in one of the pools; nothing written.")
    independent = random.Random(FEED_SEED).sample(independent_pool, FEED_SAMPLE)
    platform = random.Random(FEED_SEED).sample(platform_pool, PLATFORM_SAMPLE)
    log = {"feed_file": path.name, "source": REAL_SOURCE, "downloaded": REAL_DATE, "seed": FEED_SEED,
           "urls_in_feed": len(found), "unique_urls": len(unique),
           "independent_pool_size": len(independent_pool), "platform_pool_size": len(platform_pool),
           "independent_sampled": len(independent), "platform_sampled": len(platform),
           "method": "Pools split by the overlap check (registered domain in PhiUSIIL train/test). "
                     "25 sampled from the independent pool, 15 from the platform pool, each with "
                     "random.Random(seed).sample. First attempt (sample 25 from the whole feed, then remove "
                     "overlaps) kept only 6 and was abandoned before any evaluation (user decision)."}
    _write_real(REAL_INPUT, independent)
    _write_real(REAL_PLATFORM_INPUT, platform)
    SAMPLE_LOG.write_text(json.dumps(log, indent=2) + chr(10), encoding="utf-8")
    print(json.dumps(log, indent=2))


# ------------------------------------------------------------------ assemble

def assemble() -> None:
    domains = split_domains()
    rows, overlaps = [], []

    def add(url, label, category, source, notes):
        assert refang(defang(url)) == url, "defang/refang must round-trip exactly"
        hit = overlap(url, domains)
        if hit:
            real = category == "real_feed"
            overlaps.append({"url_defanged": WITHHELD if real else defang(url), "label": label,
                             "category": category, "overlapping_domain": "[withheld]" if real else hit})
            return
        rows.append({"url_defanged": defang(url), "label": label, "category": category, "source": source, "notes": notes})

    for url, cat, note in LEGIT_CANDIDATES:
        add(url, "legitimate", cat, HAND, note)
    for url, cat, note in SYNTHETIC:
        add(url, "phishing", cat, SYN, f"{SYN_NOTE}. {note}".strip(". ").strip())
    if REAL_INPUT.exists():
        with open(REAL_INPUT, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                add(refang(r["url_defanged"]), "phishing", "real_feed", r["source"], r.get("date_seen", ""))
    if REAL_PLATFORM_INPUT.exists():  # known-platform phishing: overlaps by definition, kept on purpose,
        with open(REAL_PLATFORM_INPUT, encoding="utf-8") as fh:  # descriptive only (never headline counts)
            for r in csv.DictReader(fh):
                rows.append({"url_defanged": r["url_defanged"], "label": "phishing", "category": "real_platform",
                             "source": r["source"], "notes": "not independent of training; descriptive only"})

    for i, r in enumerate(rows, 1):
        r["id"] = f"M{i:03d}"
    with open(MANUAL_FULL, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows(rows)
    with open(MANUAL, "w", newline="", encoding="utf-8") as fh:   # public copy
        w = csv.DictWriter(fh, fieldnames=COLUMNS)
        w.writeheader()
        w.writerows([{**r, "url_defanged": WITHHELD} if r["category"] in ("real_feed", "real_platform") else r for r in rows])
    with open(OVERLAP_REPORT, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["url_defanged", "label", "category", "overlapping_domain"])
        w.writeheader()
        w.writerows(overlaps)
    counts = {}
    for r in rows:
        key = (r["label"], "synthetic" if r["source"] == SYN else ("real" if r["category"] == "real_feed" else "hand"))
        counts[key] = counts.get(key, 0) + 1
    print(f"kept {len(rows)} URLs, removed {len(overlaps)} overlaps")
    for k, v in sorted(counts.items()):
        print(f"  {k[0]:10} {k[1]:9} {v}")
    print("removed (overlap with train/test registered domains):")
    for o in overlaps:
        print(f"  {o['label']:10} {o['category']:18} {o['overlapping_domain']}")  # real ones are withheld


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "sample-feed":
        sample_feed(Path(sys.argv[2]))
    elif sys.argv[1:] == ["assemble"]:
        assemble()
    else:
        sys.exit("usage: python -m src.manual_list sample-feed <file> | assemble")
