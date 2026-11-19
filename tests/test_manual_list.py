"""M8 manual list: defanging is safe and exact, and the list has no overlap with the splits."""
import csv
import re
from pathlib import Path

import pytest

from src.manual_list import (LEGIT_CANDIDATES, MANUAL, SYNTHETIC, defang, refang, split_domains, overlap)


@pytest.mark.parametrize("url", [u for u, _, _ in LEGIT_CANDIDATES + SYNTHETIC] + [
    "https://a.b.example.com/x.php?u=https://evil.example.org/y", "http://1.2.3.4/a.b", "example.com/x"])
def test_defang_roundtrip_and_not_clickable(url):
    d = defang(url)
    assert refang(d) == url
    assert not re.search(r"(?i)https?://", d)


@pytest.mark.skipif(not MANUAL.exists(), reason="manual list not built")
def test_manual_list_safe_and_no_overlap():
    rows = list(csv.DictReader(open(MANUAL, encoding="utf-8")))
    assert rows and set(rows[0]) == {"id", "url_defanged", "label", "category", "source", "notes"}
    assert {r["label"] for r in rows} <= {"phishing", "legitimate"}
    domains = split_domains()
    for r in rows:
        assert not re.search(r"(?i)https?://", r["url_defanged"]), r["id"]
        if r["category"] in ("real_feed", "real_platform"):
            assert r["url_defanged"].startswith("[withheld"), r["id"]   # OpenPhish URLs never committed
            continue
        assert overlap(refang(r["url_defanged"]), domains) is None, r["id"]
    assert len({r["id"] for r in rows}) == len(rows)
