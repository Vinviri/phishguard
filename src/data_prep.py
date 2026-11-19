"""M2 - dataset preparation for PhiUSIIL.

Usage (from repo root):
    python -m src.data_prep

Steps: load -> missing-value inspection -> label normalization -> duplicate
removal -> registered-domain extraction -> grouped train/test split ->
class distribution + label-bias report (train split only).

Outputs:
    data/processed/urls_clean.csv     url, is_phishing, registered_domain, split
    data/processed/prep_report.json   all numbers printed by this script
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
import tldextract
from sklearn.model_selection import StratifiedGroupKFold

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw" / "phiusiil" / "PhiUSIIL_Phishing_URL_Dataset.csv"
OUT_DIR = ROOT / "data" / "processed"
SEED = 42
N_FOLDS = 5  # one fold held out as test -> ~20 % test

# Offline: use the Public Suffix List snapshot bundled with tldextract, never fetch.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def registered_domain(url: str) -> str:
    """eTLD+1 (e.g. 'example.co.uk'); falls back to the bare host (IPs, unknown TLDs)."""
    try:
        host = urlsplit(url if "://" in url else "http://" + url).hostname or ""
    except ValueError:
        host = ""
    ext = _EXTRACT(host)
    return (ext.top_domain_under_public_suffix or host or url).lower()


def bias_report(df: pd.DataFrame) -> dict:
    """Per-class share of URL shape properties that could let a model take shortcuts."""
    parts = df["url"].map(lambda u: urlsplit(u))
    props = pd.DataFrame({
        "is_phishing": df["is_phishing"],
        "https": df["url"].str.lower().str.startswith("https://"),
        "has_scheme": df["url"].str.contains("://", regex=False),
        "host_starts_www": parts.map(lambda p: (p.hostname or "").startswith("www.")),
        "non_root_path": parts.map(lambda p: p.path not in ("", "/")),
        "has_query": parts.map(lambda p: p.query != ""),
        "trailing_slash": df["url"].str.endswith("/"),
        "url_len": df["url"].str.len(),
    })
    out = {}
    for label, g in props.groupby("is_phishing"):
        name = "phishing" if label == 1 else "legitimate"
        out[name] = {c: round(float(g[c].mean()), 4) for c in props.columns if c not in ("is_phishing", "url_len")}
        out[name]["url_len_median"] = float(g["url_len"].median())
    return out


def main() -> None:
    report: dict = {}
    raw = pd.read_csv(RAW, usecols=["URL", "label"], encoding="utf-8-sig")
    report["raw_rows"] = len(raw)

    # 1. Missing values (NaN or blank URL)
    blank = raw["URL"].isna() | raw["URL"].astype(str).str.strip().eq("")
    report["missing"] = {"url_nan_or_blank": int(blank.sum()), "label_nan": int(raw["label"].isna().sum())}
    df = raw[~blank & raw["label"].notna()].copy()

    # 2. Label normalization. PhiUSIIL: 0 = phishing, 1 = legitimate (verified on
    #    known samples; the UCI page text is contradictory). We use is_phishing (1 = phishing).
    assert set(df["label"].unique()) <= {0, 1}, df["label"].unique()
    df["is_phishing"] = (df["label"] == 0).astype(int)
    df["url"] = df["URL"].astype(str).str.strip()
    df = df[["url", "is_phishing"]]

    # 3. Duplicates: exact URL duplicates; URLs appearing with both labels are dropped entirely.
    n_conflict_urls = int((df.groupby("url")["is_phishing"].nunique() > 1).sum())
    conflicting = df.groupby("url")["is_phishing"].transform("nunique") > 1
    df = df[~conflicting]
    n_before = len(df)
    df = df.drop_duplicates("url").reset_index(drop=True)
    report["duplicates"] = {"conflicting_label_urls_dropped": n_conflict_urls,
                            "exact_duplicates_removed": n_before - len(df)}
    report["clean_rows"] = len(df)

    # 4. Registered domain (grouping key)
    df["registered_domain"] = df["url"].map(registered_domain)
    dom_sizes = df.groupby("registered_domain").size().sort_values(ascending=False)
    report["registered_domains"] = {
        "unique": int(len(dom_sizes)),
        "largest_groups": {k: int(v) for k, v in dom_sizes.head(10).items()},
        "domains_with_both_labels": int((df.groupby("registered_domain")["is_phishing"].nunique() > 1).sum()),
    }

    # 5. Grouped, stratified split: a registered domain is never in both train and test.
    sgkf = StratifiedGroupKFold(n_splits=N_FOLDS, shuffle=True, random_state=SEED)
    _, test_idx = next(sgkf.split(df, df["is_phishing"], groups=df["registered_domain"]))
    df["split"] = "train"
    df.loc[test_idx, "split"] = "test"
    train_doms = set(df.loc[df.split == "train", "registered_domain"])
    test_doms = set(df.loc[df.split == "test", "registered_domain"])
    assert not train_doms & test_doms, "domain leakage between splits"

    # 6. Class distribution
    def dist(d: pd.DataFrame) -> dict:
        c = d["is_phishing"].value_counts()
        return {"rows": len(d), "phishing": int(c.get(1, 0)), "legitimate": int(c.get(0, 0)),
                "phishing_share": round(float(d["is_phishing"].mean()), 4)}
    report["class_distribution"] = {"all": dist(df), "train": dist(df[df.split == "train"]),
                                    "test": dist(df[df.split == "test"])}

    # 7. Label-bias report - TRAIN ONLY (it informs feature decisions; test stays untouched)
    report["bias_train_only"] = bias_report(df[df.split == "train"])

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT_DIR / "urls_clean.csv", index=False)
    (OUT_DIR / "prep_report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    np.random.seed(SEED)
    main()
