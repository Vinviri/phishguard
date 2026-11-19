"""Export the Phase 2 report numbers as small CSVs for the interactive dashboard.

Usage (from repo root, after `python -m src.model train` and `evaluate`):
    python -m src.export_report [out_dir]      # default: reports/dashboard/

Reads only files Phase 2 already wrote (reports/*, data/processed/*). Test-set numbers come
from reports/test_metrics.json and the FP review; descriptive bias tables use the TRAIN split only.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
PROC = ROOT / "data" / "processed"
NAMES = {"random_forest": "Random Forest", "logreg": "Logistic regression", "majority": "Majority class"}
BIAS_LABELS = {"https": "Starts with https://", "host_starts_www": "Host starts with www.",
               "non_root_path": "Has a path", "has_query": "Has a query string", "trailing_slash": "Ends with /"}


def _pattern(r) -> str:
    if r.tld == "io":
        return ".io domain"
    if r.host_num_subdomains >= 1:
        return "Subdomain"
    if r.host_digit_ratio > 0.3:
        return "Numeric domain"
    return "Other"


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    tm = json.loads((REPORTS / "test_metrics.json").read_text())
    ts = json.loads((REPORTS / "train_summary.json").read_text())

    rows = []
    for k, v in tm["models"].items():
        (tn, fp), (fn, tp) = v["confusion_matrix"]
        pc = v["per_class"]
        rows.append(dict(model=NAMES[k], threshold=round(v["threshold"], 3), pr_auc=round(v["pr_auc"], 4),
                         accuracy=round(v["accuracy"], 4),
                         phish_precision=round(pc["phishing"]["precision"], 4), phish_recall=round(pc["phishing"]["recall"], 4),
                         phish_f1=round(pc["phishing"]["f1-score"], 4), legit_precision=round(pc["legitimate"]["precision"], 4),
                         legit_recall=round(pc["legitimate"]["recall"], 4), legit_f1=round(pc["legitimate"]["f1-score"], 4),
                         tn=tn, fp=fp, fn=fn, tp=tp))
    pd.DataFrame(rows).to_csv(out / "test_metrics.csv", index=False)

    b, d, ch = ts["baselines_cv"], ts["diagnostic_full_url_rf_cv"], ts["chosen"]
    pd.DataFrame([
        dict(model="Majority class", pr_auc_mean=b["majority"]["pr_auc"]["mean"], pr_auc_std=b["majority"]["pr_auc"]["std"], f1_mean=b["majority"]["f1"]["mean"], used="baseline"),
        dict(model="Logistic regression", pr_auc_mean=b["logreg"]["pr_auc"]["mean"], pr_auc_std=b["logreg"]["pr_auc"]["std"], f1_mean=b["logreg"]["f1"]["mean"], used="baseline"),
        dict(model="Random Forest (chosen)", pr_auc_mean=ch["pr_auc_mean"], pr_auc_std=ch["pr_auc_std"], f1_mean=ch["f1_mean"], used="shipped"),
        dict(model="RF on all URL features (diagnostic)", pr_auc_mean=d["pr_auc"]["mean"], pr_auc_std=d["pr_auc"]["std"], f1_mean=d["f1"]["mean"], used="not used"),
    ]).round(4).to_csv(out / "cv_scores.csv", index=False)

    g = pd.read_csv(REPORTS / "grid_search_cv.csv")
    grid = pd.concat([pd.json_normalize(g.params.map(json.loads)), g.drop(columns="params")], axis=1)
    grid["class_weight"] = grid["class_weight"].fillna("none")
    grid["max_depth"] = grid["max_depth"].map(lambda x: "unlimited" if pd.isna(x) else str(int(x)))
    grid["config"] = grid.apply(lambda r: f"{r.n_estimators} trees · depth {r.max_depth} · leaf {r.min_samples_leaf} · {r.class_weight}", axis=1)
    cp = ch["params"]
    grid["chosen"] = grid.apply(lambda r: "yes" if (r.n_estimators == cp["n_estimators"] and r.min_samples_leaf == cp["min_samples_leaf"]
                                                    and r.max_depth == (str(cp["max_depth"]) if cp["max_depth"] else "unlimited")
                                                    and r.class_weight == (cp["class_weight"] or "none")) else "no", axis=1)
    grid.rename(columns={"min_samples_leaf": "min_leaf"}).round(4)[
        ["config", "n_estimators", "max_depth", "min_leaf", "class_weight", "pr_auc_mean", "pr_auc_std", "f1_mean", "fit_time_s", "chosen"]
    ].to_csv(out / "grid.csv", index=False)

    pi, mdi = ts["permutation_importance_train_fold"], tm["mdi_importance"]
    pd.DataFrame([dict(feature=k, perm_mean=v["mean"], perm_std=v["std"], mdi=mdi.get(k, 0)) for k, v in pi.items()]) \
        .sort_values("perm_mean", ascending=False).round(5).to_csv(out / "importance.csv", index=False)

    oof = pd.read_csv(REPORTS / "oof_predictions_train.csv.gz")
    y, s = oof.is_phishing.to_numpy(), oof.oof_proba.to_numpy()
    P, N = int(y.sum()), int(len(y) - y.sum())
    sweep = []
    for t in np.round(np.arange(0.05, 0.951, 0.01), 2):
        pred = s >= t
        tp_, fp_ = int((pred & (y == 1)).sum()), int((pred & (y == 0)).sum())
        prec, rec = tp_ / max(tp_ + fp_, 1), tp_ / P
        sweep.append(dict(threshold=t, precision=round(prec, 4), recall=round(rec, 4),
                          f1=round(2 * prec * rec / max(prec + rec, 1e-12), 4), tp=tp_, fp=fp_, fn=P - tp_, tn=N - fp_))
    pd.DataFrame(sweep).to_csv(out / "threshold_oof.csv", index=False)

    fp = pd.read_csv(REPORTS / "false_positive_review.csv")
    te = pd.read_csv(PROC / "features_test.csv", keep_default_na=False)
    feats = te.set_index("url").loc[fp.url]
    fp["pattern"] = [_pattern(r) for _, r in feats.iterrows()]
    fp.insert(0, "rank", range(1, len(fp) + 1))
    first = fp.top_contributors.str.split(";").str[0].str.strip()
    fp["top_feature"] = first.str.split("=").str[0]
    fp["top_contribution"] = first.str.extract(r"\(\+([\d.]+)\)")[0].astype(float)
    fp["top_contributors"] = fp.top_contributors.str.replace(r"=(\d+\.\d{3})\d+", r"=\1", regex=True)
    fp.to_csv(out / "fp_review.csv", index=False)

    tr = pd.read_csv(PROC / "features_train.csv", keep_default_na=False, usecols=["tld", "is_phishing", "host_num_subdomains"])
    tl = tr.groupby("tld").is_phishing.agg(["size", "mean"]).reindex(["com", "org", "net", "co", "io", "app", "dev", "xyz", "top"]).reset_index()
    tl.columns = ["tld", "train_rows", "phishing_share"]
    tl["tld"] = "." + tl.tld
    tl.round(4).to_csv(out / "tld_prior.csv", index=False)
    sd = tr.assign(sub=tr.host_num_subdomains.clip(upper=3)).groupby("sub").is_phishing.agg(["size", "mean"]).reset_index()
    sd.columns = ["subdomains", "train_rows", "phishing_share"]
    sd["subdomains"] = sd.subdomains.map({0: "0", 1: "1", 2: "2", 3: "3+"})
    sd.round(4).to_csv(out / "subdomain_prior.csv", index=False)

    pr = json.loads((PROC / "prep_report.json").read_text())
    bt = pr["bias_train_only"]
    pd.DataFrame([dict(property=lab, legitimate=bt["legitimate"][k], phishing=bt["phishing"][k]) for k, lab in BIAS_LABELS.items()]) \
        .to_csv(out / "train_bias.csv", index=False)
    c = pr["class_distribution"]
    pd.DataFrame([dict(split=sp.capitalize(), rows=c[sp]["rows"], phishing=c[sp]["phishing"], legitimate=c[sp]["legitimate"])
                  for sp in ("train", "test")]).to_csv(out / "split.csv", index=False)
    print(f"wrote {len(list(out.glob('*.csv')))} CSVs to {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else REPORTS / "dashboard")
