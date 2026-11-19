"""M4 - model development.

Commands (run from repo root):
    python -m src.model build-features   # features_train.csv / features_test.csv
    python -m src.model train            # baselines, diagnostic, grid search, threshold, refit, save
                                         # (TRAIN split only - never reads features_test.csv)
    python -m src.model evaluate         # ONE-TIME final test evaluation (+ FP review, charts)

App helpers: load_model(), predict_url().

The ML model uses HOST features only (see PROGRESS.md: every legitimate training URL is
https://www.<host> with no path, so full-URL features would learn that template).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, classification_report,
                             confusion_matrix, f1_score, precision_recall_curve,
                             precision_score, recall_score)
from sklearn.model_selection import (GridSearchCV, StratifiedGroupKFold,
                                     cross_val_predict, cross_validate)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from src.features import FEATURE_NAMES, HOST_FEATURES, extract_features

ROOT = Path(__file__).resolve().parents[1]
PROC = ROOT / "data" / "processed"
MODELS = ROOT / "models"
REPORTS = ROOT / "reports"
MODEL_PATH = MODELS / "phishguard_rf.joblib"
BASELINES_PATH = MODELS / "baselines.joblib"
TRAIN_SUMMARY = REPORTS / "train_summary.json"
TEST_LOCK = REPORTS / ".test_evaluated"

SEED = 42
N_FOLDS = 5
MODEL_VERSION = "rf-host-v1"
TARGET = "is_phishing"
GROUP = "registered_domain"

MODEL_COLUMNS: list[str] = list(HOST_FEATURES)           # what the app model sees
NUMERIC_HOST = [c for c in MODEL_COLUMNS if c != "tld"]
ALL_NUMERIC = [c for c in FEATURE_NAMES if c != "tld"]   # diagnostic only

PARAM_GRID = {
    "clf__n_estimators": [200, 400],
    "clf__max_depth": [None, 30],
    "clf__min_samples_leaf": [1, 5],
    "clf__class_weight": [None, "balanced"],
}


# --------------------------------------------------------------------------- pipelines

def _tld_encoder() -> OneHotEncoder:
    # TLDs seen >= 50 times in the fitting data get their own column; rare and unseen
    # TLDs share one "infrequent" column. Fitted inside each CV fold (no leakage).
    return OneHotEncoder(min_frequency=50, handle_unknown="infrequent_if_exist", sparse_output=False)


def build_rf(numeric: list[str] = NUMERIC_HOST, **rf_params) -> Pipeline:
    pre = ColumnTransformer([("num", "passthrough", numeric), ("tld", _tld_encoder(), ["tld"])],
                            verbose_feature_names_out=False)
    rf = RandomForestClassifier(random_state=SEED, n_jobs=-1, **rf_params)
    return Pipeline([("pre", pre), ("clf", rf)])


def build_logreg() -> Pipeline:
    pre = ColumnTransformer([("num", StandardScaler(), NUMERIC_HOST), ("tld", _tld_encoder(), ["tld"])],
                            verbose_feature_names_out=False)
    return Pipeline([("pre", pre), ("clf", LogisticRegression(max_iter=3000, random_state=SEED))])


def build_majority() -> Pipeline:
    return Pipeline([("clf", DummyClassifier(strategy="most_frequent"))])


# --------------------------------------------------------------------------- data

def build_features() -> None:
    df = pd.read_csv(PROC / "urls_clean.csv")
    t = time.perf_counter()
    feats = pd.DataFrame([extract_features(u) for u in df["url"]], columns=list(FEATURE_NAMES))
    feats["tld"] = feats["tld"].fillna("")
    out = pd.concat([df[["url", TARGET, GROUP]].reset_index(drop=True), feats], axis=1)
    for split in ("train", "test"):
        part = out[df["split"].values == split]
        part.to_csv(PROC / f"features_{split}.csv", index=False)
        print(f"features_{split}.csv: {part.shape}")
    print(f"extracted in {time.perf_counter() - t:.1f}s")


def load_split(split: str) -> pd.DataFrame:
    df = pd.read_csv(PROC / f"features_{split}.csv", keep_default_na=False, na_values=[])
    df["tld"] = df["tld"].astype(str)
    return df


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _metrics(y, proba, threshold) -> dict:
    pred = (proba >= threshold).astype(int)
    return {
        "pr_auc": float(average_precision_score(y, proba)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
    }


# --------------------------------------------------------------------------- train

def train() -> None:
    REPORTS.mkdir(exist_ok=True)
    MODELS.mkdir(exist_ok=True)
    tr = load_split("train")  # the ONLY data this function reads
    X, y, groups = tr, tr[TARGET].to_numpy(), tr[GROUP].to_numpy()
    cv = StratifiedGroupKFold(n_splits=N_FOLDS, shuffle=True, random_state=SEED)
    folds = list(cv.split(X, y, groups))  # identical folds for every model
    scoring = {"pr_auc": "average_precision", "f1": "f1", "precision": "precision", "recall": "recall"}
    summary: dict = {"n_train": int(len(tr)), "cv": f"StratifiedGroupKFold({N_FOLDS}) by {GROUP}, seed {SEED}"}

    def cv_scores(name, est, cols):
        t = time.perf_counter()
        r = cross_validate(est, X[cols], y, cv=folds, scoring=scoring, n_jobs=1)
        res = {k: {"mean": float(np.mean(r[f"test_{k}"])), "std": float(np.std(r[f"test_{k}"]))} for k in scoring}
        print(f"[cv] {name}: " + ", ".join(f"{k}={v['mean']:.4f}±{v['std']:.4f}" for k, v in res.items())
              + f"  ({time.perf_counter() - t:.0f}s)", flush=True)
        return res

    summary["baselines_cv"] = {
        "majority": cv_scores("majority", build_majority(), MODEL_COLUMNS),
        "logreg": cv_scores("logreg", build_logreg(), MODEL_COLUMNS),
    }
    # Diagnostic: RF on ALL URL features, to quantify the template shortcut. Not used by the app.
    summary["diagnostic_full_url_rf_cv"] = cv_scores(
        "diagnostic RF all URL features", build_rf(numeric=ALL_NUMERIC, n_estimators=200), ALL_NUMERIC + ["tld"])

    # Grid search (sequential over configs; each RF uses all cores -> one model in memory at a time)
    t = time.perf_counter()
    gs = GridSearchCV(build_rf(), PARAM_GRID, cv=folds, scoring=scoring, refit=False, n_jobs=1, verbose=1)
    gs.fit(X[MODEL_COLUMNS], y)
    print(f"[grid] {len(gs.cv_results_['params'])} configs in {time.perf_counter() - t:.0f}s", flush=True)
    res = pd.DataFrame(gs.cv_results_)
    grid = pd.DataFrame({
        "params": [json.dumps({k.replace('clf__', ''): v for k, v in p.items()}) for p in res["params"]],
        "pr_auc_mean": res["mean_test_pr_auc"], "pr_auc_std": res["std_test_pr_auc"],
        "f1_mean": res["mean_test_f1"], "fit_time_s": res["mean_fit_time"],
    }).sort_values("pr_auc_mean", ascending=False)
    grid.to_csv(REPORTS / "grid_search_cv.csv", index=False)
    print(grid.to_string(index=False), flush=True)

    # Selection: simplest config within one standard error of the best PR-AUC
    best = grid.iloc[0]
    se = best["pr_auc_std"] / np.sqrt(N_FOLDS)
    eligible = grid[grid["pr_auc_mean"] >= best["pr_auc_mean"] - se].copy()
    def complexity(p):
        p = json.loads(p)
        return (p["n_estimators"], 0 if p["max_depth"] else 1, -p["min_samples_leaf"])
    eligible["cx"] = eligible["params"].map(complexity)
    chosen = eligible.sort_values(["cx", "pr_auc_mean"], ascending=[True, False]).iloc[0]
    params = json.loads(chosen["params"])
    print(f"[select] best={best['params']} {best['pr_auc_mean']:.4f}; 1-SE band >= {best['pr_auc_mean'] - se:.4f}; "
          f"chosen={params} {chosen['pr_auc_mean']:.4f}", flush=True)
    summary["grid_best"] = {"params": json.loads(best["params"]), "pr_auc_mean": float(best["pr_auc_mean"]),
                            "pr_auc_std": float(best["pr_auc_std"])}
    summary["selection_rule"] = "simplest config (fewest trees, then limited depth, then larger leaves) within 1 SE of best mean CV PR-AUC"
    summary["chosen"] = {"params": params, "pr_auc_mean": float(chosen["pr_auc_mean"]),
                         "pr_auc_std": float(chosen["pr_auc_std"]), "f1_mean": float(chosen["f1_mean"])}

    # Threshold from out-of-fold predictions on TRAIN only
    rf = build_rf(**params)
    oof = cross_val_predict(rf, X[MODEL_COLUMNS], y, cv=folds, method="predict_proba", n_jobs=1)[:, 1]
    prec, rec, thr = precision_recall_curve(y, oof)
    f1s = 2 * prec[:-1] * rec[:-1] / np.clip(prec[:-1] + rec[:-1], 1e-12, None)
    i = int(np.nanargmax(f1s))
    f1_at_05 = f1_score(y, (oof >= 0.5).astype(int))
    use_opt = f1s[i] - f1_at_05 > 0.005
    threshold = float(thr[i]) if use_opt else 0.5
    summary["threshold"] = {
        "value": threshold, "source": "out-of-fold CV predictions on train (chosen config)",
        "rule": "use max-F1 OOF threshold only if it beats 0.5 by > 0.005 F1, else 0.5",
        "oof_f1_at_0.5": float(f1_at_05), "oof_max_f1": float(f1s[i]), "oof_max_f1_threshold": float(thr[i]),
        "oof_metrics_at_chosen": _metrics(y, oof, threshold),
    }
    print(f"[threshold] OOF F1@0.5={f1_at_05:.4f}, max F1={f1s[i]:.4f} @ {thr[i]:.3f} -> using {threshold:.3f}", flush=True)
    pd.DataFrame({"row": np.arange(len(y)), TARGET: y, "oof_proba": oof.round(5)}).to_csv(
        REPORTS / "oof_predictions_train.csv.gz", index=False)

    # Permutation importance on one grouped TRAIN fold (fit on 4 folds, score held-out fold)
    tr_idx, va_idx = folds[0]
    rf_fold = build_rf(**params).fit(X.iloc[tr_idx][MODEL_COLUMNS], y[tr_idx])
    rng = np.random.default_rng(SEED)
    va_sample = rng.choice(va_idx, size=min(10_000, len(va_idx)), replace=False)
    pi = permutation_importance(rf_fold, X.iloc[va_sample][MODEL_COLUMNS], y[va_sample],
                                scoring="average_precision", n_repeats=5, random_state=SEED, n_jobs=1)
    summary["permutation_importance_train_fold"] = {
        c: {"mean": float(m), "std": float(s)} for c, m, s in zip(MODEL_COLUMNS, pi.importances_mean, pi.importances_std)}

    # Refit chosen config and baselines on full train, save
    t = time.perf_counter()
    final = build_rf(**params).fit(X[MODEL_COLUMNS], y)
    summary["final_fit_seconds"] = round(time.perf_counter() - t, 1)
    bundle = {
        "pipeline": final,
        "feature_columns": MODEL_COLUMNS,
        "threshold": threshold,
        "positive_class": "1 = phishing",
        "version": MODEL_VERSION,
        "trained_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "sklearn": sklearn.__version__,
        "dataset": "PhiUSIIL (UCI 967), data/processed/urls_clean.csv split=train",
        "dataset_sha256": _sha256(PROC / "urls_clean.csv"),
        "params": params,
        "cv_pr_auc": summary["chosen"]["pr_auc_mean"],
        "note": "Host-only features (www. stripped). Outputs a probability-like score, not a guarantee.",
    }
    joblib.dump(bundle, MODEL_PATH, compress=3)
    joblib.dump({"majority": build_majority().fit(X[MODEL_COLUMNS], y),
                 "logreg": build_logreg().fit(X[MODEL_COLUMNS], y)}, BASELINES_PATH, compress=3)
    clf = final.named_steps["clf"]
    summary["model_size"] = {"file_mb": round(MODEL_PATH.stat().st_size / 1e6, 2),
                             "total_nodes": int(sum(t.tree_.node_count for t in clf.estimators_)),
                             "mean_depth": float(np.mean([t.get_depth() for t in clf.estimators_]))}
    TRAIN_SUMMARY.write_text(json.dumps(summary, indent=2))
    print(f"[save] {MODEL_PATH.name}: {summary['model_size']}", flush=True)


# --------------------------------------------------------------------------- app helpers

def load_model(path: Path = MODEL_PATH) -> dict:
    return joblib.load(path)


def features_frame(urls: list[str], columns: list[str]) -> pd.DataFrame:
    rows = [extract_features(u) for u in urls]
    df = pd.DataFrame(rows)[columns]
    if "tld" in df:
        df["tld"] = df["tld"].astype(str)
    return df


def predict_url(bundle: dict, url: str) -> dict:
    """URL string -> extract_features -> model. Returns probability and thresholded flag."""
    X = features_frame([url], bundle["feature_columns"])
    proba = float(bundle["pipeline"].predict_proba(X)[0, 1])
    return {"phishing_probability": proba, "above_threshold": proba >= bundle["threshold"],
            "threshold": bundle["threshold"]}


# --------------------------------------------------------------------------- explanations

def rf_contributions(pipeline: Pipeline, X: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """Per-feature contributions to P(phishing) by walking every tree's decision path.

    For each split on the path, the change in the node's phishing proportion is credited to the
    split feature. bias + sum(contributions) == predict_proba (checked by caller).
    One-hot TLD columns are merged into a single 'tld' contribution.
    """
    pre, rf = pipeline.named_steps["pre"], pipeline.named_steps["clf"]
    Xt = pre.transform(X)
    names = list(pre.get_feature_names_out())
    contrib = np.zeros((Xt.shape[0], len(names)))
    bias = np.zeros(Xt.shape[0])
    for est in rf.estimators_:
        tree = est.tree_
        val = tree.value[:, 0, 1] / tree.value[:, 0, :].sum(axis=1)  # P(class 1) per node
        paths = est.decision_path(Xt)
        for i in range(Xt.shape[0]):
            nodes = paths.indices[paths.indptr[i]:paths.indptr[i + 1]]
            bias[i] += val[nodes[0]]
            for parent, child in zip(nodes[:-1], nodes[1:]):
                contrib[i, tree.feature[parent]] += val[child] - val[parent]
    contrib /= len(rf.estimators_)
    bias /= len(rf.estimators_)
    num = [n for n in names if not n.startswith("tld_")]
    merged = np.column_stack([contrib[:, [names.index(n) for n in num]],
                              contrib[:, [j for j, n in enumerate(names) if n.startswith("tld_")]].sum(axis=1)])
    return merged, bias, num + ["tld"]


# --------------------------------------------------------------------------- evaluate

def _plot_confusion(cm: np.ndarray, path: Path, threshold: float) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(5, 4.4))
    ax.imshow(cm, cmap="Blues")
    labels = ["legitimate", "phishing"]
    ax.set_xticks([0, 1], labels)
    ax.set_yticks([0, 1], labels)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    total = cm.sum()
    for (r, c), v in np.ndenumerate(cm):
        ax.text(c, r, f"{v:,}\n({v / total:.1%})", ha="center", va="center",
                color="white" if v > cm.max() / 2 else "black", fontsize=11)
    ax.set_title(f"Random Forest - test set (threshold {threshold:.2f})")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def _plot_importance(mdi: pd.Series, perm: pd.DataFrame, path: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    order = perm["mean"].sort_values().index
    fig, axes = plt.subplots(1, 2, figsize=(11, 6), sharey=True)
    axes[0].barh(order, perm.loc[order, "mean"], xerr=perm.loc[order, "std"], color="#3b6ea5")
    axes[0].set_title("Permutation importance\n(drop in PR-AUC, held-out TRAIN fold)")
    axes[1].barh(order, mdi.reindex(order).fillna(0), color="#9aa5b1")
    axes[1].set_title("Impurity importance (MDI)\n(final model, tld one-hots summed)")
    for ax in axes:
        ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def evaluate(force: bool = False) -> None:
    if TEST_LOCK.exists() and not force:
        sys.exit(f"Test set already evaluated ({TEST_LOCK.read_text().strip()}). "
                 "Re-running needs --force and must be recorded in PROGRESS.md.")
    bundle, baselines = load_model(), joblib.load(BASELINES_PATH)
    summary = json.loads(TRAIN_SUMMARY.read_text())
    te = load_split("test")
    TEST_LOCK.write_text(f"first evaluated {datetime.now(timezone.utc).isoformat(timespec='seconds')}"
                         + (" (FORCED re-run)" if force else "") + "\n")
    X, y = te[bundle["feature_columns"]], te[TARGET].to_numpy()
    thr = bundle["threshold"]

    out: dict = {"n_test": int(len(te)), "threshold": thr, "models": {}}
    probas = {"random_forest": bundle["pipeline"].predict_proba(X)[:, 1],
              "logreg": baselines["logreg"].predict_proba(X)[:, 1],
              "majority": baselines["majority"].predict_proba(X)[:, 1]}
    for name, p in probas.items():
        t = thr if name == "random_forest" else 0.5
        pred = (p >= t).astype(int)
        rep = classification_report(y, pred, target_names=["legitimate", "phishing"], output_dict=True, zero_division=0)
        out["models"][name] = {
            "threshold": t,
            "pr_auc": float(average_precision_score(y, p)),
            "per_class": {k: {m: float(rep[k][m]) for m in ("precision", "recall", "f1-score", "support")}
                          for k in ("legitimate", "phishing")},
            "accuracy": float(rep["accuracy"]),
            "confusion_matrix": confusion_matrix(y, pred).tolist(),
        }
        print(f"[test] {name}: PR-AUC={out['models'][name]['pr_auc']:.4f} acc={rep['accuracy']:.4f} "
              f"phish P/R/F1={rep['phishing']['precision']:.4f}/{rep['phishing']['recall']:.4f}/{rep['phishing']['f1-score']:.4f}")
    cm = np.array(out["models"]["random_forest"]["confusion_matrix"])
    _plot_confusion(cm, REPORTS / "confusion_matrix.png", thr)

    # importance chart
    clf, pre = bundle["pipeline"].named_steps["clf"], bundle["pipeline"].named_steps["pre"]
    mdi = pd.Series(clf.feature_importances_, index=pre.get_feature_names_out())
    mdi = pd.concat([mdi[~mdi.index.str.startswith("tld_")], pd.Series({"tld": mdi[mdi.index.str.startswith("tld_")].sum()})])
    perm = pd.DataFrame(summary["permutation_importance_train_fold"]).T
    _plot_importance(mdi, perm, REPORTS / "feature_importance.png")
    out["mdi_importance"] = mdi.sort_values(ascending=False).round(4).to_dict()

    # False-positive review: top-20 legitimate URLs by phishing probability
    p_rf = probas["random_forest"]
    legit = np.where(y == 0)[0]
    top = legit[np.argsort(-p_rf[legit], kind="stable")[:20]]
    contrib, bias, names = rf_contributions(bundle["pipeline"], X.iloc[top])
    assert np.allclose(bias + contrib.sum(axis=1), p_rf[top], atol=1e-6), "contribution decomposition mismatch"
    rows = []
    for k, idx in enumerate(top):
        order = np.argsort(-contrib[k])[:3]
        rows.append({
            "url": te["url"].iloc[idx], "phishing_probability": round(float(p_rf[idx]), 4),
            "top_contributors": "; ".join(
                f"{names[j]}={X.iloc[idx][names[j]]} (+{contrib[k, j]:.3f})" for j in order if contrib[k, j] > 0),
        })
    fp = pd.DataFrame(rows)
    fp.to_csv(REPORTS / "false_positive_review.csv", index=False)
    out["n_false_positives"] = int(((p_rf >= thr) & (y == 0)).sum())
    out["fp_review_base_rate"] = float(bias.mean())
    (REPORTS / "test_metrics.json").write_text(json.dumps(out, indent=2))
    pd.set_option("display.width", 250)
    pd.set_option("display.max_colwidth", 120)
    print(fp.to_string(index=False))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["build-features", "train", "evaluate"])
    ap.add_argument("--force", action="store_true", help="re-run evaluate even if test was already used")
    a = ap.parse_args()
    {"build-features": build_features, "train": train, "evaluate": lambda: evaluate(a.force)}[a.command]()
