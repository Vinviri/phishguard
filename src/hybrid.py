"""M6 - hybrid risk assessment (ML base tier + rule escalation).

    assess(url) -> Assessment

Method (also documented in README.md):
1. The Random Forest score (host features only) sets a BASE tier using two cut-points derived
   from TRAIN out-of-fold scores (src/hybrid_config.json):
     High   : score >= high  (lowest score where OOF precision stays >= 95 % for it and every higher score)
     Low    : score <  low   (5th percentile of training phishing scores: ~5 % of phishing is Low by design)
     Medium : in between
2. Rules can only RAISE the tier, never lower it:
     >= 2 strong hits -> High
     1 strong hit     -> one tier up
     >= 3 weak hits   -> Low becomes Medium (weak rules alone never produce High)
     info hits        -> no tier change
3. Input that cannot be parsed -> "Unknown" (Cannot analyze), never a guess.

Tiers are RISK INDICATORS, not verdicts; "Low" never means safe.
Nothing here logs, stores or transmits the URL. Only the model is cached, never inputs.

CLI:
    python -m src.hybrid derive-config   # writes src/hybrid_config.json from train OOF (frozen at m6-frozen)
    python -m src.hybrid evaluate        # ONE-TIME locked test evaluation (after the freeze)
"""
from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import numpy as np

from src.features import analyze
from src.rules import RuleHit, evaluate_parts

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = Path(__file__).with_name("hybrid_config.json")
OOF_PATH = ROOT / "reports" / "oof_predictions_train.csv.gz"
HYBRID_LOCK = ROOT / "reports" / ".hybrid_test_evaluated"

TIERS = ("Low", "Medium", "High")
TIER_LABELS = {"Low": "Low risk indicators", "Medium": "Medium risk indicators",
               "High": "High risk indicators", "Unknown": "Cannot analyze"}
SUMMARIES = {
    "High": ("High risk indicators. Several signs commonly seen in phishing were found. Do not enter "
             "passwords or payment details unless you have verified the site another way."),
    "Medium": ("Medium risk indicators. Some signs commonly seen in phishing were found. Check the "
               "address carefully before trusting it."),
    "Low": ("Low risk indicators. Few signs commonly seen in phishing were found. This does not mean "
            "the site is safe: about 5% of phishing URLs in the training data scored this low."),
    "Unknown": "Cannot analyze this input. Enter a full web address such as https://example.com.",
}
NOTE_HOSTNAME_ONLY = ("The model score is based on the hostname only (its length, subdomains, characters "
                      "and top-level domain). The path and query are checked by the rules, not by the model.")
NOTE_SUBDOMAIN = ("This address has a subdomain. The ML score may be inflated for subdomains: almost all "
                  "legitimate sites in the training data were bare domains, so the model tends to over-rate "
                  "subdomains of real sites (such as docs.python.org).")
NOTE_SHORTENER = ("This is a shortened link. Its real destination cannot be checked without visiting it, "
                  "which PhishGuard never does.")

STRONG_FOR_HIGH = 2   # >= this many strong hits -> High
WEAK_FOR_MEDIUM = 3   # >= this many weak hits -> at least Medium


@dataclass(frozen=True)
class Assessment:
    tier: str
    tier_label: str
    summary: str
    base_tier: str | None
    ml_score: float | None
    escalation: str | None
    rule_hits: tuple[RuleHit, ...]
    rule_score: int
    strong_hits: int
    weak_hits: int
    notes: tuple[str, ...]
    cut_points: dict = field(default_factory=dict)
    model_version: str = ""
    config_version: str = ""


# ------------------------------------------------------------------ config / model

@lru_cache(maxsize=1)
def load_config() -> dict:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def _model_bundle() -> dict:
    from src.model import load_model  # Random Forest only; logistic regression is never loaded here
    return load_model()


# ------------------------------------------------------------------ tier logic (pure, tested exhaustively)

def base_tier(score: float, low: float, high: float) -> str:
    if score >= high:
        return "High"
    if score < low:
        return "Low"
    return "Medium"


def escalate(base: str, strong: int, weak: int) -> tuple[str, str | None]:
    """Final tier from the base tier and rule counts. Never lower than `base`."""
    i = TIERS.index(base)
    reasons = []
    if strong >= STRONG_FOR_HIGH:
        j = 2
        reasons.append(f"{strong} strong rule indicators")
    elif strong == 1:
        j = min(i + 1, 2)
        reasons.append("1 strong rule indicator")
    else:
        j = i
    if weak >= WEAK_FOR_MEDIUM and j == 0:
        j = 1
        reasons.append(f"{weak} weak rule indicators")
    j = max(i, j)  # rules never lower the tier
    if j == i:
        return base, None
    return TIERS[j], f"Raised from {base} to {TIERS[j]}: " + " and ".join(reasons) + "."


# ------------------------------------------------------------------ public API

def assess(url: object, bundle: dict | None = None, config: dict | None = None) -> Assessment:
    """Hybrid assessment of one URL string. Never raises, fetches, logs or stores the URL."""
    cfg = config or load_config()
    cuts = {"low": cfg["cut_points"]["low"], "high": cfg["cut_points"]["high"]}
    p, f = analyze(url)
    report = evaluate_parts(p, f)
    common = dict(rule_hits=report.hits, rule_score=report.score, strong_hits=report.strong,
                  weak_hits=report.weak, cut_points=cuts, config_version=cfg["version"])
    if p.parse_error:
        return Assessment(tier="Unknown", tier_label=TIER_LABELS["Unknown"], summary=SUMMARIES["Unknown"],
                          base_tier=None, ml_score=None, escalation=None, notes=(), **common)

    b = bundle or _model_bundle()
    import pandas as pd
    X = pd.DataFrame([f])[b["feature_columns"]]
    X["tld"] = X["tld"].astype(str)
    score = float(b["pipeline"].predict_proba(X)[0, 1])
    base = base_tier(score, cuts["low"], cuts["high"])
    tier, why = escalate(base, report.strong, report.weak)

    notes = [NOTE_HOSTNAME_ONLY]
    if f["host_num_subdomains"] >= 1:
        notes.append(NOTE_SUBDOMAIN)
    if any(h.name == "shortener" for h in report.hits):
        notes.append(NOTE_SHORTENER)
    return Assessment(tier=tier, tier_label=TIER_LABELS[tier], summary=SUMMARIES[tier], base_tier=base,
                      ml_score=score, escalation=why, notes=tuple(notes),
                      model_version=b.get("version", ""), **common)


# ------------------------------------------------------------------ derive config (TRAIN OOF only)

def derive_config() -> None:
    import pandas as pd

    oof = pd.read_csv(OOF_PATH)
    y, s = oof["is_phishing"].to_numpy(), oof["oof_proba"].to_numpy()
    g = pd.DataFrame({"s": s, "y": y}).groupby("s")["y"].agg(["sum", "size"]).sort_index(ascending=False)
    g["tp"], g["n"] = g["sum"].cumsum(), g["size"].cumsum()
    g["precision"] = g["tp"] / g["n"]
    g["running_min"] = g["precision"].cummin()
    ok = g[g["running_min"] >= 0.95]
    if ok.empty:
        sys.exit("95 % precision is not reachable on train OOF: ask the user before choosing a fallback.")
    high = float(ok.index.min())
    low = float(np.quantile(s[y == 1], 0.05))
    assert low < high, (low, high)
    tiers = np.where(s >= high, "High", np.where(s < low, "Low", "Medium"))
    dist = {cls: {t: round(float(np.mean(tiers[y == v] == t)), 4) for t in TIERS}
            for cls, v in (("phishing", 1), ("legitimate", 0))}
    cfg = {
        "version": "hybrid-v1",
        "derived_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "cut_points": {"low": round(low, 5), "high": round(high, 5)},
        "method": {
            "data": "reports/oof_predictions_train.csv.gz: out-of-fold Random Forest scores on the TRAIN split "
                    "(StratifiedGroupKFold(5) by registered domain). The test split is not used.",
            "data_sha256": hashlib.sha256(OOF_PATH.read_bytes()).hexdigest(),
            "high": "Lowest score s such that precision (phishing among URLs scoring >= t) is >= 0.95 for t = s "
                    "and for every higher score t (running minimum of precision from the top).",
            "low": "5th percentile of training phishing OOF scores: about 5 % of training phishing falls in Low by design.",
            "tiers": "High: score >= high; Low: score < low; Medium: otherwise.",
            "escalation": f">= {STRONG_FOR_HIGH} strong rule hits -> High; 1 strong -> one tier up; "
                          f">= {WEAK_FOR_MEDIUM} weak hits -> Low becomes Medium; info hits never change the tier; "
                          "rules never lower the tier.",
            "prevalence_caveat": f"Precision depends on the phishing share of the data ({y.mean():.1%} in train). "
                                 "Real-world traffic has far less phishing, so real precision at these cut-points is lower.",
        },
        "train_oof_check": {
            "phishing_share": round(float(y.mean()), 4),
            "precision_at_high": round(float(ok["precision"].iloc[-1]), 4),
            "phishing_recall_at_high": round(float(ok["tp"].iloc[-1] / y.sum()), 4),
            "phishing_share_below_low": round(float(np.mean(s[y == 1] < low)), 4),
            "tier_distribution": dist,
        },
    }
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(cfg, indent=2))


# ------------------------------------------------------------------ one-time locked test evaluation

def evaluate() -> None:
    """Locked, single evaluation on TEST: ML-only vs rules-only vs hybrid. Labelled inflated."""
    import pandas as pd
    from src.features import FEATURE_NAMES

    if HYBRID_LOCK.exists():
        sys.exit(f"Hybrid test evaluation already done ({HYBRID_LOCK.read_text().strip()}).")
    cfg, b = load_config(), _model_bundle()
    low, high = cfg["cut_points"]["low"], cfg["cut_points"]["high"]
    te = pd.read_csv(ROOT / "data" / "processed" / "urls_clean.csv")
    te = te[te["split"] == "test"].reset_index(drop=True)
    HYBRID_LOCK.write_text(f"evaluated {datetime.now(timezone.utc).isoformat(timespec='seconds')} "
                           f"with {cfg['version']} / {b['version']}\n")
    y = te["is_phishing"].to_numpy()

    parts = [analyze(u) for u in te["url"]]
    feats = pd.DataFrame([f for _, f in parts], columns=list(FEATURE_NAMES))
    X = feats[b["feature_columns"]].copy()
    X["tld"] = X["tld"].astype(str)
    scores = b["pipeline"].predict_proba(X)[:, 1]
    reps = [evaluate_parts(p, f) for p, f in parts]
    strong = np.array([r.strong for r in reps])
    weak = np.array([r.weak for r in reps])
    unknown = np.array([p.parse_error for p, _ in parts])

    ml = np.array([base_tier(s, low, high) for s in scores], dtype=object)
    rules_only = np.array([escalate("Low", st, wk)[0] for st, wk in zip(strong, weak)], dtype=object)
    hybrid = np.array([escalate(bt, st, wk)[0] for bt, st, wk in zip(ml, strong, weak)], dtype=object)
    for arr in (ml, rules_only, hybrid):
        arr[unknown] = "Unknown"

    def summarize(t: np.ndarray) -> dict:
        out = {"tier_distribution": {}}
        for cls, v in (("phishing", 1), ("legitimate", 0)):
            out["tier_distribution"][cls] = {k: int(np.sum((t == k) & (y == v))) for k in TIERS + ("Unknown",)}
        for name, flagged in (("flag_medium_or_high", np.isin(t, ["Medium", "High"])), ("flag_high_only", t == "High")):
            tp, fp = int(np.sum(flagged & (y == 1))), int(np.sum(flagged & (y == 0)))
            out[name] = {"precision": round(tp / max(tp + fp, 1), 4), "recall": round(tp / max(int(y.sum()), 1), 4),
                         "false_alarm_rate": round(fp / max(int((y == 0).sum()), 1), 4), "tp": tp, "fp": fp}
        return out

    res = {
        "n_test": int(len(y)), "phishing_share": round(float(y.mean()), 4),
        "config_version": cfg["version"], "model_version": b["version"], "cut_points": cfg["cut_points"],
        "INFLATED": ("Legitimate test URLs are all bare https://www.<host> homepages, so full-URL rules "
                     "(no_https, path/query rules) cannot misfire on them here. Rules-only and hybrid "
                     "numbers overstate real-world performance; the M8 hand-made list is the real check."),
        "ml_only": summarize(ml), "rules_only": summarize(rules_only), "hybrid": summarize(hybrid),
        "escalated_by_rules": {"phishing": int(np.sum((hybrid != ml) & (y == 1))),
                               "legitimate": int(np.sum((hybrid != ml) & (y == 0)))},
    }
    (ROOT / "reports" / "hybrid_test_metrics.json").write_text(json.dumps(res, indent=2) + "\n")
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    cmd = sys.argv[1:]
    if cmd == ["derive-config"]:
        derive_config()
    elif cmd == ["evaluate"]:
        evaluate()
    else:
        sys.exit("usage: python -m src.hybrid derive-config | evaluate")
