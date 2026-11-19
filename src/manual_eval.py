"""M8 - ONE locked run of the manual evaluation list through the real hybrid.

    python -m src.manual_eval [--hide-real-urls]

Refuses to run if:
  - it already ran (reports/.manual_evaluated), or
  - any frozen file differs from tag m8-start (rules, brands, cut-points, hybrid, features, model code,
    requirements), or the saved model is not the one trained before m8-start.
Writes reports/manual_eval_results.csv (one row per URL) and reports/manual_eval_counts.json (raw counts).
No URL is fetched, resolved or visited; URLs are refanged in memory only.
"""
from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LIST = ROOT / "data" / "eval" / "manual_urls_full.csv"  # git-ignored complete list
LOCK = ROOT / "reports" / ".manual_evaluated"
RESULTS = ROOT / "reports" / "manual_eval_results.csv"
COUNTS = ROOT / "reports" / "manual_eval_counts.json"
FROZEN = ["src/rules.py", "src/brands.json", "src/hybrid_config.json", "src/hybrid.py", "src/features.py",
          "src/model.py", "requirements.txt"]


def _group(row: dict) -> str:
    if row["label"] == "legitimate":
        return "legitimate"
    if row["category"] == "real_platform":
        return "platform_phishing_descriptive"  # not independent of training; never in headline counts
    return "synthetic_phishing" if row["source"] == "synthetic" else "real_phishing"


def main(hide_real_urls: bool) -> None:
    import pandas as pd

    from src.features import analyze
    from src.hybrid import _model_bundle, assess, escalate
    from src.manual_list import refang
    from src.model import MODEL_PATH, rf_contributions

    if LOCK.exists():
        sys.exit(f"Manual evaluation already ran ({LOCK.read_text(encoding='utf-8').strip()}).")
    diff = subprocess.run(["git", "diff", "--quiet", "m8-start", "--", *FROZEN], cwd=ROOT)
    if diff.returncode != 0:
        sys.exit("Frozen files differ from tag m8-start; refusing to run.")
    bundle = _model_bundle()
    list_sha = hashlib.sha256(LIST.read_bytes()).hexdigest()
    model_sha = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    LOCK.write_text(f"evaluated {datetime.now(timezone.utc).isoformat(timespec='seconds')}; "
                    f"list sha256 {list_sha}; model {bundle['version']} trained {bundle['trained_at_utc']} "
                    f"sha256 {model_sha}; frozen at tag m8-start\n", encoding="utf-8")

    rows = list(csv.DictReader(open(LIST, encoding="utf-8")))
    out = []
    for r in rows:
        url = refang(r["url_defanged"])
        a = assess(url, bundle=bundle)
        rules_tier = "Unknown" if a.tier == "Unknown" else escalate("Low", a.strong_hits, a.weak_hits)[0]
        top = ""
        if a.tier != "Unknown":
            _, f = analyze(url)
            X = pd.DataFrame([f])[bundle["feature_columns"]]
            X["tld"] = X["tld"].astype(str)
            contrib, _, names = rf_contributions(bundle["pipeline"], X)
            order = contrib[0].argsort()[::-1][:3]
            top = "; ".join(f"{names[j]}={X.iloc[0][names[j]]} ({contrib[0, j]:+.3f})" for j in order)
        g = _group(r)
        out.append({
            "id": r["id"],
            "url_defanged": "" if (hide_real_urls and g in ("real_phishing", "platform_phishing_descriptive")) else r["url_defanged"],
            "label": r["label"], "group": g, "category": r["category"],
            "ml_tier": a.base_tier or "Unknown", "rules_tier": rules_tier, "hybrid_tier": a.tier,
            "model_score": "" if a.ml_score is None else round(a.ml_score, 3),
            "fired_rules": " ".join(f"{h.name}({h.strength[0].upper()})" for h in a.rule_hits),
            "escalation": a.escalation or "", "top_model_contributions": top,
        })
    with open(RESULTS, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(out[0]))
        w.writeheader()
        w.writerows(out)

    counts: dict = {"n": len(out), "by_group": {}, "by_category": {}}
    for key_name, key in (("by_group", "group"), ("by_category", "category")):
        buckets = defaultdict(list)
        for o in out:
            buckets[o[key]].append(o)
        for k, items in buckets.items():
            counts[key_name][k] = {"n": len(items)}
            for m in ("ml_tier", "rules_tier", "hybrid_tier"):
                counts[key_name][k][m] = {t: sum(1 for o in items if o[m] == t) for t in ("Low", "Medium", "High", "Unknown")}
    COUNTS.write_text(json.dumps(counts, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(counts["by_group"], indent=2))


if __name__ == "__main__":
    main(hide_real_urls="--hide-real-urls" in sys.argv[1:])
