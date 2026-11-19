# PhishGuard — Progress

## Milestones

| Milestone | Status | Notes |
|---|---|---|
| M1 Environment setup | Done | venv (.venv, Python 3.11.0), pinned requirements, scaffold |
| M2 Dataset preparation | Done | PhiUSIIL (CC BY 4.0), 235,370 clean URLs, grouped split 188,296 / 47,074 |
| M3 Feature engineering | Done | `src/features.py` (58 features), 46 unit tests passing, 0 crashes / 0 parse errors on 235,370 URLs (~77 µs/URL) |
| M4 Model | Done | Host-only RF `rf-host-v1`: test PR-AUC 0.9085, phishing F1 0.810 (threshold 0.386); ties logistic regression (0.9100). See `reports/model_evaluation.md` |
| M5 Rules | Not started | Phase 3 |
| M6 Hybrid | Not started | Phase 3 |
| M7 Streamlit app | Not started | Phase 4 |
| M8 Testing & docs | Not started | Phase 4 |
| M9 GitHub | Not started | Phase 4 |

## Decisions

| Date | Decision | Reason |
|---|---|---|
| 2026-11-19 | Repo root is the existing `phishguard/` folder | Avoid nesting `phishguard/phishguard` |
| 2026-11-19 | Use `tldextract` in offline mode (bundled Public Suffix List snapshot) | Accurate registered-domain extraction for grouped split and domain features, with no network access at runtime |
| 2026-11-19 | One git commit per milestone | User preference |
| 2026-11-19 | `pytest` added to requirements | Unit tests for M3 onward |
| 2026-11-19 | Dataset: PhiUSIIL (UCI 967), URL + label columns only | Clear CC BY 4.0 license, single citable source, reproducible download without an account |
| 2026-11-19 | Normalized label `is_phishing` = 1 when raw `label` == 0 | Raw label is 0 = phishing (verified on samples; UCI text contradictory) |
| 2026-11-19 | Grouped split by registered domain (eTLD+1, ICANN suffixes), StratifiedGroupKFold 5, seed 42, 20 % test | Prevents same-campaign/same-host leakage; measures generalization to unseen domains |
| 2026-11-19 | Bias analysis computed on train split only | Results inform feature decisions; the test set must not |
| 2026-11-19 | `data/processed/urls_clean.csv` (14 MB) committed | Freezes the split across sessions/library versions; license permits redistribution |
| 2026-11-19 | **ML model uses host features only** (`HOST_FEATURES`: `host_*` + `tld`), with leading `www.` stripped and scheme ignored. Path/query/`@`/encoding/HTTPS signals go to the rule engine. | Every legitimate training URL is `https://www.<host>` with no path, so full-URL features let the model learn the template (~99.7 % train accuracy) and flag real legitimate URLs with paths. Rules are not trained on the biased data. |
| 2026-11-19 | One extractor `extract_features(url)` returns all groups (`url_*`, `host_*`, `path_*`, `tld`, `parse_error`), same keys and order for every input | Same function for training and app; model picks its subset via `HOST_FEATURES` |
| 2026-11-19 | Costly checks capped at 4,096 chars (`url_length` still reports the true length; `url_is_truncated` flag) | Keeps the app responsive on huge pasted strings |
| 2026-11-19 | Malformed input never raises; sets `parse_error=1` and returns best-effort features | App must not crash; also avoids exception messages that could echo the URL into logs |

| 2026-11-19 | TLD encoded by one-hot inside the pipeline (min_frequency=50, rare/unseen pooled as "infrequent") | Simple, transparent, re-fitted in every CV fold so no leakage; resolves the Phase 1 open question |
| 2026-11-19 | RF grid (16 configs) tuned with StratifiedGroupKFold(5) by registered domain on train only; PR-AUC as selection metric | Brief requirement; PR-AUC is threshold-free and robust to the 43/57 class mix |
| 2026-11-19 | Selection rule: simplest config within 1 SE of best CV PR-AUC → `n_estimators=200, max_depth=30, min_samples_leaf=5, class_weight=balanced` (11.3 MB) | User asked to prefer smaller models within noise; here best and simplest coincided |
| 2026-11-19 | Threshold 0.386 from train out-of-fold predictions (max-F1, used because it beat 0.5 by > 0.005 F1) | User condition: thresholds only from train OOF, never test. Gain is borderline (+0.005) |
| 2026-11-19 | Test set evaluated exactly once (2026-11-19T02:42:14Z), enforced by `reports/.test_evaluated` lock | Brief requirement; re-runs need `--force` and must be logged here |
| 2026-11-19 | `models/*.joblib` stays git-ignored for now (RF 11.3 MB) | Reproducible with `python -m src.model train`; ship-or-not decided in M9 |
| 2026-11-19 | matplotlib 3.11.2 added to requirements | Report charts |

## Disclosures

- **2 test rows seen before the split (not used for any decision).** Before the split existed, ~20 raw URLs were printed to verify the label direction (the UCI page is contradictory). Two of them later landed in the test set: `ecolabelindex.com` (legitimate homepage) and an `infura-ipfs.io` phishing URL. No feature, setting or threshold was based on them. Everything else that informed design used the train split only.
- **Test set was viewed for the false-positive review** after the single evaluation. Findings go to the limitations and the Phase 3 rules, not back into the model.

## Open questions

- ~~Label-bias shortcut~~: resolved by the host-only model (see decisions).
- Phase 2: residual host-level bias. Legitimate hosts are almost always the bare registered domain (mean 0.03 subdomains vs 0.68 for phishing). This is partly a real phishing signal, but it will over-flag legitimate subdomains like `docs.python.org`. Plan: report it in the false-positive review and the M8 hand-made list.
- Phase 2: how to encode `tld` (frequency/target encoding fitted on train only, vs. a top-N one-hot).
