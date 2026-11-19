# PhishGuard - Model Evaluation (M4)

Model `rf-host-v1` · evaluated 2026-11-19 · scikit-learn 1.9.1 · Python 3.11.0

## 1. Setup

| Item | Value |
|---|---|
| Data | PhiUSIIL (UCI 967, CC BY 4.0), 235,370 URLs after cleaning |
| Split | Grouped by registered domain (eTLD+1): train 188,296 / test 47,074, both 42.7 % phishing, 0 shared domains |
| Model inputs | **Host features only** (`HOST_FEATURES`): 18 numeric host features + `tld` (one-hot, TLDs seen ≥ 50 times, rest pooled as "infrequent"). Leading `www.` stripped, scheme/path ignored. |
| Why host-only | Every legitimate URL in the data is `https://www.<host>` with no path. Full-URL features let a model learn that template instead of phishing signals (see §4). |
| Tuning | `StratifiedGroupKFold(5)` by registered domain on **train only**; 16-config grid; score = PR-AUC (average precision) |
| Selection rule | Simplest config within 1 standard error of the best mean CV PR-AUC |
| Chosen config | `n_estimators=200, max_depth=30, min_samples_leaf=5, class_weight="balanced"`. It was both the best and the simplest in the 1-SE band. |
| Threshold | **0.386**, chosen from out-of-fold predictions on train: the max-F1 OOF threshold is used only if it beats 0.5 by > 0.005 F1. OOF F1 was 0.7882 at 0.5 and 0.7932 at 0.386 (borderline: +0.005). |
| Test usage | Test set evaluated **once** (lock file `reports/.test_evaluated`, 2026-11-19T02:42:14Z). Model, threshold and baselines were frozen before. |
| Model size | 11.3 MB on disk (joblib compress=3), 471,910 nodes, final fit 19 s |

## 2. Cross-validation (train only, mean ± std over 5 grouped folds)

| Model | PR-AUC | F1 (phishing) | Precision | Recall |
|---|---|---|---|---|
| Majority class | 0.4271 ± 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| Logistic regression (scaled) | **0.8986 ± 0.0056** | 0.7851 ± 0.0199 | 0.9247 | 0.6828 |
| Random Forest (chosen, at 0.5) | 0.8964 ± 0.0105 | 0.7878 | n/a | n/a |
| *Diagnostic: RF on ALL URL features (not used)* | *0.9988 ± 0.0003* | *0.9975* | *0.9990* | *0.9960* |

The full grid is in `grid_search_cv.csv`. The top 12 configurations lie within 0.003 PR-AUC, well inside the fold spread (±0.01). The only clear effect: unlimited depth with `min_samples_leaf=1` is worse (~0.882), because those trees memorize hosts.

## 3. Final test results (single evaluation)

| Model | Threshold | PR-AUC | Accuracy | Phishing P / R / F1 | Legitimate P / R / F1 |
|---|---|---|---|---|---|
| Majority class | 0.5 | 0.4271 | 0.5729 | 0.000 / 0.000 / 0.000 | 0.573 / 1.000 / 0.729 |
| Logistic regression | 0.5 | **0.9100** | **0.8587** | **0.933** / 0.721 / **0.813** | 0.822 / **0.962** / **0.886** |
| **Random Forest** | 0.386 | 0.9085 | 0.8464 | 0.857 / **0.768** / 0.810 | **0.840** / 0.905 / 0.871 |

Random Forest confusion matrix (rows = actual, cols = predicted). See also `confusion_matrix.png`.

|  | Pred. legitimate | Pred. phishing |
|---|---|---|
| **Legitimate** | 24,396 | 2,574 (FP, 9.5 % of legitimate) |
| **Phishing** | 4,657 (FN, 23.2 % of phishing) | 15,447 |

**Reading:** the RF and logistic regression are **tied** on ranking quality (PR-AUC 0.9085 vs 0.9100). They differ mainly in operating point. The RF threshold of 0.386 trades precision for recall: it catches 957 more phishing URLs but produces 1,537 more false positives than logistic regression at 0.5. Test scores are slightly above CV (0.909 vs 0.896), within the fold-to-fold spread.

## 4. Suspicious / "too good to be true" checks

1. **Template shortcut (confirmed, avoided).** A diagnostic RF on all URL features reaches 0.9988 PR-AUC in grouped CV. That is not a real result: 100 % of legitimate URLs are `https://www.<host>` with no path, so the model only needs to check "has a path / no https / no www". That model would flag almost every real legitimate URL with a path. This is why the shipped model is host-only.
2. **Host-only score of about 0.91 PR-AUC is plausible, not suspicious.** It is far from perfect, consistent with CV, and errors make sense (see §5).
3. **Residual dataset artifacts the model still learns** (all measured on train):
   - **Subdomains:** 92 % of train hosts with one subdomain are phishing (26 % with none), because legitimate samples are almost all bare registered domains. `host_num_subdomains` is the most important feature (permutation importance 0.095 PR-AUC).
   - **TLD priors:** `.io` is 90 % phishing in train (IPFS gateways and similar), `.app` 98 %, `.dev` 99 %, `.top` 99.9 %, `.org` 13 %. The model treats TLD as a strong prior; this is the second most important feature.
   These reflect *how the dataset was collected* as much as real phishing behaviour.
4. **No leakage between splits:** grouped split asserted (0 shared registered domains); TLD encoder fitted inside each CV fold; threshold from train OOF only.
5. **Disclosure:** before the split existed, ~20 raw URLs were printed to verify label direction. Two of them later fell into the test set (`ecolabelindex.com`, an `infura-ipfs.io` URL). Neither influenced any feature, setting or threshold.

## 5. False-positive review (top 20 legitimate test URLs by phishing score)

Contributions come from walking each tree's decision path; they sum exactly to the predicted probability (verified). Full list: `false_positive_review.csv`. This review happened **after** the single test evaluation, so its findings feed the Phase 3 rules and these limitations, **not** the model.

| Pattern | Count (of 20) | Examples | Main driver |
|---|---|---|---|
| Legitimate site on a subdomain | 12 | `insurance.harley-davidson.com` (0.97), `garageguide.theaa.com` (0.95), `phuket.holidayinnresorts.com` (0.96), `jud10.flcourts.org` (0.94) | `host_num_subdomains=1` (+0.15 to +0.21), plus `host_length` and `host_num_dots` |
| Short `.io` domain | 7 | `cncf.io`, `dock.io`, `kore.io` (all 0.94) | `tld=io` (+0.39). Identical features give identical scores. |
| Numeric domain | 1 | `6717000.com` (0.94) | `host_digit_ratio`, `host_num_digits` (+0.56 combined) |

**Diagnosis:** the model has learned "a subdomain or a startup TLD means phishing" from this dataset's sampling, not from anything inherently malicious. Real-world legitimate traffic has far more subdomains (`docs.python.org`, `mail.google.com`) and `.io`/`.dev` sites than this training set, so **in practice the false-positive rate will be higher than the 9.5 % measured here.**

## 6. Limitations

- **Host-only model:** it cannot see path-based phishing on a clean-looking host (e.g. `https://sites.google.com/view/…`, compromised legitimate sites). Path, query, `@` and encoding signals are left to the Phase 3 rule engine.
- **Coarse features:** many different hosts map to the same feature vector (the seven `.io` sites above), so the model cannot tell them apart.
- **Dataset bias:** legitimate samples are popular-site homepages, which biases the model on subdomains and TLDs (§4.3). Scores should be read as *risk indicators*, not verdicts.
- **No reputation or age signals** (by design: no network lookups, no threat-intel APIs).
- **Snapshot in time:** PhiUSIIL was collected around 2023–2024. Phishing TLD and hosting trends shift.
- **Probability is not a calibrated risk.** `predict_proba` of a class-weighted RF is not a calibrated probability; the hybrid (Phase 3) should use it as one input to tiers, not as "% chance of phishing".

## 7. Artifacts

| File | Content |
|---|---|
| `models/phishguard_rf.joblib` | Bundle: pipeline, `feature_columns`, `threshold`, version, sklearn/Python versions, dataset SHA-256, params, CV PR-AUC (git-ignored, 11.3 MB) |
| `models/baselines.joblib` | Majority + logistic regression (git-ignored) |
| `reports/train_summary.json` | All CV numbers, selection, threshold, permutation importance |
| `reports/grid_search_cv.csv` | 16-config grid results |
| `reports/oof_predictions_train.csv.gz` | Out-of-fold train probabilities (for Phase 3 tier thresholds) |
| `reports/test_metrics.json` | Single test evaluation, all three models |
| `reports/confusion_matrix.png`, `reports/feature_importance.png` | Charts |
| `reports/false_positive_review.csv` | Top-20 FP review with contributions |

Reproduce: `python -m src.model build-features && python -m src.model train && python -m src.model evaluate`
(the last step refuses to run again unless `--force`, which must be recorded in PROGRESS.md).
