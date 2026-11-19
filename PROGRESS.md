# PhishGuard — Progress



## Milestones



| Milestone | Status | Notes |

|---|---|---|

| M1 Environment setup | Done | venv (.venv, Python 3.11.0), pinned requirements, scaffold |

| M2 Dataset preparation | Done | PhiUSIIL (CC BY 4.0), 235,370 clean URLs, grouped split 188,296 / 47,074 |

| M3 Feature engineering | Done | `src/features.py` (58 features), 46 unit tests passing, 0 crashes / 0 parse errors on 235,370 URLs (~77 µs/URL) |

| M4 Model | Done | Host-only RF `rf-host-v1`: test PR-AUC 0.9085, phishing F1 0.810 (threshold 0.386); ties logistic regression (0.9100). See `reports/model_evaluation.md` |

| M5 Rules | Done | `src/rules.py`: 16 rules (5 strong, 9 weak, 2 info), `src/brands.json`, 84 rule tests; strong rules fire on 1 / 107,880 legitimate train URLs |

| M6 Hybrid | Done: locked test evaluation run once after `m6-frozen`; High precision 0.955 / recall 0.697; rules escalated 5 phishing, 0 legitimate (inflated, see `reports/hybrid_evaluation.md`) | `src/hybrid.py`, `src/hybrid_config.json` (low 0.235 / high 0.568), README method section, 120 hybrid tests |

| M7 Streamlit app | Done | `app.py`, `src/presentation.py`, `.streamlit/config.toml`, 41 app tests incl. Streamlit AppTest; launches headless on localhost |

| M8 Testing & docs | Done | Manual list (32 legit, 25 real + 11 synthetic phishing, 15 platform descriptive), one locked run after tag `m8-start`: real phishing High 13/25, missed 4/25; legit High 11/32. Final README, `reports/manual_evaluation.md`, `reports/test_summary.md` (366 passed) |

| M9 GitHub | In progress | Release prepared locally (MIT LICENSE, model committed with SHA-256, README headline). Pre-push checks done (no local paths, no OpenPhish URLs in history); author email rewritten to the GitHub no-reply address |



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
| 2026-11-19 | Interactive Phase 2 report built as a private claude.ai dashboard; its data comes from `python -m src.export_report` (CSVs in `reports/dashboard/`) | User asked for a GUI report; the export script keeps the dashboard numbers reproducible from repo files |

| 2026-11-19 | Phase 3 decisions: drop logistic regression from the app (report only); one locked hybrid test evaluation, labelled inflated, only after rules/tiers/cut-points are committed and frozen; ~95 %/95 % cut-points from train OOF; no allowlist, add "ML score may be inflated for subdomains" note | User decisions |
| 2026-11-19 | `features.py` refactored to expose `url_parts()` / `analyze()`; rules and model share one parser. Re-extraction of all 235,370 URLs matched the saved feature tables exactly (0 mismatches), so the trained model is unaffected | One parsing path for training, rules and app |
| 2026-11-19 | Rule strengths: strong = ip_host, at_in_host, lookalike_host (mixed script only), brand_in_subdomain, embedded_url_in_path (different registered domain, in the PATH); weak = idn_host (single-script), brand_in_domain, brand_in_path, url_in_query, no_https, keywords, long_or_encoded, risky_extension, deep_subdomains; info = shortener, archived_copy. Weights 3 / 1 / 0 | User decisions; brand in path and redirect params are common on legitimate URLs |
| 2026-11-19 | `brand_in_domain` stays weak and must not be promoted on the train firing rate | Legit train URLs are bare homepages, so a low rate proves little (user decision) |
| 2026-11-19 | Archive exception: on archive.org / archive.today family / webcache.googleusercontent.com, an embedded URL in the path does not fire `embedded_url_in_path`; info rule `archived_copy` explains it instead | `web.archive.org/web/2020/https://example.com` is a common legitimate pattern; the exception is a fixed list, so ordinary domains cannot use it |
| 2026-11-19 | Weak-rule thresholds frozen: > 100 chars, > 3 %-encoded chars, >= 2 keywords, >= 3 subdomains, >= 4 hyphens | User decision; not tuned on test |
| 2026-11-19 | Brand matching by whole token; prefix match for brands of 6+ letters, suffix match only for 7+ letters; 4 official domains added (apple.com.cn, google.org, aboutamazon.com/.in) | From the TRAIN-only firing review: `huaweicloud` matched `icloud`; official domains were missing |
| 2026-11-19 | Rule firing rates checked on TRAIN only (`reports/rule_firing_train.csv`); no rule fires on > 1 % of legitimate train URLs | Catch over-firing rules without touching test. Path-based rules cannot fire on legit train URLs (no paths), so a hand-written real-world legitimate list in `tests/test_rules.py` covers them |

| 2026-11-19 | High cut-point = lowest score where train-OOF precision stays >= 95 % for it and every higher score (running minimum) → 0.56803; Low cut-point = 5th percentile of train-OOF phishing scores → 0.23526 | User decision (~95 %/95 %); method and data hash recorded in `src/hybrid_config.json` |
| 2026-11-19 | Escalation: >= 2 strong → High; 1 strong → +1 tier; >= 3 weak → Low becomes Medium; info never changes the tier; rules never lower | Strong rules are rare on legit URLs; weak rules are noisy so they can never produce High alone |
| 2026-11-19 | Tier labels are "Low/Medium/High risk indicators"; Low is never called safe; README states ~5 % of training phishing is Low by design and that precision depends on the 42.7 % phishing share | User decision; brief requires indicators, not verdicts |
| 2026-11-19 | Freeze at tag `m6-frozen`: rules.py, brands.json, hybrid_config.json, hybrid.py tier logic, requirements.txt. The locked hybrid test evaluation runs only after this commit | User decision; proves the evaluation could not influence the logic |

| 2026-11-19 | Locked hybrid test evaluation run once (2026-11-19T03:24:54Z) after `m6-frozen`; lock `reports/.hybrid_test_evaluated` committed with the results | User decision; no logic changed afterwards (frozen files identical to the tag) |

| 2026-11-19 | App labels: Low = "Low risk indicators" (blue-grey, not green), Medium = "Inconclusive, check carefully", High = "High risk indicators", Unknown = "Can't analyze this input"; kept in `src/presentation.py` so the frozen `hybrid.py` is unchanged | User decisions |
| 2026-11-19 | Privacy in the app: only the model is cached (`st.cache_resource`, keyed by model path); no `st.cache_data`; no logging or print; no history beyond the input box; errors are generic and never echo the URL | User requirements; enforced by source-check tests |
| 2026-11-19 | Input is shown defanged (`hxxps://example[.]com`) in `st.code`, never as a link or Markdown; rule reasons are Markdown-escaped; only fixed label text goes into the one HTML badge | Prevents clickable links and HTML/script injection; AppTest covers `<script>`, `<img onerror>`, Markdown links and `javascript:` input |
| 2026-11-19 | Model loading guarded: missing file, scikit-learn version different from the one recorded in the model, or an unreadable file shows a generic message pointing to README and stops; never a traceback | User requirement; tested with AppTest |
| 2026-11-19 | `.streamlit/config.toml`: `server.address = localhost`, `gatherUsageStats = false`, `showErrorDetails = "none"`, `toolbarMode = "viewer"`, logger level error | The first headless launch listened on all network interfaces; the brief is localhost deployment |
| 2026-11-19 | Example buttons use reserved example domains only (example.com/.org, `.example`, 192.0.2.0/24) | User option; no real sites shown as phishing examples |

| 2026-11-19 | Tag `m8-start` before building and evaluating the manual list; the evaluation script refuses to run if rules, brands, cut-points, hybrid, feature or model code, or requirements differ from the tag | User decision: no changes after seeing results |
| 2026-11-19 | Manual list stored defanged (also URLs embedded in paths); refanged only in memory; exact round-trip checked; nothing ever visited | User requirement |
| 2026-11-19 | Overlap check: drop any manual-list URL whose registered domain is in the train or test split (domain column only). Removed 10 of 42 legitimate candidates; bit.ly replaced by buff.ly | User requirement; skews legitimate URLs toward smaller sites (documented) |
| 2026-11-19 | OpenPhish feed (2026-11-19): 69 % of 300 URLs overlap PhiUSIIL (hosting platforms), 31 % do not. First attempt (sample then remove) kept 6 and was abandoned before evaluation; final: 25 sampled from the 93 independent URLs and 15 from the platform pool, seed 20261119 | User decision (option 1 + platform addition, both before any results) |
| 2026-11-19 | OpenPhish URLs not committed (redistribution not confirmed): raw feed, sampled inputs and the full list are git-ignored; the committed list withholds them; reports show only id/category/score/tier/rules | User decision |
| 2026-11-19 | Manual evaluation run once (2026-11-19T05:01:26Z, lock `reports/.manual_evaluated`); proposals in the report were NOT applied | User requirement; any change needs a new, separate list |

| 2026-11-19 | Commit `models/phishguard_rf.joblib` (11.3 MB, SHA-256 e6846267…) with a pickle security note in README | User decision (M9) |
| 2026-11-19 | Public repo `phishguard`; MIT License for code; data licenses (PhiUSIIL CC BY 4.0) listed separately; OpenPhish not included | User decision (M9) |
| 2026-11-19 | Author/committer email rewritten to the GitHub no-reply address (112366468+Vinviri@users.noreply.github.com) on all commits before the first push; also set in global git config | User decision: keep the personal email out of the public history (see Commit hash mapping) |

## Commit hash mapping (author rewrite, 2026-11-19)

Before the first push, the author/committer email of all 11 commits was changed from a personal address to the
GitHub no-reply address (`git filter-branch --env-filter`, dates and contents unchanged). Every commit hash
changed; **every tree hash is identical** to the original (verified for all 11 commits, including `m6-frozen`,
`m8-start` and the release commit), and the frozen files (rules.py, brands.json, hybrid_config.json, hybrid.py,
features.py, model.py, requirements.txt) are blob-identical at both tags. Tags `m6-frozen` and `m8-start` were
moved to the rewritten commits.

**Lock files were not edited.** `reports/.test_evaluated`, `reports/.hybrid_test_evaluated` and
`reports/.manual_evaluated` record times, tag names and file/model SHA-256 values, not commit hashes. Any commit
hash quoted elsewhere in this file or in earlier phase reports (e.g. `24d96d2` for `m8-start`) is a
**pre-rewrite** hash; use this table to find the published commit.

| Old commit | New commit | Tree (unchanged) | Tag | Subject |
|---|---|---|---|---|
| `fea5de1c1ecf` | `9532df7181db` | `7e6ddeb3830a` |  | M1: project scaffold, venv setup, pinned dependencies |
| `447696c4c7b6` | `17fa4a6d814e` | `1a98ec5b886c` |  | M2: PhiUSIIL dataset prep, grouped train/test split, bias report |
| `cb71021826e2` | `2ba1bfef694c` | `3a1ae1e65039` |  | M3: URL feature extraction module with unit tests |
| `c3f872717723` | `24abdfbbae63` | `f63cd889ec5e` |  | M4: host-only Random Forest with grouped CV tuning, baselines, one-tim |
| `db5dc063c55b` | `1cdfbb325ed7` | `1637e3306c8d` |  | M4: add dashboard data export script (reports/dashboard) |
| `48b44b7641ca` | `4d43c012ac37` | `ef78503333f2` |  | M5: rule engine with strong/weak/info rules, brand list, train firing  |
| `93f494e1c217` | `cd02d5c660bb` | `928969929f3a` | m6-frozen | M6: hybrid risk tiers (frozen before the locked test evaluation) |
| `591c11fc81de` | `7d71a044dcf7` | `0654b4262338` |  | M6: locked hybrid test evaluation (ML-only vs rules-only vs hybrid, la |
| `24d96d2e35da` | `c35859a5faf9` | `7dd89316796d` | m8-start | M7: Streamlit app with tiered risk display, privacy safeguards and App |
| `f335f93fa86e` | `56b89fcd77ab` | `63cf89f889cd` |  | M8: manual evaluation list, one locked run, final README and test summ |
| `ff128c81869c` | `91f96ff2be37` | `33aa1f409277` |  | M9: prepare public release (MIT license, committed model with SHA-256, |

## Disclosures

- **2 test rows seen before the split (not used for any decision).** Before the split existed, ~20 raw URLs were printed to verify the label direction (the UCI page is contradictory). Two of them later landed in the test set: `ecolabelindex.com` (legitimate homepage) and an `infura-ipfs.io` phishing URL. No feature, setting or threshold was based on them. Everything else that informed design used the train split only.
- **Test set was viewed for the false-positive review** after the single evaluation. Findings go to the limitations and the Phase 3 rules, not back into the model.

## Open questions

- **From the manual evaluation (proposals only, not applied):** 10 of 11 legitimate false alarms come from the subdomain bias; the rules changed no tier on the manual list; all 4 misses are short bare domains with phishing in the path. Fixes (retrain with legitimate subdomain URLs, cap subdomain-driven model tiers, path-aware signals) need a new design freeze and a **new, separate** evaluation list.
- ~~M9 model file / OpenPhish check~~: model committed; history scan found no OpenPhish URL.

- **From the hybrid evaluation:** on PhiUSIIL the rules barely change tiers (5 phishing escalated), because strong rules are rare there and the model already rates those URLs High. Their real-world value must be shown with the M8 hand-made list. Medium holds 62 % of legitimate test URLs, so the app must present Medium as "check carefully".



- ~~Label-bias shortcut~~: resolved by the host-only model (see decisions).

- Phase 2: residual host-level bias. Legitimate hosts are almost always the bare registered domain (mean 0.03 subdomains vs 0.68 for phishing). This is partly a real phishing signal, but it will over-flag legitimate subdomains like `docs.python.org`. Plan: report it in the false-positive review and the M8 hand-made list.

- Phase 2: how to encode `tld` (frequency/target encoding fitted on train only, vs. a top-N one-hot).

