# PhishGuard — Progress

## Milestones

| Milestone | Status | Notes |
|---|---|---|
| M1 Environment setup | Done | venv (.venv, Python 3.11.0), pinned requirements, scaffold |
| M2 Dataset preparation | Done | PhiUSIIL (CC BY 4.0), 235,370 clean URLs, grouped split 188,296 / 47,074 |
| M3 Feature engineering | Pending | |
| M4 Model | Not started | Phase 2 |
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

## Open questions

- **Label-bias shortcut (blocks M3 design):** 100 % of legitimate URLs are `https://www.<host>` with no path; this template alone gives ~99.7 % train accuracy. Need a decision on how the ML model should be shielded from it.
