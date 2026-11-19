# PhishGuard — Progress

## Milestones

| Milestone | Status | Notes |
|---|---|---|
| M1 Environment setup | Done | venv (.venv, Python 3.11.0), pinned requirements, scaffold |
| M2 Dataset preparation | Pending | awaiting dataset choice |
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

## Open questions

- M2: which dataset to use (options to be proposed).
