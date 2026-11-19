# PhishGuard

Hybrid (rule-based + Random Forest) phishing **URL** detector with a Streamlit UI.
Educational prototype — see `PROJECT_BRIEF.md` for the full specification.

> PhishGuard analyzes URL **strings only**. It never fetches or visits submitted URLs,
> uses no external threat-intel APIs, and does not log or store submitted URLs.
> Results are risk indicators, not a guarantee that a site is malicious or safe.

## Setup (Windows, Python 3.11)

```bash
py -3.11 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pytest
```

## Layout

```
data/        raw/ (git-ignored), processed/, README.md (source + license)
src/         features.py, rules.py, model.py, hybrid.py
tests/       unit tests
notebooks/   exploration
models/      trained model artifacts
app.py       Streamlit app (Phase 4)
```

Status: see `PROGRESS.md`.
