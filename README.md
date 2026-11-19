# PhishGuard

Hybrid (rule-based + Random Forest) phishing **URL** detector with a Streamlit UI.
Educational prototype; see `PROJECT_BRIEF.md` for the full specification.

> PhishGuard analyzes URL **strings only**. It never fetches or visits submitted URLs,
> uses no external threat-intel APIs, and does not log or store submitted URLs.
> Results are **risk indicators**, not a guarantee that a site is malicious or safe.

## Setup (Windows, Python 3.11)

```bash
py -3.11 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Use exactly the versions in `requirements.txt`. The saved model records its scikit-learn version, and
the app refuses to use a model saved with a different version.

## Run the app

```bash
streamlit run app.py
```

Open http://localhost:8501. The app listens on this machine only (`.streamlit/config.toml`), sends no
usage statistics and never shows tracebacks. If it says the model is not available, rebuild it (next section).

## Rebuild the model

`models/*.joblib` is git-ignored, so a fresh clone has no model. The committed files
(`data/processed/urls_clean.csv` with the fixed train/test split, `src/hybrid_config.json` with the frozen
cut-points) are enough to retrain. Steps 1–2 are only needed to rebuild the split from scratch.

```bash
# 1. (optional) get the raw data - PhiUSIIL, UCI dataset 967, CC BY 4.0
mkdir -p data/raw/phiusiil
curl -L -o data/raw/phiusiil/phiusiil.zip "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
cd data/raw/phiusiil && tar -xf phiusiil.zip && cd ../../..

# 2. (optional) clean the data and rebuild the grouped train/test split
python -m src.data_prep

# 3. build the feature tables (~20 s)
python -m src.model build-features

# 4. train the Random Forest on the train split (~40 min on a 12-core CPU)
python -m src.model train

# 5. run the tests (includes an end-to-end check of the saved model and the app)
pytest
```

Do **not** run `python -m src.model evaluate`, `python -m src.hybrid evaluate` or
`python -m src.hybrid derive-config` again: the test set was evaluated once (lock files in `reports/`)
and the cut-points are frozen at tag `m6-frozen`. Retraining with the same versions reproduces the same
model (fixed seeds).

## Layout

```
data/        raw/ (git-ignored), processed/, README.md (source + license)
src/         features.py  - one parser + feature extractor used by training, rules and app
             rules.py     - rule engine;  brands.json - brand list for the brand rules
             model.py     - Random Forest training/evaluation;  hybrid.py - risk tiers
             hybrid_config.json - frozen tier cut-points and how they were derived
             presentation.py - user-facing labels, colours and safe display for the app
tests/       unit tests
reports/     evaluation reports and charts
models/      trained model (git-ignored, rebuild with `python -m src.model train`)
app.py       Streamlit app
.streamlit/  app settings (localhost only, no usage stats, no tracebacks)
```

## How a URL is assessed

```
URL string ──► features.analyze()  (parse once, never fetch)
                 │
                 ├──► Random Forest on HOSTNAME features ──► model score ──► base tier
                 │
                 └──► rule engine on the WHOLE URL ──► strong / weak / info indicators
                                                            │
                         base tier + rule escalation ◄──────┘
                                     │
                                     ▼
                 Low / Medium / High risk indicators  (or "Cannot analyze")
```

### 1. Model score (host only)

A Random Forest trained on PhiUSIIL scores the **hostname** only: length, digits, hyphens,
subdomains, entropy, keywords and TLD. It does not see the path, query or scheme, because every
legitimate URL in the training data is a bare `https://www.<host>` homepage, and a full-URL model
learns that pattern instead of phishing signals (see `reports/model_evaluation.md`).

The score is shown as a **model score**, not as a "% chance of phishing". It is not a calibrated
probability.

### 2. Rule indicators (whole URL)

`src/rules.py` checks the whole URL. Each rule has a name, a strength, a weight and a reason shown to
the user.

| Strength (weight) | Rules |
|---|---|
| **Strong** (3) | IP address as host (incl. decimal/hex/octal and IPv6) · `@` before the host · host label mixing alphabets (e.g. Latin + Cyrillic, also after punycode decoding) · brand name in the subdomain of a non-official domain · a URL to a different site embedded in the path |
| **Weak** (1) | single-alphabet non-ASCII or punycode host · brand in the domain name · brand in the path/query · full URL in a query value · plain http · ≥ 2 suspicious keywords · > 100 characters, > 3 percent-encoded characters or a long hex string · executable/archive file extension · ≥ 3 subdomains, ≥ 4 hyphens or a non-standard port |
| **Info** (0) | link shortener · archived copy on an archive service |

Thresholds are frozen (not tuned on test). Brand rules use `src/brands.json`, which lists each brand's
official domains; a brand never fires on its own official domains. Archive services
(`web.archive.org/web/2020/https://example.com`) are a documented exception to the embedded-URL rule.

### 3. Risk tiers

The model score sets a **base tier** using two cut-points from `src/hybrid_config.json`:

| Base tier | Condition | How the cut-point was chosen (train out-of-fold scores only) |
|---|---|---|
| **High risk indicators** | score ≥ `high` (0.568) | Lowest score where precision stays ≥ 95 % for that score **and every higher score** |
| **Medium risk indicators** | `low` ≤ score < `high` | |
| **Low risk indicators** | score < `low` (0.235) | 5th percentile of training phishing scores |

Rules can then **raise** the tier, **never lower it**:

| Rule hits | Effect |
|---|---|
| 2 or more strong | High |
| 1 strong | one tier up (Low → Medium, Medium → High) |
| 3 or more weak | Low → Medium (weak indicators alone never produce High) |
| info | no change |

Input that cannot be parsed (empty, no host, invalid port) gets **"Cannot analyze"**, never a guess.

**Labels shown in the app** (`src/presentation.py`):

| Tier | Label | Colour |
|---|---|---|
| High | High risk indicators | red |
| Medium | Inconclusive, check carefully | amber |
| Low | Low risk indicators | blue-grey (not green, which would suggest "safe") |
| Unknown | Can't analyze this input | grey |

The app never says "safe" or "confirmed phishing". It shows the analyzed address defanged in a code block
(`hxxps://example[.]com`), never as a link, and escapes rule reasons so HTML or script text in the input
renders as plain text.

**Why this design.**
- The model is good at ranking hosts but biased by its training data, so it only sets a starting point.
- Rules catch URL tricks the model cannot see (IP hosts, `@`, look-alike letters, hidden redirects).
  Strong rules are rare on legitimate URLs (1 in 107,880 legitimate training URLs).
- Rules only escalate. A rule that "looks clean" proves nothing, and an allowlist would let a trusted
  name lower the risk of a malicious path, so there is none.
- Logistic regression tied the Random Forest in evaluation but is **not used in the app**. Two scores
  that disagree would confuse users. It appears only in the evaluation report.

### What the tiers do and do not mean

- **Low is not "safe".** About **5 % of training phishing falls in Low by design** (the cut-point is the
  5th percentile of phishing scores). Low means few risk indicators were found.
- **Precision depends on the phishing share of the data.** The 95 % precision behind the High cut-point
  was measured on training data that is 42.7 % phishing. Real-world traffic contains far less phishing,
  so the share of High results that are really phishing will be lower. These numbers do **not** describe
  real-world traffic.
- **The ML score may be inflated for subdomains.** Almost all legitimate training sites were bare domains,
  so the model over-rates subdomains of real sites (`docs.python.org` scores High on the model alone).
  The app shows this note whenever the address has a subdomain. Short `.io` domains are similarly
  over-rated.
- With these cut-points, many legitimate training URLs land in Medium (about 60 % on train out-of-fold
  scores). Medium means "check carefully", not "phishing".
- Known rule false positives: `apple.stackexchange.com` and sites named after a brand
  (`google.blognewschannel.com`) fire the strong brand-in-subdomain rule; fan sites (`apple-history.com`)
  fire the weak brand-in-domain rule; official brand domains missing from `brands.json` can fire brand rules.

Status and decisions: see `PROGRESS.md`. Model evaluation: `reports/model_evaluation.md`.
