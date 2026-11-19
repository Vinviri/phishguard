# PhishGuard

PhishGuard is a small, locally run phishing **URL** checker. It combines a rule engine with a Random Forest
model and shows the result in a Streamlit app as **risk indicators** with plain-language reasons.
It is an educational prototype (see `PROJECT_BRIEF.md`), not a production security tool.

> PhishGuard analyzes the **text of a URL only**. It never fetches, resolves or visits the site, uses no
> external threat-intelligence services, and does not log, store or send the URLs you enter.
> Results are risk indicators, not a guarantee that a site is malicious or safe.

**In one paragraph.** On the PhiUSIIL test set the hybrid looks strong (95.5 % precision for "High"), but
that test set is inflated: its legitimate URLs are all bare homepages. On a hand-made list of realistic URLs
(the real check), PhishGuard put 13 of 25 real, current phishing URLs in High and missed 4, but it also put
11 of 32 legitimate URLs in High, 10 of them because they have a subdomain. Read the
[evaluation summary](#evaluation-summary) and [limitations](#limitations) before relying on any result.

## Install (Windows, Python 3.11)

```bash
py -3.11 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

Use exactly the versions in `requirements.txt`. The saved model records its scikit-learn version, and the
app refuses to use a model saved with a different version.

## Run the app

```bash
streamlit run app.py
```

Open http://localhost:8501. The app listens on this machine only (`.streamlit/config.toml`), sends no usage
statistics and never shows tracebacks. If it says the model is not available, rebuild it (next section).

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

Do **not** rerun `python -m src.model evaluate`, `python -m src.hybrid evaluate`,
`python -m src.hybrid derive-config` or `python -m src.manual_eval`. The test set and the manual list were
each evaluated once (lock files in `reports/`), and the cut-points are frozen at tag `m6-frozen`.
Retraining with the same versions reproduces the same model (fixed seeds).

## Layout

```
data/        raw/ (git-ignored), processed/ (clean data + fixed split), eval/ (manual list), README.md
src/         features.py  - one parser + feature extractor used by training, rules and app
             rules.py     - rule engine;  brands.json - brand list for the brand rules
             model.py     - Random Forest training/evaluation;  hybrid.py - risk tiers
             hybrid_config.json - frozen tier cut-points and how they were derived
             presentation.py - user-facing labels, colours and safe display for the app
             data_prep.py, export_report.py, manual_list.py, manual_eval.py - data and evaluation scripts
tests/       unit, integration and Streamlit AppTest tests (see reports/test_summary.md)
reports/     evaluation reports, charts, lock files
models/      trained model (git-ignored)
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
          Low risk indicators / Inconclusive, check carefully / High risk indicators
                            (or "Can't analyze this input")
```

### 1. Model score (hostname only)

A Random Forest trained on PhiUSIIL scores the **hostname** only: length, digits, hyphens, subdomains,
entropy, keywords and TLD. It does not see the path, query or scheme. Every legitimate URL in the training
data is a bare `https://www.<host>` homepage, and a full-URL model learns that pattern instead of phishing
signals (0.9988 PR-AUC in cross-validation, for the wrong reason; see `reports/model_evaluation.md`).

The score is shown as a **model score** from 0 to 1, never as a "% chance of phishing". It is not a
calibrated probability.

### 2. Rule indicators (whole URL)

`src/rules.py` checks the whole URL. Each rule has a name, a strength, a weight and a reason shown to the user.

| Strength (weight) | Rules |
|---|---|
| **Strong** (3) | IP address as host (incl. decimal/hex/octal and IPv6) · `@` before the host · host label mixing alphabets (e.g. Latin + Cyrillic, also after punycode decoding) · brand name in the subdomain of a non-official domain · a URL to a different site embedded in the path |
| **Weak** (1) | single-alphabet non-ASCII or punycode host · brand in the domain name · brand in the path/query · full URL in a query value · plain http · ≥ 2 suspicious keywords · > 100 characters, > 3 percent-encoded characters or a long hex string · executable/archive file extension · ≥ 3 subdomains, ≥ 4 hyphens or a non-standard port |
| **Info** (0) | link shortener · archived copy on an archive service |

Thresholds are frozen and were not tuned on test data. Brand rules use `src/brands.json`, which lists each
brand's official domains; a brand never fires on its own official domains. Archive services
(`web.archive.org/web/2020/https://example.com`) are a documented exception to the embedded-URL rule.

### 3. Risk tiers

The model score sets a **base tier** using two cut-points from `src/hybrid_config.json`, both derived from
**train out-of-fold scores only**:

| Base tier | Condition | How the cut-point was chosen |
|---|---|---|
| High | score ≥ 0.568 | Lowest score where precision stays ≥ 95 % for that score **and every higher score** |
| Medium | 0.235 ≤ score < 0.568 | |
| Low | score < 0.235 | 5th percentile of training phishing scores |

Rules can then **raise** the tier, **never lower it**:

| Rule hits | Effect |
|---|---|
| 2 or more strong | High |
| 1 strong | one tier up (Low → Medium, Medium → High) |
| 3 or more weak | Low → Medium (weak indicators alone never produce High) |
| info | no change |

Input that cannot be parsed (empty, no host, invalid port) is not scored.

**Labels shown in the app** (`src/presentation.py`):

| Tier | Label | Colour |
|---|---|---|
| High | High risk indicators | red |
| Medium | Inconclusive, check carefully | amber |
| Low | Low risk indicators | blue-grey (not green, which would suggest "safe") |
| Unknown | Can't analyze this input | grey |

The app never says "safe" or "confirmed phishing". It shows the analyzed address defanged in a code block
(`hxxps://example[.]com`), never as a link, and escapes rule reasons so HTML or script text in the input
renders as plain text. It always shows a limitations box, the note that the model sees only the hostname,
and, for addresses with a subdomain, the note "The ML score may be inflated for subdomains".

**Why this design.**
- The model ranks hosts reasonably well but is biased by its training data, so it only sets a starting point.
- Rules catch URL tricks the model cannot see (IP hosts, `@`, look-alike letters, hidden redirects) and give
  readable reasons. Strong rules fired on 1 of 107,880 legitimate training URLs.
- Rules only escalate. A URL that passes the rules is not proven clean, and an allowlist would let a trusted
  name lower the risk of a malicious path, so there is none.
- Logistic regression tied the Random Forest (test PR-AUC 0.910 vs 0.909) but is **not used in the app**:
  two scores that disagree would confuse users. It appears only in the evaluation report.

## Evaluation summary

Full reports: `reports/model_evaluation.md` (M4), `reports/hybrid_evaluation.md` (M6),
`reports/manual_evaluation.md` (M8). An interactive version of the M4 report was built from
`python -m src.export_report`.

### PhiUSIIL test set (inflated)

Grouped split by registered domain (47,074 test URLs from unseen domains, 42.7 % phishing), evaluated once.

| | Precision | Recall | False alarms |
|---|---|---|---|
| Random Forest (threshold 0.386) | 0.857 | 0.768 | 9.5 % |
| Hybrid, "High" as a flag | 0.955 | 0.697 | 2.4 % |
| Hybrid, "Medium or High" as a flag | 0.525 | 0.956 | 64.5 % |

**Labelled inflated.** Every legitimate test URL is a bare `https://www.` homepage, so full-URL rules cannot
misfire on them and subdomain bias barely shows. Rules raised the tier of only 5 phishing URLs.

### Manual list (the real check)

A list built for this project (`data/eval/`), with no registered domain in common with the training or test
data, evaluated once through the real hybrid. Raw counts, small list:

| | Low | Medium | High |
|---|---|---|---|
| Real phishing, OpenPhish feed (25) | 4 (misses) | 8 | 13 |
| Legitimate, hand-written real sites (32) | 4 | 17 | 11 (false alarms) |

- **10 of the 11 false alarms** are legitimate sites on a subdomain (`en.wikipedia.org`, `docs.streamlit.io`,
  `support.apple.com`, …). The remaining one is a link shortener (`.ly`).
- **All 4 misses** are short, ordinary-looking bare domains where the phishing is presumably in the path, which
  the host-only model cannot see and the rules found nothing in.
- **The rules changed no tier on this list.** No strong rule fired on any real phishing URL. 11 synthetic
  URLs built to use the rule tricks were all High, but the model had already placed them there.
- Of the 300 URLs in the OpenPhish feed, **69 % were on hosting platforms that also appear in PhiUSIIL**
  (pages.dev, github.io, blogspot.com, …) and **31 %** were not. The headline sample comes from the 31 %;
  15 platform-hosted URLs are reported separately as descriptive only (all High).

## Limitations

- **Host-only model.** The model never sees the path or query. Phishing on a compromised or ordinary-looking
  site, with the malicious page in the path, gets a low model score (all 4 manual-list misses).
- **Platform-hosted phishing.** For phishing on free hosting platforms (pages.dev, github.io, blogspot, …),
  69 % of the current feed sample, the host-only model mostly sees the **platform name, not the page**. Its
  High score there reflects the platform's history in the training data. The full-URL rules carry more
  weight for such URLs, but they rarely fired on them.
- **Dataset bias.** PhiUSIIL's legitimate URLs are popular-site homepages. The model learned that subdomains
  and some TLDs (`.io`, `.app`, `.dev`, `.ly`) mean phishing, so real legitimate subdomains are over-rated
  (10 of 11 manual-list false alarms).
- **Phishing base rate.** The 95 % precision behind the High cut-point was measured on data that is about
  43 % phishing. Real traffic has far less phishing, so the share of High results that are really phishing
  will be much lower. No number in this project describes real-world traffic.
- **Medium is wide.** About 60 % of legitimate training URLs, 62 % of legitimate test URLs and 17 of 32
  legitimate manual-list URLs land in Medium. Medium means "check carefully", not "phishing".
- **Low is not safe.** About 5 % of training phishing falls in Low by design; 4 of 25 real phishing URLs did
  on the manual list.
- **Known rule false positives.** `apple.stackexchange.com` and sites named after a brand fire the strong
  brand-in-subdomain rule; fan sites fire the weak brand-in-domain rule; official domains missing from
  `brands.json` can fire brand rules.
- **No reputation, age or content signals** by design (no network access).
- **Small, dated evaluation.** The manual list has 25 real phishing and 32 legitimate URLs from one feed on one
  day (2026-11-19). PhiUSIIL dates from about 2023–2024.

## Ethics and privacy

- **No visiting, no lookups.** Submitted URLs are parsed as text. PhishGuard never fetches, resolves or opens
  them, and uses no external API. The project never visited any phishing URL during development either.
- **No storage.** The app caches only the trained model (`st.cache_resource`), never inputs. It does not log
  or save URLs, keeps no history beyond the current input box, never echoes URLs in error messages, and binds
  to localhost with Streamlit usage statistics turned off.
- **Safe display and storage.** URLs are shown and stored defanged (`hxxps://example[.]com`) so they are not
  clickable; HTML or script text in an input renders as plain text.
- **Honest output.** Results are risk indicators with reasons, never "safe" or "confirmed phishing". The
  limitations box is always visible.
- **Data use.** PhiUSIIL (UCI, CC BY 4.0) is used with attribution. Real phishing URLs from the OpenPhish
  community feed are **not redistributed**: their redistribution terms could not be confirmed, so they are
  git-ignored and reports show only per-URL category and tier.
- **Educational use.** PhishGuard is a teaching prototype. Do not use it as the only check before entering
  credentials or payment details.

## Data sources

| Data | Source | License / terms | In this repo |
|---|---|---|---|
| Training and test data | PhiUSIIL Phishing URL Dataset, UCI ML Repository (dataset 967). Prasad & Chandra (2024), *Computers & Security* 136, 103545 | CC BY 4.0 | Cleaned URLs and split in `data/processed/` |
| Real phishing for the manual list | OpenPhish community feed (openphish.com/feed.txt), downloaded 2026-11-19 | Redistribution not confirmed | **Not committed**; counts only |
| Legitimate and synthetic manual-list URLs | Written for this project | - | `data/eval/manual_urls.csv` (defanged) |

Status, decisions and their reasons: `PROGRESS.md`. Test coverage: `reports/test_summary.md`.
