# Data

## Source

**PhiUSIIL Phishing URL Dataset**
- Publisher: UCI Machine Learning Repository, dataset id 967
  - Page: https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset
  - Download: https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip
- Citation: Prasad, A. & Chandra, S. (2024). *PhiUSIIL: A diverse security profile empowered
  phishing URL detection framework based on similarity index and incremental learning.*
  Computers & Security, 136, 103545.
- License: **Creative Commons Attribution 4.0 International (CC BY 4.0)** (as stated on the UCI page).
  Redistribution of derived data (data/processed) is allowed with attribution.
- Date acquired: **2026-11-19**
- Archive SHA-256: `0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a`
- Raw file: `PhiUSIIL_Phishing_URL_Dataset.csv`: 235,795 rows, 56 columns (many are page-content
  features; **only `URL` and `label` are used**, since PhishGuard analyzes URL strings only).

## Reproduce

```bash
mkdir -p data/raw/phiusiil
curl -L -o data/raw/phiusiil/phiusiil.zip "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"
cd data/raw/phiusiil && unzip phiusiil.zip && cd ../../..
python -m src.data_prep
```

`data/raw/` is git-ignored. `data/processed/` is committed so the train/test split is fixed.

## Preparation (`src/data_prep.py`)

| Step | Result |
|---|---|
| Missing values | 0 blank/NaN URLs, 0 NaN labels |
| Label normalization | Raw `label`: **0 = phishing, 1 = legitimate** (the UCI page text is contradictory; verified on known samples such as Office365 look-alikes = 0, plain homepages = 1). Normalized to `is_phishing` (1 = phishing). |
| Duplicates | 425 exact duplicate URLs removed (after whitespace strip); 0 URLs with conflicting labels |
| Clean rows | 235,370 (100,520 phishing / 134,850 legitimate, 42.7 % phishing) |
| Grouping key | `registered_domain` = eTLD+1 via `tldextract` with its bundled Public Suffix List snapshot (offline, ICANN section only, so `x.web.app` → `web.app`). 175,509 unique. |
| Split | `StratifiedGroupKFold(5, shuffle, seed=42)`, one fold = test. Train 188,296 / Test 47,074, both 42.7 % phishing. **No registered domain appears in both sets** (asserted). |

### Why split by registered domain

Phishing campaigns reuse a domain or hosting platform for many URLs (e.g. 5.7k URLs on `web.app`,
5.5k on `firebaseapp.com`). A random row split would put sibling URLs of the same campaign in both
train and test, so the model would be scored on memorized hosts rather than on generalization to
**unseen** domains, which is the real deployment situation. A grouped split gives a more honest
(lower) test score. Free-hosting platforms are deliberately kept as single groups (ICANN suffixes only)
to be conservative.

## Known label bias (measured on TRAIN only)

| Property | Legitimate | Phishing |
|---|---|---|
| Starts with `https://` | 100 % | 50.0 % |
| Host starts with `www.` | 100 % | 40.8 % |
| Non-root path | 0 % | 28.2 % |
| Has query | 0 % | 6.2 % |
| Trailing slash | 0 % | 37.0 % |
| Median length | 27 | 34 |

**Every legitimate URL is a bare homepage of the form `https://www.<host>`.** That one template
matches 100 % of legitimate and only 0.6 % (499 / 80,416) of phishing training URLs. A model trained
on full-URL features can therefore reach ~99.7 % accuracy by learning the template, and would flag any
real legitimate URL with a path (e.g. a GitHub repo link) as phishing. See PROGRESS.md for how this is handled.

`processed/prep_report.json` contains all the numbers above.
