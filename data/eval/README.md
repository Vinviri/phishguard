# Manual evaluation list (M8)

| File | Committed? | Content |
|---|---|---|
| `manual_urls.csv` | yes | The list: `id, url_defanged, label, category, source, notes`. Real phishing rows keep id/label/category/source, but the URL is replaced by `[withheld: …]` |
| `manual_urls_full.csv` | **no** (git-ignored) | The same list with the real phishing URLs; read by `src/manual_eval.py` |
| `real_phishing_input.csv`, `real_platform_input.csv` | **no** (git-ignored) | Sampled OpenPhish URLs (defanged) |
| `raw_feed/` | **no** (git-ignored) | The raw feed file as downloaded by the project owner |
| `real_sample_log.json` | yes | Sampling counts, seed and pool sizes only (no URLs, no domains) |
| `overlap_report.csv` | yes | Hand-written legitimate candidates removed by the overlap check |

**Safety.** Every URL is stored defanged (`hxxps://`, `[.]` in hosts, and the same for any URL embedded in a
path or query). Code refangs in memory only (`src/manual_list.py: refang`). No URL in this folder has ever
been fetched, resolved or visited by this project; the feed file was downloaded by the project owner and is
read as text only.

## Sources

| Part | Source | Notes |
|---|---|---|
| Legitimate (32) | Hand-written from known real sites | Paths plausible but **not verified** (never visited). Labels assumed legitimate. |
| Synthetic phishing (11) | Invented for this project | Long invented names on real TLDs and documentation-range IPs (RFC 5737), one rule trick each. Never resolved. Caught by the rules **by construction**: not evidence of generalization. |
| Real phishing, independent (25) | **OpenPhish community feed** (openphish.com/feed.txt), downloaded 2026-11-19 by the project owner | Random sample from the URLs whose registered domain is not in PhiUSIIL. |
| Real phishing, known platforms (15) | Same OpenPhish feed | Random sample from the URLs whose platform domain is in PhiUSIIL. **Not independent of training; descriptive only; never in headline counts.** |

**OpenPhish license.** Redistribution terms of the community feed could not be confirmed, so the real
phishing URLs are **not committed and not published** anywhere in this repository. Reports show them only by
ID, category, score, tier and fired rules.

## Sampling (decided before any results)

- Feed: 300 URLs, 300 unique.
- Overlap check: a URL "overlaps" when its registered domain (eTLD+1, ICANN suffixes, same definition as the
  train/test split) appears in the PhiUSIIL train or test split. Only the split's domain column is read.
- Pools: **207 overlapping (69 %)**, almost all free hosting platforms (pages.dev, github.io, blogspot.com,
  vercel.app, netlify.app, weebly.com, …), and **93 independent (31 %)**.
- `random.Random(20261119).sample(independent_pool, 25)` and `random.Random(20261119).sample(platform_pool, 15)`.
- A first attempt (sample 25 from the whole feed, then remove overlaps) kept only 6 and was abandoned before
  any evaluation.

**Skew.** Removing overlapping domains drops big, common sites from the legitimate side (python.org,
google.com, stackoverflow.com, bit.ly, …), so legitimate URLs lean toward smaller sites, and the independent
phishing sample covers only phishing that is not on a known hosting platform.

## Rebuild

Put the feed file in `data/eval/raw_feed/`, then:

```bash
python -m src.manual_list sample-feed data/eval/raw_feed/<file>
python -m src.manual_list assemble
```

The evaluation itself (`python -m src.manual_eval --hide-real-urls`) was run once and is locked
(`reports/.manual_evaluated`).
