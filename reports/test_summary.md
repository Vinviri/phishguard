# PhishGuard - Test Summary (M8)

Run on 2026-11-19 with `pytest` (Python 3.11.0, pytest 9.2.0, Streamlit 1.67.0, scikit-learn 1.9.1), with the
trained model present:

```
366 passed in 10.18s
```

0 failed, 0 skipped. Without a trained model (fresh clone), the tests that need `models/phishguard_rf.joblib`
skip with a reason instead of failing; rebuild steps are in `README.md`.

## What is covered

| File | Tests | Covers |
|---|---|---|
| `tests/test_features.py` | 46 | One extractor, same keys and order for every input; no scheme, protocol-relative, IPv4, IPv6, decimal/hex/octal IPv4, `@` in host vs path, punycode, Unicode hosts, percent-encoding, hex runs, `//` redirects, invalid ports, 100,000-character input (capped, true length reported), empty / `None` / non-string input, entropy and ratio ranges, determinism. "www." does not change host features. |
| `tests/test_model.py` | 18 | Model uses exactly the host features; end-to-end URL → `extract_features` → model on normal, empty, malformed, IPv6 and 50,000-character input (tiny trained pipeline and, when present, the saved model); per-feature contributions sum exactly to the predicted probability; saved bundle has version metadata. |
| `tests/test_rules.py` | 84 | Every rule has name, strength, weight and a readable reason; strengths match the decisions; frozen thresholds (100 chars, 3 encoded, 2 keywords) with boundary tests; all IPv4 forms and IPv6 for `ip_host`; mixed-script vs single-script IDN (incl. punycode and broken punycode); brand rules never fire on official domains and avoid substring matches; embedded-URL rule vs same-site and archive exception; relative `?next=` does not fire; 15 hand-written real-world legitimate URLs fire no strong rule; 2 documented known false positives; never raises. |
| `tests/test_hybrid.py` | 120 | Config valid and documented (running-minimum method, ~5 % phishing below Low); tier boundaries at the cut-points; **exhaustive check that rules never lower a tier** (every base tier × 0–3 strong × 0–4 weak); weak rules alone never give High; "Unknown" for unparseable input; exact note texts and when they appear; no tier label says "safe"; logistic regression never loaded; nothing logged during an assessment. |
| `tests/test_app.py` | 41 | Exact UI labels; no "safe"/"confirmed" wording; Low not green; defang and Markdown escaping; missing model, scikit-learn version mismatch and corrupt model file give a generic message (function and Streamlit AppTest); end-to-end URL → features → model → hybrid → view for 13 inputs; generic analysis errors never echo the URL; source checks: no `st.cache_data`, no logging, exactly one `st.cache_resource`; **Streamlit AppTest**: limitations box, example buttons, normal / empty / very long input, and `<script>`, `<img onerror>`, Markdown link and `javascript:` input rendered only as defanged plain text. |
| `tests/test_manual_list.py` | 57 | Defang/refang round-trips exactly and leaves nothing clickable (including URLs embedded in paths); the committed manual list has the required columns, no live `http(s)://` text, withheld OpenPhish URLs, unique ids, and **no registered domain shared with the train/test splits**. |

## Not covered by automated tests

- Visual layout of the Streamlit app in a real browser (AppTest checks content, not rendering).
- Real-world accuracy: covered by the one-time manual evaluation (`reports/manual_evaluation.md`), not by unit tests.
- Retraining reproducibility end to end (about 40 minutes); the saved-model tests check the trained artifact instead.
