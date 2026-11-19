# PhishGuard - Hybrid Evaluation (M6, locked)

Evaluated **once** on 2026-11-19T03:24:54Z (`reports/.hybrid_test_evaluated`) with `hybrid-v1` / `rf-host-v1`,
**after** the freeze commit tagged `m6-frozen` (rules, brand list, cut-points, tier logic, requirements).
Nothing was changed after this run. Raw numbers: `reports/hybrid_test_metrics.json`.

> **INFLATED.** Every legitimate test URL is a bare `https://www.<host>` homepage. Full-URL rules
> (plain http, path and query rules) therefore cannot misfire on legitimate URLs in this test set:
> they fired on **0** of 26,970 legitimate URLs here, which will not hold on real traffic. Rules-only and
> hybrid numbers overstate real-world performance. The M8 hand-made URL list (not drawn from the test
> set) is the real check.

## Setup

| Item | Value |
|---|---|
| Test set | 47,074 URLs from registered domains never seen in training (42.7 % phishing) |
| Cut-points | low 0.23526, high 0.56803, both from train out-of-fold scores (`src/hybrid_config.json`) |
| ML-only | Base tier from the Random Forest score and the cut-points |
| Rules-only | Same escalation logic starting from Low (no model) |
| Hybrid | Base tier from the model, then rule escalation (the app's method) |

## Tier distribution

| | Phishing: Low | Medium | High | Legitimate: Low | Medium | High |
|---|---|---|---|---|---|---|
| ML-only | 885 (4.4 %) | 5,205 (25.9 %) | 14,014 (69.7 %) | 9,577 (35.5 %) | 16,738 (62.1 %) | 655 (2.4 %) |
| Rules-only | 19,660 (97.8 %) | 444 (2.2 %) | 0 | 26,970 (100 %) | 0 | 0 |
| **Hybrid** | **881 (4.4 %)** | **5,208 (25.9 %)** | **14,015 (69.7 %)** | **9,577 (35.5 %)** | **16,738 (62.1 %)** | **655 (2.4 %)** |

No input was "Cannot analyze".

## Two ways to read a tier as a flag

| Flag when | Method | Precision | Recall | False alarm rate |
|---|---|---|---|---|
| **High only** | ML-only | 0.955 | 0.697 | 2.4 % |
| | Rules-only | n/a (0 flagged) | 0.000 | 0.0 % |
| | **Hybrid** | **0.955** | **0.697** | **2.4 %** |
| **Medium or High** | ML-only | 0.525 | 0.956 | 64.5 % |
| | Rules-only | 1.000 | 0.022 | 0.0 % |
| | **Hybrid** | **0.525** | **0.956** | **64.5 %** |

Rules escalated **5** phishing URLs and **0** legitimate URLs above their ML tier.

## What this shows

1. **The cut-points behave as designed on unseen domains.** High precision is 95.5 % (target ≥ 95 % on train)
   and 4.4 % of phishing falls in Low (designed as about 5 %). Train and test agree, so the cut-points were not overfit.
2. **On this dataset the rules add almost nothing measurable.** Strong rules fire on about 2 % of phishing, and
   when they do, the model has usually already placed the URL in High. Rules-only never reaches High because no
   test URL fires two strong rules. This is an honest result, not a bug. The rules exist for tricks this
   dataset barely contains: IP hosts, `@`, look-alike letters, brand-in-subdomain and hidden redirects. Their
   value is in the **explanations** they give and in URLs outside this dataset. M8 has to show that.
3. **Medium is wide.** 62 % of legitimate test URLs land in Medium, mostly because the Low cut-point targets
   95 % phishing recall and the model over-rates subdomains and some TLDs. "Medium or High" as a flag gives a
   64.5 % false alarm rate, so **Medium must be presented as "check carefully", not as a phishing verdict.**
   The app text already does this.
4. **Precision depends on the 42.7 % phishing share.** In real traffic, where phishing is much rarer, the share of
   High results that are really phishing will be lower than 95.5 %.
5. **Logistic regression** is not part of the hybrid (report-only, see `reports/model_evaluation.md`).

## Limitations carried into Phase 4

- Inflation (see the box above): rules cannot misfire on this test set's legitimate URLs.
- The model's subdomain and `.io` bias puts many legitimate URLs in Medium and some in High (for example
  `docs.python.org`). The app shows the subdomain note; there is no allowlist by design.
- Rules' real-world value and false positives must be checked with the M8 hand-made list, which must not
  contain test URLs.
