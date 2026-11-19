# PhishGuard - Manual Evaluation (M8, locked)

Run **once** on 2026-11-19T05:01:26Z through the real hybrid (`python -m src.manual_eval --hide-real-urls`).
Rules, brand list, cut-points, hybrid logic, feature code, model code and requirements were identical to tag
`m8-start` (checked by the script). Lock: `reports/.manual_evaluated` (list SHA-256 `e72e088d…`, model
`rf-host-v1` SHA-256 `e6846267…`). Nothing was changed after this run.

**This list is the real check of PhishGuard.** The PhiUSIIL test-set results are inflated (its legitimate URLs
are all bare homepages). Numbers below are raw counts on a small list, not rates to generalize from.

## 1. The list

| Group | URLs | Source | Counts in headline? |
|---|---|---|---|
| Legitimate | 32 | Hand-written real sites: docs/subdomain 8, login redirects 7, long ordinary 6, repo paths 4, brand in path 3, single-script IDN 2, archive 1, shortener 1 | Yes |
| Real phishing (independent) | 25 | OpenPhish community feed, 2026-11-19, random sample (seed 20261119) of the URLs whose registered domain is **not** in PhiUSIIL | Yes |
| Synthetic phishing | 11 | Invented, one rule trick each | Reported separately |
| Real phishing on known platforms | 15 | Same feed, random sample (same seed) of URLs whose platform domain **is** in PhiUSIIL | **No**: not independent of training, descriptive only |

- **Feed split.** Of the 300 URLs in the feed, **207 (69 %)** are on registered domains that also occur in
  PhiUSIIL, almost all free hosting platforms (pages.dev 139, github.io 16, blogspot.com 16, vercel.app 9,
  netlify.app 6, weebly.com 5, …). Only **93 (31 %)** are on domains PhiUSIIL does not contain. The
  independent sample comes from those 93, so it represents phishing that is *not* on a known platform.
  A first attempt (sample 25 from the whole feed, then remove overlaps) kept only 6 and was abandoned
  before any evaluation.
- **Overlap removal skews the legitimate side toward smaller sites.** 10 of 42 legitimate candidates were
  removed because their domain is in PhiUSIIL (python.org, mozilla.org, postgresql.org, google.com ×2,
  djangoproject.com, stackoverflow.com ×2, etsy.com, ikea.com); bit.ly was replaced by buff.ly. Big,
  well-known sites are therefore under-represented.
- **Synthetic URLs are caught by the rules by construction** (each was built to trigger one rule). They show
  that the rules work as specified, not that PhishGuard generalizes. Only the 25 real phishing URLs are
  evidence about generalization.
- Real phishing URLs are **not published** (OpenPhish redistribution terms not confirmed): they appear here
  only by ID, category, score, tier and fired rules.

## 2. Headline results (hybrid, raw counts)

| | Low risk indicators | Inconclusive, check carefully (Medium) | High risk indicators |
|---|---|---|---|
| **Real phishing (25)** | **4** (misses) | 8 | **13** |
| **Legitimate (32)** | 4 | 17 | **11** (false alarms) |

- Real phishing reaching **High: 13 of 25**; reaching at least Medium: **21 of 25**; missed (Low): **4 of 25**.
- Legitimate in **High: 11 of 32**; in Medium: 17 of 32; in Low: 4 of 32.
- Read as a strict flag ("High only"): 13 of 25 phishing flagged against 11 of 32 legitimate.
  Read loosely ("Medium or High"): 21 of 25 phishing against 28 of 32 legitimate.
  **On realistic legitimate URLs the tiers separate the classes poorly.** The PhiUSIIL test set showed
  2.4 % of legitimate URLs in High; here it is 11 of 32.

Legitimate results by category (hybrid tier):

| Category | Low | Medium | High |
|---|---|---|---|
| docs / subdomain sites (8) | 1 | 2 | 5 |
| login redirects (7) | 0 | 4 | 3 |
| long ordinary URLs (6) | 1 | 4 | 1 |
| repo paths (4) | 1 | 3 | 0 |
| brand in path (3) | 1 | 2 | 0 |
| single-script IDN (2) | 0 | 2 | 0 |
| archive (1) | 0 | 0 | 1 |
| shortener (1) | 0 | 0 | 1 |

## 3. What the rules add: ML-only vs rules-only vs hybrid

| Group | ML-only (Low / Medium / High) | Rules-only (Low / Medium / High) | Hybrid (Low / Medium / High) |
|---|---|---|---|
| Real phishing (25) | 4 / 8 / 13 | 25 / 0 / 0 | 4 / 8 / 13 |
| Legitimate (32) | 4 / 17 / 11 | 31 / 1 / 0 | 4 / 17 / 11 |
| Synthetic phishing (11) | 0 / 0 / 11 | 2 / 9 / 0 | 0 / 0 / 11 |
| Known-platform phishing (15, descriptive) | 0 / 0 / 15 | 15 / 0 / 0 | 0 / 0 / 15 |

**The rules changed no tier on this list.** Hybrid equals ML-only in every group.

- **No strong rule fired on any real phishing URL (0 of 25)** or on any legitimate URL (0 of 32). Weak rules
  fired on 8 of 25 real phishing URLs (plain http 6, brand in domain 2, long/encoded 2), never 3 at once.
- Strong rules fired on 9 of 11 synthetic URLs as designed (the 2 risky-extension URLs only trigger weak
  rules). But the model had already put all 11 in High: long invented names on `.top`/`.xyz`/`.site`/`.click`
  look like phishing to the host model, so escalation had nothing left to raise.
- Today's real phishing in this sample does not use the classic tricks the strong rules target (IP hosts,
  `@`, look-alike letters, brand in subdomain, embedded URLs). The rules' measurable value here is their
  **explanations**, not their detection.

## 4. Every miss (real phishing in Low): 4 of 25

All four share one profile: a **short, bare registered domain** (10–13 characters, no subdomain, no hyphens,
no digits), three of them on a two-part country suffix and one on a two-letter country TLD, with a short path
(1–3 segments) that contains no suspicious keyword or brand name.

| ID | Model score | Fired rules | Why it was missed |
|---|---|---|---|
| M050 | 0.223 | none | Ordinary-looking short domain, HTTPS, short keyword-free path. Indistinguishable from the bare legitimate homepages the model was trained on. |
| M055 | 0.182 | plain http (weak) | Same profile on a two-part country suffix; one weak rule cannot raise the tier. |
| M060 | 0.152 | none | Same profile; the path has a single short segment. |
| M064 | 0.182 | none | Same profile as M055 (two-part country suffix, three short path segments). |

Most likely these are compromised or look-alike small-business sites where the phishing page lives in the
path. The host-only model cannot see the path, and the path has nothing the rules look for.

## 5. Every false alarm (legitimate in High): 11 of 32

| ID | Site (defanged) | Model score | Main model contributions | Why |
|---|---|---|---|---|
| M002 | `pandas[.]pydata[.]org` | 0.813 | 1 subdomain (+0.230), 2 dots (+0.142) | Subdomain bias |
| M003 | `docs[.]streamlit[.]io` | 0.914 | 1 subdomain (+0.219), TLD .io (+0.159) | Subdomain + .io bias |
| M004 | `en[.]wikipedia[.]org` | 0.831 | 1 subdomain (+0.269), 2 dots (+0.161) | Subdomain bias |
| M007 | `learn[.]microsoft[.]com` | 0.968 | 1 subdomain (+0.199), brand keyword in host (+0.151) | Subdomain + brand word in an official host |
| M008 | `fastapi[.]tiangolo[.]com` | 0.921 | 1 subdomain (+0.246), 2 dots (+0.144) | Subdomain bias |
| M014 | `login[.]microsoftonline[.]com` | 0.951 | 1 subdomain (+0.159), brand keyword in host (+0.122) | Subdomain + brand word; also 3 weak rules (full URL in query, keywords, encoding) |
| M016 | `news[.]ycombinator[.]com` | 0.948 | 1 subdomain (+0.246), 2 dots (+0.133) | Subdomain bias |
| M019 | `id[.]atlassian[.]com` | 0.891 | 1 subdomain (+0.260), 2 dots (+0.145) | Subdomain bias |
| M020 | `web[.]archive[.]org` | 0.816 | 1 subdomain (+0.239), 2 dots (+0.150) | Subdomain bias (the archive info rule cannot lower a tier, by design) |
| M021 | `buff[.]ly` | 0.752 | TLD .ly (+0.336) | Short-domain TLD prior (.ly is common among shorteners in the phishing data) |
| M031 | `support[.]apple[.]com` | 0.965 | 1 subdomain (+0.159), brand keyword in host (+0.137) | Subdomain + brand word in an official host |

**10 of the 11 false alarms are driven by a single subdomain.** This is the dataset artifact documented in M4:
legitimate training URLs are almost all bare domains, so "has a subdomain" became the model's strongest
phishing signal. The app shows the "ML score may be inflated for subdomains" note on every one of these 10.
The rules did not cause any false alarm.

## 6. Known-platform phishing (not independent of training, descriptive only)

Not included in any headline count. These 15 URLs are on platforms whose domain appears in PhiUSIIL
(pages.dev, github.io, blogspot.com, …). The model has seen those platform names, mostly as phishing, so a
High tier here says little about generalization. For platform-hosted phishing the host-only model mostly
sees the **platform name, not the page**; the full-URL rules carry more weight there, but on these 15 they
fired only weak indicators (plain http 6, deep subdomains 2, long/encoded 1, brand in path 1).

| ID | Category | Hybrid tier |
|---|---|---|
| M069 | real_platform | High |
| M070 | real_platform | High |
| M071 | real_platform | High |
| M072 | real_platform | High |
| M073 | real_platform | High |
| M074 | real_platform | High |
| M075 | real_platform | High |
| M076 | real_platform | High |
| M077 | real_platform | High |
| M078 | real_platform | High |
| M079 | real_platform | High |
| M080 | real_platform | High |
| M081 | real_platform | High |
| M082 | real_platform | High |
| M083 | real_platform | High |

All 15 are High, which mostly reflects the platform name, not the individual page.

## 7. Proposals (not applied)

Nothing below was changed. Each would need a **new, separate** evaluation list, because this list has now
been seen.

1. **Fix the subdomain bias at its source.** Retrain with legitimate URLs that include subdomains and paths
   (another dataset or an added legitimate source), or evaluate a model without `host_num_subdomains` /
   `host_num_dots`. This addresses 10 of 11 false alarms.
2. **Treat the model score as weaker evidence for hosts with a subdomain**, for example cap the model-only base
   tier at Medium when the only drivers are subdomain-count features. This changes the tier logic and must
   be designed and frozen before a new list is evaluated.
3. **Path-aware signals for bare short domains.** All 4 misses were short bare domains with phishing in the
   path. A path-based model, or rules on path patterns seen in current kits, would be needed; keyword rules
   did not fire on these paths.
4. **Re-check the Low cut-point** on a new list: 4 of 25 real phishing fell in Low (design target about 5 % on
   train).
5. **Shortener and archive hosts**: the info rules explain them but cannot lower the tier, so `buff.ly` and
   `web.archive.org` reached High. Changing that would break the "rules never lower" principle and needs a
   deliberate decision.

## 8. Limitations of this evaluation

- Small list: 25 real phishing and 32 legitimate URLs. Counts, not rates.
- Legitimate URLs are hand-picked and their paths were never verified (never visited); labels are assumed.
- Overlap removal skews legitimate URLs toward smaller sites and the real-phishing sample toward phishing
  that is not on known hosting platforms (31 % of the feed).
- One feed, one day (OpenPhish, 2026-11-19).
- Synthetic URLs are caught by construction and are not evidence of generalization.

## 9. Per-URL results

### Legitimate (32)

| ID | Category | URL (defanged) | Model score | ML-only | Rules-only | Hybrid | Fired rules |
|---|---|---|---|---|---|---|---|
| M001 | docs_subdomain | `hxxps://scikit-learn[.]org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html` | 0.238 | Medium | Low | Medium | none |
| M002 | docs_subdomain | `hxxps://pandas[.]pydata[.]org/docs/reference/api/pandas.read_csv.html` | 0.813 | High | Low | High | none |
| M003 | docs_subdomain | `hxxps://docs[.]streamlit[.]io/develop/api-reference/widgets/st.text_input` | 0.914 | High | Low | High | none |
| M004 | docs_subdomain | `hxxps://en[.]wikipedia[.]org/wiki/Phishing` | 0.831 | High | Low | High | none |
| M005 | docs_subdomain | `hxxps://kubernetes[.]io/docs/concepts/overview/` | 0.299 | Medium | Low | Medium | none |
| M006 | docs_subdomain | `hxxps://numpy[.]org/doc/stable/reference/generated/numpy.quantile.html` | 0.115 | Low | Low | Low | none |
| M007 | docs_subdomain | `hxxps://learn[.]microsoft[.]com/en-us/dotnet/csharp/tour-of-csharp/` | 0.968 | High | Low | High | none |
| M008 | docs_subdomain | `hxxps://fastapi[.]tiangolo[.]com/tutorial/first-steps/` | 0.921 | High | Low | High | none |
| M009 | repo_path | `hxxps://github[.]com/scikit-learn/scikit-learn/blob/main/README.rst` | 0.301 | Medium | Low | Medium | none |
| M010 | repo_path | `hxxps://github[.]com/streamlit/streamlit/issues` | 0.301 | Medium | Low | Medium | none |
| M011 | repo_path | `hxxps://gitlab[.]com/gitlab-org/gitlab/-/issues` | 0.301 | Medium | Low | Medium | none |
| M012 | repo_path | `hxxps://bitbucket[.]org/atlassian/python-bitbucket/src/master/` | 0.119 | Low | Low | Low | none |
| M013 | login_redirect | `hxxps://github[.]com/login?return_to=https%3A%2F%2Fgithub.com%2Fsettings%2Fprofile` | 0.301 | Medium | Low | Medium | url_in_query (weak) long_or_encoded (weak) |
| M014 | login_redirect | `hxxps://login[.]microsoftonline[.]com/common/oauth2/v2.0/authorize?client_id=00000000-0000-0000-0000-000000000000&redirect_uri=https%3A%2F%2Fportal.azure.com` | 0.951 | High | Medium | High | url_in_query (weak) keywords (weak) long_or_encoded (weak) |
| M015 | login_redirect | `hxxps://www[.]reddit[.]com/login/?dest=https%3A%2F%2Fwww.reddit.com%2Fr%2Fpython%2F` | 0.285 | Medium | Low | Medium | url_in_query (weak) long_or_encoded (weak) |
| M016 | login_redirect | `hxxps://news[.]ycombinator[.]com/login?goto=news` | 0.948 | High | Low | High | none |
| M017 | login_redirect | `hxxps://discord[.]com/login?redirect_to=%2Fchannels%2F%40me` | 0.298 | Medium | Low | Medium | none |
| M018 | login_redirect | `hxxps://www[.]figma[.]com/login?next=%2Ffiles%2Frecent` | 0.305 | Medium | Low | Medium | none |
| M019 | login_redirect | `hxxps://id[.]atlassian[.]com/login?continue=https%3A%2F%2Fwww.atlassian.com%2F` | 0.891 | High | Low | High | url_in_query (weak) long_or_encoded (weak) |
| M020 | archive | `hxxps://web[.]archive[.]org/web/2020/hxxps://www[.]python[.]org/` | 0.816 | High | Low | High | archived_copy (info) |
| M021 | shortener | `hxxps://buff[.]ly/3Xk9PyDocs` | 0.752 | High | Low | High | shortener (info) |
| M022 | idn_single_script | `hxxps://www[.]bücher[.]de/` | 0.242 | Medium | Low | Medium | idn_host (weak) |
| M023 | idn_single_script | `hxxps://президент[.]рф/` | 0.315 | Medium | Low | Medium | idn_host (weak) |
| M024 | brand_in_path | `hxxps://github[.]com/paypal/paypal-js` | 0.301 | Medium | Low | Medium | brand_in_path (weak) |
| M025 | brand_in_path | `hxxps://www[.]npmjs[.]com/package/@paypal/react-paypal-js` | 0.305 | Medium | Low | Medium | brand_in_path (weak) |
| M026 | brand_in_path | `hxxps://pypi[.]org/project/google-cloud-storage/` | 0.067 | Low | Low | Low | brand_in_path (weak) |
| M027 | long_ordinary | `hxxps://www[.]nytimes[.]com/2024/05/01/technology/artificial-intelligence-regulation.html` | 0.303 | Medium | Low | Medium | none |
| M028 | long_ordinary | `hxxps://www[.]booking[.]com/hotel/nl/example-amsterdam.html?checkin=2025-06-01&checkout=2025-06-03&group_adults=2` | 0.307 | Medium | Low | Medium | long_or_encoded (weak) |
| M029 | long_ordinary | `hxxps://arxiv[.]org/abs/1706.03762` | 0.072 | Low | Low | Low | none |
| M030 | long_ordinary | `hxxps://www[.]youtube[.]com/watch?v=dQw4w9WgXcQ&list=PLFgquLnL59alCl_2TQvOiD5Vgm1hCaGSI` | 0.298 | Medium | Low | Medium | none |
| M031 | long_ordinary | `hxxps://support[.]apple[.]com/en-us/102208` | 0.965 | High | Low | High | none |
| M032 | long_ordinary | `hxxps://www[.]theguardian[.]com/technology/2024/jan/15/ai-chatbots-regulation-europe` | 0.259 | Medium | Low | Medium | none |

### Real phishing, independent (25) - URLs withheld

| ID | Category | Model score | ML-only | Rules-only | Hybrid | Fired rules |
|---|---|---|---|---|---|---|
| M044 | real_feed | 0.721 | High | Low | High | none |
| M045 | real_feed | 0.808 | High | Low | High | no_https (weak) long_or_encoded (weak) |
| M046 | real_feed | 0.696 | High | Low | High | none |
| M047 | real_feed | 0.485 | Medium | Low | Medium | none |
| M048 | real_feed | 0.83 | High | Low | High | none |
| M049 | real_feed | 0.789 | High | Low | High | none |
| M050 | real_feed | 0.223 | Low | Low | Low | none |
| M051 | real_feed | 0.382 | Medium | Low | Medium | no_https (weak) |
| M052 | real_feed | 0.721 | High | Low | High | none |
| M053 | real_feed | 0.86 | High | Low | High | brand_in_domain (weak) |
| M054 | real_feed | 0.527 | Medium | Low | Medium | long_or_encoded (weak) |
| M055 | real_feed | 0.182 | Low | Low | Low | no_https (weak) |
| M056 | real_feed | 0.485 | Medium | Low | Medium | none |
| M057 | real_feed | 0.281 | Medium | Low | Medium | no_https (weak) |
| M058 | real_feed | 0.863 | High | Low | High | none |
| M059 | real_feed | 0.854 | High | Low | High | none |
| M060 | real_feed | 0.152 | Low | Low | Low | none |
| M061 | real_feed | 0.439 | Medium | Low | Medium | none |
| M062 | real_feed | 0.709 | High | Low | High | none |
| M063 | real_feed | 0.699 | High | Low | High | none |
| M064 | real_feed | 0.182 | Low | Low | Low | none |
| M065 | real_feed | 0.76 | High | Low | High | brand_in_domain (weak) no_https (weak) |
| M066 | real_feed | 0.353 | Medium | Low | Medium | none |
| M067 | real_feed | 0.353 | Medium | Low | Medium | none |
| M068 | real_feed | 0.593 | High | Low | High | no_https (weak) |

### Synthetic phishing (11) - invented, caught by construction

| ID | Trick | URL (defanged, invented) | Model score | ML-only | Rules-only | Hybrid | Fired rules |
|---|---|---|---|---|---|---|---|
| M033 | syn_ip_host | `hxxp://203[.]0[.]113[.]45/secure-login/paypal/verify.php` | 0.993 | High | Medium | High | ip_host (strong) brand_in_path (weak) no_https (weak) keywords (weak) |
| M034 | syn_ip_host | `hxxp://3405803821/account/update/login` | 0.924 | High | Medium | High | ip_host (strong) no_https (weak) keywords (weak) |
| M035 | syn_at_trick | `hxxp://www[.]paypal[.]com@secure-verify-account-x7q2vn[.]top/login` | 0.913 | High | Medium | High | at_in_host (strong) no_https (weak) keywords (weak) |
| M036 | syn_brand_subdomain | `hxxps://paypal[.]com[.]resolution-center-k8m3vqz[.]xyz/signin?country=US` | 0.98 | High | Medium | High | brand_in_subdomain (strong) |
| M037 | syn_brand_subdomain | `hxxp://secure[.]chase[.]com[.]online-banking-verify-t6r2pk[.]info/login/verify-account` | 0.978 | High | Medium | High | brand_in_subdomain (strong) no_https (weak) keywords (weak) deep_subdomains (weak) |
| M038 | syn_lookalike | `hxxps://аpple-id-support-q3n8xv[.]com/signin` | 0.873 | High | Medium | High | lookalike_host (strong) keywords (weak) |
| M039 | syn_lookalike | `hxxps://xn--aypal-resolution-k7m2wq-k2s[.]com/webapps/signin` | 0.917 | High | Medium | High | lookalike_host (strong) deep_subdomains (weak) |
| M040 | syn_embedded_url | `hxxps://cdn-static-files-n2k7rq[.]site//secure-paypal-login-h5j9wd[.]top/verify` | 0.88 | High | Medium | High | embedded_url_in_path (strong) brand_in_path (weak) keywords (weak) |
| M041 | syn_embedded_url | `hxxps://redirect-gateway-z8p4qm[.]click/r/hxxps://appleid-verify-w3k6tb[.]top/` | 0.868 | High | Medium | High | embedded_url_in_path (strong) |
| M042 | syn_risky_extension | `hxxp://invoice-docs-share-m7v2xc[.]top/files/Invoice_2025_0193.zip` | 0.903 | High | Low | High | no_https (weak) risky_extension (weak) |
| M043 | syn_risky_extension | `hxxps://update-player-q9w2jd[.]xyz/download/PlayerUpdate.exe` | 0.896 | High | Low | High | risky_extension (weak) |
