"""M7 - user-facing presentation of a hybrid assessment (labels, colours, safe display).

Keeps all UI wording out of the frozen tier logic in src/hybrid.py. The app (app.py) only
renders what `build_view` returns. Nothing here logs, stores or transmits the URL.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import sklearn

from src.features import MAX_ANALYZE_LEN
from src.hybrid import assess

UI_LABELS = {
    "Low": "Low risk indicators",
    "Medium": "Inconclusive, check carefully",
    "High": "High risk indicators",
    "Unknown": "Can't analyze this input",
}
UI_SUMMARIES = {
    "High": ("Several signs commonly seen in phishing were found. Do not enter passwords or payment "
             "details unless you have verified the site another way."),
    "Medium": ("Some signs often seen in phishing were found, but many legitimate sites score here too. "
               "Check the address carefully before trusting it."),
    "Low": ("Few signs commonly seen in phishing were found. This does not mean the site is safe: about 5% "
            "of phishing URLs in the training data scored this low."),
    "Unknown": "This doesn't look like a web address PhishGuard can read. Enter a full address such as https://example.com.",
}
# Low is blue-grey on purpose: green would suggest "safe".
TIER_COLORS = {"Low": "#5b7083", "Medium": "#b7791f", "High": "#c53030", "Unknown": "#718096"}

MSG_MODEL_MISSING = ("The trained model is not available, so URLs can't be analyzed yet. "
                     "See \"Rebuild the model\" in README.md.")
MSG_MODEL_VERSION = ("The trained model was saved with a different scikit-learn version than the one installed, "
                     "so its results can't be trusted. Install the versions in requirements.txt or rebuild the "
                     "model (see \"Rebuild the model\" in README.md).")
MSG_MODEL_LOAD = "The trained model could not be loaded. See \"Rebuild the model\" in README.md."
MSG_ANALYSIS_FAILED = "Something went wrong while analyzing this input. Nothing was saved. Try a different address."

DISPLAY_MAX = 500  # characters of the input echoed back to the user


def load_model_safely(path: Path) -> tuple[dict | None, str | None]:
    """(bundle, None) on success, else (None, generic message). Never raises, never shows a traceback."""
    try:
        if not Path(path).exists():
            return None, MSG_MODEL_MISSING
        bundle = joblib.load(path)
        if bundle.get("sklearn") != sklearn.__version__:
            return None, MSG_MODEL_VERSION
        return bundle, None
    except Exception:
        return None, MSG_MODEL_LOAD


def defang(url: str) -> str:
    """Non-clickable display form: hxxp(s):// and [.] instead of dots."""
    s = url
    low = s.lower()
    if low.startswith("https"):
        s = "hxxps" + s[5:]
    elif low.startswith("http"):
        s = "hxxp" + s[4:]
    return s.replace(".", "[.]")


def md_escape(text: str) -> str:
    """Escape Markdown/HTML-significant characters so text renders literally."""
    out = []
    for ch in str(text):
        if ch in "\\`*_{}[]()#+-.!|<>~&:":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


@dataclass(frozen=True)
class View:
    tier: str
    label: str
    color: str
    summary: str
    score: float | None
    cut_points: dict
    escalation: str | None
    hits: tuple[tuple[str, str, str], ...]   # (name, strength, reason), strong first
    notes: tuple[str, ...]
    display_url: str                          # defanged, shortened; show with st.code only
    truncated_note: str | None
    error: str | None = None


def _display(url: str) -> str:
    d = defang(url)
    if len(d) > DISPLAY_MAX:
        d = d[:DISPLAY_MAX] + f" … ({len(d) - DISPLAY_MAX:,} more characters)"
    return d


def build_view(url: object, bundle: dict) -> View:
    """URL string -> extract_features -> model -> hybrid -> display data. Never raises."""
    text = url if isinstance(url, str) else ""
    stripped = text.strip()
    shown = _display(stripped)
    truncated = (f"Only the first {MAX_ANALYZE_LEN:,} characters were analyzed "
                 f"(the input has {len(stripped):,}).") if len(stripped) > MAX_ANALYZE_LEN else None
    try:
        a = assess(stripped, bundle=bundle)
    except Exception:
        return View(tier="Unknown", label=UI_LABELS["Unknown"], color=TIER_COLORS["Unknown"],
                    summary=UI_SUMMARIES["Unknown"], score=None, cut_points={}, escalation=None, hits=(),
                    notes=(), display_url=shown, truncated_note=truncated, error=MSG_ANALYSIS_FAILED)
    order = {"strong": 0, "weak": 1, "info": 2}
    hits = tuple((h.name, h.strength, h.reason) for h in sorted(a.rule_hits, key=lambda h: order[h.strength]))
    escalation = a.escalation
    if escalation:  # use the UI names of the tiers in the explanation
        for tier, label in UI_LABELS.items():
            escalation = escalation.replace(f" {tier} ", f" {label} ").replace(f" {tier}:", f" {label}:")
    return View(tier=a.tier, label=UI_LABELS[a.tier], color=TIER_COLORS[a.tier], summary=UI_SUMMARIES[a.tier],
                score=a.ml_score, cut_points=a.cut_points, escalation=escalation, hits=hits, notes=a.notes,
                display_url=shown, truncated_note=truncated)
