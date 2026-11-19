"""M7 app tests: end-to-end analysis path, Streamlit AppTest, model-loading failures, privacy checks."""
from pathlib import Path

import joblib
import pytest
import sklearn

from src.model import MODEL_PATH
from src.presentation import (MSG_MODEL_LOAD, MSG_MODEL_MISSING, MSG_MODEL_VERSION, TIER_COLORS, UI_LABELS,
                              UI_SUMMARIES, build_view, defang, load_model_safely, md_escape)

ROOT = Path(__file__).resolve().parents[1]
APP = str(ROOT / "app.py")
BUNDLE, LOAD_ERR = load_model_safely(MODEL_PATH)
needs_model = pytest.mark.skipif(BUNDLE is None, reason=f"model unavailable: {LOAD_ERR}")


# ------------------------------------------------------------------ labels / wording

def test_ui_labels_exact():
    assert UI_LABELS == {"Low": "Low risk indicators", "Medium": "Inconclusive, check carefully",
                         "High": "High risk indicators", "Unknown": "Can't analyze this input"}


def test_no_safe_or_confirmed_wording():
    for t in list(UI_LABELS.values()) + list(UI_SUMMARIES.values()):
        low = t.lower().replace("does not mean the site is safe", "")
        assert "safe" not in low and "confirmed" not in low


def test_low_is_not_green():
    assert TIER_COLORS["Low"] == "#5b7083"


def test_defang_and_escape():
    assert defang("https://evil.example/a.php") == "hxxps://evil[.]example/a[.]php"
    assert defang("HTTP://x.y") == "hxxp://x[.]y"
    assert md_escape("<script>[x](javascript:y)") == "\\<script\\>\\[x\\]\\(javascript\\:y\\)"


# ------------------------------------------------------------------ model loading failures (no crash)

def test_missing_model_message(tmp_path):
    bundle, err = load_model_safely(tmp_path / "nope.joblib")
    assert bundle is None and err == MSG_MODEL_MISSING and "README" in err


def test_version_mismatch_message(tmp_path):
    p = tmp_path / "old.joblib"
    joblib.dump({"sklearn": "0.0.1", "pipeline": None}, p)
    bundle, err = load_model_safely(p)
    assert bundle is None and err == MSG_MODEL_VERSION and "README" in err


def test_corrupt_model_message(tmp_path):
    p = tmp_path / "bad.joblib"
    p.write_bytes(b"not a joblib file")
    assert load_model_safely(p) == (None, MSG_MODEL_LOAD)


# ------------------------------------------------------------------ end-to-end smoke: URL -> features -> model -> hybrid -> view

E2E = ["https://www.example.com", "http://paypal.com.account-verify.example/login", "http://192.0.2.10/secure/update",
       "https://docs.example.org/guide", "", "   ", "not a url", "http://[::1", "http://[2001:db8::1]/admin",
       "javascript:alert(1)", "<script>alert(1)</script>", "http://xn--pypal-4ve.com/", "https://e.com/" + "z" * 10_000]


@needs_model
@pytest.mark.parametrize("url", E2E)
def test_end_to_end_view(url):
    v = build_view(url, BUNDLE)
    assert v.label == UI_LABELS[v.tier] and v.summary == UI_SUMMARIES[v.tier]
    assert v.error is None
    if v.tier == "Unknown":
        assert v.score is None
    else:
        assert 0.0 <= v.score <= 1.0
    assert "http://" not in v.display_url and "https://" not in v.display_url  # defanged
    assert len(v.display_url) < 600


@needs_model
def test_long_input_truncation_note():
    v = build_view("https://e.com/" + "z" * 10_000, BUNDLE)
    assert v.truncated_note and "4,096" in v.truncated_note


def test_analysis_error_is_generic():
    class Broken:
        def predict_proba(self, X):
            raise RuntimeError("secret internal detail http://user-url.example")
    from src.model import MODEL_COLUMNS
    v = build_view("https://www.example.com", {"pipeline": Broken(), "feature_columns": MODEL_COLUMNS})
    assert v.error and "user-url" not in v.error and "secret" not in v.error


# ------------------------------------------------------------------ source checks (privacy)

@pytest.mark.parametrize("path", ["app.py", "src/presentation.py", "src/hybrid.py", "src/rules.py", "src/features.py"])
def test_no_url_logging_or_data_cache(path):
    src = (ROOT / path).read_text(encoding="utf-8")
    assert "cache_data" not in src
    assert "import logging" not in src and "logging." not in src
    if path != "src/rules.py":  # rules.py prints only in its train-set CLI report
        assert "print(" not in src or path in ("src/hybrid.py",)


def test_app_caches_only_model():
    src = (ROOT / "app.py").read_text(encoding="utf-8")
    assert src.count("@st.cache_resource") == 1 and "def get_model" in src


# ------------------------------------------------------------------ Streamlit AppTest

AppTest = pytest.importorskip("streamlit.testing.v1").AppTest


def run_app(monkeypatch, model_path=None):
    if model_path is not None:
        monkeypatch.setenv("PHISHGUARD_MODEL_PATH", str(model_path))
    else:
        monkeypatch.delenv("PHISHGUARD_MODEL_PATH", raising=False)
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    return at


def analyze(at, text):
    at.text_input(key="url_input").input(text)
    next(b for b in at.button if b.label == "Analyze").click()
    at.run()
    return at


def all_markdown(at):
    return [m.value for m in at.markdown] + [c.value for c in at.caption]


def test_app_missing_model_shows_message(monkeypatch, tmp_path):
    at = run_app(monkeypatch, tmp_path / "missing.joblib")
    assert not at.exception
    assert any(MSG_MODEL_MISSING == e.value for e in at.error)
    assert any("Limitations" in w.value for w in at.warning)


def test_app_version_mismatch_shows_message(monkeypatch, tmp_path):
    p = tmp_path / "old.joblib"
    joblib.dump({"sklearn": "0.0.1"}, p)
    at = run_app(monkeypatch, p)
    assert not at.exception
    assert any(MSG_MODEL_VERSION == e.value for e in at.error)


@needs_model
def test_app_limitations_box_and_examples(monkeypatch):
    at = run_app(monkeypatch)
    assert not at.exception
    w = " ".join(x.value for x in at.warning)
    assert "never visits the site" in w and "not a guarantee" in w
    assert {"Plain homepage", "Brand in subdomain", "IP address host", "Subdomain"} <= {b.label for b in at.button}


@needs_model
def test_app_analyze_normal_url(monkeypatch):
    at = analyze(run_app(monkeypatch), "http://paypal.com.account-verify.example/login")
    assert not at.exception
    md = " ".join(all_markdown(at))
    assert any(label in md for label in UI_LABELS.values())
    assert "Model score" in [m.label for m in at.metric]
    assert "%" not in at.metric[0].value
    assert "brand_in_subdomain" in md
    assert at.code[0].value == defang("http://paypal.com.account-verify.example/login")
    assert at.info  # notes shown


@needs_model
def test_app_example_button(monkeypatch):
    at = run_app(monkeypatch)
    next(b for b in at.button if b.label == "IP address host").click()
    at.run()
    assert not at.exception
    assert "ip_host" in " ".join(all_markdown(at))


@needs_model
@pytest.mark.parametrize("text", ["", "   "])
def test_app_empty_input(monkeypatch, text):
    at = analyze(run_app(monkeypatch), text)
    assert not at.exception
    assert any(UI_LABELS["Unknown"] in m for m in all_markdown(at))


@needs_model
def test_app_very_long_input(monkeypatch):
    long_url = "https://example.com/" + "z" * 8000
    at = analyze(run_app(monkeypatch), long_url)
    assert not at.exception
    assert any("were analyzed" in c.value for c in at.caption)
    assert len(at.code[0].value) < 600


@needs_model
@pytest.mark.parametrize("text", [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<b>bold</b>[click](javascript:alert(1))",
    "javascript:alert(document.cookie)",
    "JAVASCRIPT:alert(1)//http://example.com",
])
def test_app_html_and_javascript_render_as_plain_text(monkeypatch, text):
    at = analyze(run_app(monkeypatch), text)
    assert not at.exception
    assert at.code[0].value == defang(text)        # shown verbatim (defanged) in a code block
    for m in all_markdown(at):                       # never injected into Markdown/HTML
        assert text not in m
        assert "<script" not in m and "onerror" not in m and "javascript:" not in m.lower()
