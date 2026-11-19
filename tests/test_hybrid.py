"""M6 hybrid tests: tier logic, cut-points, notes, unknown inputs, no logging."""
import itertools
import logging

import numpy as np
import pytest

from src import hybrid
from src.hybrid import (NOTE_HOSTNAME_ONLY, NOTE_SHORTENER, NOTE_SUBDOMAIN, SUMMARIES, TIER_LABELS,
                        TIERS, assess, base_tier, escalate, load_config)
from src.model import MODEL_COLUMNS, MODEL_PATH

CFG = load_config()
LOW, HIGH = CFG["cut_points"]["low"], CFG["cut_points"]["high"]


class FixedScore:
    """Stand-in pipeline that returns a fixed score, to test tiers without the trained model."""
    def __init__(self, score):
        self.score = score

    def predict_proba(self, X):
        return np.array([[1 - self.score, self.score]] * len(X))


def bundle(score):
    return {"pipeline": FixedScore(score), "feature_columns": MODEL_COLUMNS, "version": "test"}


# ------------------------------------------------------------------ config

def test_config_valid_and_documented():
    assert 0 < LOW < HIGH < 1
    for key in ("data", "data_sha256", "high", "low", "tiers", "escalation", "prevalence_caveat"):
        assert key in CFG["method"]
    assert "running minimum" in CFG["method"]["high"]
    assert CFG["train_oof_check"]["precision_at_high"] >= 0.95
    assert abs(CFG["train_oof_check"]["phishing_share_below_low"] - 0.05) < 0.01


# ------------------------------------------------------------------ base tier boundaries

def test_base_tier_boundaries():
    assert base_tier(HIGH, LOW, HIGH) == "High"
    assert base_tier(np.nextafter(HIGH, 0), LOW, HIGH) == "Medium"
    assert base_tier(LOW, LOW, HIGH) == "Medium"
    assert base_tier(np.nextafter(LOW, 0), LOW, HIGH) == "Low"
    assert base_tier(0.0, LOW, HIGH) == "Low" and base_tier(1.0, LOW, HIGH) == "High"


# ------------------------------------------------------------------ escalation: exhaustive

@pytest.mark.parametrize("base,strong,weak", list(itertools.product(TIERS, range(4), range(5))))
def test_rules_never_lower_and_follow_spec(base, strong, weak):
    tier, why = escalate(base, strong, weak)
    i, j = TIERS.index(base), TIERS.index(tier)
    assert j >= i, "rules must never lower the tier"
    expected = i
    if strong >= 2:
        expected = 2
    elif strong == 1:
        expected = min(i + 1, 2)
    if weak >= 3 and expected == 0:
        expected = 1
    assert j == max(i, expected)
    assert (why is None) == (j == i)


@pytest.mark.parametrize("weak", range(0, 10))
def test_weak_rules_alone_never_give_high(weak):
    assert escalate("Low", 0, weak)[0] != "High"
    assert escalate("Medium", 0, weak)[0] == "Medium"


def test_escalation_message():
    tier, why = escalate("Low", 1, 3)
    assert tier == "Medium" and why.startswith("Raised from Low to Medium")


# ------------------------------------------------------------------ assess() with a fixed score

URLS = ["https://www.example.com", "http://paypal.com.secure-login.ru/verify/account", "http://192.168.0.1/login",
        "https://docs.python.org/3/", "https://bit.ly/3abc", "http://a.b.c.d.example.com:8080/login/verify/account%20%41%42%43",
        "https://github.com/paypal/repo", "http://xn--pypal-4ve.com/"]


@pytest.mark.parametrize("url", URLS)
@pytest.mark.parametrize("score", [0.0, (LOW + HIGH) / 2, 0.99])
def test_assess_final_tier_never_below_ml_tier(url, score):
    a = assess(url, bundle=bundle(score))
    assert a.base_tier == base_tier(score, LOW, HIGH)
    assert TIERS.index(a.tier) >= TIERS.index(a.base_tier)
    assert a.tier_label == TIER_LABELS[a.tier] and a.summary == SUMMARIES[a.tier]
    assert a.cut_points == {"low": LOW, "high": HIGH}


def test_two_strong_rules_give_high_even_with_low_score():
    a = assess("http://paypal.com@192.168.0.1/", bundle=bundle(0.0))  # at_in_host + ip_host
    assert a.strong_hits >= 2 and a.tier == "High" and a.base_tier == "Low"


@pytest.mark.parametrize("url", ["", "   ", None, 42, "http://[::1", "http://", "https://example.com:99999/"])
def test_unknown_for_unparseable(url):
    a = assess(url, bundle=bundle(0.99))
    assert a.tier == "Unknown" and a.ml_score is None and a.base_tier is None
    assert a.tier_label == "Cannot analyze"


# ------------------------------------------------------------------ notes and wording

def test_notes():
    plain = assess("https://www.example.com", bundle=bundle(0.1))
    assert plain.notes == (NOTE_HOSTNAME_ONLY,)
    sub = assess("https://docs.python.org/3/", bundle=bundle(0.1))
    assert NOTE_SUBDOMAIN in sub.notes and NOTE_SHORTENER not in sub.notes
    short = assess("https://bit.ly/3abc", bundle=bundle(0.1))
    assert NOTE_SHORTENER in short.notes and NOTE_SUBDOMAIN not in short.notes
    assert NOTE_SUBDOMAIN in assess("https://mail.example.co.uk", bundle=bundle(0.1)).notes
    assert NOTE_SUBDOMAIN not in assess("https://www.example.co.uk", bundle=bundle(0.1)).notes  # www. excluded


def test_exact_note_text():
    assert "may be inflated for subdomains" in NOTE_SUBDOMAIN
    assert NOTE_HOSTNAME_ONLY.startswith("The model score is based on the hostname only")
    assert "never does" in NOTE_SHORTENER


def test_never_called_safe():
    for tier, label in TIER_LABELS.items():
        assert "safe" not in label.lower()
    for tier, text in SUMMARIES.items():
        if tier == "Low":
            assert "does not mean the site is safe" in text
        else:
            assert "safe" not in text.lower()
    assert TIER_LABELS["Low"] == "Low risk indicators"


# ------------------------------------------------------------------ privacy / model choice

def test_no_logging_during_assessment(caplog):
    with caplog.at_level(logging.DEBUG):
        assess("http://paypal.com.secure-login.ru/verify?u=secret-user@example.com", bundle=bundle(0.5))
    assert caplog.records == []


def test_logistic_regression_not_loaded(monkeypatch):
    import joblib
    loaded = []
    real = joblib.load
    monkeypatch.setattr(joblib, "load", lambda p, *a, **k: loaded.append(str(p)) or real(p, *a, **k))
    hybrid._model_bundle.cache_clear()
    if MODEL_PATH.exists():
        assess("https://www.example.com")
        assert loaded and all("baselines" not in p for p in loaded)
    hybrid._model_bundle.cache_clear()


@pytest.mark.skipif(not MODEL_PATH.exists(), reason="trained model not present")
@pytest.mark.parametrize("url", URLS + ["", "https://www.wikipedia.org"])
def test_real_model_end_to_end(url):
    a = assess(url)
    if a.tier != "Unknown":
        assert 0.0 <= a.ml_score <= 1.0 and a.model_version == "rf-host-v1"
        assert TIERS.index(a.tier) >= TIERS.index(a.base_tier)
