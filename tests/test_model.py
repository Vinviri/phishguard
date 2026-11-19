"""End-to-end smoke tests: raw URL string -> extract_features -> model -> probability."""
import numpy as np
import pytest

from src.features import HOST_FEATURES
from src.model import (MODEL_COLUMNS, MODEL_PATH, build_rf, features_frame,
                       load_model, predict_url, rf_contributions)

LEGIT = ["https://www.example.com", "https://www.wikipedia.org", "https://www.python.org",
         "https://www.bbc.co.uk", "https://www.github.com", "https://www.cinematheque.fr"] * 5
PHISH = ["http://secure-login-paypal.verify-account.xyz", "http://192.168.0.1",
         "https://a1b2c3d4.web.app", "http://xn--pypal-4ve.com", "http://update.bank-verify.top",
         "http://login.microsoft.com.evil-1234.ru"] * 5
ODD_INPUTS = ["", "   ", "not a url", "http://[::1]:8080/x", "http://[::1", "example.com",
              "http://a.com:99999", "x" * 50_000, "https://www.example.com/path?q=1"]


@pytest.fixture(scope="module")
def tiny_bundle():
    X = features_frame(LEGIT + PHISH, MODEL_COLUMNS)
    y = np.array([0] * len(LEGIT) + [1] * len(PHISH))
    pipe = build_rf(n_estimators=10).fit(X, y)
    return {"pipeline": pipe, "feature_columns": MODEL_COLUMNS, "threshold": 0.5}


def test_model_columns_are_host_features():
    assert MODEL_COLUMNS == list(HOST_FEATURES)


@pytest.mark.parametrize("url", ODD_INPUTS + LEGIT[:3] + PHISH[:3])
def test_tiny_model_end_to_end(tiny_bundle, url):
    r = predict_url(tiny_bundle, url)
    assert 0.0 <= r["phishing_probability"] <= 1.0
    assert r["above_threshold"] == (r["phishing_probability"] >= 0.5)


def test_contributions_sum_to_probability(tiny_bundle):
    X = features_frame(PHISH[:3] + LEGIT[:3], MODEL_COLUMNS)
    contrib, bias, names = rf_contributions(tiny_bundle["pipeline"], X)
    proba = tiny_bundle["pipeline"].predict_proba(X)[:, 1]
    assert np.allclose(bias + contrib.sum(axis=1), proba)
    assert names[-1] == "tld"


@pytest.mark.skipif(not MODEL_PATH.exists(), reason="trained model not present (run python -m src.model train)")
def test_saved_model_end_to_end():
    bundle = load_model()
    assert bundle["feature_columns"] == MODEL_COLUMNS
    assert 0.0 < bundle["threshold"] < 1.0
    for key in ("version", "sklearn", "trained_at_utc", "dataset_sha256", "params"):
        assert key in bundle
    for url in ODD_INPUTS + ["https://www.wikipedia.org", "http://secure-paypal-login.verify-acc.xyz"]:
        r = predict_url(bundle, url)
        assert 0.0 <= r["phishing_probability"] <= 1.0
