"""PhishGuard - Streamlit app (M7).

Run:  streamlit run app.py

Privacy: the URL is analyzed in memory only. It is never fetched, logged, cached or stored.
Only the trained model is cached (st.cache_resource). The URL is never inserted into HTML or
Markdown: it is shown defanged inside st.code, and rule reasons are escaped.
"""
from __future__ import annotations

import html
import os
from pathlib import Path

import streamlit as st

from src.model import MODEL_PATH
from src.presentation import build_view, load_model_safely, md_escape

EXAMPLES = {  # reserved example domains (RFC 2606 / RFC 5737); not real sites
    "Plain homepage": "https://www.example.com",
    "Brand in subdomain": "http://paypal.com.account-verify.example/login",
    "IP address host": "http://192.0.2.10/secure/update",
    "Subdomain": "https://docs.example.org/guide",
}
STRENGTH_TEXT = {"strong": "Strong indicator", "weak": "Weak indicator", "info": "Information"}


@st.cache_resource(show_spinner=False)
def get_model(path: str):
    """Load the model once per path. Caches the model only - never any input."""
    return load_model_safely(Path(path))


def _use_example(url: str) -> None:
    st.session_state["url_input"] = url
    st.session_state["run_now"] = True


def render_result(view) -> None:
    st.markdown(
        f'<div style="display:inline-block;padding:0.45rem 0.9rem;border-radius:0.4rem;'
        f'background:{view.color};color:#ffffff;font-weight:600;font-size:1.15rem">{html.escape(view.label, quote=False)}</div>',
        unsafe_allow_html=True,  # fixed label text only; never user input
    )
    st.write(view.summary)
    if view.error:
        st.error(view.error)

    st.caption("Analyzed address (shown defanged so it is not clickable)")
    st.code(view.display_url, language=None)
    if view.truncated_note:
        st.caption(view.truncated_note)

    if view.score is not None:
        c1, c2 = st.columns([1, 2])
        c1.metric("Model score", f"{view.score:.3f}",
                  help="Score from 0 to 1 based on the hostname only. It is not a probability.")
        c2.caption(f"Model score (0–1, hostname only). Below {view.cut_points['low']:.3f} the model alone gives "
                   f"low risk indicators; {view.cut_points['high']:.3f} and above it gives high risk indicators. "
                   "Rules can raise the result, never lower it.")
    if view.escalation:
        st.markdown(md_escape(view.escalation))

    st.subheader("Rule indicators")
    if not view.hits:
        st.write("No rule indicators found.")
    for name, strength, reason in view.hits:
        st.markdown(f"**{STRENGTH_TEXT[strength]}** · `{name}`  \n{md_escape(reason)}")

    if view.notes:
        st.subheader("Notes")
        for note in view.notes:
            st.info(note)


def main() -> None:
    st.set_page_config(page_title="PhishGuard", layout="centered")
    st.title("PhishGuard")
    st.caption("Hybrid phishing URL checker: rule indicators plus a machine-learning model score.")
    st.warning(
        "**Limitations.** PhishGuard only reads the text of the address you enter. It never visits the site, "
        "never sends the address anywhere and does not save it. Results are risk indicators, not a guarantee: "
        "a site can be dangerous even with low indicators, and legitimate sites can show high ones."
    )

    bundle, model_error = get_model(os.environ.get("PHISHGUARD_MODEL_PATH", str(MODEL_PATH)))
    if model_error:
        st.error(model_error)
        st.stop()

    st.caption("Try an example (reserved example domains, not real sites):")
    cols = st.columns(len(EXAMPLES))
    for col, (label, url) in zip(cols, EXAMPLES.items()):
        col.button(label, on_click=_use_example, args=(url,), width="stretch")

    with st.form("analyze"):
        url = st.text_input("Web address to analyze", key="url_input", max_chars=8192,
                            placeholder="https://example.com/login")
        submitted = st.form_submit_button("Analyze", type="primary")

    if submitted or st.session_state.pop("run_now", False):
        render_result(build_view(st.session_state.get("url_input", url), bundle))

    with st.expander("How this works"):
        st.markdown(
            "1. The address is split into parts (host, path, query) without contacting it.\n"
            "2. A Random Forest scores the **hostname** and sets a starting level.\n"
            "3. Rules check the whole address for tricks such as IP-address hosts, `@` signs, look-alike "
            "letters, brand names in subdomains and hidden redirects.\n"
            "4. Rules can raise the level, never lower it.\n\n"
            "See README.md for the method, the evaluation and its limits."
        )


main()
