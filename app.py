"""RepoGuard AI — Streamlit entry point.

Run:  streamlit run app.py
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from repoguard.config import settings
from repoguard.models import Finding, Severity
from repoguard.notifier import DNotifierBridge
from repoguard.patcher import get_engine
from repoguard.scanner import scan

# ---------------------------------------------------------------------------
# Page setup
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="RepoGuard AI",
    page_icon="🛡️",
    layout="wide",
)

SEVERITY_COLORS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}
SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}
# Hex palette for the findings table (pandas Styler)
SEVERITY_HEX = {
    "CRITICAL": "#ff4b4b",
    "HIGH": "#ff8c42",
    "MEDIUM": "#ffd11a",
    "LOW": "#4da3ff",
    "INFO": "#9aa5b1",
}

# Tasteful hero banner + metric polish
st.markdown(
    """
    <style>
    .hero {
        background: linear-gradient(135deg, #0f2027 0%, #203a43 55%, #2c5364 100%);
        padding: 20px 26px; border-radius: 14px; margin-bottom: 6px;
        border: 1px solid #31465a;
    }
    .hero h1 { color: #ffffff; margin: 0; font-size: 1.7rem; letter-spacing: .3px; }
    .hero p  { color: #cfe3f0; margin: 6px 0 0 0; font-size: .95rem; }
    div[data-testid="stMetricValue"] { font-size: 1.7rem; }
    </style>
    <div class="hero">
        <h1>🛡️ RepoGuard AI</h1>
        <p>Autonomous Vulnerability &amp; Patch Agent — The Scout, The Explainer, The Messenger.</p>
    </div>
    """,
    unsafe_allow_html=True,
)


@st.cache_resource
def get_bridge() -> DNotifierBridge:
    """One shared DNotifier bridge per app session."""
    return DNotifierBridge()


def _severity_table(df: pd.DataFrame) -> pd.DataFrame:
    """Return a pandas Styler that colour-codes the Severity column."""

    def _paint(row):
        color = SEVERITY_HEX.get(str(row["Severity"]), "#888888")
        return [
            f"color: {color}; font-weight: 700" if col == "Severity" else ""
            for col in row.index
        ]

    return df.style.apply(_paint, axis=1)


# ---------------------------------------------------------------------------
# Sidebar — engine + credentials status
# ---------------------------------------------------------------------------
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.title("RepoGuard AI")
    st.caption("Autonomous Vulnerability & Patch Agent")

    engine_choice = st.radio(
        "AI Engine",
        ["dnotifier", "openai", "offline"],
        format_func={
            "dnotifier": "🤖 DNotifier AI (RAG)",
            "openai": "🌐 OpenAI-compatible",
            "offline": "📐 Offline rules only",
        }.__getitem__,
        help="DNotifier AI uses the sponsor pipeline + OWASP knowledge base.",
    )

    st.divider()
    st.subheader("Status")
    st.write(
        "DNotifier:",
        "✅ configured" if settings.dnotifier_ready else "❌ missing .env values",
    )
    st.write(
        "Fallback AI:",
        f"✅ {settings.openai_model}" if settings.openai_ready else "⚪ not set",
    )
    st.caption(f"Receiver: {settings.dnotifier_receiver_id}")

    if st.button("📚 Seed OWASP knowledge base", use_container_width=True):
        status = get_bridge().seed_knowledge_base()
        (st.success if status.ok else st.warning)(status.detail)

# ---------------------------------------------------------------------------
# Main area
# ---------------------------------------------------------------------------
tab_scan, tab_ask = st.tabs(["🔍 Scan & Patch", "💬 Ask DNotifier AI"])

with tab_scan:
    st.markdown(
        "**Paste a Python/JS snippet or upload a file.** The Scout finds "
        "vulnerabilities; the Auto-Patch Engineer proposes a secure fix "
        "(human review required before applying)."
    )

    uploaded = st.file_uploader("Upload .py / .js file", type=["py", "js", "txt"])
    default_code = ""
    if uploaded is not None:
        # OWASP: decode as text with replacement — never execute uploads.
        default_code = uploaded.getvalue().decode("utf-8", errors="replace")

    code = st.text_area(
        "Source code",
        value=default_code,
        height=320,
        placeholder="Paste code here…",
        label_visibility="collapsed",
    )

    if st.button("🚀 Scan", type="primary"):
        if not code.strip():
            st.warning("Nothing to scan — paste or upload some code first.")
        else:
            with st.spinner("Scanning…"):
                result = scan(code)
            st.session_state["scan_result"] = result
            st.session_state["source_code"] = code
            # A new scan invalidates any stale patch/brief from the old one.
            for key in list(st.session_state.keys()):
                if key.startswith(("patch_result_", "ai_brief")):
                    del st.session_state[key]

    # ---- Results ----------------------------------------------------------
    result = st.session_state.get("scan_result")
    if result:
        counts = {sev.value: 0 for sev in Severity}
        for f in result.findings:
            counts[f.severity.value] += 1

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Security score", f"{result.security_score}/100")
        c2.metric("Findings", len(result.findings))
        c3.metric(
            "Critical / High",
            f"{counts['CRITICAL']} / {counts['HIGH']}",
        )
        c4.metric("Language", result.language.value.upper())
        st.caption(f"Lines scanned: {result.total_lines}")
        if result.truncated:
            st.warning("Input was truncated to the configured size guardrail.")

        if not result.findings:
            st.success("✅ No known vulnerability patterns detected in this snippet.")
            st.caption(
                "Note: static heuristics cannot prove absence of bugs — treat a "
                "clean scan as 'no obvious issues', not a guarantee."
            )
        else:
            # ---- Severity chart + findings table ---------------------------
            st.subheader("Overview")
            col_chart, col_table = st.columns([1, 2])

            with col_chart:
                chart_df = pd.DataFrame(
                    {
                        "Severity": list(counts.keys()),
                        "Count": list(counts.values()),
                    }
                ).set_index("Severity")
                st.bar_chart(chart_df, height=260)

            with col_table:
                table_df = pd.DataFrame(
                    [
                        {
                            "Severity": f.severity.value,
                            "Rule": f.rule_id,
                            "Title": f.title,
                            "Line": f.line_no,
                            "OWASP": f.owasp,
                        }
                        for f in result.findings
                    ]
                )
                st.dataframe(
                    _severity_table(table_df),
                    use_container_width=True,
                    hide_index=True,
                    height=260,
                )

            # ---- Per-finding cards (worst first) ---------------------------
            st.subheader("Findings")
            ordered = sorted(result.findings, key=lambda f: SEVERITY_RANK[f.severity])
            for i, finding in enumerate(ordered):
                color = SEVERITY_COLORS[finding.severity]
                with st.expander(
                    f"{color} {finding.severity.value} · {finding.rule_id} — "
                    f"{finding.title} (line {finding.line_no})"
                ):
                    st.markdown(f"**Why dangerous:** {finding.description}")
                    st.markdown(f"**OWASP:** {finding.owasp}")
                    st.code(finding.code, language="python")

                    if st.button("🩹 Generate secure patch", key=f"genpatch_{i}"):
                        engine = get_engine(engine_choice)
                        with st.spinner(f"Generating patch via {engine.name}…"):
                            try:
                                patch = engine.generate(
                                    finding, st.session_state["source_code"]
                                )
                                # NOTE: key must NOT collide with a widget key —
                                # Streamlit reserves widget-key namespaces.
                                st.session_state[f"patch_result_{i}"] = patch
                            except Exception as exc:  # demo-day insurance
                                st.error(f"Patch generation failed: {exc}")

                # Patch result renders OUTSIDE the expander: Streamlit collapses
                # expanders on rerun (e.g. after the button click), which would
                # otherwise hide the freshly generated patch from the user.
                patch = st.session_state.get(f"patch_result_{i}")
                if patch is not None and hasattr(patch, "engine"):
                    st.info(
                        f"🩹 Patch for {finding.rule_id} — generated via *{patch.engine}*"
                    )
                    st.markdown("**Explanation**")
                    st.write(patch.explanation)
                    if getattr(patch, "attack_scenario", ""):
                        st.markdown("**Attack scenario**")
                        st.write(patch.attack_scenario)
                    if patch.patched_code:
                        st.markdown("**Patched code**")
                        st.code(patch.patched_code, language="python")
                    if patch.diff:
                        st.markdown("**Unified diff**")
                        st.code(patch.diff, language="diff")
                    if getattr(patch, "verify_steps", ""):
                        st.markdown("**How to verify**")
                        st.write(patch.verify_steps)
                    st.caption(
                        "⚠️ Review every AI suggestion before committing — "
                        "human-in-the-loop by design."
                    )

        # ---- AI executive brief + notify -----------------------------------
        st.divider()
        st.subheader("🤖 AI Security Brief")
        st.caption(
            "One-screen prioritised summary for the whole scan — "
            "generated through the DNotifier AI pipeline."
        )
        if st.button("Generate executive summary", key="btn_brief"):
            with st.spinner("Asking DNotifier AI for a brief…"):
                st.session_state["ai_brief"] = get_bridge().security_brief(result)
        if st.session_state.get("ai_brief"):
            st.markdown(st.session_state["ai_brief"])

        st.divider()
        if st.button("🔔 Notify team via DNotifier"):
            status = get_bridge().notify_scan(result)
            (st.success if status.ok else st.warning)(status.detail)

with tab_ask:
    st.markdown(
        "Ask anything about secure-coding — answers are grounded in the "
        "OWASP cheat-sheet seeded into the DNotifier knowledge base."
    )
    question = st.text_input(
        "Question",
        placeholder="e.g. How should I safely hash passwords in Python?",
    )
    if st.button("Ask", type="primary") and question.strip():
        with st.spinner("Thinking…"):
            answer = get_bridge().ask(question)
        st.write(answer)
