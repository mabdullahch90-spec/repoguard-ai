"""RepoGuard AI — visual theme (the "sexy GUI" layer).

Pure CSS + HTML injected through ``st.markdown`` — zero extra dependencies,
so the Streamlit Community Cloud build stays fast and deterministic.

Contents
--------
``THEME_CSS``   global stylesheet (dark cyber-security look, neon accents,
                glassmorphism cards, glow buttons, terminal-style code input)
``inject()``    call once, right after ``st.set_page_config``
``hero()``      animated top banner with gradient title + capability chips
``how_it_works()`` three glass cards explaining the engine pipeline
``kpi_row()``   the four result KPI cards (score is colour-banded)
``severity_bars()`` horizontal severity breakdown (replaces the default chart)
``pills()``     severity / OWASP / line chips used inside finding cards
``footer()``    branded footer

All markup is static or built from numbers/whitelisted enums — user code is
never interpolated into HTML (XSS-safe by construction).
"""

from __future__ import annotations

from typing import Mapping

import streamlit as st

# ---------------------------------------------------------------------------
# Global stylesheet
# ---------------------------------------------------------------------------
THEME_CSS = """
<style>
/* ---------- Fonts ------------------------------------------------------- */
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

/* ---------- App canvas: deep navy + neon glows + faint grid ------------- */
.stApp {
    background:
        radial-gradient(1100px 560px at 85% -8%, rgba(0,255,168,.10), transparent 60%),
        radial-gradient(900px 520px at -12% 18%, rgba(0,208,255,.10), transparent 55%),
        repeating-linear-gradient(0deg, rgba(255,255,255,.022) 0 1px, transparent 1px 44px),
        repeating-linear-gradient(90deg, rgba(255,255,255,.022) 0 1px, transparent 1px 44px),
        linear-gradient(180deg, #070b14 0%, #0a1122 55%, #070b14 100%) !important;
    background-attachment: fixed;
    font-family: 'Space Grotesk', sans-serif;
}
html, body, [class*="css"], .stApp { font-family: 'Space Grotesk', sans-serif; }

/* Headings */
h1, h2, h3, h4, [data-testid="stHeading"] div {
    font-family: 'Space Grotesk', sans-serif !important;
    letter-spacing: .2px;
}

/* Kill default Streamlit gutters feel */
.block-container { padding-top: 1.4rem !important; }

/* ---------- Selection / scrollbar -------------------------------------- */
::selection { background: rgba(0,255,168,.28); color: #fff; }
::-webkit-scrollbar { width: 10px; height: 10px; }
::-webkit-scrollbar-track { background: #0a0f1c; }
::-webkit-scrollbar-thumb { background: #1d2b45; border-radius: 8px; }
::-webkit-scrollbar-thumb:hover { background: #2a3f66; }

/* ---------- Top bar ----------------------------------------------------- */
header[data-testid="stHeader"] { background: transparent; }
[data-testid="stDecoration"] { opacity: .35; }
footer, [data-testid="stFooter"] { display: none !important; }
[data-testid="stStatusWidget"] { opacity: .55; }

/* ---------- Sidebar ----------------------------------------------------- */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0b1324 0%, #080d1a 100%) !important;
    border-right: 1px solid rgba(0,255,168,.16);
    box-shadow: 6px 0 30px rgba(0,0,0,.35);
}
section[data-testid="stSidebar"] [data-testid="stImage"] img {
    filter: drop-shadow(0 0 12px rgba(0,255,168,.55));
}
section[data-testid="stSidebar"] h1 {
    font-size: 1.45rem !important;
    background: linear-gradient(90deg, #00ffa8, #00d0ff);
    -webkit-background-clip: text; background-clip: text; color: transparent;
}
section[data-testid="stSidebar"] [data-testid="stDivider"] hr {
    border-color: rgba(0,255,168,.25) !important;
}
section[data-testid="stSidebar"] [role="radiogroup"] label {
    background: rgba(255,255,255,.035);
    border: 1px solid rgba(255,255,255,.08);
    border-radius: 10px;
    padding: 6px 10px;
    margin-bottom: 6px;
    transition: border-color .15s ease, box-shadow .15s ease;
}
section[data-testid="stSidebar"] [role="radiogroup"] label:hover {
    border-color: rgba(0,255,168,.45);
}
section[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {
    border-color: #00ffa8;
    box-shadow: 0 0 12px rgba(0,255,168,.28);
}

/* ---------- Buttons: neon glow ----------------------------------------- */
[data-testid="stButton"] button {
    background: rgba(255,255,255,.04) !important;
    border: 1px solid rgba(0,208,255,.35) !important;
    color: #d9f7ff !important;
    border-radius: 10px !important;
    font-weight: 600 !important;
    letter-spacing: .3px;
    transition: transform .12s ease, box-shadow .15s ease, border-color .15s ease;
}
[data-testid="stButton"] button:hover {
    border-color: #00ffa8 !important;
    box-shadow: 0 0 16px rgba(0,255,168,.35);
    transform: translateY(-1px);
}
[data-testid="stButton"] button[kind="primary"],
[data-testid="stButton"] button[data-testid="baseButton-primary"],
[data-testid="baseButton-primary"] {
    background: linear-gradient(135deg, #00ffa8 0%, #00d0ff 100%) !important;
    color: #04121a !important;
    border: none !important;
    font-weight: 800 !important;
    box-shadow: 0 0 22px rgba(0,255,168,.35);
}
[data-testid="stButton"] button[kind="primary"]:hover,
[data-testid="stButton"] button[data-testid="baseButton-primary"]:hover,
[data-testid="baseButton-primary"]:hover {
    box-shadow: 0 0 34px rgba(0,255,168,.6);
    transform: translateY(-2px);
}

/* ---------- File uploader ---------------------------------------------- */
[data-testid="stFileUploader"] {
    background: rgba(255,255,255,.03);
    border: 1px dashed rgba(0,255,168,.35);
    border-radius: 12px;
    padding: 6px;
}
[data-testid="stFileUploader"] div[role="button"] { border-color: transparent !important; }

/* ---------- Code textarea: terminal look ------------------------------- */
[data-testid="stTextArea"] textarea {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: .86rem !important;
    line-height: 1.5 !important;
    background: #05080f !important;
    color: #c8ffe0 !important;
    caret-color: #00ffa8 !important;
    border: 1px solid rgba(0,255,168,.28) !important;
    border-radius: 12px !important;
    box-shadow: inset 0 0 24px rgba(0,255,168,.05);
}
[data-testid="stTextArea"] textarea::placeholder { color: #4f6a86 !important; }
[data-testid="stTextArea"] textarea:focus {
    border-color: #00ffa8 !important;
    box-shadow: 0 0 18px rgba(0,255,168,.28) !important;
}

/* ---------- Code blocks ------------------------------------------------- */
[data-testid="stCode"] pre, pre code, .stCode {
    font-family: 'JetBrains Mono', monospace !important;
    background: #05080f !important;
    border: 1px solid rgba(255,255,255,.08);
    border-radius: 10px !important;
}

/* ---------- Alerts (success/info/warning/error) ------------------------- */
[data-testid="stAlert"], [data-testid="stSuccess"], [data-testid="stInfo"],
[data-testid="stWarning"], [data-testid="stError"] {
    border-radius: 12px !important;
    border: 1px solid rgba(255,255,255,.10) !important;
    background: rgba(255,255,255,.045) !important;
    backdrop-filter: blur(6px);
}

/* ---------- Expanders: glass cards -------------------------------------- */
/* Streamlit 1.66 renders expanders as bare <details> (no data-testid). */
details {
    background: rgba(255,255,255,.035) !important;
    border: 1px solid rgba(255,255,255,.09) !important;
    border-left: 3px solid #00d0ff !important;
    border-radius: 12px !important;
    margin: 7px 0 !important;
    transition: border-color .15s ease, box-shadow .15s ease;
}
details:hover {
    border-left-color: #00ffa8 !important;
    box-shadow: 0 0 18px rgba(0,255,168,.14);
}
details summary { font-weight: 600; }
details[open] { border-left-color: #00ffa8 !important; }

/* ---------- Dataframe --------------------------------------------------- */
[data-testid="stDataFrame"] {
    border: 1px solid rgba(255,255,255,.08);
    border-radius: 12px;
    overflow: hidden;
}

/* ---------- Divider ----------------------------------------------------- */
[data-testid="stDivider"] hr { border-color: rgba(0,208,255,.22) !important; }

/* ---------- Spinner ----------------------------------------------------- */
[data-testid="stSpinner"] { color: #00ffa8 !important; }

/* ---------- Headings: section labels ----------------------------------- */
h2, h3 { color: #eaf4ff !important; }
[data-testid="stSubheader"] div { letter-spacing: 1.2px; text-transform: uppercase; font-size: .95rem !important; color: #8ff7dd !important; }

/* ======================================================================== */
/*  OUR COMPONENTS                                                          */
/* ======================================================================== */

/* ---------- Hero -------------------------------------------------------- */
.rg-hero {
    position: relative;
    display: flex; align-items: center; justify-content: space-between; gap: 18px;
    background: linear-gradient(135deg, rgba(13,21,38,.92) 0%, rgba(9,14,28,.92) 100%);
    border: 1px solid rgba(0,255,168,.22);
    border-radius: 18px;
    padding: 26px 30px;
    margin-bottom: 14px;
    overflow: hidden;
    box-shadow: 0 10px 40px rgba(0,0,0,.45), inset 0 1px 0 rgba(255,255,255,.05);
}
.rg-hero::before {
    content: "";
    position: absolute; inset: 0;
    background: radial-gradient(600px 200px at 90% 120%, rgba(0,208,255,.18), transparent 65%);
    pointer-events: none;
}
.rg-eyebrow {
    font-size: .72rem; font-weight: 600; letter-spacing: 2.4px;
    color: #7fe9cf; text-transform: uppercase;
    display: flex; align-items: center; gap: 8px; margin-bottom: 8px;
}
.rg-dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: #00ffa8; box-shadow: 0 0 10px #00ffa8;
    animation: rgPulse 1.6s ease-in-out infinite;
}
.rg-title {
    font-size: 2.5rem !important; font-weight: 700 !important;
    margin: 0 !important; line-height: 1.05; color: #fff !important;
    letter-spacing: .5px;
}
.rg-grad {
    background: linear-gradient(90deg, #00ffa8, #00d0ff, #7c5cff, #00ffa8);
    background-size: 300% 100%;
    -webkit-background-clip: text; background-clip: text;
    color: transparent !important;
    animation: rgShift 5s linear infinite;
    filter: drop-shadow(0 0 18px rgba(0,255,168,.35));
}
.rg-tag { color: #b9cbe0; font-size: .98rem; margin: 8px 0 12px 0; }
.rg-tag b { color: #eaf7ff; }
.rg-badges { display: flex; flex-wrap: wrap; gap: 8px; }
.rg-chip {
    font-size: .74rem; font-weight: 600;
    background: rgba(0,255,168,.08);
    border: 1px solid rgba(0,255,168,.30);
    color: #a9ffe4;
    padding: 4px 11px; border-radius: 999px;
    white-space: nowrap;
}
.rg-hero-art {
    font-size: 5.4rem; line-height: 1;
    animation: rgFloat 4s ease-in-out infinite;
    filter: drop-shadow(0 0 26px rgba(0,255,168,.5));
    user-select: none;
}
@keyframes rgShift  { 0% { background-position: 0% 0; } 100% { background-position: 300% 0; } }
@keyframes rgPulse  { 0%,100% { opacity: 1; } 50% { opacity: .35; } }
@keyframes rgFloat  { 0%,100% { transform: translateY(0); } 50% { transform: translateY(-9px); } }

/* ---------- How-it-works cards ------------------------------------------ */
.rg-grid3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 4px 0 14px 0; }
.rg-step {
    background: rgba(255,255,255,.035);
    border: 1px solid rgba(255,255,255,.09);
    border-radius: 14px;
    padding: 16px 16px 14px 16px;
    position: relative;
    transition: transform .15s ease, border-color .15s ease, box-shadow .15s ease;
}
.rg-step:hover {
    transform: translateY(-3px);
    border-color: rgba(0,255,168,.45);
    box-shadow: 0 8px 26px rgba(0,0,0,.4);
}
.rg-step-n {
    font-size: .68rem; font-weight: 700; letter-spacing: 2px;
    color: #00d0ff; margin-bottom: 6px;
}
.rg-step-t { font-weight: 700; color: #eaf7ff; font-size: .98rem; margin-bottom: 5px; }
.rg-step-d { color: #93a9c4; font-size: .82rem; line-height: 1.45; }

/* ---------- Intro strip -------------------------------------------------- */
.rg-strip {
    background: rgba(0,208,255,.06);
    border: 1px solid rgba(0,208,255,.22);
    border-radius: 12px;
    padding: 11px 16px;
    color: #cfe8ff; font-size: .92rem;
    margin-bottom: 10px;
}
.rg-strip b { color: #fff; }

/* ---------- KPI row ------------------------------------------------------ */
.rg-kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 6px 0 4px 0; }
.rg-kpi {
    background: rgba(255,255,255,.035);
    border: 1px solid rgba(255,255,255,.10);
    border-left: 4px solid var(--kpi-accent, #00d0ff);
    border-radius: 14px;
    padding: 14px 16px;
    box-shadow: 0 6px 22px rgba(0,0,0,.30);
}
.rg-kpi-num {
    font-size: 1.9rem; font-weight: 700; color: #fff; line-height: 1.1;
    text-shadow: 0 0 22px rgba(0,208,255,.35);
}
.rg-kpi-num span { font-size: .95rem; color: #7e94b3; font-weight: 500; }
.rg-kpi-cap {
    margin-top: 5px; font-size: .68rem; font-weight: 700;
    letter-spacing: 1.6px; color: #8fa6c4; text-transform: uppercase;
}
.rg-kpi.good { --kpi-accent: #00ffa8; } .rg-kpi.good .rg-kpi-num { text-shadow: 0 0 22px rgba(0,255,168,.4); }
.rg-kpi.warn { --kpi-accent: #ffd11a; } .rg-kpi.warn .rg-kpi-num { text-shadow: 0 0 22px rgba(255,209,26,.4); }
.rg-kpi.bad  { --kpi-accent: #ff4b4b; } .rg-kpi.bad  .rg-kpi-num { text-shadow: 0 0 22px rgba(255,75,75,.45); }
.rg-kpi.info { --kpi-accent: #00d0ff; }

/* ---------- Severity bars ------------------------------------------------ */
.rg-bars {
    background: rgba(255,255,255,.03);
    border: 1px solid rgba(255,255,255,.09);
    border-radius: 14px;
    padding: 16px 18px;
}
.rg-bars-h {
    font-size: .7rem; font-weight: 700; letter-spacing: 1.8px;
    color: #8ff7dd; text-transform: uppercase; margin-bottom: 12px;
}
.rg-bar-row { display: flex; align-items: center; gap: 10px; margin-bottom: 9px; }
.rg-bar-row:last-child { margin-bottom: 0; }
.rg-bar-tag {
    width: 86px; flex: none; font-size: .66rem; font-weight: 700;
    letter-spacing: 1px; text-align: center;
    padding: 3px 0; border-radius: 6px;
}
.rg-bar-tag.CRITICAL { background: rgba(255,75,75,.16); color: #ff6b6b; border: 1px solid rgba(255,75,75,.5); }
.rg-bar-tag.HIGH     { background: rgba(255,140,66,.16); color: #ff9e5e; border: 1px solid rgba(255,140,66,.5); }
.rg-bar-tag.MEDIUM   { background: rgba(255,209,26,.14); color: #ffe066; border: 1px solid rgba(255,209,26,.45); }
.rg-bar-tag.LOW      { background: rgba(77,163,255,.15); color: #7cc0ff; border: 1px solid rgba(77,163,255,.5); }
.rg-bar-tag.INFO     { background: rgba(154,165,177,.14); color: #b8c2cc; border: 1px solid rgba(154,165,177,.45); }
.rg-bar-track {
    flex: 1; height: 14px; border-radius: 8px;
    background: rgba(255,255,255,.05);
    overflow: hidden;
}
.rg-bar-fill {
    height: 100%; border-radius: 8px;
    min-width: 0;
    box-shadow: 0 0 14px currentColor;
    transition: width .5s ease;
}
.rg-bar-fill.CRITICAL { background: linear-gradient(90deg, #ff4b4b, #ff7b7b); color: #ff4b4b; }
.rg-bar-fill.HIGH     { background: linear-gradient(90deg, #ff8c42, #ffb074); color: #ff8c42; }
.rg-bar-fill.MEDIUM   { background: linear-gradient(90deg, #ffd11a, #ffe570); color: #ffd11a; }
.rg-bar-fill.LOW      { background: linear-gradient(90deg, #4da3ff, #86c6ff); color: #4da3ff; }
.rg-bar-fill.INFO     { background: linear-gradient(90deg, #9aa5b1, #c3cbd3); color: #9aa5b1; }
.rg-bar-count { width: 30px; text-align: right; font-weight: 700; color: #e6f2ff; font-size: .9rem; }
.rg-bar-row.zero { opacity: .32; }

/* ---------- Pills --------------------------------------------------------- */
.rg-pills { display: flex; flex-wrap: wrap; gap: 7px; margin: 2px 0 10px 0; }
.rg-pill {
    font-size: .66rem; font-weight: 700; letter-spacing: 1.1px;
    padding: 3px 10px; border-radius: 999px;
    border: 1px solid rgba(255,255,255,.20);
    color: #dbe7f5; background: rgba(255,255,255,.05);
}
.rg-pill.p-crit { background: rgba(255,75,75,.16); border-color: rgba(255,75,75,.6); color: #ff8080; }
.rg-pill.p-high { background: rgba(255,140,66,.16); border-color: rgba(255,140,66,.6); color: #ffb184; }
.rg-pill.p-med  { background: rgba(255,209,26,.14); border-color: rgba(255,209,26,.55); color: #ffe570; }
.rg-pill.p-low  { background: rgba(77,163,255,.15); border-color: rgba(77,163,255,.6); color: #9ecfff; }
.rg-pill.p-info { background: rgba(154,165,177,.14); border-color: rgba(154,165,177,.55); color: #c6cfd8; }
.rg-pill.p-owasp { border-color: rgba(0,208,255,.55); color: #7fe3ff; background: rgba(0,208,255,.08); }

/* ---------- Footer -------------------------------------------------------- */
.rg-footer {
    margin-top: 26px;
    padding: 14px 18px 4px 18px;
    border-top: 1px solid rgba(0,255,168,.18);
    text-align: center;
    color: #7c92b3;
    font-size: .78rem;
    letter-spacing: .4px;
}
.rg-footer b { color: #a9ffe4; }
.rg-footer .rg-dot { display: inline-block; margin: 0 6px -1px 6px; }
</style>
"""


# ---------------------------------------------------------------------------
# Component helpers
# ---------------------------------------------------------------------------
def inject() -> None:
    """Install the global stylesheet. Call once, after ``set_page_config``."""
    st.markdown(THEME_CSS, unsafe_allow_html=True)


def hero() -> None:
    """Animated hero banner with gradient title and capability chips."""
    st.markdown(
        """
<div class="rg-hero">
  <div class="rg-hero-copy">
    <div class="rg-eyebrow"><span class="rg-dot"></span> Defensive security · OWASP-aligned · Open source</div>
    <h1 class="rg-title">RepoGuard <span class="rg-grad">AI</span></h1>
    <p class="rg-tag">Autonomous <b>Vulnerability</b> &amp; <b>Patch</b> agent —
       <b>The Scout</b>, <b>The Explainer</b>, <b>The Messenger</b>.</p>
    <div class="rg-badges">
      <span class="rg-chip">⚡ 13 OWASP rules</span>
      <span class="rg-chip">🩹 AI secure patches</span>
      <span class="rg-chip">🔔 realtime alerts</span>
      <span class="rg-chip">🧠 AI security brief</span>
      <span class="rg-chip">🧪 11/11 tests</span>
    </div>
  </div>
  <div class="rg-hero-art">🛡️</div>
</div>
""",
        unsafe_allow_html=True,
    )


def how_it_works() -> None:
    """Three glass cards explaining the engine pipeline (pre-scan state)."""
    st.markdown(
        """
<div class="rg-grid3">
  <div class="rg-step">
    <div class="rg-step-n">STEP 01</div>
    <div class="rg-step-t">🔍 The Scout</div>
    <div class="rg-step-d">13 deterministic OWASP-mapped rules scan your code as
      text — secrets, injection, weak crypto, unsafe deserialization.
      <b>Zero code execution.</b></div>
  </div>
  <div class="rg-step">
    <div class="rg-step-n">STEP 02</div>
    <div class="rg-step-t">🤖 The Auto-Patch Engineer</div>
    <div class="rg-step-d">AI turns each finding into an explanation, a concrete
      attack scenario and a minimal secure patch with ±12 lines of context.</div>
  </div>
  <div class="rg-step">
    <div class="rg-step-n">STEP 03</div>
    <div class="rg-step-t">🔔 The Messenger</div>
    <div class="rg-step-d">One-tap realtime push to your team plus a prioritised
      executive security brief — powered by the DNotifier pipeline.</div>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )


def kpi_row(
    score: int,
    total: int,
    critical: int,
    high: int,
    language: str,
    lines: int,
) -> None:
    """Four KPI cards; the score card is colour-banded (bad/warn/good)."""
    band = "good" if score >= 80 else ("warn" if score >= 50 else "bad")
    lang = (language or "code").upper()
    st.markdown(
        f"""
<div class="rg-kpis">
  <div class="rg-kpi {band}">
    <div class="rg-kpi-num">{score}<span>/100</span></div>
    <div class="rg-kpi-cap">Security score</div>
  </div>
  <div class="rg-kpi info">
    <div class="rg-kpi-num">{total}</div>
    <div class="rg-kpi-cap">Findings</div>
  </div>
  <div class="rg-kpi {"bad" if critical else ("warn" if high else "good")}">
    <div class="rg-kpi-num">{critical}<span> / {high}</span></div>
    <div class="rg-kpi-cap">Critical / High</div>
  </div>
  <div class="rg-kpi info">
    <div class="rg-kpi-num">{lang}</div>
    <div class="rg-kpi-cap">{lines} lines scanned</div>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )


def severity_bars(counts: Mapping[str, int]) -> None:
    """Horizontal colour-banded severity breakdown (chart replacement)."""
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    total = max((counts.get(k, 0) for k in order), default=0)
    rows = []
    for sev in order:
        n = int(counts.get(sev, 0))
        width = 0 if total == 0 else max(4.0, round(100.0 * n / total, 1)) if n else 0
        zero = "" if n else " zero"
        rows.append(
            f'<div class="rg-bar-row{zero}">'
            f'<span class="rg-bar-tag {sev}">{sev}</span>'
            f'<div class="rg-bar-track"><div class="rg-bar-fill {sev}" '
            f'style="width:{width}%"></div></div>'
            f'<span class="rg-bar-count">{n}</span></div>'
        )
    st.markdown(
        '<div class="rg-bars"><div class="rg-bars-h">Severity breakdown</div>'
        + "".join(rows)
        + "</div>",
        unsafe_allow_html=True,
    )


_SEV_PILL = {
    "CRITICAL": "p-crit",
    "HIGH": "p-high",
    "MEDIUM": "p-med",
    "LOW": "p-low",
    "INFO": "p-info",
}


def pills(severity: str, owasp: str, line_no: int, rule_id: str) -> None:
    """Severity + OWASP + line chips shown at the top of each finding card."""
    sev_cls = _SEV_PILL.get(severity, "p-info")
    st.markdown(
        f"""
<div class="rg-pills">
  <span class="rg-pill {sev_cls}">{severity}</span>
  <span class="rg-pill p-owasp">{owasp}</span>
  <span class="rg-pill">LINE {line_no}</span>
  <span class="rg-pill">{rule_id}</span>
</div>
""",
        unsafe_allow_html=True,
    )


def footer() -> None:
    """Branded footer (replaces the default Streamlit one via CSS)."""
    st.markdown(
        """
<div class="rg-footer">
  <span class="rg-dot"></span>
  <b>RepoGuard AI</b> · MIT license · built defensive-first ·
  AI pipeline &amp; realtime notify by <b>DNotifier</b> ·
  human-in-the-loop patches — review before you commit
</div>
""",
        unsafe_allow_html=True,
    )
