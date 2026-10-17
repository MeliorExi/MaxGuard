import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import os
import sys
import csv
import io
from datetime import datetime
from dotenv import load_dotenv
VERSION = "0.8.0 Alpha"
APP_NAME = "MaxGuard"

print(f"{APP_NAME} {VERSION}")


load_dotenv()

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analyzer.threat_engine import get_threat_summary
from maxguard.ai.ollama_client import AIUnavailable, explain_all

IS_CLOUD = os.getenv("STREAMLIT_CLOUD", "false").lower() == "true"

st.set_page_config(
    page_title="Max-Guard Security Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
/* ── Global ── */
.main .block-container {
    padding-top: 1rem !important;
    padding-bottom: 3rem !important;
    max-width: 1400px !important;
}

/* ── Main header card ── */
.main-header {
    background: linear-gradient(135deg, #0c1a36 0%, #080f20 100%);
    border: 1px solid #1e3a5f;
    border-radius: 14px;
    padding: 22px 28px;
    margin-bottom: 20px;
    position: relative;
    overflow: hidden;
}
.main-header::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, #3B8BD4, #00d4ff, #3B8BD4, transparent);
}
.main-header-title {
    font-size: 24px;
    font-weight: 700;
    color: #e2e8f0;
    margin: 0 0 4px 0;
    letter-spacing: -0.3px;
}
.main-header-sub {
    font-size: 13px;
    color: #475569;
    margin: 0;
}
.badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 5px;
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-right: 6px;
    margin-top: 12px;
}
.badge-blue   { background:#1e3a5f; color:#60a5fa; }
.badge-green  { background:#142e22; color:#4ade80; }
.badge-purple { background:#2a1a4a; color:#c084fc; }
.badge-amber  { background:#3a2400; color:#fbbf24; }

/* ── Section headers ── */
.section-header {
    border-left: 3px solid #3B8BD4;
    padding-left: 14px;
    margin: 28px 0 14px 0;
}
.section-header h3 {
    color: #e2e8f0 !important;
    font-size: 13px !important;
    font-weight: 700 !important;
    margin: 0 !important;
    text-transform: uppercase;
    letter-spacing: 1.2px;
}

/* ── Violation severity colors ── */
.violation-critical { color: #f43f5e !important; font-weight: 700; }
.violation-high     { color: #f97316 !important; font-weight: 700; }
.violation-medium   { color: #eab308 !important; font-weight: 700; }
.violation-low      { color: #3B8BD4 !important; font-weight: 700; }
.violation-none     { color: #22c55e !important; font-weight: 700; }

/* ── Metric cards ── */
[data-testid="stMetric"] {
    background: linear-gradient(135deg, #0c1a3680 0%, #080f2080 100%) !important;
    border: 1px solid #1e3a5f !important;
    border-radius: 10px !important;
    padding: 16px 18px !important;
    transition: border-color 0.2s;
}
[data-testid="stMetric"]:hover { border-color: #3B8BD4 !important; }
[data-testid="stMetricLabel"] > div {
    font-size: 10px !important;
    font-weight: 700 !important;
    text-transform: uppercase !important;
    letter-spacing: 1px !important;
    color: #475569 !important;
}
[data-testid="stMetricValue"] > div {
    font-size: 26px !important;
    font-weight: 700 !important;
    color: #e2e8f0 !important;
    font-family: 'Consolas', 'Fira Code', monospace !important;
}

/* ── Buttons ── */
.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #1e3d7d 0%, #2563a8 100%) !important;
    border: 1px solid #3B8BD4 !important;
    color: #bfdbfe !important;
    font-weight: 600 !important;
    border-radius: 8px !important;
    transition: all 0.2s ease !important;
}
.stButton > button[kind="primary"]:hover {
    box-shadow: 0 0 18px rgba(59, 139, 212, 0.35) !important;
    transform: translateY(-1px) !important;
}
.stButton > button:not([kind="primary"]) {
    border: 1px solid #1e3a5f !important;
    border-radius: 8px !important;
}

/* ── Expanders ── */
[data-testid="stExpander"] {
    border: 1px solid #1e3a5f !important;
    border-radius: 8px !important;
}
[data-testid="stExpander"]:hover { border-color: #3B8BD4 !important; }

/* ── Dataframe ── */
[data-testid="stDataFrame"] {
    border: 1px solid #1e3a5f !important;
    border-radius: 8px !important;
}

/* ── Divider ── */
hr { border-color: #1e3a5f !important; }

/* ── IR Step cards ── */
.ir-step-box {
    border-radius: 10px;
    padding: 16px 18px 14px 18px;
    margin-bottom: 10px;
    border: 1px solid;
}
.ir-step-title {
    font-weight: 700;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    margin-bottom: 6px;
}
.ir-step-desc {
    font-size: 12px;
    margin-bottom: 10px;
    opacity: 0.6;
    font-style: italic;
}
.ir-step-body {
    font-size: 13px;
    color: #cbd5e1;
    line-height: 1.7;
}
.ir-step-body ul { margin: 4px 0 0 20px; padding: 0; }
.ir-step-body li { margin-bottom: 5px; }

/* ── Welcome cards ── */
.welcome-card {
    background: linear-gradient(135deg, #0c1a36 0%, #080f20 100%);
    border: 1px solid #1e3a5f;
    border-radius: 12px;
    padding: 20px;
    height: 100%;
    transition: border-color 0.2s, box-shadow 0.2s;
}
.welcome-card:hover {
    border-color: #3B8BD4;
    box-shadow: 0 4px 20px rgba(59,139,212,0.12);
}
.welcome-card-icon  { font-size: 26px; margin-bottom: 10px; }
.welcome-card-title { font-size: 12px; font-weight: 700; color: #e2e8f0; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.8px; }
.welcome-card-desc  { font-size: 12px; color: #475569; line-height: 1.6; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: #080f20; }
::-webkit-scrollbar-thumb { background: #1e3a5f; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #3B8BD4; }

/* ── Pulse animation for CRITICAL threat ── */
@keyframes threat-pulse {
    0%, 100% { box-shadow: 0 0 0 0 rgba(244, 63, 94, 0.4); }
    50%       { box-shadow: 0 0 0 10px rgba(244, 63, 94, 0); }
}
.threat-critical-pulse { animation: threat-pulse 2s ease-in-out infinite; }

/* ── Code inline ── */
code {
    background: #0c1a36 !important;
    color: #60a5fa !important;
    border: 1px solid #1e3a5f !important;
    border-radius: 4px !important;
    padding: 1px 6px !important;
    font-size: 12px !important;
}
</style>
""", unsafe_allow_html=True)

st.markdown("""
<div class="main-header">
    <div style="display:flex; align-items:center; gap:16px;">
        <div style="font-size:42px; line-height:1;">🛡️</div>
        <div>
            <div class="main-header-title">Max-Guard</div>
            <div class="main-header-sub">PCI-DSS Network Security Scanner &nbsp;·&nbsp; CCSU</div>
        </div>
    </div>
    <div style="margin-top:12px;">
        <span class="badge badge-blue">AI-Powered</span>
        <span class="badge badge-green">PCI-DSS v4.0</span>
        <span class="badge badge-purple">GPT-4o-mini</span>
        <span class="badge badge-amber">Scapy</span>
    </div>
</div>
""", unsafe_allow_html=True)

st.sidebar.title("Scan Controls")
st.sidebar.markdown(f"**Mode:** {'☁️ Cloud' if IS_CLOUD else '💻 Local'}")
st.sidebar.divider()


def run_local_scan(packet_count):
    from scanner.sniffer import start_sniffing, captured_packets
    captured_packets.clear()
    with st.spinner(f"Scanning network... capturing {packet_count} packets"):
        start_sniffing(packet_count=packet_count)
    # Step 5.6 - Auto-save results to scan_results.json after every live scan.
    # This file is what gets uploaded to the cloud dashboard for remote analysis.
    try:
        save_data = {
            "packets":   list(captured_packets),
            "scan_time": datetime.now().isoformat(),
            "total":     len(captured_packets)
        }
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scan_results.json"), "w") as f:
            json.dump(save_data, f, indent=2, default=str)
        st.sidebar.success("scan_results.json saved automatically.")
    except Exception as e:
        st.sidebar.warning(f"Auto-save failed: {str(e)}")
    return captured_packets


def load_packets_from_file(uploaded_file):
    # Step 5.5 — Cloud mode JSON handling
    # Accepts two formats:
    #   Format A (list):  [ {packet}, {packet}, ... ]           <- sniffer.py default output
    #   Format B (dict):  { "packets": [...], "scan_time": ... } <- exported from dashboard
    content = uploaded_file.read().decode("utf-8")
    data = json.loads(content)
    if isinstance(data, list):
        return data
    elif isinstance(data, dict) and "packets" in data:
        return data["packets"]
    else:
        st.error("Unrecognised JSON format. File must be a packet list or contain a 'packets' key.")
        return []


def render_threat_badge(level):
    colors = {
        "CRITICAL": "#f43f5e",
        "HIGH":     "#f97316",
        "MEDIUM":   "#eab308",
        "LOW":      "#3B8BD4",
        "NONE":     "#22c55e"
    }
    icons = {
        "CRITICAL": "🔴",
        "HIGH":     "🟠",
        "MEDIUM":   "🟡",
        "LOW":      "🔵",
        "NONE":     "🟢"
    }
    color = colors.get(level, "#64748b")
    icon  = icons.get(level, "⚪")
    pulse = "threat-critical-pulse" if level == "CRITICAL" else ""
    st.markdown(f"""
<div class="{pulse}" style="display:inline-flex; align-items:center; gap:14px;
     background:{color}18; border:2px solid {color}66;
     border-radius:12px; padding:14px 28px; margin:10px 0;">
    <span style="font-size:28px;">{icon}</span>
    <div>
        <div style="font-size:10px; color:{color}99; font-weight:700;
                    text-transform:uppercase; letter-spacing:1.2px; margin-bottom:2px;">Threat Level</div>
        <div style="color:{color}; font-size:22px; font-weight:800;
                    letter-spacing:2px; font-family:monospace;">{level}</div>
    </div>
</div>
""", unsafe_allow_html=True)


def render_severity_gauge(score):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={"x": [0, 1], "y": [0, 1]},
        title={"text": "Severity Score", "font": {"size": 16}},
        gauge={
            "axis": {"range": [0, 10], "tickwidth": 1, "tickcolor": "white", "nticks": 11},
            "bar": {"color": "#3B8BD4"},
            "steps": [
                {"range": [0, 3],  "color": "#1a4a2e"},
                {"range": [3, 5],  "color": "#1a3a5c"},
                {"range": [5, 7],  "color": "#4a3a00"},
                {"range": [7, 9],  "color": "#4a2000"},
                {"range": [9, 10], "color": "#4a0000"},
            ],
            "threshold": {
                "line": {"color": "white", "width": 3},
                "thickness": 0.8,
                "value": score
            }
        }
    ))
    fig.update_layout(
        height=280,
        margin=dict(t=60, b=20, l=40, r=40),
        paper_bgcolor="rgba(0,0,0,0)",
        font_color="white",
        font=dict(size=12)
    )
    st.plotly_chart(fig, use_container_width=True)


def render_overview_metrics(packets, result):
    col1, col2, col3, col4, col5 = st.columns(5)
    total      = result["total_packets"]
    violations = result["total_violations"]
    rate       = round((violations / total * 100), 1) if total > 0 else 0
    score      = result["severity"]["overall_score"]
    devices    = len(result["affected_devices"])

    col1.metric("Total Packets",    total)
    col2.metric("PCI Violations",   violations,
                delta=f"{rate}% of traffic" if violations > 0 else None,
                delta_color="inverse")
    col3.metric("Affected Devices", devices)
    col4.metric("Severity Score",   f"{score}/10")
    col5.metric("Threat Level",     result["threat_level"])


def render_charts(packets, result):
    df = pd.DataFrame(packets)

    st.markdown('<div class="section-header"><h3>Traffic Analysis</h3></div>',
                unsafe_allow_html=True)

    # ── Row 1: Protocol pie  |  Severity gauge ────────────────────────────────
    col1, col2 = st.columns(2)

    with col1:
        if "protocol" in df.columns:
            protocol_counts = df["protocol"].value_counts().reset_index()
            protocol_counts.columns = ["Protocol", "Count"]
            fig = px.pie(
                protocol_counts, values="Count", names="Protocol",
                title="Protocol Distribution",
                color_discrete_sequence=["#3B8BD4", "#1D9E75", "#E8593C", "#9F6BDD"]
            )
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        render_severity_gauge(result["severity"]["overall_score"])

    # ── Row 2: Violation timeline  |  Top Talkers ─────────────────────────────
    col3, col4 = st.columns(2)

    with col3:
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"])
            violations_df = df[df["pci_violation"] == True].copy()
            if not violations_df.empty:
                violations_df["minute"] = violations_df["timestamp"].dt.floor("s")
                timeline = violations_df.groupby("minute").size().reset_index(name="count")
                fig = px.line(
                    timeline, x="minute", y="count",
                    title="Violation Timeline",
                    labels={"minute": "Time", "count": "Violations"},
                    color_discrete_sequence=["#ff4444"]
                )
                fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No violations to plot on timeline.")

    with col4:
        patterns    = result.get("patterns", {})
        top_talkers = patterns.get("top_talkers", [])
        if top_talkers:
            talkers_df = pd.DataFrame(top_talkers)
            fig = px.bar(
                talkers_df, x="ip", y="count",
                title="Top Talkers (by packet count)",
                labels={"ip": "IP Address", "count": "Packets"},
                color="count",
                color_continuous_scale="Blues"
            )
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", font_color="white")
            st.plotly_chart(fig, use_container_width=True)

    # ── Row 3: Violations by Protocol ─────────────────────────────────────────
    # Replaces the old "Top Destination Ports" full-width bar chart.
    # Raw port numbers (21, 23, 80) carry no meaning to a stakeholder or professor.
    # Protocol names (FTP, Telnet, HTTP) map directly to PCI-DSS requirements and
    # communicate risk at a glance. Color-coded by severity level.
    violations_df = df[df["pci_violation"] == True].copy() if "pci_violation" in df.columns else pd.DataFrame()

    if not violations_df.empty and "protocol" in violations_df.columns:
        viol_proto = violations_df["protocol"].value_counts().reset_index()
        viol_proto.columns = ["Protocol", "Violations"]

        PROTO_COLORS = {
            "FTP":    "#E53E3E",
            "TELNET": "#C53030",
            "HTTP":   "#DD6B20",
            "RDP":    "#D69E2E",
            "IMAP":   "#B7791F",
            "POP3":   "#B7791F",
            "TCP":    "#E53E3E",
            "UDP":    "#DD6B20",
        }
        color_map = {
            row["Protocol"]: PROTO_COLORS.get(row["Protocol"].upper(), "#718096")
            for _, row in viol_proto.iterrows()
        }

        fig = px.bar(
            viol_proto, x="Protocol", y="Violations",
            title="PCI-DSS Violations by Protocol",
            labels={"Protocol": "Protocol / Service", "Violations": "Violation Count"},
            color="Protocol",
            color_discrete_map=color_map,
            text="Violations"
        )
        fig.update_traces(textposition="outside")
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            font_color="white",
            title_font_color="white",
            showlegend=False
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.success("✅ No PCI-DSS violations detected — violations by protocol chart not applicable.")


def render_violations_table(packets):
    df = pd.DataFrame(packets)
    violations_df = df[df["pci_violation"] == True]
    if not violations_df.empty:
        st.markdown('<div class="section-header"><h3>PCI-DSS Violations Detected</h3></div>',
                    unsafe_allow_html=True)

        display_columns = [
            "timestamp",
            "src_ip",
            "dst_ip",
            "protocol",
            "dst_port",
            "violation_detail",
        ]

        if "explanation" in violations_df.columns:
            display_columns.append("explanation")

        st.dataframe(
            violations_df[display_columns],
            use_container_width=True,
        )

    else:
        st.success("No PCI-DSS violations detected in this scan.")


def render_affected_devices(result):
    devices = result.get("affected_devices", [])
    if not devices:
        return
    st.markdown('<div class="section-header"><h3>Affected Devices</h3></div>',
                unsafe_allow_html=True)
    for device in devices:
        with st.expander(f"{device['ip']} — {device['device_type']} — {device['violation_count']} violations"):
            st.markdown(f"**IP Address:** `{device['ip']}`")
            st.markdown(f"**Device Type:** {device['device_type']}")
            st.markdown(f"**Total Violations:** {device['violation_count']}")
            st.markdown("**Violations Found:**")
            for v in device["violations"]:
                st.markdown(f"- {v}")


def render_investigation_guides(result):
    guides = result.get("investigation_guides", {})
    if not guides:
        return
    st.markdown('<div class="section-header"><h3>Investigation & Remediation Guides</h3></div>',
                unsafe_allow_html=True)
    st.markdown("Step-by-step guidance for each violation found in this scan.")
    for protocol, guide in guides.items():
        with st.expander(f"How to investigate and fix: {protocol}"):
            st.markdown(f"**PCI-DSS Requirement:** `{guide['pci_requirement']}`")
            st.divider()
            st.markdown("**What it is:**")
            st.info(guide["what_it_is"])
            st.markdown("**How to investigate:**")
            for step in guide["how_to_investigate"]:
                st.markdown(f"- {step}")
            st.markdown("**How to fix:**")
            for step in guide["how_to_fix"]:
                st.markdown(f"- {step}")


def render_ir_section(result):
    """
    5-step AI Incident Response Advisor.
    Sits directly below the AI analysis output inside render_ai_analysis().
    Sends actual detected threat data to GPT-4o-mini and returns a plan
    structured around: Identify, Assess Risk, Contain, Eradicate, Recover.
    """
    st.markdown('<div class="section-header"><h3>🚨 AI Incident Response Advisor</h3></div>',
                unsafe_allow_html=True)
    st.markdown(
        "Based on the threats detected in this scan, the AI generates a concrete "
        "5-step incident response plan tailored to the exact violations found."
    )

    # Reference strip showing all 5 steps
    IR_META = [
        ("01", "Identify",    "#E67E22",
         "Review alerts, monitor for prevented activity, and hunt for malicious behavior."),
        ("02", "Assess Risk", "#E74C3C",
         "Determine impact based on targeted asset and notify relevant partners."),
        ("03", "Contain",     "#8E44AD",
         "Stop the attack from spreading or getting worse."),
        ("04", "Eradicate",   "#C0392B",
         "Remove the threat, disable unauthorized access, notify state/federal partners."),
        ("05", "Recover",     "#27AE60",
         "Fix architecture weaknesses and update Security Awareness Training."),
    ]
    ref_cols = st.columns(5)
    for i, (num, name, color, desc) in enumerate(IR_META):
        with ref_cols[i]:
            st.markdown(f"""
<div style="background:{color}15; border:1px solid {color}44; border-radius:8px;
            padding:10px; text-align:center; min-height:110px;">
    <div style="font-size:10px; font-weight:700; color:{color};
                text-transform:uppercase; letter-spacing:0.5px; margin-bottom:4px;">Step {num}</div>
    <div style="font-size:13px; font-weight:700; color:{color}; margin-bottom:6px;">{name}</div>
    <div style="font-size:10px; color:#888; line-height:1.4;">{desc[:65]}...</div>
</div>
""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col_a, col_b = st.columns([4, 1])
    with col_a:
        extra = st.text_input(
            "Add extra context (optional)",
            placeholder="e.g. violations on POS terminal at register 3, scan ran at 2:14 AM...",
            key="ir_extra_context"
        )
    with col_b:
        st.markdown("<br>", unsafe_allow_html=True)
        run_ir = st.button("🛡️ Generate IR Plan", type="primary", key="ir_run_btn")

    if run_ir:
        threat_context = (
            f"Threat level: {result.get('threat_level', 'UNKNOWN')}\n"
            f"Total violations: {result.get('total_violations', 0)}\n"
            f"Violation types detected: {', '.join(result.get('violation_types', []))}\n"
            f"Affected devices: {len(result.get('affected_devices', []))}\n"
            f"AI analysis summary: {result.get('analysis', '')[:600]}"
        )
        if extra:
            threat_context += f"\nAdditional context: {extra}"

        with st.spinner("Generating 5-step incident response plan..."):
            try:
                from openai import OpenAI
                settings = load_settings()

                client = OpenAI( 
                    api_key=settings["api_key"]
                )

                ir_prompt = f"""You are a PCI-DSS v4.0 incident response expert for a retail environment.
A network security scanner (Max-Guard) detected the following:

{threat_context}

Generate a 5-step incident response plan. Respond ONLY in valid JSON, no markdown, no preamble.

Required structure:
{{
  "identify":    {{ "actions": ["...", "...", "...", "..."] }},
  "assess_risk": {{ "actions": ["...", "...", "..."] }},
  "contain":     {{ "actions": ["...", "...", "...", "..."] }},
  "eradicate":   {{ "actions": ["...", "...", "..."] }},
  "recover":     {{ "actions": ["...", "...", "...", "..."] }}
}}

Rules:
- Actions must be specific to the exact violation types detected (FTP, HTTP, Telnet, etc.)
- Reference the PCI-DSS v4.0 requirement number in at least one action per step
- Actions must be immediately executable by a retail security team, not generic advice
- Each step should have 3 to 4 actions"""

                response = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[
                        {"role": "system", "content": "You are a PCI-DSS incident response expert. Respond only in valid JSON."},
                        {"role": "user",   "content": ir_prompt}
                    ],
                    max_tokens=1000,
                    temperature=0.2
                )
                raw     = response.choices[0].message.content.strip()
                clean   = raw.replace("```json", "").replace("```", "").strip()
                ir_plan = json.loads(clean)
                st.session_state["ir_plan"] = ir_plan
                st.rerun()

            except Exception as e:
                st.error(f"IR plan generation failed: {str(e)}")

    # ── Render IR plan cards ───────────────────────────────────────────────────
    if "ir_plan" in st.session_state:
        ir = st.session_state["ir_plan"]

        STEPS = [
            ("identify",    "Step 1: Identify",    "#E67E22",
             "Review alerts, monitor for prevented activity, and hunt for malicious behavior."),
            ("assess_risk", "Step 2: Assess Risk",  "#E74C3C",
             "Determine the potential impact based on the targeted asset (device, application, data, or department) and notify relevant partners."),
            ("contain",     "Step 3: Contain",      "#8E44AD",
             "Stop the attack from spreading or getting worse."),
            ("eradicate",   "Step 4: Eradicate",    "#C0392B",
             "Remove the threat (e.g. viruses), disable unauthorized access, and notify state/federal/utility partners."),
            ("recover",     "Step 5: Recover",      "#27AE60",
             "Identify architecture weaknesses, evaluate new technologies or process changes, and incorporate lessons learned into Security Awareness Training."),
        ]

        st.markdown("---")
        st.markdown("#### AI-Generated Incident Response Plan")
        st.caption(
            f"Tailored to this scan — Threat Level: **{result.get('threat_level', '?')}** | "
            f"Violations: **{result.get('total_violations', 0)}** | PCI-DSS v4.0 references included."
        )

        for key, label, color, description in STEPS:
            step_data    = ir.get(key, {})
            actions      = step_data.get("actions", [])
            actions_html = "".join([f"<li>{a}</li>" for a in actions])

            st.markdown(f"""
<div class="ir-step-box" style="background:{color}12; border-color:{color}55;">
    <div class="ir-step-title" style="color:{color};">{label}</div>
    <div class="ir-step-desc" style="color:#999;">{description}</div>
    <div class="ir-step-body"><ul>{actions_html}</ul></div>
</div>
""", unsafe_allow_html=True)

        st.caption(
            "For authorized networks only. All IR actions should be reviewed "
            "by a qualified security professional before execution."
        )


def render_ai_analysis(result):
    st.markdown('<div class="section-header"><h3>AI Threat Analysis (GPT-4o-mini)</h3></div>',
                unsafe_allow_html=True)
    render_threat_badge(result["threat_level"])
    st.markdown(result["analysis"])

    st.divider()

    # IR Advisor lives directly below the AI analysis output
    render_ir_section(result)


def render_exports(packets, result):
    st.markdown('<div class="section-header"><h3>Export Reports</h3></div>',
                unsafe_allow_html=True)
    col1, col2, col3 = st.columns(3)

    with col1:
        json_str = json.dumps(packets, indent=2)
        st.download_button(
            label="Download scan_results.json",
            data=json_str,
            file_name=f"maxguard_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

    with col2:
        violations = [p for p in packets if p.get("pci_violation")]
        if violations:
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=violations[0].keys())
            writer.writeheader()
            writer.writerows(violations)
            st.download_button(
                label="Download violations.csv",
                data=output.getvalue(),
                file_name=f"maxguard_violations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )

    with col3:
        summary = f"""MAX-GUARD EXECUTIVE SUMMARY
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*50}

THREAT LEVEL: {result['threat_level']}
SEVERITY SCORE: {result['severity']['overall_score']}/10
TOTAL PACKETS: {result['total_packets']}
TOTAL VIOLATIONS: {result['total_violations']}

VIOLATIONS FOUND:
{chr(10).join(f'- {v}' for v in result['violation_types'])}

AFFECTED DEVICES:
{chr(10).join(f"- {d['ip']} ({d['device_type']}): {d['violation_count']} violations" for d in result['affected_devices'])}

FULL AI ANALYSIS:
{result['analysis']}
"""
        st.download_button(
            label="Download executive_summary.txt",
            data=summary,
            file_name=f"maxguard_executive_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain"
        )


def display_results(packets):
    if not packets:
        st.warning("No packets captured.")
        return

    with st.spinner("Running AI threat analysis..."):
        result = get_threat_summary(packets)

    # Generate local AI explanations only for packets flagged as PCI-DSS violations.
    # Convert each packet into the finding format expected by the Ollama client.
    violations = [p for p in packets if p.get("pci_violation")]

    if violations:
        findings = []

        for packet in violations:
            violation_type = (
                packet.get("violation_detail")
                or "Unknown PCI-DSS violation"
            )

            # Only map a control when the existing finding identifies it.
            controls = []
            if "PCI DSS 4.2.1" in violation_type:
                controls.append({
                    "framework": "PCI-DSS",
                    "control_id": "4.2.1",
                })

            findings.append({
                "rule_id": violation_type,
                "title": violation_type,
                "protocol": packet.get("protocol") or "Unknown",
                "dst_port": (
                    packet.get("dst_port")
                    or packet.get("src_port")
                    or "Unknown"
                ),
                "details": (
                    f"{violation_type}. "
                    f"Source IP: {packet.get('src_ip') or 'Unknown'}. "
                    f"Destination IP: {packet.get('dst_ip') or 'Unknown'}."
                ),
                "controls": controls,
            })

        # If local Ollama is unavailable, preserve the scan results and
        # use a fallback message instead of stopping the dashboard.
        try:
            with st.spinner("Generating local AI explanations..."):
                explain_all(findings)

        except AIUnavailable:
            st.warning(
                "Local AI is unavailable. "
                "Reports will still be generated without AI explanations."
            )
            for finding in findings:
                finding["explanation"] = "Local AI unavailable"

        # Attach each generated explanation to its original packet so the
	# violations table and exported results can display it.
        for packet, finding in zip(violations, findings):
            packet["explanation"] = finding["explanation"]



    render_overview_metrics(packets, result)
    st.divider()
    render_charts(packets, result)
    st.divider()

    st.markdown('<div class="section-header"><h3>All Captured Packets</h3></div>',
                unsafe_allow_html=True)
    st.dataframe(pd.DataFrame(packets), use_container_width=True)
    st.divider()

    render_violations_table(packets)
    st.divider()
    render_affected_devices(result)
    st.divider()
    render_investigation_guides(result)
    st.divider()
    render_ai_analysis(result)   # IR section lives inside here
    st.divider()
    render_exports(packets, result)


# ── Entrypoint ─────────────────────────────────────────────────────────────────
if IS_CLOUD:
    st.sidebar.markdown("### Upload Scan Results")
    uploaded_file = st.sidebar.file_uploader("Upload scan_results.json", type="json")
    if uploaded_file is not None:
        packets = load_packets_from_file(uploaded_file)
        st.success(f"Loaded {len(packets)} packets from file.")
        display_results(packets)
    else:
        st.info("Upload a scan_results.json file from the sidebar to begin analysis.")
else:
    st.sidebar.markdown("### Scan Settings")
    packet_count = st.sidebar.slider("Packets to capture", 10, 500, 100, step=10)
    st.sidebar.divider()
    st.sidebar.markdown("### Load Previous Scan")
    uploaded_file = st.sidebar.file_uploader("Upload scan_results.json", type="json")

    if uploaded_file is not None:
        packets = load_packets_from_file(uploaded_file)
        st.success(f"Loaded {len(packets)} packets from uploaded file.")
        display_results(packets)
    elif st.sidebar.button("Start Live Scan", type="primary"):
        packets = run_local_scan(packet_count)
        display_results(packets)
    else:
        st.markdown("""
<div style="text-align:center; padding:40px 0 24px 0;">
    <div style="font-size:52px; margin-bottom:12px;">🛡️</div>
    <div style="font-size:26px; font-weight:700; color:#e2e8f0; margin-bottom:8px;">Welcome to Max-Guard</div>
    <div style="font-size:14px; color:#475569; max-width:540px; margin:0 auto; line-height:1.7;">
        AI-driven PCI-DSS v4.0 compliance scanner for retail environments.
        Capture live network traffic, detect violations in real time, and get
        AI-powered incident response plans.
    </div>
</div>
""", unsafe_allow_html=True)

        c1, c2, c3, c4 = st.columns(4)
        features = [
            ("🔍", "Live Capture",     "Real-time packet sniffing with Scapy. Set packet count and click Start Live Scan."),
            ("⚡", "AI Analysis",      "GPT-4o-mini analyzes each scan and flags PCI-DSS violations instantly."),
            ("📋", "Compliance Export","Export JSON, CSV, and executive summary reports for audit or review."),
            ("🚨", "IR Advisor",       "AI-generated 5-step incident response plan tailored to your exact threats."),
        ]
        for col, (icon, title, desc) in zip([c1, c2, c3, c4], features):
            with col:
                st.markdown(f"""
<div class="welcome-card">
    <div class="welcome-card-icon">{icon}</div>
    <div class="welcome-card-title">{title}</div>
    <div class="welcome-card-desc">{desc}</div>
</div>
""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        qs_col1, qs_col2 = st.columns(2)
        with qs_col1:
            st.markdown("""
<div style="background:linear-gradient(135deg,#0c1a36,#080f20);border:1px solid #1e3a5f;
            border-radius:10px;padding:20px 22px;height:100%;">
    <div style="color:#3B8BD4;font-size:10px;font-weight:700;text-transform:uppercase;
                letter-spacing:1.2px;margin-bottom:12px;">🖥️ Live Scan</div>
    <div style="color:#94a3b8;font-size:13px;line-height:1.7;">
        1. Run as <strong style="color:#e2e8f0;">Administrator</strong><br>
        2. Set packet count with the slider<br>
        3. Click <strong style="color:#3B8BD4;">Start Live Scan</strong> in the sidebar
    </div>
</div>
""", unsafe_allow_html=True)
        with qs_col2:
            st.markdown("""
<div style="background:linear-gradient(135deg,#0c1a36,#080f20);border:1px solid #1e3a5f;
            border-radius:10px;padding:20px 22px;height:100%;">
    <div style="color:#22c55e;font-size:10px;font-weight:700;text-transform:uppercase;
                letter-spacing:1.2px;margin-bottom:12px;">☁️ Upload Results</div>
    <div style="color:#94a3b8;font-size:13px;line-height:1.7;">
        1. Export <code>scan_results.json</code> from a local scan<br>
        2. Use the <strong style="color:#e2e8f0;">sidebar uploader</strong><br>
        3. Analysis runs automatically on upload
    </div>
</div>
""", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("""
<div style="background:linear-gradient(135deg,#0c1a36,#080f20);border:1px solid #1e3a5f;
            border-radius:10px;padding:18px 22px;">
    <div style="color:#64748b;font-size:10px;font-weight:700;text-transform:uppercase;
                letter-spacing:1.2px;margin-bottom:14px;">PCI-DSS Violations Detected</div>
    <div style="display:flex;flex-wrap:wrap;gap:8px;">
        <span style="background:#3a0f0f;color:#f87171;padding:5px 14px;border-radius:6px;font-size:11px;font-weight:700;font-family:monospace;">FTP &nbsp;:21</span>
        <span style="background:#3a0f0f;color:#f87171;padding:5px 14px;border-radius:6px;font-size:11px;font-weight:700;font-family:monospace;">Telnet :23</span>
        <span style="background:#3a1a00;color:#fb923c;padding:5px 14px;border-radius:6px;font-size:11px;font-weight:700;font-family:monospace;">HTTP &nbsp;:80</span>
        <span style="background:#3a1a00;color:#fb923c;padding:5px 14px;border-radius:6px;font-size:11px;font-weight:700;font-family:monospace;">HTTP-Alt :8080</span>
        <span style="background:#3a2400;color:#fbbf24;padding:5px 14px;border-radius:6px;font-size:11px;font-weight:700;font-family:monospace;">POP3 :110</span>
        <span style="background:#3a2400;color:#fbbf24;padding:5px 14px;border-radius:6px;font-size:11px;font-weight:700;font-family:monospace;">IMAP :143</span>
        <span style="background:#1e2a3a;color:#60a5fa;padding:5px 14px;border-radius:6px;font-size:11px;font-weight:700;font-family:monospace;">RDP &nbsp;:3389</span>
    </div>
    <div style="margin-top:12px;color:#334155;font-size:11px;">All detections mapped to PCI-DSS v4.0 Requirement 4.2.1 and 1.3.2</div>
</div>
""", unsafe_allow_html=True)
