"""
Aegis AI SOC Dashboard — Steps 15 & 16.
Run: streamlit run dashboard/app.py
"""
import sys
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict, Counter

sys.path.insert(0, str(Path(__file__).parent.parent))

import streamlit as st

from collector.collector import load_events, event_count
from alerts.manager import load_alerts, alert_count

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Aegis AI SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
.metric-card { background:#1e2737; border-radius:8px; padding:16px 20px; }
.sev-critical { color:#f87171; font-weight:700; }
.sev-high     { color:#fb923c; font-weight:700; }
.sev-medium   { color:#fbbf24; font-weight:600; }
.sev-low      { color:#4ade80; }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ───────────────────────────────────────────────────────────────────
st.sidebar.title("🛡️ Aegis AI SOC")
st.sidebar.caption("AI Security Operations Center")
page = st.sidebar.radio("View", ["Dashboard", "Alerts", "Events", "Incident Detail"])
st.sidebar.divider()
if st.sidebar.button("🔄 Refresh"):
    st.rerun()

# ── Data loading ─────────────────────────────────────────────────────────────
@st.cache_data(ttl=10)
def get_events():
    return load_events()

@st.cache_data(ttl=10)
def get_alerts():
    return load_alerts()

events = get_events()
alerts = get_alerts()

SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
SEV_COLOR = {"critical": "sev-critical", "high": "sev-high", "medium": "sev-medium", "low": "sev-low"}


# ── Dashboard ─────────────────────────────────────────────────────────────────
if page == "Dashboard":
    st.title("Aegis AI — Security Operations Center")

    counts = alert_count()
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Events", f"{len(events):,}")
    col2.metric("Total Alerts", f"{counts['total']:,}")
    col3.metric("🔴 Critical", f"{counts.get('critical', 0)}")
    col4.metric("🟠 High", f"{counts.get('high', 0)}")

    st.divider()

    # Event timeline
    st.subheader("Security Events Over Time")
    if events:
        by_hour: dict[str, int] = defaultdict(int)
        for e in events:
            try:
                t = datetime.fromisoformat(e["timestamp"])
                by_hour[t.strftime("%H:00")] += 1
            except Exception:
                pass
        if by_hour:
            hours = sorted(by_hour.keys())
            st.bar_chart({h: by_hour[h] for h in hours})
    else:
        st.info("No events yet. Run `python evaluation/generate_traffic.py` first.")

    st.divider()

    col_a, col_b = st.columns(2)

    with col_a:
        st.subheader("Events by Application")
        app_counts = Counter(e.get("application", "unknown") for e in events)
        if app_counts:
            st.bar_chart(dict(app_counts.most_common()))

    with col_b:
        st.subheader("Events by Type")
        type_counts = Counter(e.get("event_type", "unknown") for e in events)
        if type_counts:
            st.bar_chart(dict(type_counts.most_common(8)))

    st.divider()

    st.subheader("Recent Alerts")
    if alerts:
        for a in sorted(alerts, key=lambda x: x.get("timestamp", ""), reverse=True)[:10]:
            sev = a.get("severity", "low")
            emoji = SEV_EMOJI.get(sev, "⚪")
            st.markdown(
                f"{emoji} **{a.get('alert_id','?')}** — {a.get('reason','')[:100]}  "
                f"`{sev.upper()}` · user: `{a.get('user_id','?')}` · {a.get('timestamp','')[:19]}"
            )
    else:
        st.info("No alerts yet. Run `python evaluation/replay.py` to generate them.")


# ── Alerts ────────────────────────────────────────────────────────────────────
elif page == "Alerts":
    st.title("Alerts")

    sev_filter = st.selectbox("Severity", ["all", "critical", "high", "medium", "low"])
    filtered = alerts if sev_filter == "all" else [a for a in alerts if a.get("severity") == sev_filter]

    st.caption(f"{len(filtered)} alerts")

    if filtered:
        for a in sorted(filtered, key=lambda x: x.get("timestamp", ""), reverse=True):
            sev = a.get("severity", "low")
            with st.expander(f"{SEV_EMOJI.get(sev,'⚪')} {a.get('alert_id','?')} — {a.get('reason','')[:80]}"):
                col1, col2 = st.columns(2)
                col1.markdown(f"**Severity:** `{sev.upper()}`")
                col1.markdown(f"**User:** `{a.get('user_id','?')}`")
                col2.markdown(f"**Time:** {a.get('timestamp','')[:19]}")
                col2.markdown(f"**Type:** {a.get('incident_type','?')}")
                st.markdown(f"**Rules fired:** {', '.join(a.get('rules_fired', []))}")
                st.markdown(f"**Reason:** {a.get('reason','')}")
                if a.get("event_ids"):
                    st.markdown(f"**Related events:** {', '.join(a['event_ids'][:5])}")
    else:
        st.info("No alerts match the filter.")


# ── Events ────────────────────────────────────────────────────────────────────
elif page == "Events":
    st.title("Event Log")

    user_filter = st.text_input("Filter by user (blank = all)", "")
    type_filter = st.selectbox("Event type", ["all"] + sorted({e.get("event_type","") for e in events}))

    filtered = events
    if user_filter:
        filtered = [e for e in filtered if e.get("user_id") == user_filter]
    if type_filter != "all":
        filtered = [e for e in filtered if e.get("event_type") == type_filter]

    st.caption(f"{len(filtered)} events")

    cols = st.columns([2, 2, 2, 2, 1, 1])
    cols[0].markdown("**Timestamp**")
    cols[1].markdown("**User**")
    cols[2].markdown("**Application**")
    cols[3].markdown("**Event Type**")
    cols[4].markdown("**Risk**")
    cols[5].markdown("**Decision**")

    for e in sorted(filtered, key=lambda x: x.get("timestamp",""), reverse=True)[:200]:
        cols = st.columns([2, 2, 2, 2, 1, 1])
        cols[0].text(e.get("timestamp","")[:19])
        cols[1].text(e.get("user_id",""))
        cols[2].text(e.get("application",""))
        cols[3].text(e.get("event_type",""))
        sev = e.get("risk","low")
        cols[4].markdown(f"<span class='{SEV_COLOR.get(sev,'')}'>{sev}</span>", unsafe_allow_html=True)
        cols[5].text(e.get("decision",""))


# ── Incident Detail ────────────────────────────────────────────────────────────
elif page == "Incident Detail":
    st.title("Incident Investigation")
    st.caption("Select an alert to view the full attack chain.")

    if not alerts:
        st.info("No alerts available. Run the replay first.")
    else:
        alert_options = {
            f"{a.get('alert_id','?')} [{a.get('severity','?').upper()}] — {a.get('user_id','?')} — {a.get('reason','')[:60]}": a
            for a in sorted(alerts, key=lambda x: x.get("timestamp",""), reverse=True)
        }
        choice = st.selectbox("Alert", list(alert_options.keys()))
        selected = alert_options[choice]

        sev = selected.get("severity","low")
        st.markdown(f"### {SEV_EMOJI.get(sev,'⚪')} {selected.get('alert_id','?')} — `{sev.upper()}`")

        col1, col2 = st.columns(2)
        col1.markdown(f"**User:** `{selected.get('user_id','?')}`")
        col1.markdown(f"**Type:** {selected.get('incident_type','?')}")
        col2.markdown(f"**Detected:** {selected.get('timestamp','')[:19]}")
        col2.markdown(f"**Rules:** {', '.join(selected.get('rules_fired',[]))}")

        st.divider()
        st.markdown(f"**Reason:** {selected.get('reason','')}")

        # Attack chain: fetch related events
        related_ids = set(selected.get("event_ids", []))
        user = selected.get("user_id")
        related_events = [
            e for e in events
            if e.get("event_id") in related_ids or e.get("user_id") == user
        ]
        related_events = sorted(related_events, key=lambda e: e.get("timestamp",""))

        if related_events:
            st.divider()
            st.subheader("Attack Chain")
            for e in related_events[:20]:
                sev_e = e.get("risk","low")
                emoji = SEV_EMOJI.get(sev_e,"⚪")
                tool = f" → `{e['tool']}`" if e.get("tool") else ""
                doc = f" `{e['document']}`" if e.get("document") else ""
                decision = e.get("decision","")
                badge = "🚫" if decision == "blocked" else ("⚠️" if decision == "flagged" else "✓")
                st.markdown(
                    f"`{e.get('timestamp','')[:19]}` {emoji} **{e.get('event_type','')}**"
                    f"{tool}{doc} {badge} `{decision}`"
                )
