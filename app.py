from pathlib import Path
from datetime import datetime
from io import BytesIO
from urllib.parse import quote
import ipaddress
import os
import re
import subprocess

import pandas as pd
import plotly.express as px
import requests
import streamlit as st

from log_parser import classify
from detection_engine import detect_events


# =========================================================
# CONFIGURATION
# =========================================================

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_LOG = BASE_DIR / "export" / "kali_journal.log"
VT_BASE = "https://www.virustotal.com/api/v3"

st.set_page_config(
    page_title="SHIELD | Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# =========================================================
# THEME
# =========================================================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Inter:wght@400;500;600;700;800&display=swap');

:root {
    --shield-bg: #080C09;
    --shield-panel: #101812;
    --shield-panel-2: #141F17;
    --shield-border: #263B2B;
    --shield-green: #55F477;
    --shield-text: #E6F2E8;
    --shield-muted: #A5B7A8;
}

html, body, [class*="css"] {
    font-family: Inter, sans-serif;
}

.stApp {
    background: var(--shield-bg);
    color: var(--shield-text);
}

[data-testid="stHeader"] {
    background: #080C09;
}

[data-testid="stSidebar"] {
    background: #0B120D;
    border-right: 1px solid var(--shield-border);
}

.block-container {
    padding-top: 1.5rem;
    max-width: 1600px;
}

h1, h2, h3, h4 {
    color: #F0FFF2 !important;
}

p, label, .stMarkdown {
    color: var(--shield-text);
}

.stCaption, [data-testid="stCaptionContainer"] {
    color: var(--shield-muted) !important;
}

.shield-header {
    padding: 24px;
    border: 1px solid #347A43;
    border-radius: 12px;
    background: linear-gradient(120deg, #122319, #090F0B);
    margin-bottom: 24px;
    box-shadow: 0 0 22px rgba(85,244,119,0.07);
}

.shield-title {
    color: var(--shield-green);
    font-family: 'Share Tech Mono', monospace;
    font-size: 38px;
    font-weight: 800;
    letter-spacing: 5px;
    text-shadow: 0 0 14px rgba(85,244,119,0.3);
}

.shield-subtitle {
    color: #B6CDBA;
    font-size: 12px;
    margin-top: 7px;
    letter-spacing: 1px;
}

.metric-card {
    background: var(--shield-panel);
    border: 1px solid var(--shield-border);
    border-radius: 10px;
    padding: 18px;
    min-height: 108px;
}

.metric-label {
    color: #B3C5B7;
    font-size: 11px;
    letter-spacing: 1px;
}

.metric-value {
    color: var(--shield-green);
    font-family: 'Share Tech Mono', monospace;
    font-size: 29px;
    font-weight: 800;
    margin-top: 9px;
}

.small-muted {
    color: var(--shield-muted);
    font-size: 12px;
}

[data-testid="stDataFrame"] {
    border: 1px solid var(--shield-border);
    border-radius: 9px;
}

.stButton button, .stDownloadButton button {
    background: #14251A;
    color: #E8F5EA;
    border: 1px solid #347A43;
    border-radius: 7px;
    font-weight: 600;
    transition: all 0.18s ease;
}

.stButton button:hover, .stDownloadButton button:hover {
    background: #1D3925;
    color: var(--shield-green);
    border-color: var(--shield-green);
    box-shadow: 0 0 12px rgba(85,244,119,0.15);
}

[data-testid="stSidebar"] div[role="radiogroup"] label {
    border-radius: 7px;
    padding: 8px 10px;
    margin: 2px 0;
    border: 1px solid transparent;
}

[data-testid="stSidebar"] div[role="radiogroup"] label:hover {
    background: #17291C;
    border-color: #347A43;
}

[data-testid="stSidebar"] [aria-checked="true"] {
    background: #193422;
    border-color: #55F477;
}

[data-testid="stMetricValue"] {
    color: var(--shield-green);
}

.stProgress > div > div > div > div {
    background-color: var(--shield-green);
}

input, textarea, [data-baseweb="select"] {
    background-color: #111A13 !important;
    color: #E6F2E8 !important;
}

hr {
    border-color: var(--shield-border);
}

div[data-testid="stAlert"] {
    border: 1px solid var(--shield-border);
}

.js-plotly-plot .plotly text {
    fill: #DDEBE0 !important;
}

.js-plotly-plot .legend text {
    fill: #E6F2E8 !important;
}

footer {
    visibility: hidden;
}
</style>
""", unsafe_allow_html=True)


# =========================================================
# LOG ANALYSIS
# =========================================================

@st.cache_data(show_spinner=False)
@st.cache_data(show_spinner=False)
def load_logs(path, mtime_ns=0, file_size=0):
    path = Path(path)

    columns = [
        "Line", "Timestamp", "Event Type", "Raw Log",
        "Event ID", "Level", "Provider", "Message"
    ]

    if not path.is_file():
        return pd.DataFrame(columns=columns)

    records = []

    try:
        if path.suffix.lower() == ".json":
            from log_parser import load_windows_json

            records = load_windows_json(path)

        else:
            with path.open(
                "r", encoding="utf-8", errors="replace"
            ) as file:
                for number, raw in enumerate(file, start=1):
                    raw = raw.rstrip("\r\n")
                    if not raw.strip():
                        continue

                    match = re.match(
                        r"^(\d{4}-\d{2}-\d{2}[T ][^\s]+)", raw
                    )
                    timestamp = match.group(1) if match else "Unknown"

                    try:
                        event_type = classify(raw)
                    except Exception:
                        event_type = "other"

                    records.append({
                        "Line": number,
                        "Timestamp": timestamp,
                        "Event Type": str(event_type),
                        "Raw Log": raw,
                        "Event ID": None,
                        "Level": None,
                        "Provider": None,
                        "Message": raw,
                    })

    except (OSError, ValueError, json.JSONDecodeError) as exc:
        st.error(f"Could not read log file: {exc}")

    return pd.DataFrame(records, columns=columns)

    records = []

    try:
        with path.open("r", encoding="utf-8", errors="replace") as file:
            for number, raw in enumerate(file, start=1):
                raw = raw.rstrip("\r\n")
                if not raw.strip():
                    continue

                match = re.match(
                    r"^(\d{4}-\d{2}-\d{2}[T ][^\s]+)", raw
                )
                timestamp = match.group(1) if match else "Unknown"

                try:
                    event_type = classify(raw)
                except Exception:
                    event_type = "other"

                records.append({
                    "Line": number,
                    "Timestamp": timestamp,
                    "Event Type": str(event_type),
                    "Raw Log": raw,
                })
    except OSError as exc:
        st.error(f"Could not read log file: {exc}")

    return pd.DataFrame(records, columns=columns)


@st.cache_data(show_spinner=False)
def get_alerts(log_path=None, mtime_ns=0, file_size=0):
    try:
        result = detect_events(log_path or DEFAULT_LOG)
        if isinstance(result, pd.DataFrame):
            return result.to_dict("records")
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            for key in ("alerts", "events", "detections", "results"):
                if isinstance(result.get(key), list):
                    return result[key]
            return [result]
        return []
    except Exception as exc:
        st.warning(f"Detection engine error: {exc}")
        return []


def normalise_alert(alert):
    if isinstance(alert, dict):
        return {str(k): v for k, v in alert.items()}
    return {"Details": str(alert)}


def get_value(item, *keys, default="Unknown"):
    for key in keys:
        if key in item and item[key] not in (None, ""):
            return item[key]
    return default


@st.cache_data(show_spinner=False)
def extract_ip_iocs(df):
    """Extract unique valid IPv4/IPv6 addresses from log lines."""
    results = {}

    if df.empty:
        return pd.DataFrame(
            columns=["IP Address", "Type", "Occurrences", "Example Log"]
        )

    # Candidate matching; ipaddress validates every candidate afterward.
    pattern = re.compile(
        r"(?<![0-9A-Fa-f:.])"
        r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}"
        r"(?![0-9A-Fa-f.])"
        r"|"
        r"(?<![0-9A-Fa-f:])"
        r"[0-9A-Fa-f:]{2,39}"
        r"(?![0-9A-Fa-f:])"
    )

    for _, row in df.iterrows():
        raw = str(row.get("Raw Log", ""))

        for candidate in pattern.findall(raw):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue

            address = str(ip)

            if ip.is_loopback:
                category = "Loopback"
            elif ip.is_global:
                category = "Public"
            elif ip.is_private and not ip.is_reserved:
                category = "Private"
            else:
                category = "Other/Reserved"

            if address not in results:
                results[address] = {
                    "IP Address": address,
                    "Type": category,
                    "Occurrences": 0,
                    "Example Log": raw[:500],
                }

            results[address]["Occurrences"] += 1

    return pd.DataFrame(list(results.values()))


def show_vt_ip_result(report):
    st.markdown(f"### VirusTotal report: `{report['indicator']}`")

    a, b, c, d = st.columns(4)
    a.metric("Malicious", report["malicious"])
    b.metric("Suspicious", report["suspicious"])
    c.metric("Harmless", report["harmless"])
    d.metric("Engines with results", report["total_engines"])

    if report["malicious"] > 0:
        st.error("Some engines flagged this IP. Investigate the evidence.")
    elif report["suspicious"] > 0:
        st.warning("Some engines marked this IP suspicious. Review context.")
    else:
        st.info(
            "No malicious or suspicious detections in this report. "
            "This does not guarantee the IP is safe."
        )

    st.write("**Country:**", report.get("country") or "Not provided")
    st.write("**Network owner:**", report.get("as_owner") or "Not provided")
    st.link_button("Open full VirusTotal report", report["report_url"])


# =========================================================
# VIRUSTOTAL: API KEY AND INPUT VALIDATION
# =========================================================

def get_vt_api_key():
    """Read key from Streamlit secrets or environment, never from source code."""
    try:
        secret = st.secrets.get("VT_API_KEY", "")
    except Exception:
        secret = ""

    return str(secret or os.environ.get("VT_API_KEY", "")).strip()


def validate_indicator(kind, raw_value):
    value = raw_value.strip()

    if not value:
        raise ValueError("Enter an IP address or domain.")

    if any(char in value for char in ("\n", "\r", "\t", " ")):
        raise ValueError("Spaces are not allowed in an indicator.")

    if kind == "IP address":
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            raise ValueError("Enter a valid IPv4 or IPv6 address.")

        if not parsed.is_global:
            raise ValueError(
                "Only public global IP addresses can be queried. "
                "Private, loopback, link-local and reserved IPs are blocked."
            )

        return str(parsed)

    # Accept a bare domain, not a URL, path, port or wildcard.
    value = value.rstrip(".").lower()

    if "://" in value or "/" in value or ":" in value or "*" in value:
        raise ValueError(
            "Enter only a domain, e.g. example.com — not a URL or path."
        )

    if len(value) > 253 or "." not in value:
        raise ValueError("Enter a valid fully qualified domain name.")

    labels = value.split(".")

    for label in labels:
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not re.fullmatch(r"[a-z0-9-]+", label)
        ):
            raise ValueError("The domain format is invalid.")

    return value


def virustotal_lookup(kind, indicator, api_key):
    """
    Read-only VirusTotal API v3 report lookup.
    Does not submit a new scan or upload a file.
    """
    if kind == "IP address":
        endpoint = f"{VT_BASE}/ip_addresses/{quote(indicator, safe=':')}"
    else:
        endpoint = f"{VT_BASE}/domains/{quote(indicator, safe='')}"

    headers = {
        "x-apikey": api_key,
        "accept": "application/json",
    }

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            timeout=(5, 20),
        )
    except requests.Timeout:
        raise RuntimeError("VirusTotal request timed out. Try again later.")
    except requests.RequestException as exc:
        raise RuntimeError(f"Network request failed: {exc}")

    if response.status_code == 401:
        raise RuntimeError("API key rejected. Check your VirusTotal API key.")
    if response.status_code == 403:
        raise RuntimeError(
            "Access denied. This endpoint may be restricted for your account."
        )
    if response.status_code == 404:
        raise RuntimeError(
            "No report found for this indicator. This is not proof it is safe."
        )
    if response.status_code == 429:
        raise RuntimeError(
            "VirusTotal rate/quota limit reached. Wait before trying again."
        )
    if response.status_code == 400:
        raise RuntimeError("VirusTotal rejected the indicator format.")
    if response.status_code != 200:
        raise RuntimeError(
            f"VirusTotal returned HTTP {response.status_code}. "
            "No verdict has been inferred."
        )

    try:
        payload = response.json()
        data = payload["data"]["attributes"]
    except (ValueError, KeyError, TypeError):
        raise RuntimeError("VirusTotal returned an unexpected response.")

    stats = data.get("last_analysis_stats") or {}

    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("harmless", 0) or 0)
    undetected = int(stats.get("undetected", 0) or 0)
    timeout_count = int(stats.get("timeout", 0) or 0)
    total = sum([
        malicious, suspicious, harmless, undetected, timeout_count
    ])

    return {
        "indicator": indicator,
        "kind": kind,
        "reputation": data.get("reputation"),
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": timeout_count,
        "total_engines": total,
        "country": data.get("country"),
        "as_owner": data.get("as_owner"),
        "asn": data.get("asn"),
        "last_analysis_date": data.get("last_analysis_date"),
        "last_analysis_stats": stats,
        "report_url": (
            f"https://www.virustotal.com/gui/ip-address/{indicator}"
            if kind == "IP address"
            else f"https://www.virustotal.com/gui/domain/{indicator}"
        ),
    }


# =========================================================
# PDF REPORT
# =========================================================

def create_pdf_report(df, alerts, source_name):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        )
    except ImportError:
        return None

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        rightMargin=35, leftMargin=35,
        topMargin=35, bottomMargin=35,
    )
    styles = getSampleStyleSheet()

    story = [
        Paragraph("SHIELD Security Analysis Report", styles["Title"]),
        Paragraph(f"Source: {source_name}", styles["Normal"]),
        Paragraph(
            "Generated: " + datetime.now().astimezone().isoformat(
                timespec="seconds"
            ),
            styles["Normal"],
        ),
        Spacer(1, 16),
        Paragraph("Summary", styles["Heading2"]),
    ]

    rows = [
        ["Metric", "Value"],
        ["Log lines", str(len(df))],
        [
            "Event categories",
            str(df["Event Type"].nunique()) if not df.empty else "0",
        ],
        ["Detection patterns", str(len(alerts))],
    ]

    table = Table(rows, colWidths=[270, 180])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123B40")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7),
    ]))
    story.extend([table, Spacer(1, 16)])

    if not df.empty:
        story.append(Paragraph("Event Categories", styles["Heading2"]))
        counts = df["Event Type"].value_counts().head(30)
        event_rows = [["Event type", "Log lines"]]
        event_rows.extend([[str(k), str(v)] for k, v in counts.items()])

        event_table = Table(event_rows, colWidths=[300, 150], repeatRows=1)
        event_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#123B40")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 5),
        ]))
        story.extend([event_table, Spacer(1, 16)])

    story.append(Paragraph("Detection Results", styles["Heading2"]))

    if not alerts:
        story.append(Paragraph("No structured detections.", styles["Normal"]))
    else:
        for index, raw_alert in enumerate(alerts, start=1):
            alert = normalise_alert(raw_alert)
            text = f"<b>Detection {index}</b><br/>"
            for key, value in alert.items():
                safe_key = str(key).replace("&", "&amp;").replace("<", "&lt;")
                safe_value = (
                    str(value).replace("&", "&amp;")
                    .replace("<", "&lt;").replace(">", "&gt;")
                )
                text += f"{safe_key}: {safe_value}<br/>"
            story.extend([
                Paragraph(text, styles["Normal"]),
                Spacer(1, 8),
            ])

    story.extend([
        Spacer(1, 12),
        Paragraph(
            "Rule-based detections are investigative leads, not proof "
            "of an attack. Log-line counts are not necessarily unique "
            "incidents. Unmatched events are not automatically safe.",
            styles["Italic"],
        ),
    ])

    doc.build(story)
    return buffer.getvalue()


# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.markdown("""
<div class="shield-title" style="font-size:27px;">🛡 SHIELD</div>
<div class="shield-subtitle">SECURITY OPERATIONS CENTER</div>
""", unsafe_allow_html=True)

st.sidebar.divider()

page = st.sidebar.radio(
    "NAVIGATION",
    [
        "Overview",
        "Threat Investigation",
        "Event Explorer",
        "IOC Extraction",
        "IP & Domain Lookup",
        "Reports",
    ],
)

st.sidebar.divider()
st.sidebar.markdown("### Log Source")

if "active_log" not in st.session_state:
    st.session_state.active_log = str(DEFAULT_LOG)

uploaded = st.sidebar.file_uploader(
    "Upload a log file",
    type=["log", "txt", "journal", "csv", "json"],
)

if uploaded is not None:
    upload_dir = BASE_DIR / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    upload_path = upload_dir / Path(uploaded.name).name
    contents = uploaded.getvalue()

    if not upload_path.exists() or upload_path.read_bytes() != contents:
        upload_path.write_bytes(contents)

    st.session_state.active_log = str(upload_path)

active_log = Path(st.session_state.active_log)

st.sidebar.caption(f"Active source: {active_log.name}")

if st.sidebar.button("Use default Kali log", use_container_width=True):
    st.session_state.active_log = str(DEFAULT_LOG)
    st.rerun()

if st.sidebar.button("Export available local logs", use_container_width=True):
    try:
        export_dir = BASE_DIR / "export"
        export_dir.mkdir(parents=True, exist_ok=True)
        output_file = export_dir / "kali_journal.log"

        proc = subprocess.run(
            ["journalctl", "--no-pager", "-o", "short-iso"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if proc.returncode == 0 and proc.stdout.strip():
            output_file.write_text(proc.stdout, encoding="utf-8")
            st.session_state.active_log = str(output_file)
            st.sidebar.success(
                f"Exported {len(proc.stdout.splitlines()):,} lines."
            )
            st.rerun()
        else:
            st.sidebar.error(
                (proc.stderr.strip() or "No journal output.")[:400]
            )
    except Exception as exc:
        st.sidebar.error(f"Export failed: {exc}")

st.sidebar.divider()
st.sidebar.caption("Evidence-first analysis • Local log processing")


# =========================================================
# SHARED DATA AND HEADER
# =========================================================

log_stat = Path(active_log).stat() if Path(active_log).is_file() else None
log_mtime_ns = log_stat.st_mtime_ns if log_stat else 0
log_file_size = log_stat.st_size if log_stat else 0

df = load_logs(str(active_log), log_mtime_ns, log_file_size)

try:
    is_default_source = active_log.resolve() == DEFAULT_LOG.resolve()
except OSError:
    is_default_source = False

alerts = get_alerts(str(active_log), log_mtime_ns, log_file_size)

st.markdown("""
<div class="shield-header">
    <div class="shield-title">SHIELD</div>
    <div style="font-size:17px;color:#E5EDF5;font-weight:600;margin-top:7px;">
        Technology That Protects. Intelligence That Empowers.
    </div>
    <div class="shield-subtitle">
        SECURITY OPERATIONS • LOG INTELLIGENCE • INVESTIGATION
    </div>
</div>
""", unsafe_allow_html=True)


# =========================================================
# IOC EXTRACTION AND MANUAL LOOKUP
# =========================================================

if page == "IOC Extraction":
    st.subheader("IOC Extraction")
    st.write(
        "Extract unique IP addresses from the active log file. "
        "Extraction is local; VirusTotal is contacted only when you "
        "explicitly submit a lookup."
    )

    st.info(f"Active log source: {active_log.name}")

    iocs = extract_ip_iocs(df)

    if iocs.empty:
        st.warning("No valid IP addresses were found in the loaded logs.")
    else:
        public_count = int((iocs["Type"] == "Public").sum())
        private_count = int((iocs["Type"] == "Private").sum())
        other_count = int((iocs["Type"] == "Other/Reserved").sum())

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Unique IPs", len(iocs))
        m2.metric("Public IPs", public_count)
        m3.metric("Private IPs", private_count)
        m4.metric("Other/Reserved", other_count)

        st.markdown("### Extracted indicators")
        st.dataframe(iocs, use_container_width=True, hide_index=True)

        st.download_button(
            "Download extracted IPs as CSV",
            iocs.to_csv(index=False).encode("utf-8"),
            file_name="shield_extracted_iocs.csv",
            mime="text/csv",
        )

        public_ips = sorted(
            iocs.loc[iocs["Type"] == "Public", "IP Address"].unique().tolist()
        )

        st.divider()
        st.markdown("### Manually investigate a public IP")

        if not public_ips:
            st.warning(
                "No public global IPs were found. Private and reserved "
                "addresses cannot be queried from this page."
            )
        else:
            api_key = get_vt_api_key()

            if not api_key:
                st.warning(
                    "VirusTotal API key is not configured. Set VT_API_KEY "
                    "in the terminal, then restart Streamlit."
                )

            with st.form("ioc_manual_vt_form"):
                selected_ip = st.selectbox(
                    "Choose an extracted public IP",
                    public_ips,
                )
                lookup_clicked = st.form_submit_button(
                    "Look up selected IP on VirusTotal",
                    disabled=not bool(api_key),
                    use_container_width=True,
                )

            if lookup_clicked:
                try:
                    with st.spinner("Retrieving existing report..."):
                        report = virustotal_lookup(
                            "IP address", selected_ip, api_key
                        )
                    st.session_state["ioc_vt_report"] = report
                except (ValueError, RuntimeError) as exc:
                    st.error(str(exc))

            report = st.session_state.get("ioc_vt_report")
            if report:
                show_vt_ip_result(report)

    st.caption(
        "Public IPs can still be shared infrastructure or legitimate "
        "services. Investigate the log context before treating an IP "
        "as malicious. VirusTotal lookups may share queried indicators."
    )


# =========================================================
# IP & DOMAIN REPUTATION LOOKUP
# =========================================================

if page == "IP & Domain Lookup":
    st.subheader("VirusTotal IP & Domain Investigation")

    st.write(
        "Look up an existing VirusTotal report for a public IP address "
        "or a domain. SHIELD does not submit new scans."
    )

    st.warning(
        "Privacy: VirusTotal states that queried indicators can be added "
        "to its shared dataset. Do not query private, confidential, or "
        "personally identifiable indicators."
    )

    api_key = get_vt_api_key()

    if not api_key:
        st.error("VirusTotal API key is not configured.")
        st.markdown(
            "Set `VT_API_KEY` in the same terminal before starting "
            "Streamlit. Never paste your API key into public chats or code."
        )

    with st.form("vt_lookup_form"):
        kind = st.radio(
            "Indicator type",
            ["IP address", "Domain"],
            horizontal=True,
        )

        example = (
            "8.8.8.8"
            if kind == "IP address"
            else "example.com"
        )

        indicator_input = st.text_input(
            "IP address or domain",
            placeholder=example,
        )

        submitted = st.form_submit_button(
            "Look up report",
            use_container_width=True,
        )

    if submitted:
        try:
            if not api_key:
                raise ValueError(
                    "Configure VT_API_KEY before requesting a report."
                )

            indicator = validate_indicator(kind, indicator_input)

            # The API call happens only after the user presses the button.
            with st.spinner("Retrieving existing VirusTotal report..."):
                report = virustotal_lookup(kind, indicator, api_key)

            st.session_state["vt_last_report"] = report

        except ValueError as exc:
            st.error(str(exc))
        except RuntimeError as exc:
            st.error(str(exc))

    report = st.session_state.get("vt_last_report")

    if report:
        st.divider()
        st.markdown(f"### Report: `{report['indicator']}`")

        malicious = report["malicious"]
        suspicious = report["suspicious"]
        total = report["total_engines"]

        c1, c2, c3, c4 = st.columns(4)

        c1.metric("Malicious detections", malicious)
        c2.metric("Suspicious detections", suspicious)
        c3.metric("Harmless", report["harmless"])
        c4.metric("Engines with results", total)

        if total == 0:
            st.info(
                "The report has no usable analysis statistics. "
                "No safe or malicious verdict can be inferred."
            )
        elif malicious > 0:
            st.error(
                f"{malicious} engines marked this indicator malicious. "
                "Investigate the detections and context; this is not "
                "a standalone confirmation of an attack."
            )
        elif suspicious > 0:
            st.warning(
                f"{suspicious} engines marked this indicator suspicious. "
                "Review the report and other evidence."
            )
        else:
            st.info(
                "No malicious or suspicious detections are reported in "
                "these statistics. This does not guarantee safety."
            )

        details = {
            "Indicator type": report["kind"],
            "Reputation score": (
                report["reputation"]
                if report["reputation"] is not None
                else "Not provided"
            ),
            "Country": report["country"] or "Not provided",
            "ASN": report["asn"] if report["asn"] is not None else "Not provided",
            "Network owner": report["as_owner"] or "Not provided",
            "Undetected": report["undetected"],
            "Timed out": report["timeout"],
            "Last analysis timestamp": (
                report["last_analysis_date"]
                if report["last_analysis_date"] is not None
                else "Not provided"
            ),
        }

        st.markdown("### Report details")
        st.dataframe(
            pd.DataFrame(
                [{"Field": k, "Value": v} for k, v in details.items()]
            ),
            use_container_width=True,
            hide_index=True,
        )

        st.link_button(
            "Open full VirusTotal report",
            report["report_url"],
        )

        st.caption(
            "Results reflect the returned VirusTotal report and may be "
            "incomplete or outdated. A low detection count is not proof "
            "that an indicator is safe."
        )

    st.info(
        "Public API access depends on your VirusTotal account and quota. "
        "HTTP 403 may indicate restricted access; HTTP 429 indicates a "
        "rate or quota limit."
    )


# =========================================================
# OVERVIEW
# =========================================================

elif page == "Overview":
    total_lines = len(df)
    category_count = df["Event Type"].nunique() if not df.empty else 0

    auth_failures = 0
    if not df.empty:
        event_types = df["Event Type"].astype(str)

        linux_failures = event_types.str.contains(
            r"pam_authentication_failure|authentication.failure|ssh_login_failure|ssh_failed_password|ssh_invalid_user|failed password|invalid user",
            case=False, regex=True, na=False,
        )

        windows_failures = (
            pd.to_numeric(df["Event ID"], errors="coerce") == 4625
            if "Event ID" in df.columns
            else pd.Series(False, index=df.index)
        )

        auth_failures = int((linux_failures | windows_failures).sum())

    metrics = [
        ("LOG LINES ANALYSED", f"{total_lines:,}"),
        ("EVENT CATEGORIES", f"{category_count:,}"),
        ("AUTH FAILURE LINES", f"{auth_failures:,}"),
        ("DETECTION PATTERNS", f"{len(alerts):,}"),
    ]

    cols = st.columns(4)
    for col, (label, value) in zip(cols, metrics):
        col.markdown(
            f'<div class="metric-card"><div class="metric-label">{label}</div>'
            f'<div class="metric-value">{value}</div></div>',
            unsafe_allow_html=True,
        )

    left, right = st.columns([1, 1.35], gap="large")

    with left:
        st.subheader("Event Distribution")
        if df.empty:
            st.info("No log events available.")
        else:
            counts = (
                df["Event Type"].value_counts()
                .rename_axis("Event Type")
                .reset_index(name="Log Lines")
                .head(12)
            )

            colors_list = [
                "#45F0C1", "#00B8D9", "#5687FF", "#A78BFA",
                "#FFB84D", "#FF6B81", "#38BDF8", "#A3E635",
                "#F97316", "#E879F9", "#2DD4BF", "#94A3B8",
            ]

            fig = px.pie(
                counts, names="Event Type", values="Log Lines",
                hole=0.68, color_discrete_sequence=colors_list,
            )
            fig.update_traces(
                textposition="inside",
                textinfo="percent",
                textfont=dict(color="#FFFFFF", size=12),
                marker=dict(line=dict(color="#0B1723", width=3)),
                hovertemplate=(
                    "<b>%{label}</b><br>Log lines: %{value:,}"
                    "<br>Share: %{percent}<extra></extra>"
                ),
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#D9E6EF", size=11),
                legend=dict(title_text=""),
                margin=dict(t=10, b=10, l=10, r=10),
                height=340,
            )
            st.plotly_chart(
                fig, use_container_width=True,
                config={"displayModeBar": False},
            )
            st.caption("Counts represent log lines, not unique incidents.")

    with right:
        st.subheader("Detection Feed")
        if not alerts:
            st.info(
                "No structured detections are available. "
                "This does not mean the logs are threat-free."
            )
        else:
            rows = []
            for index, raw_alert in enumerate(alerts, start=1):
                item = normalise_alert(raw_alert)
                rows.append({
                    "ID": f"DET-{index:03}",
                    "Severity": get_value(
                        item, "severity", "Severity", default="Review"
                    ),
                    "User": get_value(item, "user", "User"),
                    "Service": get_value(item, "service", "Service"),
                    "Evidence": get_value(
                        item, "reason", "evidence", "Evidence", default="Review"
                    ),
                })
            st.dataframe(
                pd.DataFrame(rows), use_container_width=True, hide_index=True
            )
            st.caption("Potential patterns require investigation.")

    st.subheader("Event Timeline")
    if df.empty:
        st.info("No timeline data available.")
    else:
        timeline = df[df["Timestamp"] != "Unknown"].copy()
        timeline["Parsed Time"] = pd.to_datetime(
            timeline["Timestamp"], errors="coerce", utc=True
        )
        timeline = timeline.dropna(subset=["Parsed Time"])

        if timeline.empty:
            st.info("No recognised timestamps in this log format.")
        else:
            timeline = (
                timeline.set_index("Parsed Time")
                .resample("1h").size()
                .rename("Log Lines").reset_index()
            )
            fig = px.area(timeline, x="Parsed Time", y="Log Lines")
            fig.update_traces(
                line=dict(color="#48F0C1", width=2),
                fillcolor="rgba(72,240,193,0.12)",
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#D9E6EF",
                height=280,
                xaxis_title="Time (UTC)",
                yaxis_title="Log lines per hour",
            )
            st.plotly_chart(
                fig, use_container_width=True,
                config={"displayModeBar": False},
            )

    st.subheader("Recent Log Evidence")
    if not df.empty:
        st.dataframe(
            df.tail(12).iloc[::-1],
            use_container_width=True,
            hide_index=True,
        )


# =========================================================
# THREAT INVESTIGATION
# =========================================================

elif page == "Threat Investigation":
    st.subheader("Threat Investigation")
    st.caption("Review evidence before drawing conclusions.")

    if not alerts:
        st.info(
            "No structured detections are available for this source. "
            "The current detection engine uses the default Kali log."
        )
    else:
        records = [normalise_alert(a) for a in alerts]

        selected = st.selectbox(
            "Select detection",
            range(len(records)),
            format_func=lambda i: (
                f"Detection {i + 1}: "
                f"{get_value(records[i], 'severity', 'Severity')} — "
                f"{get_value(records[i], 'user', 'User')}"
            ),
        )

        item = records[selected]

        display_names = {
            "user": "User",
            "service": "Service",
            "source_ip": "Source IP",
            "count": "Event Count",
            "start": "First Seen",
            "end": "Last Seen",
            "severity": "Severity",
            "event_type": "Event Type",
            "reason": "Evidence",
        }

        for key, value in item.items():
            if value not in (None, ""):
                label = display_names.get(key, key.replace("_", " ").title())
                st.markdown(f"**{label}:** {value}")

        user = str(get_value(item, "user", "User", default=""))
        service = str(get_value(item, "service", "Service", default=""))

        evidence_df = df

        if not df.empty:
            mask = pd.Series(False, index=df.index)

            if user and user != "Unknown":
                mask |= df["Raw Log"].str.contains(
                    re.escape(user), case=False, na=False
                )

            if service and service != "Unknown":
                mask |= df["Raw Log"].str.contains(
                    re.escape(service), case=False, na=False
                )

            evidence_df = df[mask] if mask.any() else df.iloc[0:0]

        st.subheader("Matching Log Evidence")

        if evidence_df.empty:
            st.info("No matching lines found with the available alert fields.")
        else:
            st.dataframe(
                evidence_df, use_container_width=True, hide_index=True
            )
            st.download_button(
                "Download evidence CSV",
                evidence_df.to_csv(index=False).encode("utf-8"),
                file_name="shield_investigation_evidence.csv",
                mime="text/csv",
            )

    st.warning(
        "A detection is an investigative lead, not proof of malicious activity."
    )


# =========================================================
# EVENT EXPLORER
# =========================================================

elif page == "Event Explorer":
    st.subheader("Event Explorer")
    st.caption(f"Source: {active_log.name}")

    if df.empty:
        st.info("No log lines available.")
    else:
        c1, c2 = st.columns(2)
        search_text = c1.text_input(
            "Search raw logs", placeholder="sudo, failed, ssh"
        )
        options = sorted(df["Event Type"].dropna().unique().tolist())
        selected_types = c2.multiselect(
            "Filter event categories", options, default=options
        )

        filtered = df[df["Event Type"].isin(selected_types)]

        if search_text.strip():
            filtered = filtered[
                filtered["Raw Log"].str.contains(
                    search_text.strip(), case=False, na=False
                )
            ]

        st.write(f"**{len(filtered):,}** matching log lines")
        st.dataframe(
            filtered, use_container_width=True, hide_index=True, height=480
        )
        st.download_button(
            "Export filtered logs as CSV",
            filtered.to_csv(index=False).encode("utf-8"),
            file_name="shield_filtered_logs.csv",
            mime="text/csv",
        )


# =========================================================
# REPORTS
# =========================================================

elif page == "Reports":
    st.subheader("Reports & Exports")

    if df.empty:
        st.info("No log data available.")
    else:
        c1, c2 = st.columns(2)

        with c1:
            st.markdown("### CSV Report")
            st.download_button(
                "Download complete log CSV",
                df.to_csv(index=False).encode("utf-8"),
                file_name="shield_log_analysis.csv",
                mime="text/csv",
                use_container_width=True,
            )

        with c2:
            st.markdown("### PDF Security Report")
            pdf = create_pdf_report(df, alerts, active_log.name)

            if pdf is None:
                st.error("Install ReportLab: python -m pip install reportlab")
            else:
                st.download_button(
                    "Download PDF report",
                    pdf,
                    file_name="shield_security_report.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                )

        st.subheader("Event Category Summary")
        summary = (
            df["Event Type"].value_counts()
            .rename_axis("Event Type")
            .reset_index(name="Log Lines")
        )
        st.dataframe(summary, use_container_width=True, hide_index=True)


# =========================================================
# FOOTER
# =========================================================

st.divider()
st.markdown(
    '<div class="small-muted">SHIELD • Evidence-first security analysis • '
    'Unmatched events are not automatically safe.</div>',
    unsafe_allow_html=True,
)
