from pathlib import Path

path = Path("app.py")
code = path.read_text(encoding="utf-8")

if '"IOC Extraction"' in code:
    print("IOC Extraction already exists. No changes made.")
    raise SystemExit(0)

nav_old = '''        "Event Explorer",
        "IP & Domain Lookup",'''

nav_new = '''        "Event Explorer",
        "IOC Extraction",
        "IP & Domain Lookup",'''

if nav_old not in code:
    raise SystemExit("Navigation anchor not found. app.py unchanged.")

code = code.replace(nav_old, nav_new, 1)

helper_anchor = '''def get_value(item, *keys, default="Unknown"):
    for key in keys:
        if key in item and item[key] not in (None, ""):
            return item[key]
    return default
'''

helpers = helper_anchor + '''

def extract_ip_iocs(df):
    """Extract unique IP indicators from log lines without contacting VT."""
    results = {}

    if df.empty:
        return pd.DataFrame(
            columns=["IP Address", "Type", "Occurrences", "Example Log"]
        )

    pattern = re.compile(
        r"(?<![0-9A-Fa-f:.])"
        r"(?:[0-9]{1,3}\\\\.){3}[0-9]{1,3}"
        r"(?![0-9A-Fa-f:. )])"
        r"|"
        r"(?<![0-9A-Fa-f:])"
        r"(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
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

            if ip.is_global:
                category = "Public"
            elif ip.is_private:
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
'''

if helper_anchor not in code:
    raise SystemExit("Helper-function anchor not found. app.py unchanged.")

code = code.replace(helper_anchor, helpers, 1)

page_anchor = '''# =========================================================
# IP & DOMAIN REPUTATION LOOKUP
# =========================================================

if page == "IP & Domain Lookup":'''

ioc_page = '''# =========================================================
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

if page == "IP & Domain Lookup":'''

if page_anchor not in code:
    raise SystemExit("Page insertion anchor not found. app.py unchanged.")

code = code.replace(page_anchor, ioc_page, 1)

path.write_text(code, encoding="utf-8")
print("IOC Extraction added. Existing app.py backup is app.py.backup")
