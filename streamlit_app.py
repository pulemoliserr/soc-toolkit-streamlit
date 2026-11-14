"""SOC Analyst Toolkit: interactive demos of core security-analyst skills.

Built on projects from the Google Cybersecurity Professional Certificate.
Everything runs locally in the browser session; no data leaves the app.
"""
import ipaddress
import random
import re
import sqlite3
from datetime import date, time, timedelta
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(page_title="SOC Analyst Toolkit", page_icon="🛡️", layout="wide")
HERE = Path(__file__).parent


# ---------------------------------------------------------------- data ----
@st.cache_resource
def build_database():
    """Create a synthetic login/employee database with a planted incident."""
    rnd = random.Random(42)
    departments = ["Marketing", "Sales", "Finance", "Human Resources", "Information Technology"]
    buildings = ["East", "West", "North", "South", "Central"]
    countries = ["USA", "US", "MEX", "MEXICO", "CAN", "CANADA"]
    employees = []
    for i in range(1, 121):
        user = f"user{i:03d}"
        employees.append(dict(
            employee_id=1000 + i,
            device_id=f"dev{rnd.randint(10**6, 10**7):x}",
            username=user,
            department=rnd.choice(departments),
            office=f"{rnd.choice(buildings)}-{rnd.randint(100, 499)}",
        ))
    attempts, eid = [], 1
    start = date(2022, 5, 1)
    for _ in range(1400):
        e = rnd.choice(employees)
        hour = min(23, max(6, int(rnd.gauss(12, 3))))
        attempts.append(dict(
            event_id=eid, username=e["username"],
            login_date=str(start + timedelta(days=rnd.randint(0, 13))),
            login_time=str(time(hour, rnd.randint(0, 59), rnd.randint(0, 59))),
            country=rnd.choice(countries),
            ip_address=f"192.168.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}",
            success=int(rnd.random() > 0.08),
        ))
        eid += 1
    # planted incident: brute force against one account on the evening of 2022-05-09
    for k in range(35):
        attempts.append(dict(
            event_id=eid, username="user042", login_date="2022-05-09",
            login_time=str(time(21, 3 + k // 6, (k * 7) % 60)),
            country="CAN", ip_address="192.168.66.142", success=int(k == 34),
        ))
        eid += 1
    con = sqlite3.connect(":memory:", check_same_thread=False)
    pd.DataFrame(attempts).to_sql("log_in_attempts", con, index=False)
    pd.DataFrame(employees).to_sql("employees", con, index=False)
    return con


def run_query(sql):
    sql = sql.strip().rstrip(";")
    if not re.match(r"(?is)^\s*(select|with)\b", sql) or ";" in sql:
        raise ValueError("Only a single read-only SELECT statement is allowed.")
    return pd.read_sql_query(sql, build_database())


# --------------------------------------------------------------- header ---
st.title("🛡️ SOC Analyst Toolkit")
st.caption(
    "Interactive demos of security-analyst tasks: log investigation with SQL, packet-capture "
    "triage, access-list automation and Linux permissions. All data is synthetic."
)
st.caption("🌗 Switch between light and dark mode in the menu (⋮, top right).")

tab_sql, tab_pcap, tab_allow, tab_perm = st.tabs(
    ["🔎 Login investigation (SQL)", "📡 tcpdump triage", "📋 Allow-list updater", "🐧 Linux permissions"]
)

# ------------------------------------------------------------- SQL tab ----
with tab_sql:
    st.subheader("Investigate suspicious logins")
    st.write(
        "Build a filter and the matching SQL is generated and run against a synthetic "
        "`log_in_attempts` table. There's a planted incident to find. Hint: the evening of 2022-05-09."
    )
    c1, c2, c3, c4 = st.columns(4)
    failed_only = c1.checkbox("Failed attempts only", value=True)
    after = c2.time_input("After time", value=time(18, 0))
    dates = c3.multiselect(
        "Dates", [str(date(2022, 5, d)) for d in range(1, 15)], default=["2022-05-08", "2022-05-09"]
    )
    exclude_mex = c4.checkbox("Exclude Mexico (MEX%)", value=False)

    where = []
    if failed_only:
        where.append("success = 0")
    if after:
        where.append(f"login_time > '{after.strftime('%H:%M:%S')}'")
    if dates:
        where.append("(" + " OR ".join(f"login_date = '{d}'" for d in dates) + ")")
    if exclude_mex:
        where.append("NOT country LIKE 'MEX%'")
    sql = "SELECT *\nFROM log_in_attempts"
    if where:
        sql += "\nWHERE " + "\n  AND ".join(where)
    sql += "\nORDER BY login_date, login_time;"
    st.code(sql, language="sql")
    df = run_query(sql)
    m1, m2, m3 = st.columns(3)
    m1.metric("Matching events", len(df))
    m2.metric("Distinct users", df["username"].nunique() if len(df) else 0)
    m3.metric("Distinct source IPs", df["ip_address"].nunique() if len(df) else 0)

    if len(df):
        top = df.groupby(["username", "ip_address"]).size().reset_index(name="attempts")
        top = top.sort_values("attempts", ascending=False).head(10)
        threshold = st.slider("Alert threshold (failed attempts per user + IP)", 3, 30, 10)
        flagged = top[top["attempts"] >= threshold]
        if len(flagged):
            st.error(
                f"⚠️ Possible brute force: {', '.join(flagged['username'])} from "
                f"{', '.join(flagged['ip_address'])}. Next step: check whether a later attempt succeeded."
            )
        st.bar_chart(top.set_index("username")["attempts"])
        st.dataframe(df, width="stretch", hide_index=True)

    with st.expander("✍️ Write your own query (read-only)"):
        custom = st.text_area(
            "SQL",
            "SELECT username, ip_address, COUNT(*) AS failures\nFROM log_in_attempts\n"
            "WHERE success = 0\nGROUP BY username, ip_address\nHAVING failures >= 5\n"
            "ORDER BY failures DESC;",
            height=150,
        )
        st.caption("Tables: `log_in_attempts`, `employees`")
        try:
            st.dataframe(run_query(custom), width="stretch", hide_index=True)
        except Exception as exc:  # noqa: BLE001  (show any SQL error to the user)
            st.warning(str(exc))

# ------------------------------------------------------------ pcap tab ----
LINE = re.compile(
    r"^(?P<ts>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+(?P<src>[\w.\-]+?)\s+>\s+(?P<dst>[\w.\-]+?):\s+(?P<rest>.*)$"
)


def split_host(h):
    parts = h.split(".")
    if len(parts) == 5:
        return ".".join(parts[:4]), parts[4]
    return h, ""


def parse_tcpdump(text):
    rows = []
    for raw in text.splitlines():
        m = LINE.match(raw.strip())
        if not m:
            continue
        src, sport = split_host(m["src"])
        dst, dport = split_host(m["dst"])
        rest = m["rest"]
        flags = re.search(r"Flags \[([^\]]*)\]", rest)
        if "ICMP" in rest:
            proto = "ICMP"
        elif flags:
            proto = "TCP"
        elif dport in ("domain", "53") or re.search(r"\b[A-Z]+\?", rest):
            proto = "DNS/UDP"
        else:
            proto = "other"
        rows.append(dict(time=m["ts"], src=src, sport=sport, dst=dst, dport=dport,
                         proto=proto, flags=flags[1] if flags else "", info=rest))
    return pd.DataFrame(rows)


with tab_pcap:
    st.subheader("Triage a tcpdump capture")
    st.write("Paste tcpdump output or load a sample. The analyzer summarises the traffic and flags common problems.")
    sample = st.radio("Sample", ["DNS outage (port 53 unreachable)", "SYN flood", "Paste my own"], horizontal=True)
    default = ""
    if sample.startswith("DNS"):
        default = (HERE / "samples/dns_outage.txt").read_text()
    elif sample.startswith("SYN"):
        default = (HERE / "samples/syn_flood.txt").read_text()
    text = st.text_area("tcpdump output", default, height=200)
    pk = parse_tcpdump(text)
    if pk.empty:
        st.info("No tcpdump lines recognised yet.")
    else:
        a, b, c = st.columns(3)
        a.metric("Packets parsed", len(pk))
        b.metric("Unique sources", pk["src"].nunique())
        c.metric("Protocols", ", ".join(sorted(pk["proto"].unique())))
        findings = []
        unreach = pk[pk["info"].str.contains("unreachable", case=False)]
        if len(unreach):
            port = re.search(r"port (\d+)", unreach.iloc[0]["info"])
            findings.append((
                "error",
                f"**{len(unreach)} ICMP destination-unreachable** responses from {unreach['src'].iloc[0]}"
                + (f" for UDP port {port[1]}" if port else "")
                + ". The host is reachable but no service is listening on that port"
                + (" (DNS is down, so names can't be resolved)." if port and port[1] == "53" else "."),
            ))
        tcp = pk[pk["proto"] == "TCP"]
        if len(tcp):
            syn = tcp[tcp["flags"] == "S"].groupby("src").size()
            ack = tcp[tcp["flags"] == "."].groupby("src").size()
            ratio = pd.DataFrame({"SYN": syn, "ACK": ack}).fillna(0).astype(int)
            ratio["half_open"] = ratio["SYN"] - ratio["ACK"]
            ratio = ratio.sort_values("half_open", ascending=False)
            worst = ratio.iloc[0]
            if worst["SYN"] >= 20 and worst["half_open"] / max(worst["SYN"], 1) > 0.8:
                findings.append((
                    "error",
                    f"**Likely SYN flood (DoS)** from {ratio.index[0]}: {worst['SYN']} SYNs and "
                    f"{worst['ACK']} completed handshakes. Recommend SYN cookies, per-source rate "
                    "limiting and upstream DDoS protection. IP blocking alone is weak because sources can be spoofed.",
                ))
            st.write("**TCP handshake completion by source**")
            st.dataframe(ratio, width="stretch")
        for level, msg in findings or [("success", "No common attack or outage patterns detected.")]:
            getattr(st, level)(msg)
        st.dataframe(pk, width="stretch", hide_index=True)

# ----------------------------------------------------------- allow tab ----
with tab_allow:
    st.subheader("Update an IP allow list")
    st.write("Removes revoked addresses from an allow list. This is the Python algorithm from my portfolio, now as a tool.")
    sample_allow = (HERE / "samples/allow_list.txt").read_text()
    left, right = st.columns(2)
    allow_text = left.text_area("allow_list.txt", sample_allow, height=260)
    remove_text = right.text_area(
        "Remove list (one per line)", "192.168.97.225\n192.168.158.170\n192.168.201.40\n192.168.58.57", height=260
    )
    tokens = allow_text.split()
    header = tokens[0] if tokens and not re.match(r"^\d", tokens[0]) else None
    current = tokens[1:] if header else tokens
    remove, invalid = [], []
    for ip in remove_text.split():
        try:
            ipaddress.ip_address(ip)
            remove.append(ip)
        except ValueError:
            invalid.append(ip)
    to_remove = set(remove)
    kept = [ip for ip in current if ip not in to_remove]
    removed = [ip for ip in current if ip in to_remove]
    x, y, z = st.columns(3)
    x.metric("Before", len(current))
    y.metric("Removed", len(removed))
    z.metric("After", len(kept))
    if invalid:
        st.warning(f"Ignored invalid addresses: {', '.join(invalid)}")
    missing = sorted(to_remove - set(removed))
    if missing:
        st.info(f"Not in allow list: {', '.join(missing)}")
    output = "\n".join(([header] if header else []) + kept)
    st.download_button("⬇️ Download updated allow_list.txt", output, file_name="allow_list.txt")
    with st.expander("View the Python behind this"):
        st.code((HERE / "update_allow_list.py").read_text(), language="python")

# ------------------------------------------------------------ perm tab ----
def perm_string(octal):
    return "".join(
        ("r" if d & 4 else "-") + ("w" if d & 2 else "-") + ("x" if d & 1 else "-")
        for d in (int(c) for c in octal)
    )


with tab_perm:
    st.subheader("Linux permission calculator")
    st.write("Tick permissions to get the `chmod` command, or audit a file against least-privilege rules.")
    cols = st.columns(3)
    digits = []
    for col, who in zip(cols, ["User (u)", "Group (g)", "Other (o)"]):
        with col:
            st.markdown(f"**{who}**")
            r = st.checkbox("read", True, key=f"{who}r")
            w = st.checkbox("write", who.startswith("User"), key=f"{who}w")
            xx = st.checkbox("execute", False, key=f"{who}x")
            digits.append(4 * r + 2 * w + xx)
    octal = "".join(map(str, digits))
    is_dir = st.toggle("This is a directory")
    pstr = ("d" if is_dir else "-") + perm_string(octal)
    st.code(f"{pstr}\nchmod {octal} <name>", language="bash")
    issues = []
    if digits[2] & 2:
        issues.append("**Other can write.** Anyone on the system can modify this. Fix: `chmod o-w <name>`")
    if is_dir and digits[2] & 1:
        issues.append("Other can enter this directory (`x`). Check that this is intended.")
    if digits[1] & 2:
        issues.append("Group has write access. Confirm every group member needs it.")
    for msg in issues:
        st.warning(msg)
    if not issues:
        st.success("No obvious least-privilege issues.")
    st.caption(f"Symbolic: u={perm_string(octal)[0:3].replace('-', '')} "
               f"g={perm_string(octal)[3:6].replace('-', '')} o={perm_string(octal)[6:9].replace('-', '')}")

st.divider()
st.caption(
    "Built with Streamlit · Synthetic data only · "
    "[Source code on GitHub](https://github.com/pulemoliserr/soc-toolkit-streamlit) · "
    "[Portfolio](https://pulemolise.net/cybersecurity/)"
)
