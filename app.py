import streamlit as st
import requests
import time
import datetime

st.set_page_config(page_title="🔐 PQC SSL/TLS Scanner", page_icon="🔍")
st.title("🔍 PQC-Aware SSL/TLS External Scanner")

# --- Input Box ---
domain = st.text_input("Enter a hostname (e.g., www.example.com):")

# --- Helper Functions ---
def start_ssl_scan(domain):
    url = "https://api.ssllabs.com/api/v4/analyze"
    params = {"host": domain, "publish": "off", "startNew": "on", "all": "done"}
    r = requests.get(url, params=params)
    return r.json()

def poll_for_results(domain):
    url = "https://api.ssllabs.com/api/v4/analyze"
    while True:
        r = requests.get(url, params={"host": domain})
        data = r.json()
        if data.get("status") == "READY":
            return data
        elif data.get("status") == "ERROR":
            raise Exception("Scan failed")
        time.sleep(10)

# --- PQC Evaluation Logic ---
def evaluate_pqc_level(key_strength, sig_alg, protocols, not_after):
    score = 0

    # Key strength check
    if key_strength < 2048:
        score += 2
    elif key_strength < 4096:
        score += 1

    # Signature algorithm
    if "sha1" in sig_alg.lower() or "md5" in sig_alg.lower():
        score += 2
    elif "sha256" in sig_alg.lower():
        score += 1

    # TLS version
    supported_tls13 = any(p.get("version") == "TLS 1.3" for p in protocols)
    if not supported_tls13:
        score += 1

    # Cert expiry (Harvest Now / Decrypt Later)
    expiry_ts = not_after / 1000
    expiry_date = datetime.datetime.fromtimestamp(expiry_ts)
    delta_days = (expiry_date - datetime.datetime.now()).days
    if delta_days > 365:
        score += 1

    if score <= 1:
        return "🟢 Low PQC Risk (Modern TLS)", score
    elif score <= 3:
        return "🟡 Medium PQC Risk (Some Legacy)", score
    else:
        return "🔴 High PQC Risk (Weak Crypto)", score

# --- Main Scan Trigger ---
if st.button("Start Scan"):
    if not domain.strip():
        st.warning("Please enter a valid hostname.")
    else:
        with st.spinner("Submitting scan request to SSL Labs..."):
            start_ssl_scan(domain)
        with st.spinner("Waiting for SSL Labs to complete scan (this may take up to 2 minutes)..."):
            result = poll_for_results(domain)

        if result:
            endpoint = result["endpoints"][0]
            details = endpoint.get("details", {})
            cert = details.get("cert", {})
            protocols = details.get("protocols", [])
            suites = details.get("suites", {}).get("list", [])

            key_strength = cert.get("keyStrength", 0)
            sig_alg = cert.get("sigAlg", "?")
            not_after = cert.get("notAfter", 0)

            pqc_level, pqc_score = evaluate_pqc_level(key_strength, sig_alg, protocols, not_after)

            st.success("✅ SSL Labs Scan Complete")

            st.markdown("### 🧩 TLS Details")
            st.write(f"**Key Strength:** {key_strength} bits")
            st.write(f"**Signature Algorithm:** {sig_alg}")
            st.write(f"**Supported TLS Versions:** {[p['version'] for p in protocols]}")
            st.write(f"**Certificate Expiry:** {datetime.datetime.fromtimestamp(not_after / 1000).strftime('%Y-%m-%d')}")

            st.markdown("### 🔐 PQC Readiness Level")
            st.info(pqc_level)
        else:
            st.error("Failed to get SSL Labs results.")
