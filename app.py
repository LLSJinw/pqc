import streamlit as st
import requests
import time
import re

st.set_page_config(page_title="🔐 PQC SSL/TLS Risk Analyzer", page_icon="🔐")
st.title("🔐 PQC SSL/TLS Risk Analyzer (via SSL Labs API)")

API_BASE = "https://api.ssllabs.com/api/v3"

def get_analysis(hostname):
    params = {"host": hostname, "publish": "off", "startNew": "on", "all": "done"}
    return requests.get(f"{API_BASE}/analyze", params=params)

def poll_analysis(hostname):
    attempts = 0
    while attempts < 30:
        resp = requests.get(f"{API_BASE}/analyze", params={"host": hostname})
        if resp.status_code != 200:
            return None, f"API error: {resp.status_code}"
        data = resp.json()
        status = data.get("status")
        st.text(f"Status: {status}, waiting 5 seconds...")
        if status == "READY":
            return data, None
        elif status in ("ERROR", "DNS", "INACTIVE"):
            return None, f"Scan failed with status: {status}"
        time.sleep(5)
        attempts += 1
    return None, "Scan timed out."

def determine_pqc_risk(cert_key_alg, key_size, tls_versions):
    if cert_key_alg != "RSA" or key_size >= 4096:
        return "🟢 Low PQC Risk"
    if "TLS 1.3" in tls_versions:
        return "🟡 Moderate PQC Risk"
    return "🔴 High PQC Risk"

# UI Input
hostname = st.text_input("Enter hostname (e.g., www.example.com):")

if st.button("Run PQC Check") and hostname:
    st.subheader("🔍 Analysis in Progress")
    response = get_analysis(hostname)
    if response.status_code != 200:
        st.error(f"Failed to submit analysis: {response.status_code}")
    else:
        data, error = poll_analysis(hostname)
        if error:
            st.error(error)
        elif data:
            st.success("✅ Analysis complete!")
            try:
                endpoint = data.get("endpoints", [{}])[0]
                details_resp = requests.get(f"{API_BASE}/getEndpointData", params={"host": hostname, "s": endpoint.get("ipAddress"), "fromCache": "on"})
                details = details_resp.json()
                cert = details.get("details", {}).get("cert", {})
                protocols = details.get("details", {}).get("protocols", [])

                key_alg = cert.get("keyAlg", "Unknown")
                key_size = cert.get("keySize", 0)
                tls_versions = ", ".join(p.get("name") for p in protocols)
                pqc_risk = determine_pqc_risk(key_alg, key_size, tls_versions)

                st.markdown(f"**Key Algorithm:** {key_alg}")
                st.markdown(f"**Key Size:** {key_size}")
                st.markdown(f"**TLS Versions:** {tls_versions if tls_versions else 'Unknown'}")
                st.markdown(f"**PQC Risk Level:** {pqc_risk}")

            except Exception as e:
                st.error(f"Error parsing response: {e}")

        st.markdown("### 🐞 Debug Log")
        st.code(response.text)
else:
    st.caption("Enter a valid public hostname to check SSL/TLS parameters")
