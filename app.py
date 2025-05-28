import requests
import time
import streamlit as st

st.set_page_config(page_title="PQC SSL Risk Scanner", page_icon="🔐")
st.title("🔐 PQC SSL/TLS Risk Analyzer (via SSL Labs API)")

target = st.text_input("Enter hostname (e.g., www.example.com):")

def analyze_ssl_tls_pqc(hostname):
    api_url = "https://api.ssllabs.com/api/v3/analyze"
    status_url = f"{api_url}?host={hostname}&all=done"

    debug_log = []

    try:
        # Step 1: Initiate the scan
        init_resp = requests.get(status_url)
        debug_log.append(f"Initial request status code: {init_resp.status_code}")
        if init_resp.status_code != 200:
            debug_log.append(f"Error response: {init_resp.text}")
            return None, "\n".join(debug_log)

        data = init_resp.json()
        while data.get("status") not in ["READY", "ERROR"]:
            debug_log.append(f"Status: {data.get('status')}, waiting 5 seconds...")
            time.sleep(5)
            data = requests.get(status_url).json()

        if data.get("status") == "ERROR":
            debug_log.append("SSL Labs returned ERROR status.")
            return None, "\n".join(debug_log)

        endpoints = data.get("endpoints", [])
        if not endpoints:
            debug_log.append("No endpoints returned from SSL Labs.")
            return None, "\n".join(debug_log)

        details = endpoints[0].get("details", {})
        cert = details.get("cert", {})
        key_alg = cert.get("sigAlg", "Unknown")
        key_size = cert.get("keySize", 0)
        expires = cert.get("notAfter", 0)
        tls_versions = [proto.get("name", "") for proto in details.get("protocols", [])]

        # Risk analysis
        risk = "🟢 Low PQC Risk"
        if key_size < 3072 or "RSA" in key_alg:
            risk = "🔴 High PQC Risk"
        elif "TLS 1.2" in tls_versions and "TLS 1.3" not in tls_versions:
            risk = "🟡 Medium PQC Risk"

        result = {
            "Key Algorithm": key_alg,
            "Key Size": key_size,
            "TLS Versions": ", ".join(tls_versions),
            "PQC Risk Level": risk,
        }
        return result, "\n".join(debug_log)

    except Exception as e:
        debug_log.append(f"Exception occurred: {e}")
        return None, "\n".join(debug_log)

if st.button("Run PQC Check"):
    if not target:
        st.warning("Please enter a hostname.")
    else:
        with st.spinner("Contacting SSL Labs API and analyzing..."):
            result, debug = analyze_ssl_tls_pqc(target)
            if result:
                st.success("✅ Analysis complete!")
                for k, v in result.items():
                    st.markdown(f"**{k}:** {v}")
            else:
                st.error("❌ An error occurred during analysis.")
            st.markdown("### 🐞 Debug Log")
            st.code(debug)
