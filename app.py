import json
import pandas as pd
import streamlit as st
import os
import re
import requests
from email import policy
from email.parser import BytesParser
st.set_page_config(page_title="Autonomous Cybersecurity Agent - Day 5", layout="wide")
API_URL = "https://api.airia.ai/v2/PipelineExecution/03e44d6f-167f-4c46-be5a-d9d6ab3fa100"
API_KEY = st.secrets.get("AIRIA_API_KEY", os.getenv("AIRIA_API_KEY", ""))
def parse_eml(uploaded_file) -> str:
    msg = BytesParser(policy=policy.default).parse(uploaded_file)
    subject = msg["subject"] or ""
    sender = msg["from"] or ""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body += part.get_content()
                except Exception:
                    pass
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = ""
    return f"Subject: {subject}\nFrom: {sender}\n\n{body}".strip()
def bullets(title, items):
    st.markdown(f"**{title}**")
    if not items:
        st.write("—")
        return
    for x in items:
        st.markdown(f"- {x}")
def ioc_table(iocs):
    st.markdown("**IOCs**")
    if not iocs:
        st.write("—")
        return
    df = pd.DataFrame({"IOC": iocs})
    st.dataframe(df, use_container_width=True)
def invoke_airia(user_input: str) -> dict:
    api_key = st.secrets.get("AIRIA_API_KEY", os.getenv("AIRIA_API_KEY", ""))
    if not api_key:
        return {"error": "Missing AIRIA_API_KEY. Set it in Streamlit Secrets."}
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }
    payload = {"userInput": user_input, "asyncOutput": False}
    r = requests.post(API_URL, json=payload, headers=headers, timeout=60)
    r.raise_for_status()
    return r.json()
def extract_json_from_text(text: str) -> dict:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        raise json.JSONDecodeError("No JSON object found", text, 0)
    return json.loads(m.group(0))
def analyze_email_airia(email_content: str) -> dict:
    prompt = (
        "You are Obsidiax, an email phishing risk analyzer.\n"
        "Return ONLY valid JSON. No markdown. No extra text.\n"
        "Use this exact schema:\n"
        "{\n"
        '  "risk_score": 0-100,\n'
        '  "confidence": 0.0-1.0,\n'
        '  "verdict": "PHISHING"|"LEGIT",\n'
        '  "explanation": ["..."],\n'
        '  "persona": "...",\n'
        '  "recommended_action": ["..."]\n'
        "}\n\n"
        "Email:\n"
        f"{email_content}\n"
    )
    raw = invoke_airia(prompt)
    if "error" in raw:
        return raw
    model_text = raw.get("result", "")
    if not isinstance(model_text, str):
        return EMAIL_FALLBACK
    try:
        cleaned = extract_json_from_text(model_text)
        if "risk_score" not in cleaned or "verdict" not in cleaned:
            return EMAIL_FALLBACK
        cleaned["risk_score"] = int(cleaned.get("risk_score", 0))
        cleaned["confidence"] = float(cleaned.get("confidence", 0.5))
        exp = cleaned.get("explanation", [])
        cleaned["explanation"] = exp if isinstance(exp, list) else [str(exp)]
        ra = cleaned.get("recommended_action", [])
        cleaned["recommended_action"] = ra if isinstance(ra, list) else [str(ra)]
        cleaned["persona"] = cleaned.get("persona", "Unknown")
        return cleaned
    except Exception:
        return EMAIL_FALLBACK
def analyze_honeypot_airia(log_text: str) -> dict:
    prompt = (
        "You are Obsidiax, a honeypot attack storyteller.\n"
        "Return ONLY valid JSON. No markdown. No extra text.\n"
        "Use this exact schema:\n"
        "{\n"
        '  "severity": "LOW"|"MEDIUM"|"HIGH",\n'
        '  "confidence": 0.0-1.0,\n'
        '  "summary": "...",\n'
        '  "timeline": ["..."],\n'
        '  "ioc": ["..."],\n'
        '  "persona": "...",\n'
        '  "recommended_action": ["..."]\n'
        "}\n\n"
        "Honeypot log:\n"
        f"{log_text}\n"
    )
    raw = invoke_airia(prompt)
    if "error" in raw:
        return raw
    model_text = raw.get("result", "")
    if not isinstance(model_text, str):
        return HONEYPOT_FALLBACK
    try:
        cleaned = extract_json_from_text(model_text)
        if "severity" not in cleaned or "summary" not in cleaned:
            return HONEYPOT_FALLBACK
        cleaned["confidence"] = float(cleaned.get("confidence", 0.5))
        tl = cleaned.get("timeline", [])
        cleaned["timeline"] = tl if isinstance(tl, list) else [str(tl)]
        ioc = cleaned.get("ioc", [])
        cleaned["ioc"] = ioc if isinstance(ioc, list) else [str(ioc)]
        ra = cleaned.get("recommended_action", [])
        cleaned["recommended_action"] = ra if isinstance(ra, list) else [str(ra)]
        cleaned["persona"] = cleaned.get("persona", "Unknown")
        return cleaned
    except Exception:
        return HONEYPOT_FALLBACK
st.title("Autonomous Cybersecurity Agent")
st.caption("Turning phishing emails and honeypot logs into clear threat intelligence.")
tab_email, tab_honeypot = st.tabs(["📧 Email Analyzer", "🍯 Honeypot Storyteller"])
with tab_email:
    left, right = st.columns(2)
    with left:
        st.subheader("Input Email")
        pasted_email = st.text_area("Paste email content (optional)", height=220)
        eml_file = st.file_uploader("Or upload a real email (.eml)", type=["eml"])
        st.info("Email integration: .eml upload simulates real email ingestion.")
        analyze_email = st.button("Analyze Email", type="primary")
    with right:
        st.subheader("Output")
        if analyze_email:
            email_text = ""
            if eml_file is not None:
                email_text = parse_eml(eml_file)
            else:
                email_text = pasted_email or ""

            if len(email_text.strip()) < 20:
                st.error("Please paste or upload a real email with enough content.")
            else:
                with st.spinner("Analyzing email…"):
                    result = analyze_email_airia(email_text)
                    if "error" in result:
                        st.error(result["error"])
                        st.stop()
                st.metric("Risk Score", result["risk_score"])
                st.write(f"**Verdict:** {result['verdict']}")
                st.write(f"**Confidence:** {result['confidence']:.2f}")
                st.write(f"**Hacker Persona:** {result['persona']}")
                bullets("Explanation", result["explanation"])
                bullets("Recommended Action", result["recommended_action"])
                st.download_button(
                    "Download JSON Result",
                    data=json.dumps(result, indent=2),
                    file_name="email_analysis.json",
                    mime="application/json"
                )
with tab_honeypot:
    left, right = st.columns(2)
    if "honeypot_text" not in st.session_state:
        st.session_state["honeypot_text"] = ""
    with left:
        st.subheader("Input Honeypot Log")
        load_sample = st.button("Load sample honeypot log")
        if load_sample:
            try:
                with open("sample_inputs/sample_honeypot_log.json", "r", encoding="utf-8") as f:
                    st.session_state["honeypot_text"] = f.read()
                st.success("Sample honeypot log loaded.")
            except Exception:
                st.warning("Sample file not found.")
        honeypot_text = st.text_area(
            "Paste honeypot log (JSON/text)",
            height=260,
            value=st.session_state["honeypot_text"]
        )
        analyze_honeypot = st.button("Generate Attack Story", type="primary")
    with right:
        st.subheader("Output")
        if analyze_honeypot:
            if len(honeypot_text.strip()) < 20:
                st.error("Please paste a honeypot log or load the sample.")
            else:
                with st.spinner("Generating attack story…"):
                    result = analyze_honeypot_airia(honeypot_text)
                    if "error" in result:
                        st.error(result["error"])
                        st.stop()   
                st.write(f"**Severity:** {result['severity']}")
                st.write(f"**Confidence:** {result['confidence']:.2f}")
                st.write(f"**Attacker Persona:** {result['persona']}")
                st.markdown("**Summary**")
                st.write(result["summary"])
                bullets("Timeline", result["timeline"])
                ioc_table(result["ioc"])
                bullets("Recommended Action", result["recommended_action"])
                st.download_button(
                    "Download JSON Result",
                    data=json.dumps(result, indent=2),
                    file_name="honeypot_analysis.json",
                    mime="application/json"
                )
