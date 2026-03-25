import streamlit as st
import requests

st.set_page_config(page_title="SecureCode AI", layout="wide", page_icon="🛡️")

# UI CSS 
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@500;700&display=swap');

    html, body, [class*="css"] { font-family: 'Syne', sans-serif; }
    code, .log-container { font-family: 'JetBrains Mono', monospace !important; }

    .log-container {
        background: #0d1117;
        color: #c9d1d9;
        padding: 16px;
        border-radius: 10px;
        overflow-x: auto;
        font-size: 13px;
        border: 1px solid #30363d;
    }
    .log-line { display: flex; padding: 2px 0; border-bottom: 1px solid #161b22; }
    .log-line:hover { background: #161b22; }
    .line-number { width: 44px; color: #484f58; text-align: right; margin-right: 16px; user-select: none; flex-shrink: 0; }
    .line-content { white-space: pre-wrap; word-break: break-all; }

    .risk-critical { background-color: rgba(255,0,0,0.12); border-left: 3px solid #f85149; color: #ffa198; }
    .risk-high     { background-color: rgba(255,140,0,0.12); border-left: 3px solid #d29922; color: #e3b341; }
    .risk-medium   { background-color: rgba(187,128,9,0.10); border-left: 3px solid #8b949e; color: #d2a679; }
    .risk-low      { border-left: 3px solid #1f6feb; }

    .llm-badge      { background: #0d2818; color: #3fb950; font-size: 11px; padding: 3px 10px; border-radius: 20px; border: 1px solid #3fb950; font-family: 'JetBrains Mono', monospace; }
    .fallback-badge { background: #1c1c1c; color: #8b949e; font-size: 11px; padding: 3px 10px; border-radius: 20px; border: 1px solid #484f58; font-family: 'JetBrains Mono', monospace; }

    .stButton>button { border-radius: 8px !important; font-family: 'Syne', sans-serif !important; font-weight: 600 !important; }
</style>
""", unsafe_allow_html=True)


# HEADER 
st.title("🛡️ SecureCode AI")
st.markdown("**Pre-Commit Security Gate & CI/CD Analyzer**")
st.caption("Prevent developers from committing hardcoded secrets, credentials, and security risks into version control — with AI-powered remediation insights.")
st.divider()

#  SIDEBAR
st.sidebar.header("🔧 Input Configuration")

input_type = st.sidebar.selectbox(
    "Select Input Type",
    ["log", "py", "js", "ts", "env", "text", "sql", "chat", "pdf", "doc"],
    format_func=lambda x: {
        "log": "📋 Log File",
        "py":  "🐍 Python Code",
        "js":  "🟨 JavaScript",
        "ts":  "🔷 TypeScript",
        "env": "⚙️  .env Config",
        "text":"📝 Plain Text",
        "sql": "🗄️  SQL",
        "chat":"💬 Chat Input",
        "pdf": "📄 PDF Document",
        "doc": "📃 Word Document",
    }.get(x, x)
)

uploaded_file = st.sidebar.file_uploader(
    "Upload File",
    type=["pdf", "docx", "txt", "log", "py", "js", "ts", "env"],
    help="Supports: Python, JS/TS, .env, logs, text, PDF, DOCX"
)

text_input = st.sidebar.text_area(
    "Or paste code / text / log",
    height=140,
    placeholder="""# Paste your code, log, or .env here
# Example:
password=admin123
api_key=sk-prod-xyz
SECRET_KEY=jwt-secret-abc"""
)

st.sidebar.divider()
st.sidebar.subheader("⚙️ Policy Options")
mask_values    = st.sidebar.checkbox("🔒 Mask sensitive values", value=True)
block_critical = st.sidebar.checkbox("🚫 Block on high/critical risk", value=False)

#  DEMO SAMPLES
st.sidebar.divider()
st.sidebar.subheader("🧪 Quick Demo Samples")

col_a, col_b = st.sidebar.columns(2)
sample_text = ""

if col_a.button("Python Code", use_container_width=True):
    sample_text = """import os
import requests

# TODO: remove hardcoded key before merging
API_KEY = "sk-prod-abc123xyz"
DB_PASSWORD = "admin@1234"
SECRET_KEY = "my-jwt-secret-key"

def get_user(email):
    # FIXME: hardcoded password here
    password = "hunter2"
    return requests.get(f"https://api.example.com/user?email={email}&key={API_KEY}")
"""

if col_b.button("App Log", use_container_width=True):
    sample_text = """[2026-03-24 10:00:01] INFO Starting service
email=admin@company.com
password=admin123
api_key=sk-prod-xyz123abc
[2026-03-24 10:00:05] ERROR NullPointerException at LoginService.java:45
[2026-03-24 10:00:06] DEBUG token=eyJhbGciOiJIUzI1NiJ9.payload.sig
"""

# MAIN ANALYZE BUTTON 
if st.button("🚀 Scan for Security Issues", type="primary", use_container_width=True):
    with st.spinner("Scanning for secrets, credentials, and security risks..."):
        try:
            data = {"input_type": input_type}
            display_text = ""
            api_url = "https://securecode-ai-j38r.onrender.com/upload"

            effective_text = sample_text if sample_text else text_input

            if uploaded_file is not None:
                if len(uploaded_file.getvalue()) > 5 * 1024 * 1024:
                    st.error("❌ File too large. Please upload a file under 5MB.")
                    st.stop()

                if uploaded_file.name.endswith(('.txt', '.log', '.py', '.js', '.ts', '.env')):
                    display_text = uploaded_file.getvalue().decode("utf-8", errors="ignore")
                else:
                    display_text = f"Binary file: {uploaded_file.name}\nExtracting and scanning contents..."

                files = {"file": (uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type)}
                response = requests.post(api_url, data=data, files=files)

            else:
                content = effective_text or """[2026-03-24 10:00:01] INFO Starting service
email=admin@company.com
password=admin123
api_key=sk-prod-xyz123abc
SECRET_KEY=super-secret-jwt-key
ERROR: NullPointerException at com.company.service.LoginService.java:45"""
                display_text = content
                data["content"] = content
                response = requests.post(api_url, data=data)

            #  RESULTS 
            if response.status_code == 200:
                result = response.json()
                st.success("✅ Scan Completed!")

                col1, col2, col3 = st.columns(3)
                risk_level = result.get("risk_level", "low")
                risk_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(risk_level, "🟡")
                action = result.get("action", "passed")
                action_emoji = {"blocked": "🚫", "masked": "🔒", "passed": "✅"}.get(action, "✅")

                col1.metric("Risk Level",    f"{risk_emoji} {risk_level.upper()}")
                col2.metric("Risk Score",    result.get("risk_score", 0))
                col3.metric("Policy Action", f"{action_emoji} {action.upper()}")

                st.divider()

                left, right = st.columns(2)

                with left:
                    st.subheader("📋 Summary")
                    st.info(result.get("summary", "No summary"))

                    st.subheader("🔍 Findings")
                    findings = result.get("findings", [])
                    if findings:
                        for f in findings:
                            emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(f["risk"], "🟡")
                            raw_value = f.get("value", "")
                            if raw_value in ("****", "[BLOCKED]", None, ""):
                                display_value = "*(masked)*" if raw_value == "****" else (raw_value or "—")
                            else:
                                display_value = f"`{raw_value}`"
                            st.write(f"{emoji} **{f['type'].upper()}** · Line {f.get('line', 'N/A')} → {display_value}")
                    else:
                        st.success("✅ No sensitive data detected.")

                with right:
                    st.subheader("💡 AI Security Insights")
                    insights_source = result.get("insights_source", "llm")
                    if insights_source == "llm":
                        st.markdown('<span class="llm-badge">⚡ Powered by Claude AI</span>', unsafe_allow_html=True)
                    else:
                        st.markdown('<span class="fallback-badge">⚠️ Rule-based fallback</span>', unsafe_allow_html=True)
                    st.write("")
                    for insight in result.get("insights", ["No insights generated"]):
                        st.write(f"• {insight}")

                #  LOG VIEWER 
                st.divider()
                st.subheader("📜 Highlighted Source View")

                html_logs = '<div class="log-container">'
                lines = display_text.split('\n')
                finding_lines = {f.get("line"): f.get("risk") for f in result.get("findings", []) if f.get("line")}

                for i, line in enumerate(lines, 1):
                    css_class = f"risk-{finding_lines[i]}" if i in finding_lines else ""
                    safe_line = line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                    html_logs += f'<div class="log-line {css_class}"><div class="line-number">{i}</div><div class="line-content">{safe_line}</div></div>'

                html_logs += '</div>'
                st.markdown(html_logs, unsafe_allow_html=True)

            elif response.status_code == 413:
                st.error("❌ File too large. Please upload a file under 5MB.")
            else:
                st.error(f"Backend Error: {response.status_code} — {response.text}")

        except Exception as e:
            st.error(f"❌ Could not connect to backend. Make sure uvicorn is running.\n\nError: {e}")

#  FOOTER
st.divider()
st.caption("SecureCode AI · Software Development Domain · SISA Hackathon March 2026 ·")