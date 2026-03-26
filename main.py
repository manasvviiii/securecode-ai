from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import io
import logging
import time
import re
import os
from anthropic import AsyncAnthropic, APIError
from docx import Document
import PyPDF2

#  OBSERVABILITY SETUP 
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("securecode")

#  CLAUDE API CLIENT 
_api_key = os.environ.get("ANTHROPIC_API_KEY", "")
client = AsyncAnthropic(api_key=_api_key) if _api_key else None
if not client:
    logger.warning("[BOOT] ANTHROPIC_API_KEY not set — rule-based fallback will be used for all insights.")

app = FastAPI(title="SecureCode AI - Code & Log Security Analyzer")

MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

# MODELS
class Finding(BaseModel):
    type: str
    risk: str
    line: Optional[int] = None
    value: Optional[str] = None

class AnalyzeResponse(BaseModel):
    summary: str
    content_type: str
    findings: List[Finding]
    risk_score: int
    risk_level: str
    action: str
    insights: List[str]
    insights_source: str  # "llm" or "fallback"

class AnalyzeRequest(BaseModel):
    input_type: str
    content: str
    options: Optional[Dict[str, Any]] = None


# DETECTION ENGINE
def detect_sensitive_data(text: str) -> List[Finding]:
    findings = []
    lines = text.splitlines()

    for i, line in enumerate(lines, 1):

        # 1. PASSWORD — critical
        if re.search(r'password\s*[:=]\s*\S+', line, re.IGNORECASE):
            match = re.search(r'password\s*[:=]\s*(\S+)', line, re.IGNORECASE)
            value = match.group(1) if match else "****"
            findings.append(Finding(type="password", risk="critical", line=i, value=value))

        # 2. API KEY / TOKEN / SECRET — high
        elif re.search(r'(api_key|apikey|secret|token)\s*[:=]\s*\S+', line, re.IGNORECASE):
            match = re.search(r'(api_key|apikey|secret|token)\s*[:=]\s*(\S+)', line, re.IGNORECASE)
            value = match.group(2) if match else "****"
            findings.append(Finding(type="api_key", risk="high", line=i, value=value))

        # 3. HARDCODED SECRETS IN CODE — critical (SDE-specific)
        elif re.search(r'(AWS_SECRET|AWS_ACCESS|PRIVATE_KEY|DB_PASSWORD|DATABASE_URL|SECRET_KEY|JWT_SECRET)\s*=\s*["\']?\S+', line, re.IGNORECASE):
            match = re.search(r'(AWS_SECRET|AWS_ACCESS|PRIVATE_KEY|DB_PASSWORD|DATABASE_URL|SECRET_KEY|JWT_SECRET)\s*=\s*["\']?(\S+)', line, re.IGNORECASE)
            value = match.group(2) if match else "****"
            findings.append(Finding(type="hardcoded_secret", risk="critical", line=i, value=value))

        # 4. .ENV VARIABLE LEAK — high (SDE-specific)
        elif re.search(r'^[A-Z_]{3,}=.+', line) and re.search(r'(key|secret|pass|token|auth|cred)', line, re.IGNORECASE):
            match = re.search(r'^([A-Z_]{3,})=(.+)', line)
            value = match.group(2) if match else "****"
            findings.append(Finding(type="env_variable_leak", risk="high", line=i, value=value))

        # 5. EMAIL — low
        elif re.search(r'[\w\.-]+@[\w\.-]+\.\w+', line):
            match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', line)
            findings.append(Finding(type="email", risk="low", line=i, value=match.group(0)))

        # 6. PHONE NUMBER — medium
        elif (
            re.search(r'(phone|mobile|contact|tel|cell|ph)\s*[:=]', line, re.IGNORECASE)
            and not re.search(r'\d{4}-\d{2}-\d{2}', line)
            and re.search(r'(\+?[\d\s\-().]{10,15})', line)
        ):
            match = re.search(r'(\+?[\d\s\-().]{10,15})', line)
            findings.append(Finding(type="phone_number", risk="medium", line=i, value=match.group(1).strip()))

        
        # 7. STACK TRACE / ERROR — medium
        elif re.search(r'(traceback|nullpointer|exception in thread)', line, re.IGNORECASE) or (re.search(r'\berror\b', line, re.IGNORECASE) and not re.search(r'(except |logging\.|raise |return |def )', line, re.IGNORECASE)):
            findings.append(Finding(type="stack_trace", risk="medium", line=i, value=None))
        # 8. INSECURE TODO/FIXME in code — medium (SDE-specific)
        elif re.search(r'(TODO|FIXME|HACK).*(password|key|secret|token|auth|remove|hardcoded)', line, re.IGNORECASE):
            findings.append(Finding(type="insecure_todo", risk="medium", line=i, value=line.strip()))

        # 9. PRIVATE KEY BLOCK — critical (SDE-specific)
        elif re.search(r'-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----', line):
            findings.append(Finding(type="private_key", risk="critical", line=i, value="[PRIVATE KEY BLOCK]"))

    return findings


# POLICY ENGINE 
def apply_policy(findings: list, content: str, options: dict) -> tuple:
    mask = options.get("mask", False)
    block_high_risk = options.get("block_high_risk", False)

    risk_score = len(findings) * 3 + sum(
        5 if f.risk == "critical" else 3 if f.risk == "high" else 1
        for f in findings
    )
    risk_level = (
        "critical" if risk_score >= 12 else
        "high"     if risk_score >= 8  else
        "medium"   if risk_score >= 4  else
        "low"
    )

    action = "passed"

    if block_high_risk and risk_level in ["critical", "high"]:
        action = "blocked"
        findings = [
            Finding(type=f.type, risk=f.risk, line=f.line, value="[BLOCKED]")
            for f in findings
        ]
        return findings, risk_level, action

    if mask:
        action = "masked"
        findings = [
            Finding(type=f.type, risk=f.risk, line=f.line, value="****" if f.value else None)
            for f in findings
        ]

    return findings, risk_level, action


def compute_risk_score(findings: list) -> int:
    return len(findings) * 3 + sum(
        5 if f.risk == "critical" else 3 if f.risk == "high" else 1
        for f in findings
    )


 
# FIX 2: Use AsyncAnthropic + await so we never block the event loop.
async def generate_insights(text: str, findings: list, content_type: str = "log") -> tuple:
    """Generate security insights using Claude API asynchronously. Returns (insights list, source)."""
    findings_context = "\n".join([f"- {f.risk.upper()}: {f.type} (line {f.line})" for f in findings])

    type_context = "source code" if content_type in ["py", "js", "ts", "env"] else "log/text content"

    prompt = f"""You are a DevSecOps security expert reviewing {type_context} for a software engineering team.

Security findings detected:
{findings_context or 'None'}

Content snippet (first 1200 chars):
{text[:1200]}

Generate exactly 3 concise, technical, actionable security insights for a software developer.
Each insight must:
- Start with the risk level in brackets e.g. [CRITICAL], [HIGH], [MEDIUM], [LOW]
- Be specific to what was found
- Include a concrete remediation step

Return ONLY 3 lines, each starting with a dash (-). No intro, no extra text."""

    try:
        # FIX 1 continued: guard against missing key at call time too
        if not client:
            raise ValueError("Claude client not initialized — ANTHROPIC_API_KEY missing.")

        message = await client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}]
        )
        text_response = message.content[0].text.strip()

        insights = [
            line.lstrip("- *").strip()
            for line in text_response.split('\n')
            if len(line.strip()) > 10
            and not line.strip().lower().startswith("here are")
            and not line.strip().lower().startswith("here is")
            and not line.strip().lower().startswith("based on")
        ]

        if insights:
            return insights[:3], "llm"
        return ["Review content manually. AI parsing returned empty response."], "fallback"

    except Exception as e:
        logger.warning(f"[CLAUDE DEGRADED] Claude API unavailable, using rule-based fallback. Reason: {e}")
        fallback = []
        types = {f.type for f in findings}
        if "password" in types or "hardcoded_secret" in types:
            fallback.append("[CRITICAL] Plaintext credential detected — rotate immediately and move to environment variables or a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault).")
        if "api_key" in types or "env_variable_leak" in types:
            fallback.append("[HIGH] API key or secret exposed — revoke the key, reissue a new one, and store it in .env (never commit to version control). Add .env to .gitignore.")
        if "private_key" in types:
            fallback.append("[CRITICAL] Private key detected in source — remove immediately, rotate the key pair, and use SSH agent or key management service instead.")
        if "stack_trace" in types:
            fallback.append("[MEDIUM] Stack trace leaked — internal system details may be exploitable. Disable debug mode in production and sanitize error responses.")
        if "insecure_todo" in types:
            fallback.append("[MEDIUM] Insecure TODO/FIXME comment found — remove hardcoded credentials referenced in comments before merging to main.")
        if "email" in types:
            fallback.append("[LOW] Email address found in content — verify if PII logging is intentional and compliant with data protection policies (GDPR/CCPA).")
        result = fallback[:3] if fallback else ["No critical findings. Review content manually for edge-case anomalies."]
        return result, "fallback"


#ENDPOINT 1: JSON API (For Judges / CI-CD) 
@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_json(request: AnalyzeRequest):
    start = time.time()
    logger.info(f"[REQUEST] /analyze input_type={request.input_type}")

    try:
        content = request.content or f"Simulated {request.input_type} content..."
        options = request.options or {}

        if len(content.encode("utf-8")) > MAX_FILE_SIZE:
            raise HTTPException(status_code=413, detail="Content too large. Maximum allowed size is 5MB.")

        findings = detect_sensitive_data(content)
        findings, risk_level, action = apply_policy(findings, content, options)
        risk_score = compute_risk_score(findings)
        ai_insights, insights_source = await generate_insights(content, findings, request.input_type)

        logger.info(f"[RESPONSE] /analyze risk={risk_level} findings={len(findings)} action={action} source={insights_source} dur={time.time()-start:.3f}s")

        return AnalyzeResponse(
            summary=f"Analyzed {request.input_type} content. Detected {len(findings)} security issue(s).",
            content_type=request.input_type,
            findings=findings,
            risk_score=risk_score,
            risk_level=risk_level,
            action=action,
            insights=ai_insights,
            insights_source=insights_source
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[ERROR] /analyze {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ENDPOINT 2: FILE UPLOAD (For Streamlit UI)
@app.post("/upload", response_model=AnalyzeResponse)
async def upload_file(
    input_type: str = Form(...),
    content: str = Form(""),
    file: Optional[UploadFile] = File(None)
):
    start = time.time()
    filename = file.filename if file else "none"
    logger.info(f"[REQUEST] /upload input_type={input_type} file={filename}")

    detected_type = input_type

    try:
        if file:
            file_content = await file.read()

            if len(file_content) > MAX_FILE_SIZE:
                raise HTTPException(
                    status_code=413,
                    detail=f"File too large. Max 5MB. Got {len(file_content) // 1024}KB."
                )

            fname = file.filename.lower()

            if fname.endswith(".pdf"):
                reader = PyPDF2.PdfReader(io.BytesIO(file_content))
                content = "\n".join(page.extract_text() or "" for page in reader.pages)
                detected_type = "pdf"
            elif fname.endswith(".docx"):
                doc = Document(io.BytesIO(file_content))
                content = "\n".join(para.text for para in doc.paragraphs)
                detected_type = "doc"
            elif fname.endswith(".py"):
                content = file_content.decode("utf-8", errors="ignore")
                detected_type = "py"
            elif fname.endswith((".js", ".ts")):
                content = file_content.decode("utf-8", errors="ignore")
                detected_type = "js"
            elif fname.endswith(".env") or fname.startswith(".env"):
                content = file_content.decode("utf-8", errors="ignore")
                detected_type = "env"
            else:
                content = file_content.decode("utf-8", errors="ignore")

        if not content:
            content = """[2026-03-24 10:00:01] INFO Starting service
email=admin@company.com
password=admin123
api_key=sk-prod-xyz123abc
SECRET_KEY=super-secret-jwt-key
ERROR: NullPointerException at com.company.service.LoginService.java:45"""

        findings = detect_sensitive_data(content)
        default_options = {"mask": True, "block_high_risk": False}
        findings, risk_level, action = apply_policy(findings, content, default_options)
        risk_score = compute_risk_score(findings)
        ai_insights, insights_source = await generate_insights(content, findings, detected_type)

        logger.info(f"[RESPONSE] /upload risk={risk_level} findings={len(findings)} action={action} source={insights_source} dur={time.time()-start:.3f}s")

        return AnalyzeResponse(
            summary=f"Scanned {fname if file else 'text input'}. Found {len(findings)} security issue(s).",
            content_type=detected_type,
            findings=findings,
            risk_score=risk_score,
            risk_level=risk_level,
            action=action,
            insights=ai_insights,
            insights_source=insights_source
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[ERROR] /upload {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


#  HEALTH CHECK 
@app.get("/health")
def health_check():
    logger.info("[HEALTH] ping")
    return {"status": "ok", "service": "SecureCode AI", "version": "2.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)