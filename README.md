# SecureCode AI 🛡️

**AI-Powered Code & Log Security Analyzer for Software Engineers**

A developer-focused security tool that scans source code, `.env` configs, and logs for hardcoded secrets, credential leaks, and security risks — with Claude AI-powered remediation insights, line-level highlighting, and a compliant REST API.

**Domain: Software Development (SDE)**
**Event: SISA Hackathon — March 2026**

---

## 🚀 Key Features

- **Multi-Source Ingestion** — Supports `.py`, `.js`, `.ts`, `.env`, `.log`, `.txt`, `.pdf`, `.docx`, raw text, SQL, and chat input
- **9-Pattern Detection Engine** — Regex scanning for passwords, API keys, hardcoded secrets, `.env` leaks, private keys, stack traces, insecure TODOs, emails, and phone numbers
- **Claude AI Insights** — Context-aware, actionable remediation advice powered by Claude (Anthropic), with graceful rule-based fallback
- **Risk Engine** — Classifies findings as Critical / High / Medium / Low with a composite risk score
- **Policy Engine** — Configurable masking and blocking of high-risk content
- **Line-Level Highlighting** — Custom log viewer with color-coded risk markers per line
- **Dual API** — `/analyze` (strict JSON for CI/CD) and `/upload` (multipart for UI)

---

## 🛠️ Tech Stack

| Layer      | Technology                          |
|------------|-------------------------------------|
| Backend    | FastAPI, Python, Pydantic           |
| AI         | Claude API (Anthropic) — `claude-sonnet-4-20250514` |
| Frontend   | Streamlit + Custom HTML/CSS         |
| Parsers    | PyPDF2, python-docx                 |
| Observability | Python logging (structured)      |

---

## ⚙️ Setup & Run

### 1. Install dependencies

```bash
pip install fastapi uvicorn streamlit requests anthropic PyPDF2 python-docx pydantic python-multipart
```

### 2. Set your Claude API key

```bash
export ANTHROPIC_API_KEY=your_api_key_here
```

### 3. Start the backend

```bash
uvicorn main:app --reload --port 8000
```

### 4. Start the frontend (new terminal)

```bash
streamlit run app.py
```

Open [http://localhost:8501](http://localhost:8501)

---

## 📡 API Reference

### `POST /analyze` — JSON endpoint (for CI/CD / judges)

**Request:**
```json
{
  "input_type": "py",
  "content": "API_KEY = 'sk-prod-xyz'\npassword = 'admin123'",
  "options": {
    "mask": true,
    "block_high_risk": false
  }
}
```

**Response:**
```json
{
  "summary": "Analyzed py content. Detected 2 security issue(s).",
  "content_type": "py",
  "findings": [
    { "type": "api_key",  "risk": "high",     "line": 1, "value": "****" },
    { "type": "password", "risk": "critical",  "line": 2, "value": "****" }
  ],
  "risk_score": 11,
  "risk_level": "high",
  "action": "masked",
  "insights": [
    "[CRITICAL] Plaintext password detected — rotate immediately and move to a secrets manager.",
    "[HIGH] API key exposed in source — revoke and reissue, store in environment variables.",
    "[HIGH] Avoid hardcoding secrets in source files — use os.environ or dotenv libraries."
  ],
  "insights_source": "llm"
}
```

### `POST /upload` — Multipart file upload (for Streamlit UI)

Form fields: `input_type` (str), `content` (str, optional), `file` (file, optional)

### `GET /health`

```json
{ "status": "ok", "service": "SecureCode AI", "version": "2.0" }
```

---

## 🔍 Detection Patterns

| Pattern               | Risk Level | Trigger                                      |
|-----------------------|------------|----------------------------------------------|
| Password in content   | Critical   | `password=`, `password:`                     |
| Hardcoded secret      | Critical   | `SECRET_KEY=`, `DB_PASSWORD=`, `JWT_SECRET=` |
| Private key block     | Critical   | `-----BEGIN RSA PRIVATE KEY-----`            |
| API key / token       | High       | `api_key=`, `token=`, `apikey=`              |
| .env variable leak    | High       | `UPPERCASE_VAR=` with key/secret/auth        |
| Stack trace / error   | Medium     | Exception, NullPointer, Traceback            |
| Insecure TODO/FIXME   | Medium     | TODO/FIXME referencing password/key/secret   |
| Phone number          | Medium     | Phone label + digit pattern                  |
| Email address         | Low        | Standard email regex                         |

---

## 🎯 Problem Solved

Developers accidentally commit secrets — API keys, passwords, JWT secrets — to version control or leave them in logs. This is one of the top causes of production security incidents.

**SecureCode AI** acts as a pre-commit / pre-deploy scanner that:
1. Detects secrets and credentials before they reach production
2. Classifies risk severity
3. Provides AI-generated, actionable fix suggestions
4. Exposes a REST API that can plug into any CI/CD pipeline

---

## 🏗️ Architecture

```
Input (Code / Log / File / Text)
        ↓
   Validation (size, type)
        ↓
  Parser (PDF / DOCX / plain text)
        ↓
  Detection Engine (9 regex patterns)
        ↓
  Risk Engine (score + classify)
        ↓
  Policy Engine (mask / block)
        ↓
  Claude AI (insights + remediation)
        ↓
  Response (JSON + UI rendering)
```

---

## ⚡ Challenges Faced

- **Regex precision** — Balancing false-positive rate (e.g. timestamps matching phone patterns) required careful pattern design with context guards
- **LLM reliability** — Added graceful fallback to rule-based insights so the app functions even without API connectivity
- **File type diversity** — Unified processing pipeline for binary (PDF, DOCX) and text (py, env, log) formats
- **UI line highlighting** — Custom HTML/CSS injection in Streamlit to achieve VS Code-style line-level risk markers

---

## 📁 Project Structure

```
.
├── main.py        # FastAPI backend — detection, risk, policy, Claude AI
├── app.py         # Streamlit frontend — UI, file upload, results display
└── README.md      # This file
```