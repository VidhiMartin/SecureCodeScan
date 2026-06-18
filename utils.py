import os
import requests
import json
import logging
import re
from typing import Dict, Any, List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

LLM_API_KEY = os.getenv("OPENROUTER_API_KEY")
LLM_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "nvidia/nemotron-3-super-120b-a12b:free"

REQUIRED_KEYS = {"name", "severity", "cwe", "vulnerable_code", "risk", "fix"}

# -------------------------------------------------------------------
# Plain-text multi‑vulnerability prompt
# -------------------------------------------------------------------
_SYSTEM_PROMPT_MULTI = (
    "You are a static analysis security engine.\n"
    "List ALL vulnerabilities in the provided code.\n"
    "For each vulnerability, output exactly one line in this format:\n\n"
    "CWE-ID | vulnerable_code_snippet | risk (max 15 words) | fix (one line, max 15 words)\n\n"
    "Separate fields with the pipe character \" | \" (space pipe space).\n"
    "Do NOT use markdown, code blocks, or any other text. Just the lines.\n"
    "Order by severity, most critical first.\n"
    "If no vulnerabilities, output a single line: \"No issues found\"."
)

_FEW_SHOT_MULTI = [
    {
        "user": (
            "Language: python\n\n"
            "Code:\n"
            "from flask import request\n"
            "import os, sqlite3\n"
            "@app.route('/login', methods=['POST'])\n"
            "def login():\n"
            "    user = request.form['user']\n"
            "    pass = request.form['pass']\n"
            "    query = f\"SELECT * FROM users WHERE user='{user}' AND pass='{pass}'\"\n"
            "    db.execute(query)\n"
            "@app.route('/ping')\n"
            "def ping():\n"
            "    host = request.args.get('host')\n"
            "    os.system(f'ping {host}')\n"
        ),
        "assistant": (
            "CWE-89 | db.execute(query) | SQL injection allows authentication bypass | Use parameterised queries\n"
            "CWE-78 | os.system(f'ping {host}') | Command injection via host parameter | Use subprocess.run with shell=False"
        )
    }
]

# Single-vulnerability fallback (same as before – reliable JSON)
_SYSTEM_PROMPT_SINGLE = (
    "You are a static analysis security engine.\n"
    "Return exactly one JSON object for the most critical vulnerability.\n"
    "Use these keys: name, severity, cwe, vulnerable_code, risk, fix.\n"
    "If no vulnerability, return {\"name\": \"No issues found\"}."
)

_FEW_SHOT_SINGLE = [
    {
        "user": (
            "Language: python\n\n"
            "Code:\n"
            "from flask import request\n"
            "import os, sqlite3\n"
            "@app.route('/login', methods=['POST'])\n"
            "def login():\n"
            "    user = request.form['user']\n"
            "    pass = request.form['pass']\n"
            "    query = f\"SELECT * FROM users WHERE user='{user}' AND pass='{pass}'\"\n"
            "    db.execute(query)\n"
        ),
        "assistant": json.dumps({
            "name": "SQL Injection",
            "severity": "10/10",
            "cwe": "CWE-89",
            "vulnerable_code": "query = f\"SELECT * FROM users WHERE user='{user}' AND pass='{pass}'\"",
            "risk": "User input directly concatenated into SQL query allows authentication bypass.",
            "fix": "Use parameterised queries."
        })
    }
]

def _parse_text_list(raw: str) -> List[Dict]:
    """Parse a plain‑text list of lines with pipe‑separated fields."""
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if not lines:
        return []
    # Check for the "no issues" case
    if lines[0].lower().startswith("no issues"):
        return []
    vulns = []
    for line in lines:
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 4:
            continue  # skip malformed lines
        cwe, code_snippet, risk, fix = parts[0], parts[1], parts[2], parts[3]
        vulns.append({
            "name": cwe,                # use CWE as the name for the card
            "severity": "N/A",
            "cwe": cwe,
            "vulnerable_code": code_snippet,
            "risk": risk,
            "fix": fix
        })
    return vulns

def _parse_json_object(raw: str) -> Dict:
    raw = re.sub(r'```(?:json)?\s*|\s*```', '', raw).strip()
    match = re.search(r'\{.*\}', raw, re.DOTALL)
    if not match:
        raise ValueError("No JSON object found")
    return json.loads(match.group(0))

def _validate_vuln(v: Dict) -> Dict:
    for key in REQUIRED_KEYS:
        if key not in v:
            v[key] = "N/A"
    return v

def _most_critical(vulns: List[Dict]) -> Dict:
    if not vulns:
        return {
            "name": "No issues found",
            "severity": "N/A",
            "cwe": "N/A",
            "vulnerable_code": "N/A",
            "risk": "No security issues detected.",
            "fix": "N/A"
        }
    return vulns[0]  # list is already sorted by severity

def _run_llm(system: str, few_shot: List, user_prompt: str, max_tokens: int, timeout: int) -> str:
    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://securecodescanner.vercel.app",
        "X-Title": "Enterprise Secure Scanner",
    }
    messages = [{"role": "system", "content": system}]
    for ex in few_shot:
        messages.append({"role": "user", "content": ex["user"]})
        messages.append({"role": "assistant", "content": ex["assistant"]})
    messages.append({"role": "user", "content": user_prompt})

    payload = {
        "model": MODEL,
        "messages": messages,
        "temperature": 0.05,
        "max_tokens": max_tokens,
    }
    resp = requests.post(LLM_ENDPOINT, headers=headers, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"].strip()

def analyze_code(code: str, language: str) -> Dict[str, Any]:
    if not LLM_API_KEY:
        logger.error("OPENROUTER_API_KEY not set.")
        return {
            "status": "error",
            "error_code": "NO_API_KEY",
            "vulnerabilities": [],
            "most_critical": {"name": "Error", "details": "API key not configured."}
        }

    sanitized = code.replace("<", "&lt;").replace(">", "&gt;")
    user_prompt_multi = (
        f"Language: {language}\n\n"
        f"Code:\n{sanitized}\n\n"
        "List ALL vulnerabilities using the pipe-separated format."
    )

    # Try the plain‑text list first
    try:
        raw = _run_llm(_SYSTEM_PROMPT_MULTI, _FEW_SHOT_MULTI, user_prompt_multi, 4096, 90)
        vulns = _parse_text_list(raw)
        if vulns:
            return {
                "status": "success",
                "vulnerabilities": vulns,
                "most_critical": vulns[0]
            }
        else:
            return {
                "status": "success",
                "vulnerabilities": [],
                "most_critical": _most_critical([])
            }
    except Exception as e:
        logger.warning(f"Plain‑text list failed: {e}, falling back to single JSON.")

    # Fallback to single‑vulnerability JSON
    try:
        user_prompt_single = (
            f"Language: {language}\n\n"
            f"Code:\n{sanitized}\n\n"
            "Return exactly one JSON object for the most critical vulnerability."
        )
        raw = _run_llm(_SYSTEM_PROMPT_SINGLE, _FEW_SHOT_SINGLE, user_prompt_single, 400, 30)
        obj = _parse_json_object(raw)
        obj = _validate_vuln(obj)
        if obj.get("name") == "No issues found":
            obj.setdefault("severity", "N/A")
            obj.setdefault("cwe", "N/A")
            obj.setdefault("vulnerable_code", "N/A")
            obj.setdefault("risk", "No security issues detected.")
            obj.setdefault("fix", "N/A")
        return {
            "status": "success",
            "vulnerabilities": [obj],
            "most_critical": obj
        }
    except Exception as e2:
        logger.error(f"Single‑vuln also failed: {e2}")
        return {
            "status": "error",
            "error_code": "INVALID_RESPONSE",
            "vulnerabilities": [],
            "most_critical": {"name": "Error", "details": "LLM could not generate valid output."}
        }
