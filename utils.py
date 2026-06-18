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
# Primary prompt – bare JSON array (most reliable for free model)
# -------------------------------------------------------------------
_SYSTEM_PROMPT_MULTI = (
    "You are a static analysis security engine.\n"
    "Find ALL vulnerabilities in the provided code.\n\n"
    "Return **only** a JSON array of objects. No other text, no markdown.\n"
    "Each object must have exactly these keys:\n"
    '  "cwe"      – CWE number and short name (e.g., "CWE-78: OS Command Injection")\n'
    '  "severity" – a string like "9/10"\n'
    '  "vulnerable_code" – the exact vulnerable line (keep it short, under 50 chars)\n'
    '  "risk"     – how an attacker would exploit it, max 15 words\n'
    '  "fix"      – one‑line fix, max 20 words; if the fix is trivial (e.g., debug=False), just state it\n'
    "Order the array from most critical to least critical.\n"
    "If no vulnerabilities exist, return an empty array []."
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
        "assistant": json.dumps([
            {
                "cwe": "CWE-89: SQL Injection",
                "severity": "10/10",
                "vulnerable_code": "db.execute(query)",
                "risk": "Attacker bypasses login by injecting SQL",
                "fix": "Use parameterised queries"
            },
            {
                "cwe": "CWE-78: OS Command Injection",
                "severity": "9/10",
                "vulnerable_code": "os.system(f'ping {host}')",
                "risk": "Attacker controls host parameter to run commands",
                "fix": "Use subprocess.run with shell=False"
            }
        ])
    }
]

# -------------------------------------------------------------------
# Fallback – plain‑text list with pipe separators, but now very strict
# -------------------------------------------------------------------
_SYSTEM_PROMPT_MULTI_TEXT = (
    "List ALL vulnerabilities. Output exactly one line per vulnerability, using this format:\n"
    "CWE-ID: Name | severity/10 | vulnerable code snippet | risk (max 15 words) | fix (max 20 words)\n"
    "Example line:\n"
    "CWE-89: SQL Injection | 10/10 | db.execute(query) | Attacker bypasses login | Use parameterised queries\n\n"
    "Do NOT include any other text. Do NOT repeat these instructions. Start directly with the first vulnerability line.\n"
    "If no vulnerabilities, output only the word NONE."
)

_FEW_SHOT_MULTI_TEXT = [
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
            "CWE-89: SQL Injection | 10/10 | db.execute(query) | Attacker bypasses login | Use parameterised queries\n"
            "CWE-78: OS Command Injection | 9/10 | os.system(f'ping {host}') | Attacker controls host to run commands | Use subprocess.run with shell=False"
        )
    }
]

# -------------------------------------------------------------------
# Single‑vulnerability JSON fallback (very reliable)
# -------------------------------------------------------------------
_SYSTEM_PROMPT_SINGLE = (
    "You are a static analysis security engine.\n"
    "Return exactly ONE JSON object for the most critical vulnerability.\n"
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
            "cwe": "CWE-89: SQL Injection",
            "vulnerable_code": "query = f\"SELECT * FROM users WHERE user='{user}' AND pass='{pass}'\"",
            "risk": "Attacker bypasses login by injecting SQL",
            "fix": "Use parameterised queries"
        })
    }
]

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def _extract_json_array(raw: str) -> List[Dict]:
    """Extract a JSON array from the LLM output (handles fences and leading/trailing text)."""
    raw = re.sub(r'```(?:json)?\s*|\s*```', '', raw).strip()
    # Try to parse the whole string as JSON first
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return parsed
    except:
        pass
    # Look for the first array
    start = raw.find('[')
    end = raw.rfind(']')
    if start != -1 and end != -1 and end > start:
        try:
            parsed = json.loads(raw[start:end+1])
            if isinstance(parsed, list):
                return parsed
        except:
            pass
    raise ValueError("No JSON array found in response.")

def _parse_text_list(raw: str) -> List[Dict]:
    """Parse pipe‑separated lines, skipping any instruction lines."""
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    vulns = []
    for line in lines:
        # Ignore lines that look like instructions
        if line.lower().startswith(("we need", "list all", "output", "example", "do not", "return")):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 5:
            cwe_name, severity, code_snippet, risk, fix = parts[0], parts[1], parts[2], parts[3], parts[4]
            vulns.append({
                "name": cwe_name,          # contains CWE-ID and name
                "severity": severity,
                "cwe": cwe_name,
                "vulnerable_code": code_snippet,
                "risk": risk,
                "fix": fix
            })
    return vulns

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
    return vulns[0]   # already sorted

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

# -------------------------------------------------------------------
# Main analysis function
# -------------------------------------------------------------------
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
        "Return only a JSON array of vulnerabilities as instructed. No other text."
    )

    # Strategy 1: Bare JSON array
    try:
        raw = _run_llm(_SYSTEM_PROMPT_MULTI, _FEW_SHOT_MULTI, user_prompt_multi, 4096, 90)
        vulns = _extract_json_array(raw)
        vulns = [_validate_vuln(v) for v in vulns]
        if vulns:
            return {"status": "success", "vulnerabilities": vulns, "most_critical": vulns[0]}
        else:
            return {"status": "success", "vulnerabilities": [], "most_critical": _most_critical([])}
    except Exception as e:
        logger.warning(f"Bare JSON array failed: {e}. Trying pipe‑list fallback.")

    # Strategy 2: Pipe‑separated text list
    try:
        raw = _run_llm(_SYSTEM_PROMPT_MULTI_TEXT, _FEW_SHOT_MULTI_TEXT, user_prompt_multi, 4096, 60)
        vulns = _parse_text_list(raw)
        vulns = [_validate_vuln(v) for v in vulns]
        if vulns:
            return {"status": "success", "vulnerabilities": vulns, "most_critical": vulns[0]}
        else:
            return {"status": "success", "vulnerabilities": [], "most_critical": _most_critical([])}
    except Exception as e:
        logger.warning(f"Pipe list failed: {e}. Falling back to single JSON.")

    # Strategy 3: Single‑vulnerability JSON (ultimate fallback)
    try:
        user_prompt_single = (
            f"Language: {language}\n\n"
            f"Code:\n{sanitized}\n\n"
            "Return exactly one JSON object for the most critical vulnerability."
        )
        raw = _run_llm(_SYSTEM_PROMPT_SINGLE, _FEW_SHOT_SINGLE, user_prompt_single, 400, 30)
        obj = json.loads(raw)
        obj = _validate_vuln(obj)
        if obj.get("name") == "No issues found":
            obj.setdefault("severity", "N/A")
            obj.setdefault("cwe", "N/A")
            obj.setdefault("vulnerable_code", "N/A")
            obj.setdefault("risk", "No security issues detected.")
            obj.setdefault("fix", "N/A")
        return {"status": "success", "vulnerabilities": [obj], "most_critical": obj}
    except Exception as e2:
        logger.error(f"All strategies failed: {e2}")
        return {
            "status": "error",
            "error_code": "INVALID_RESPONSE",
            "vulnerabilities": [],
            "most_critical": {"name": "Error", "details": "LLM could not generate valid output."}
        }
