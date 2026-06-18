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
# PRIMARY: Bare JSON array
# -------------------------------------------------------------------
_SYSTEM_PROMPT_BARE_ARR = (
    "You are a static analysis security engine.\n"
    "Find ALL vulnerabilities in the code.\n\n"
    "Return **only** a JSON array. No markdown, no code blocks, no explanations.\n"
    "Each element of the array is an object with exactly these keys:\n"
    '  "cwe"      – CWE number and short name (e.g., "CWE-78: OS Command Injection")\n'
    '  "severity" – string like "9/10"\n'
    '  "vulnerable_code" – the vulnerable line (keep under 50 chars)\n'
    '  "risk"     – how an attacker would exploit it, max 15 words\n'
    '  "fix"      – one‑line fix, max 20 words\n\n'
    "Order from most critical to least critical.\n"
    "If no vulnerabilities exist, return an empty array []."
)

_FEW_SHOT_BARE_ARR = [
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
                "risk": "Attacker bypasses login",
                "fix": "Use parameterised queries"
            },
            {
                "cwe": "CWE-78: OS Command Injection",
                "severity": "9/10",
                "vulnerable_code": "os.system(f'ping {host}')",
                "risk": "Attacker controls host to run commands",
                "fix": "Use subprocess.run with shell=False"
            }
        ])
    }
]

# -------------------------------------------------------------------
# FALLBACK: Pipe‑separated list (faster and now cleaned up)
# -------------------------------------------------------------------
_SYSTEM_PROMPT_PIPE = (
    "List ALL vulnerabilities. For each vulnerability output exactly one line with fields separated by \" | \".\n"
    "Format: CWE-ID: Name | severity/10 | vulnerable code | risk (max 15 words) | fix (max 20 words)\n"
    "Example: CWE-89: SQL Injection | 10/10 | cur.execute(query) | Attacker bypasses login | Use parameterised queries\n\n"
    "Do NOT include any other text, no dashes, no bullet points. If no vulnerabilities, output the word NONE."
)

_FEW_SHOT_PIPE = [
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
# ULTIMATE FALLBACK: Single vulnerability
# -------------------------------------------------------------------
_SYSTEM_PROMPT_SINGLE = (
    "You are a security code scanner. Find the most critical vulnerability.\n"
    "Common sources of untrusted input (user‑controlled data):\n"
    "- Flask: request.args, request.form, request.json, request.data\n"
    "- Django: request.GET, request.POST\n"
    "- PHP: $_GET, $_POST\n"
    "- Node/Express: req.query, req.body\n"
    "- Java: request.getParameter()\n"
    "Common dangerous functions: os.system, subprocess.Popen, eval, exec, cursor.execute, pickle.loads, open() with user path.\n\n"
    "Return a JSON object with keys: name, severity, cwe, vulnerable_code, risk, fix.\n"
    "If no vulnerability is found, return {\"name\": \"No issues found\"}."
)

_FEW_SHOT_SINGLE = [
    {
        "user": (
            "Language: python\n\n"
            "Code:\n"
            "from flask import request\n"
            "import os\n"
            "@app.route('/ping')\n"
            "def ping():\n"
            "    host = request.args.get('host')\n"
            "    os.system(f'ping {host}')\n"
        ),
        "assistant": json.dumps({
            "name": "Command Injection",
            "severity": "9/10",
            "cwe": "CWE-78: OS Command Injection",
            "vulnerable_code": "os.system(f'ping {host}')",
            "risk": "Attacker can execute arbitrary commands",
            "fix": "Use subprocess.run with shell=False"
        })
    }
]

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def _extract_json_array(raw: str) -> List[Dict]:
    """Extract a JSON array from text, ignoring surrounding noise."""
    raw = re.sub(r'```(?:json)?\s*|\s*```', '', raw).strip()
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return parsed
    except:
        pass
    start = raw.find('[')
    end = raw.rfind(']')
    if start != -1 and end != -1 and end > start:
        try:
            parsed = json.loads(raw[start:end+1])
            if isinstance(parsed, list):
                return parsed
        except:
            pass
    raise ValueError("No JSON array found")

def _parse_pipe_list(raw: str) -> List[Dict]:
    """Parse pipe‑separated lines, skipping instruction echoes and cleaning bullet marks."""
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if lines and lines[0].upper() == "NONE":
        return []
    vulns = []
    for line in lines:
        # Skip lines that are obviously instructions or echoes of the format description
        lower = line.lower()
        if any(lower.startswith(skip) for skip in (
            "we need", "list all", "output", "return", "example", "do not",
            "now format", "format:", "cwe-id:", "cwe:", "severity/10", "code:", "risk:", "fix:"
        )):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) == 5 and "/" in parts[1]:
            cwe_name, severity, code, risk, fix = parts
            # Remove leading dash/asterisk/bullet from the name
            cwe_name = re.sub(r'^[\-\*\•\s]+', '', cwe_name).strip()
            vulns.append({
                "name": cwe_name,
                "severity": severity,
                "cwe": cwe_name,
                "vulnerable_code": code,
                "risk": risk,
                "fix": fix
            })
    return vulns

def _extract_json_object(raw: str) -> Dict:
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
    return vulns[0]

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
    user_prompt = f"Language: {language}\n\nCode:\n{sanitized}\n\nList all vulnerabilities."

    # ---- Strategy 1: Bare JSON array ----
    try:
        raw = _run_llm(_SYSTEM_PROMPT_BARE_ARR, _FEW_SHOT_BARE_ARR, user_prompt, 4096, 90)
        vulns = _extract_json_array(raw)
        vulns = [_validate_vuln(v) for v in vulns]
        if vulns:
            return {"status": "success", "vulnerabilities": vulns, "most_critical": vulns[0]}
        else:
            return {"status": "success", "vulnerabilities": [], "most_critical": _most_critical([])}
    except Exception as e:
        logger.warning(f"Bare array failed: {e}")

    # ---- Strategy 2: Pipe‑separated list ----
    try:
        raw = _run_llm(_SYSTEM_PROMPT_PIPE, _FEW_SHOT_PIPE, user_prompt, 4096, 60)
        vulns = _parse_pipe_list(raw)
        vulns = [_validate_vuln(v) for v in vulns]
        if vulns:
            return {"status": "success", "vulnerabilities": vulns, "most_critical": vulns[0]}
        else:
            return {"status": "success", "vulnerabilities": [], "most_critical": _most_critical([])}
    except Exception as e:
        logger.warning(f"Pipe list failed: {e}")

    # ---- Strategy 3: Single vulnerability ----
    try:
        raw = _run_llm(_SYSTEM_PROMPT_SINGLE, _FEW_SHOT_SINGLE, user_prompt, 400, 30)
        obj = _extract_json_object(raw)
        obj = _validate_vuln(obj)
        if obj.get("name") == "No issues found":
            obj.setdefault("severity", "N/A")
            obj.setdefault("cwe", "N/A")
            obj.setdefault("vulnerable_code", "N/A")
            obj.setdefault("risk", "No security issues detected.")
            obj.setdefault("fix", "N/A")
        return {"status": "success", "vulnerabilities": [obj], "most_critical": obj}
    except Exception as e:
        logger.error(f"All strategies failed: {e}")
        return {
            "status": "error",
            "error_code": "INVALID_RESPONSE",
            "vulnerabilities": [],
            "most_critical": {"name": "Error", "details": "LLM could not generate valid output."}
        }
