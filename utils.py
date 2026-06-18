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
# PRIMARY: Pipe‑separated list (extremely reliable, allows many vulns)
# -------------------------------------------------------------------
_SYSTEM_PROMPT_MULTI = (
    "You are a static analysis security engine.\n"
    "List ALL vulnerabilities in the provided code. Output exactly one line per vulnerability.\n"
    "Each line must follow this EXACT format (separate fields with the pipe symbol | ):\n"
    "CWE-ID: Name | severity/10 | vulnerable code snippet | risk (max 15 words) | fix (max 20 words)\n\n"
    "Example line:\n"
    "CWE-89: SQL Injection | 10/10 | cur.execute(query) | Attacker bypasses login | Use parameterised queries\n\n"
    "RULES:\n"
    "- Do NOT include any other text, commentary, or markdown.\n"
    "- Do NOT repeat these instructions.\n"
    "- If there are no vulnerabilities, output just the word NONE.\n"
    "- Order from most critical to least critical.\n"
    "- Use only the pipe character to separate fields, nothing else."
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
            "CWE-89: SQL Injection | 10/10 | db.execute(query) | Attacker bypasses login | Use parameterised queries\n"
            "CWE-78: OS Command Injection | 9/10 | os.system(f'ping {host}') | Attacker controls host to run commands | Use subprocess.run with shell=False"
        )
    }
]

# -------------------------------------------------------------------
# ROBUST FALLBACK: Single vulnerability with full taint tracking
# -------------------------------------------------------------------
_SYSTEM_PROMPT_SINGLE = (
    "You are a static analysis security engine specialised in web and desktop vulnerabilities.\n"
    "Find the single most critical vulnerability in the given code.\n\n"
    "**Rules**\n"
    "1. Only report if user‑controlled data reaches a dangerous sink without proper sanitisation.\n"
    "2. Never flag a dangerous function with static/trusted input.\n"
    "3. Return exactly ONE JSON object with keys: name, severity, cwe, vulnerable_code, risk, fix.\n"
    "4. If no vulnerability, return {\"name\": \"No issues found\"}.\n\n"
    "**Untrusted sources** (examples)\n"
    "- Python Flask: request.args, request.form, request.json, request.data, request.headers, request.cookies\n"
    "- Python Django: request.GET, request.POST, request.body, request.META\n"
    "- Others: input(), sys.argv, os.environ, file reads, etc.\n"
    "- JavaScript/TypeScript (Node/Express): req.query, req.body, req.params, req.headers, req.cookies\n"
    "- Java: request.getParameter(), @RequestParam\n"
    "- PHP: $_GET, $_POST, $_REQUEST, $_COOKIE, file_get_contents('php://input')\n"
    "**Dangerous sinks** (examples)\n"
    "- Command: os.system, subprocess.Popen(shell=True), eval, exec, child_process.exec, system(), popen()\n"
    "- SQL: cursor.execute, db.Query, mysql_query, sqlite3_exec, Statement.executeQuery\n"
    "- Path traversal: open(), file_get_contents, readfile, fs.readFile (with untrusted path)\n"
    "- Deserialisation: pickle.loads, yaml.load (unsafe), unserialize, ObjectInputStream\n"
    "- XSS: document.write, innerHTML, dangerouslySetInnerHTML\n\n"
    "**Response format**\n"
    "Exactly one JSON object. No markdown, no extra text."
)

_FEW_SHOT_SINGLE = [
    {
        "user": (
            "Language: python\n\n"
            "Code:\n"
            "from flask import request\n"
            "import sqlite3\n"
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
def _parse_pipe_list(raw: str) -> List[Dict]:
    """Parse a list of pipe‑separated lines into vulnerability dicts.
    Ignores lines that don't match the expected format."""
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    # If the first non‑empty line is "NONE", return empty list
    if lines and lines[0].upper() == "NONE":
        return []
    vulns = []
    for line in lines:
        # Skip lines that look like instructions or echoes
        if line.lower().startswith(("we need", "list all", "output", "example", "do not", "return", "rule")):
            continue
        parts = [p.strip() for p in line.split("|")]
        # We expect exactly 5 parts: CWE:Name, severity, code, risk, fix
        if len(parts) == 5:
            cwe_name, severity, code_snippet, risk, fix = parts
            # Basic validation: severity should contain a slash (e.g., "9/10")
            if "/" in severity:
                vulns.append({
                    "name": cwe_name,          # e.g., "CWE-89: SQL Injection"
                    "severity": severity,
                    "cwe": cwe_name,
                    "vulnerable_code": code_snippet,
                    "risk": risk,
                    "fix": fix
                })
        # else: skip malformed lines
    return vulns

def _extract_json_object(raw: str) -> Dict:
    """Extract a single JSON object from the text."""
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
    return vulns[0]  # already sorted

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
# Main function
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

    # ----- Primary attempt: pipe‑separated list -----
    user_prompt_multi = (
        f"Language: {language}\n\n"
        f"Code:\n{sanitized}\n\n"
        "List all vulnerabilities using the pipe format exactly as instructed."
    )
    try:
        raw = _run_llm(_SYSTEM_PROMPT_MULTI, _FEW_SHOT_MULTI, user_prompt_multi, 4096, 90)
        vulns = _parse_pipe_list(raw)
        if vulns:
            return {"status": "success", "vulnerabilities": vulns, "most_critical": vulns[0]}
        else:
            # Maybe the model returned NONE (no vulnerabilities) – that's valid
            return {"status": "success", "vulnerabilities": [], "most_critical": _most_critical([])}
    except Exception as e:
        logger.warning(f"Pipe‑list attempt failed: {e}. Falling back to single JSON.")

    # ----- Fallback: Single vulnerability with full taint knowledge -----
    user_prompt_single = (
        f"Language: {language}\n\n"
        f"Code:\n{sanitized}\n\n"
        "Return exactly one JSON object for the most critical vulnerability."
    )
    try:
        raw = _run_llm(_SYSTEM_PROMPT_SINGLE, _FEW_SHOT_SINGLE, user_prompt_single, 400, 30)
        obj = _extract_json_object(raw)
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
