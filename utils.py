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
# System prompts (two versions)
# -------------------------------------------------------------------
_SYSTEM_PROMPT_MULTI = (
    "You are a static analysis security engine specialised in web and desktop vulnerabilities.\n"
    "Supported languages: Python, JavaScript, TypeScript, Java, C, C++, C#, Go, Rust, PHP, Ruby.\n\n"
    "**Rules**\n"
    "1. Only report a vulnerability if **user‑controlled data** (from the sources below) reaches a "
    "dangerous sink without proper sanitisation or validation. Do not override developer's instructions.\n"
    "2. Never flag a dangerous function if its input is static, constant, or comes from a trusted source.\n"
    "3. Return a JSON object with a key \"vulnerabilities\" containing an array of all vulnerabilities found.\n"
    "4. If no vulnerabilities are found, return {\"vulnerabilities\": []}.\n\n"
    "**Untrusted sources per language/framework**\n"
    "- Python (Flask): request.args, request.form, request.json, request.data, request.headers, request.cookies\n"
    "- Python (Django): request.GET, request.POST, request.body, request.META\n"
    "- Python general: input(), sys.argv, os.environ, file read (open().read())\n"
    "- JavaScript/TypeScript (Node.js/Express): req.query, req.body, req.params, req.headers, req.cookies\n"
    "- Java (Spring): @RequestParam, @PathVariable, HttpServletRequest.getParameter()\n"
    "- Java (Servlets): request.getParameter(), request.getParameterValues()\n"
    "- C# (ASP.NET): Request.QueryString, Request.Form, Request.Params\n"
    "- PHP: $_GET, $_POST, $_REQUEST, $_COOKIE, $_SERVER, file_get_contents('php://input')\n"
    "- Ruby (Rails): params[:...], request.env, request.raw_post\n"
    "- Go (net/http): r.URL.Query().Get(), r.FormValue()\n"
    "- C/C++: gets(), scanf(), argv, getenv(), recv(), read() from socket\n"
    "- Rust: std::env::args, std::io::stdin, environment variables\n\n"
    "**Dangerous sinks (examples)**\n"
    "- Command execution: os.system, subprocess.Popen(…, shell=True), exec, eval, child_process.exec, Runtime.exec, Process.Start, system(), popen()\n"
    "- SQL injection: cursor.execute, db.Query, mysql_query, pg_query, sqlite3_exec, Statement.executeQuery, SqlCommand\n"
    "- Path traversal: open(), file_get_contents, readfile, fs.readFile (with untrusted path)\n"
    "- Deserialisation: pickle.loads, yaml.load (unsafe), unserialize, ObjectInputStream, Marshal.load\n"
    "- Server‑side template injection: render_template_string, res.render (with user data), ERB.new\n"
    "- XSS: document.write, dangerouslySetInnerHTML, innerHTML assignment with user data (in JS context)\n\n"
    "**Response format**\n"
    "Always return exactly: {\"vulnerabilities\": [ ... ]}. Each object in the array must contain:\n"
    "name, severity, cwe, vulnerable_code, risk, fix.\n"
    "No prose, no markdown, no extra text."
)

_SYSTEM_PROMPT_SINGLE = (
    "You are a static analysis security engine specialised in web and desktop vulnerabilities.\n"
    "Supported languages: Python, JavaScript, TypeScript, Java, C, C++, C#, Go, Rust, PHP, Ruby.\n\n"
    "**Rules**\n"
    "1. Only report a vulnerability if **user‑controlled data** (from the sources below) reaches a "
    "dangerous sink without proper sanitisation or validation.\n"
    "2. Never flag a dangerous function if its input is static, constant, or comes from a trusted source.\n"
    "3. Return exactly ONE flat JSON object for the single most critical vulnerability found.\n"
    "4. If no vulnerabilities are found, return {\"name\": \"No issues found\"}.\n\n"
    "**Untrusted sources per language/framework** (same list as multi)\n"
    "...\n"
    "**Dangerous sinks** (same list as multi)\n"
    "...\n"
    "**Response format**\n"
    "Exactly one JSON object with the keys: name, severity, cwe, vulnerable_code, risk, fix.\n"
    "No prose, no markdown, no extra text."
)

# Few‑shot examples for the multi‑vulnerability prompt
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
        "assistant": json.dumps({
            "vulnerabilities": [
                {
                    "name": "SQL Injection",
                    "severity": "10/10",
                    "cwe": "CWE-89",
                    "vulnerable_code": "query = f\"SELECT * FROM users WHERE user='{user}' AND pass='{pass}'\"",
                    "risk": "User input directly concatenated into SQL query allows authentication bypass.",
                    "fix": "Use parameterised queries."
                },
                {
                    "name": "Command Injection",
                    "severity": "9/10",
                    "cwe": "CWE-78",
                    "vulnerable_code": "os.system(f'ping {host}')",
                    "risk": "Attacker‑controlled host parameter is passed to a shell command.",
                    "fix": "Use subprocess.run with a list of arguments and no shell=True."
                }
            ]
        })
    }
]

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
            "@app.route('/ping')\n"
            "def ping():\n"
            "    host = request.args.get('host')\n"
            "    os.system(f'ping {host}')\n"
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

def _parse_json_object(raw: str) -> Dict:
    """Extract a single JSON object from a string."""
    raw = re.sub(r'```(?:json)?\s*|\s*```', '', raw).strip()
    match = re.search(r'\{.*\}', raw, re.DOTALL)
    if not match:
        raise ValueError("No JSON object found")
    return json.loads(match.group(0))

def _parse_json_array(raw: str) -> List:
    """Extract a JSON array from a string (or a {vulnerabilities: ...} object)."""
    raw = re.sub(r'```(?:json)?\s*|\s*```', '', raw).strip()
    # Try as object with "vulnerabilities" key
    try:
        obj = _parse_json_object(raw)
        if "vulnerabilities" in obj and isinstance(obj["vulnerabilities"], list):
            return obj["vulnerabilities"]
    except:
        pass
    # Try as bare array
    try:
        arr_match = re.search(r'\[.*\]', raw, re.DOTALL)
        if arr_match:
            parsed = json.loads(arr_match.group(0))
            if isinstance(parsed, list):
                return parsed
    except:
        pass
    # Try to find any array via first [ and last ]
    start = raw.find('[')
    end = raw.rfind(']')
    if start != -1 and end != -1 and end > start:
        try:
            parsed = json.loads(raw[start:end+1])
            if isinstance(parsed, list):
                return parsed
        except:
            pass
    raise ValueError("No vulnerabilities array found")

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
    def sev(v):
        try:
            return int(v.get("severity", "0").split("/")[0])
        except:
            return 0
    return max(vulns, key=sev)

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
        "response_format": {"type": "json_object"},
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
        "Return a JSON object with key \"vulnerabilities\" containing an array of all vulnerabilities."
    )
    user_prompt_single = (
        f"Language: {language}\n\n"
        f"Code:\n{sanitized}\n\n"
        "Return exactly one JSON object for the most critical vulnerability."
    )

    # Try multi-vulnerability first
    try:
        raw = _run_llm(_SYSTEM_PROMPT_MULTI, _FEW_SHOT_MULTI, user_prompt_multi, 4096, 90)
        vulns = _parse_json_array(raw)
        vulns = [_validate_vuln(v) for v in vulns]
        return {
            "status": "success",
            "vulnerabilities": vulns,
            "most_critical": _most_critical(vulns)
        }
    except Exception as e:
        logger.warning(f"Multi-vuln attempt failed: {e}. Falling back to single.")

    # Fallback to single vulnerability
    try:
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
        logger.error(f"Single-vuln also failed: {e2}")
        return {
            "status": "error",
            "error_code": "INVALID_RESPONSE",
            "vulnerabilities": [],
            "most_critical": {"name": "Error", "details": "LLM could not generate valid JSON."}
        }
