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
# Multi‑vulnerability prompt – minimal fields for maximum listing
# -------------------------------------------------------------------
_SYSTEM_PROMPT_MULTI = (
    "You are a static analysis security engine.\n"
    "Your job is to find **all** vulnerabilities in the provided code, but report each one with only "
    "the absolute minimum information needed.\n"
    "Supported languages: Python, JavaScript, TypeScript, Java, C, C++, C#, Go, Rust, PHP, Ruby.\n\n"
    "**Rules**\n"
    "1. Only report a vulnerability if user‑controlled data reaches a dangerous sink without proper sanitisation.\n"
    "2. Never flag a dangerous function with static/trusted input.\n"
    "3. Return a JSON object with a key \"vulnerabilities\" containing an array of ALL vulnerabilities found.\n"
    "   Order them by severity, most critical first.\n"
    "4. If no issues, return {\"vulnerabilities\": []}.\n\n"
    "**Untrusted sources** (same list as before)\n"
    "- Python Flask: request.args, request.form, request.json, request.data, request.headers, request.cookies\n"
    "- Python Django: request.GET, request.POST, request.body, request.META\n"
    "- Other: input(), sys.argv, os.environ, file reads (open().read()), etc.\n"
    "- JavaScript/TypeScript (Node/Express): req.query, req.body, req.params, req.headers, req.cookies\n"
    "- Java: request.getParameter(), @RequestParam, etc.\n"
    "- PHP: $_GET, $_POST, $_REQUEST, $_COOKIE, $_SERVER, file_get_contents('php://input')\n"
    "- etc. (full list omitted for brevity – use common sense)\n\n"
    "**Dangerous sinks** (examples)\n"
    "- Command: os.system, subprocess.Popen(shell=True), eval, exec, child_process.exec, system(), popen()\n"
    "- SQL: cursor.execute, db.Query, mysql_query, sqlite3_exec, Statement.executeQuery\n"
    "- Path traversal: open(), file_get_contents, readfile, fs.readFile (with untrusted path)\n"
    "- Deserialisation: pickle.loads, yaml.load, unserialize, ObjectInputStream\n"
    "- XSS: document.write, innerHTML, dangerouslySetInnerHTML\n\n"
    "**Response format** – EVERY OBJECT MUST BE MINIMAL AND CONTAIN ONLY THESE FOUR KEYS:\n"
    "  \"cwe\" : a CWE ID like \"CWE‑89\"\n"
    "  \"vulnerable_code\" : the exact line (or tiny snippet) that is vulnerable (max 40 characters if possible)\n"
    "  \"risk\" : very short description (max 15 words)\n"
    "  \"fix\" : one‑line fix (max 15 words)\n\n"
    "Example object:\n"
    "{\"cwe\": \"CWE‑89\", \"vulnerable_code\": \"cur.execute(query)\", \"risk\": \"SQL injection allows authentication bypass\", \"fix\": \"Use parameterised queries\"}\n\n"
    "No markdown, no prose, no extra keys. Return ONLY the {\"vulnerabilities\": [...]} object."
)

# Single‑vulnerability fallback – still uses full keys, but minimal content
_SYSTEM_PROMPT_SINGLE = (
    "You are a static analysis security engine.\n"
    "Return exactly ONE JSON object for the most critical vulnerability. Use the same four keys: "
    "cwe, vulnerable_code, risk, fix.\n"
    "If no vulnerability, return {\"vulnerabilities\": []} (but as a single object? We'll keep it consistent; "
    "we'll adapt). Actually, for simplicity the single fallback will return the same wrapper format."
    "But we need to keep backward compatibility. I'll handle that."
)

# For single fallback, we'll just reuse the multi prompt but ask for top 1.

# Few‑shot example for multi
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
                    "cwe": "CWE-89",
                    "vulnerable_code": "db.execute(query)",
                    "risk": "SQL injection allows authentication bypass",
                    "fix": "Use parameterised queries"
                },
                {
                    "cwe": "CWE-78",
                    "vulnerable_code": "os.system(f'ping {host}')",
                    "risk": "Command injection via host parameter",
                    "fix": "Use subprocess.run with shell=False"
                }
            ]
        })
    }
]

# For single fallback, we'll just ask for top 1 in the multi format and take the first element.

def _parse_json_object(raw: str) -> Dict:
    raw = re.sub(r'```(?:json)?\s*|\s*```', '', raw).strip()
    match = re.search(r'\{.*\}', raw, re.DOTALL)
    if not match:
        raise ValueError("No JSON object found")
    return json.loads(match.group(0))

def _parse_json_array(raw: str) -> List:
    raw = re.sub(r'```(?:json)?\s*|\s*```', '', raw).strip()
    # Try object with "vulnerabilities" key
    try:
        obj = _parse_json_object(raw)
        if "vulnerabilities" in obj and isinstance(obj["vulnerabilities"], list):
            return obj["vulnerabilities"]
    except:
        pass
    # Try bare array
    try:
        arr_match = re.search(r'\[.*\]', raw, re.DOTALL)
        if arr_match:
            parsed = json.loads(arr_match.group(0))
            if isinstance(parsed, list):
                return parsed
    except:
        pass
    # Try from first [ to last ]
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
    # Ensure all required frontend keys exist; fill missing with "N/A"
    for key in REQUIRED_KEYS:
        if key not in v:
            # If the minimal keys are present, we can map them
            if key == "name":
                # derive a short name from cwe if not provided
                if "cwe" in v:
                    v[key] = v["cwe"]  # or a short description, but keep it simple
                else:
                    v[key] = "Vulnerability"
            elif key == "severity":
                v[key] = "N/A"  # minimal format doesn't include severity
            elif key == "cwe" and "cwe" in v:
                pass  # already there
            elif key == "vulnerable_code" and "vulnerable_code" in v:
                pass
            elif key == "risk" and "risk" in v:
                pass
            elif key == "fix" and "fix" in v:
                pass
            else:
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
    # Without severity, just return the first one (most critical already first)
    return vulns[0] if vulns else {}

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
    # Multi attempt: ask for all vulnerabilities with minimal fields
    user_prompt_multi = (
        f"Language: {language}\n\n"
        f"Code:\n{sanitized}\n\n"
        "Return a JSON object with key \"vulnerabilities\" containing an array of ALL vulnerabilities. "
        "Use the minimal format: cwe, vulnerable_code, risk, fix."
    )
    # Single fallback: top 1 in same format
    user_prompt_single = (
        f"Language: {language}\n\n"
        f"Code:\n{sanitized}\n\n"
        "Return a JSON object with key \"vulnerabilities\" containing an array with the SINGLE most critical vulnerability. "
        "Use the minimal format."
    )

    # Try multi first
    try:
        raw = _run_llm(_SYSTEM_PROMPT_MULTI, _FEW_SHOT_MULTI, user_prompt_multi, 4096, 90)
        vulns = _parse_json_array(raw)
        vulns = [_validate_vuln(v) for v in vulns]
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
        logger.warning(f"Multi-vuln failed: {e}, trying single.")

    # Fallback to single
    try:
        raw = _run_llm(_SYSTEM_PROMPT_MULTI, _FEW_SHOT_MULTI, user_prompt_single, 400, 30)
        vulns = _parse_json_array(raw)
        vulns = [_validate_vuln(v) for v in vulns]
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
    except Exception as e2:
        logger.error(f"Single-vuln also failed: {e2}")
        return {
            "status": "error",
            "error_code": "INVALID_RESPONSE",
            "vulnerabilities": [],
            "most_critical": {"name": "Error", "details": "LLM could not generate valid JSON."}
        }
