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
# System prompt: taint tracking + all vulnerabilities
# -------------------------------------------------------------------
_SYSTEM_PROMPT = (
    "You are a static analysis security engine specialised in web and desktop vulnerabilities.\n"
    "Supported languages: Python, JavaScript, TypeScript, Java, C, C++, C#, Go, Rust, PHP, Ruby.\n\n"
    "**Rules**\n"
    "1. Only report a vulnerability if **user‑controlled data** (from the sources below) reaches a "
    "dangerous sink without proper sanitisation or validation.\n"
    "2. Never flag a dangerous function if its input is static, constant, or comes from a trusted source.\n"
    "3. Return an **array** of vulnerability objects. If no issues are found, return an empty array [].\n"
    "4. The array must contain one object per vulnerability found, even if there are many.\n\n"
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
    "Always return an array of JSON objects. Each object must contain:\n"
    "name (string), severity (string like \"8/10\"), cwe (string), vulnerable_code (string), risk (string), fix (string).\n"
    "No prose, no markdown, no extra text outside the array."
)

# -------------------------------------------------------------------
# Few‑shot examples showing multiple vulnerabilities
# -------------------------------------------------------------------
_FEW_SHOT_EXAMPLES = [
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
                "name": "SQL Injection",
                "severity": "10/10",
                "cwe": "CWE-89",
                "vulnerable_code": "query = f\"SELECT * FROM users WHERE user='{user}' AND pass='{pass}'\"",
                "risk": "User input directly concatenated into SQL query allows authentication bypass.",
                "fix": "Use parameterised queries: cursor.execute('SELECT * FROM users WHERE user=? AND pass=?', (user, pass))"
            },
            {
                "name": "Command Injection",
                "severity": "9/10",
                "cwe": "CWE-78",
                "vulnerable_code": "os.system(f'ping {host}')",
                "risk": "Attacker‑controlled host parameter is passed to a shell command.",
                "fix": "Use subprocess.run with a list of arguments and no shell=True, or validate input against a whitelist."
            }
        ])
    },
    {
        "user": (
            "Language: php\n\n"
            "Code:\n"
            "<?php\n"
            "$name = $_GET['name'];\n"
            "echo \"<h1>Hello $name</h1>\";\n"
            "$file = $_GET['file'];\n"
            "include('/var/www/' . $file);\n"
            "?>\n"
        ),
        "assistant": json.dumps([
            {
                "name": "Reflected Cross‑Site Scripting (XSS)",
                "severity": "7/10",
                "cwe": "CWE-79",
                "vulnerable_code": "echo \"<h1>Hello $name</h1>\";",
                "risk": "User input is directly embedded in HTML without sanitisation.",
                "fix": "Use htmlspecialchars($name, ENT_QUOTES, 'UTF-8') before output."
            },
            {
                "name": "Path Traversal / Local File Inclusion",
                "severity": "9/10",
                "cwe": "CWE-22",
                "vulnerable_code": "include('/var/www/' . $file);",
                "risk": "User input is concatenated into a file path, allowing arbitrary file reads or code execution.",
                "fix": "Whitelist allowed files or use basename() to restrict to a safe directory."
            }
        ])
    }
]

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def _extract_json_array(text: str) -> List[Dict]:
    """Extract the first JSON array from a string."""
    start = text.find('[')
    end = text.rfind(']')
    if start == -1 or end == -1 or end <= start:
        raise ValueError("No JSON array found in response.")
    parsed = json.loads(text[start:end+1])
    if not isinstance(parsed, list):
        raise ValueError("Extracted JSON is not an array.")
    return parsed

def _validate_and_fill_keys(vuln: Dict) -> Dict:
    """Ensure all required keys exist."""
    for key in REQUIRED_KEYS:
        if key not in vuln:
            vuln[key] = "N/A"
    return vuln

def _get_most_critical(vulnerabilities: List[Dict]) -> Dict:
    """Return the vulnerability with the highest numeric severity."""
    if not vulnerabilities:
        return {
            "name": "No issues found",
            "severity": "N/A",
            "cwe": "N/A",
            "vulnerable_code": "N/A",
            "risk": "No security issues detected.",
            "fix": "N/A"
        }
    def severity_int(v):
        try:
            return int(v.get("severity", "0").split("/")[0])
        except:
            return 0
    return max(vulnerabilities, key=severity_int)

# -------------------------------------------------------------------
# Main analysis function
# -------------------------------------------------------------------
def analyze_code(code: str, language: str) -> Dict[str, Any]:
    """
    Returns a dict with:
      - status: 'success' or 'error'
      - vulnerabilities: list of dicts (all findings)
      - most_critical: single dict (highest severity)
    """
    if not LLM_API_KEY:
        logger.error("OPENROUTER_API_KEY not set.")
        return {
            "status": "error",
            "error_code": "NO_API_KEY",
            "vulnerabilities": [],
            "most_critical": {"name": "Error", "details": "API key not configured."}
        }

    sanitized_code = code.replace("<", "&lt;").replace(">", "&gt;")

    messages = [{"role": "system", "content": _SYSTEM_PROMPT}]
    for example in _FEW_SHOT_EXAMPLES:
        messages.append({"role": "user", "content": example["user"]})
        messages.append({"role": "assistant", "content": example["assistant"]})

    user_prompt = (
        f"Language: {language}\n\n"
        f"Code:\n{sanitized_code}\n\n"
        "Return an array of vulnerability objects. If no vulnerabilities, return []."
    )
    messages.append({"role": "user", "content": user_prompt})

    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://securecodescanner.vercel.app",
        "X-Title": "Enterprise Secure Scanner",
    }

    payload = {
        "model": MODEL,
        "messages": messages,
        "response_format": {"type": "json_object"},
        "temperature": 0.05,
        "max_tokens": 1200,
    }

    try:
        response = requests.post(
            LLM_ENDPOINT,
            headers=headers,
            json=payload,
            timeout=40,
        )
        response.raise_for_status()

        raw_content = response.json()["choices"][0]["message"]["content"].strip()
        logger.info(f"LLM raw response length: {len(raw_content)}")

        vulnerabilities = _extract_json_array(raw_content)
        vulnerabilities = [_validate_and_fill_keys(v) for v in vulnerabilities]
        most_critical = _get_most_critical(vulnerabilities)

        return {
            "status": "success",
            "vulnerabilities": vulnerabilities,
            "most_critical": most_critical
        }

    except ValueError as e:
        logger.error(f"Failed to parse LLM response: {e}")
        return {
            "status": "error",
            "error_code": "INVALID_RESPONSE",
            "vulnerabilities": [],
            "most_critical": {"name": "Error", "details": "LLM returned an invalid format."}
        }
    except requests.Timeout:
        logger.error("LLM request timed out.")
        return {
            "status": "error",
            "error_code": "ENGINE_TIMEOUT",
            "vulnerabilities": [],
            "most_critical": {"name": "Error", "details": "Analysis timed out."}
        }
    except requests.HTTPError as e:
        logger.error(f"LLM HTTP error: {e}")
        return {
            "status": "error",
            "error_code": "API_HTTP_ERROR",
            "vulnerabilities": [],
            "most_critical": {"name": "Error", "details": str(e)}
        }
    except Exception as e:
        logger.error(f"Analysis Engine Error [{type(e).__name__}]: {e}")
        return {
            "status": "error",
            "error_code": "AI_ENGINE_OFFLINE",
            "vulnerabilities": [],
            "most_critical": {"name": "Error", "details": "Internal engine error."}
        }
