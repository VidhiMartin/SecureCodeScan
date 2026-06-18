import os
import requests
import json
import logging
import re
from typing import Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

LLM_API_KEY = os.getenv("OPENROUTER_API_KEY")
LLM_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "nvidia/nemotron-3-super-120b-a12b:free"

REQUIRED_KEYS = {"name", "severity", "cwe", "vulnerable_code", "risk", "fix"}

# -------------------------------------------------------------------
# System prompt: taint sources, sinks, and rules for all languages
# -------------------------------------------------------------------
_SYSTEM_PROMPT = (
    "You are a static analysis security engine specialised in web and desktop vulnerabilities.\n"
    "You analyse code in: Python, JavaScript, TypeScript, Java, C, C++, C#, Go, Rust, PHP, Ruby.\n\n"
    "**Rules**\n"
    "1. Only report a vulnerability if **user‑controlled data** (from the sources below) reaches a "
    "dangerous sink without proper sanitisation or validation.\n"
    "2. Never flag a dangerous function if its input is static, constant, or comes from a trusted source.\n"
    "3. If no vulnerability is found, return a JSON object with \"name\": \"No issues found\".\n\n"
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
    "Always return exactly one flat JSON object with the keys:\n"
    "name, severity (as a string like \"8/10\"), cwe (e.g., \"CWE-78\"), vulnerable_code, risk, fix.\n"
    "No prose, no markdown, no arrays."
)

# -------------------------------------------------------------------
# Few‑shot examples covering multiple languages and taint flows
# -------------------------------------------------------------------
_FEW_SHOT_EXAMPLES = [
    # 1. Python Flask command injection
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
            "    return 'ok'\n"
        ),
        "assistant": json.dumps({
            "name": "Command Injection",
            "severity": "9/10",
            "cwe": "CWE-78",
            "vulnerable_code": "os.system(f'ping {host}')",
            "risk": "Attacker‑controlled 'host' parameter is directly embedded in a shell command.",
            "fix": "Use subprocess.run with a list of arguments and no shell=True, or validate the input against a whitelist."
        })
    },
    # 2. Java Servlet SQL injection
    {
        "user": (
            "Language: java\n\n"
            "Code:\n"
            "protected void doGet(HttpServletRequest req, HttpServletResponse resp) {\n"
            "    String user = req.getParameter(\"user\");\n"
            "    String query = \"SELECT * FROM users WHERE name = '\" + user + \"'\";\n"
            "    Statement stmt = conn.createStatement();\n"
            "    ResultSet rs = stmt.executeQuery(query);\n"
            "}"
        ),
        "assistant": json.dumps({
            "name": "SQL Injection",
            "severity": "10/10",
            "cwe": "CWE-89",
            "vulnerable_code": "String query = \"SELECT * FROM users WHERE name = '\" + user + \"'\";",
            "risk": "User input directly concatenated into SQL query allows arbitrary SQL execution.",
            "fix": "Use PreparedStatement with parameterised queries."
        })
    },
    # 3. PHP Arbitrary File Read (path traversal)
    {
        "user": (
            "Language: php\n\n"
            "Code:\n"
            "$file = $_GET['page'];\n"
            "readfile(\"/var/www/html/\" . $file);\n"
        ),
        "assistant": json.dumps({
            "name": "Path Traversal",
            "severity": "8/10",
            "cwe": "CWE-22",
            "vulnerable_code": "readfile(\"/var/www/html/\" . $file);",
            "risk": "User input is appended to a file path without sanitisation, allowing reading of arbitrary files.",
            "fix": "Use a whitelist of allowed filenames or realpath() with basename() to validate the final path."
        })
    },
    # 4. Node.js/Express Server‑Side Template Injection
    {
        "user": (
            "Language: javascript\n\n"
            "Code:\n"
            "const express = require('express');\n"
            "const app = express();\n"
            "app.get('/hello', (req, res) => {\n"
            "    const name = req.query.name;\n"
            "    res.render('index', { title: `Hello ${name}` });\n"
            "});\n"
        ),
        "assistant": json.dumps({
            "name": "Server‑Side Template Injection (SSTI)",
            "severity": "9/10",
            "cwe": "CWE-1336",
            "vulnerable_code": "res.render('index', { title: `Hello ${name}` })",
            "risk": "User input is embedded in a template without sanitisation, potentially leading to remote code execution.",
            "fix": "Sanitise the input, use a template engine that auto‑escapes, or avoid embedding raw input in templates."
        })
    }
]

def analyze_code(code: str, language: str) -> Dict[str, Any]:
    """
    Performs a security audit via LLM with explicit taint tracking
    for web and desktop applications across 11 languages.
    """
    if not LLM_API_KEY:
        logger.error("OPENROUTER_API_KEY not set.")
        return {"error_code": "NO_API_KEY", "details": "API key not configured."}

    # Prevent prompt injection via XML/HTML tag smuggling
    sanitized_code = code.replace("<", "&lt;").replace(">", "&gt;")

    # Build the messages list: system prompt, then all few‑shot examples,
    # then the actual user request.
    messages = [{"role": "system", "content": _SYSTEM_PROMPT}]
    for example in _FEW_SHOT_EXAMPLES:
        messages.append({"role": "user", "content": example["user"]})
        messages.append({"role": "assistant", "content": example["assistant"]})

    # Final user prompt with the real code
    user_prompt = (
        f"Language: {language}\n\n"
        f"Code:\n{sanitized_code}\n\n"
        "Return ONE JSON object for the single most critical vulnerability. "
        "If none found, use name \"No issues found\"."
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
        "temperature": 0.05,   # near‑deterministic for security analysis
        "max_tokens": 400,
    }

    try:
        response = requests.post(
            LLM_ENDPOINT,
            headers=headers,
            json=payload,
            timeout=30,          # hard 30s wall‑clock limit
        )
        response.raise_for_status()

        raw_content = response.json()["choices"][0]["message"]["content"].strip()

        # Extract the first JSON object from the response
        match = re.search(r'\{.*\}', raw_content, re.DOTALL)
        if not match:
            raise ValueError("No JSON object found in response.")

        parsed = json.loads(match.group(0))

        # Validate required keys
        missing = REQUIRED_KEYS - parsed.keys()
        if missing:
            logger.warning(f"LLM response missing keys: {missing}")
            for key in missing:
                parsed[key] = "N/A"

        # If the model returned "No issues found", keep that as the name but ensure all keys exist
        if parsed.get("name") == "No issues found":
            parsed.setdefault("severity", "N/A")
            parsed.setdefault("cwe", "N/A")
            parsed.setdefault("vulnerable_code", "N/A")
            parsed.setdefault("risk", "No security issues detected.")
            parsed.setdefault("fix", "N/A")

        return parsed

    except requests.Timeout:
        logger.error("LLM request timed out after 30s.")
        return {"error_code": "ENGINE_TIMEOUT", "details": "Analysis timed out. Please retry."}
    except requests.HTTPError as e:
        logger.error(f"LLM HTTP error: {e}")
        return {"error_code": "API_HTTP_ERROR", "details": str(e)}
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode failed: {e}")
        return {"error_code": "INVALID_RESPONSE", "details": "Engine returned malformed JSON."}
    except Exception as e:
        logger.error(f"Analysis Engine Error [{type(e).__name__}]: {e}")
        return {"error_code": "AI_ENGINE_OFFLINE", "details": str(e)}
