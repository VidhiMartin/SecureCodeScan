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

# Required keys in a valid response
REQUIRED_KEYS = {"name", "severity", "cwe", "vulnerable_code", "risk", "fix"}

# Cached few-shot example string to avoid re-serializing on every call
_FEW_SHOT_EXAMPLE = json.dumps({
    "name": "Arbitrary Code Execution",
    "severity": "10/10",
    "cwe": "CWE-94",
    "vulnerable_code": "eval(user_input)",
    "risk": "Allows execution of malicious scripts.",
    "fix": "Avoid dynamic execution; use safe alternatives."
})


def analyze_code(code: str, language: str) -> Dict[str, Any]:
    """
    Performs a security audit via LLM.
    Returns a flat JSON object for the most severe detected vulnerability.
    """
    if not LLM_API_KEY:
        logger.error("OPENROUTER_API_KEY not set.")
        return {"error_code": "NO_API_KEY", "details": "API key not configured."}

    # Prevent prompt injection via XML tag smuggling
    sanitized_code = code.replace("<", "&lt;").replace(">", "&gt;")

    # Lean, structured prompt — fewer tokens = faster response
    prompt = (
        f"Language: {language}\n\n"
        f"Code:\n{sanitized_code}\n\n"
        "Return ONE JSON object for the single most critical vulnerability. "
        "Use exactly these keys: name, severity, cwe, vulnerable_code, risk, fix. "
        "No prose, no markdown, no arrays."
    )

    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://securecodescanner.vercel.app",
        "X-Title": "Enterprise Secure Scanner",
    }

    payload = {
        "model": MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a static analysis security engine. "
                    "Respond with exactly one flat JSON object containing: "
                    "name, severity, cwe, vulnerable_code, risk, fix. "
                    "No arrays, no extra keys, no markdown."
                ),
            },
            # Few-shot: teach the expected format
            {"role": "user", "content": "Audit: eval(user_input)"},
            {"role": "assistant", "content": _FEW_SHOT_EXAMPLE},
            {"role": "user", "content": prompt},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.05,   # Near-deterministic for security analysis
        "max_tokens": 400,     # Response is small — cap aggressively to cut latency
    }

    try:
        response = requests.post(
            LLM_ENDPOINT,
            headers=headers,
            json=payload,
            timeout=30,          # Hard 30s wall-clock limit
        )
        response.raise_for_status()

        raw_content = response.json()["choices"][0]["message"]["content"].strip()

        # Extract first JSON object from response
        match = re.search(r'\{.*\}', raw_content, re.DOTALL)
        if not match:
            raise ValueError("No JSON object found in response.")

        parsed = json.loads(match.group(0))

        # Validate required keys are present
        missing = REQUIRED_KEYS - parsed.keys()
        if missing:
            logger.warning(f"LLM response missing keys: {missing}")
            # Fill missing keys rather than failing entirely
            for key in missing:
                parsed[key] = "N/A"

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
