import os
import re
import json
import logging
import ast
import requests
import hashlib
import time
import threading
from typing import Dict, Any, List, Optional, Tuple
from functools import lru_cache

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------- Environment ----------
LLM_API_KEY = os.getenv("OPENROUTER_API_KEY")
NVD_API_KEY = os.getenv("NVE_KEY") or os.getenv("NVD_KEY")

LLM_ENDPOINT = "https://openrouter.ai/api/v1/chat/completions"

PRIMARY_MODEL = "google/gemini-2.0-flash-exp:free"
FALLBACK_MODEL = "qwen/qwen3-coder-480b-a35b:free"

REQUIRED_KEYS = {"cwe", "severity", "vulnerable_code", "risk", "fix", "line_number"}
MAX_CODE_LENGTH = 15000
MAX_TOKENS = 32000
TIMEOUT = 90
MAX_WORKERS = 1

llm_semaphore = threading.Semaphore(MAX_WORKERS)

# ---------- Language match detection ----------
def is_language_match(code: str, declared_lang: str) -> Tuple[bool, str]:
    def strip_non_code(text: str) -> str:
        text = re.sub(r'#.*?$', '', text, flags=re.M)
        text = re.sub(r'"""[\s\S]*?"""', '', text)
        text = re.sub(r"'''[\s\S]*?'''", '', text)
        text = re.sub(r'"(?:[^"\\]|\\.)*"', '', text)
        text = re.sub(r"'(?:[^'\\]|\\.)*'", '', text)
        return text
