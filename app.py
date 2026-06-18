import os
import json
import re
import logging
import hashlib
import pyotp
import qrcode
import io
import base64
import time
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import firebase_admin
from firebase_admin import credentials, auth, firestore
from utils import analyze_code


# --- Security Configuration & Logging ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Set a secret key for Flask (required for sessions, flash, etc.)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24).hex())  # ALWAYS set in production env
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB request cap

# Enterprise Rate Limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["100 per hour"],
    storage_uri="memory://"   # For production, replace with Redis or Vercel KV
)

# --- Enterprise Policy Constants ---
TENANT_ID = os.getenv("FIREBASE_TENANT_ID", "Ent-Test-avvoo-9vpee")
MAX_CODE_SIZE = 50_000

# --- Firebase Admin & Firestore Initialization ---
firebase_key = os.getenv("FIREBASE_KEY")
db = None

if not firebase_admin._apps:
    try:
        if firebase_key and firebase_key.strip().startswith('{'):
            cred_dict = json.loads(firebase_key)
            if "private_key" in cred_dict:
                cred_dict["private_key"] = cred_dict["private_key"].replace("\\n", "\n")
            cred = credentials.Certificate(cred_dict)
        else:
            # Fallback: treat FIREBASE_KEY as a file path (not recommended)
            cred = credentials.Certificate(firebase_key)

        firebase_admin.initialize_app(cred, {
            'projectId': os.getenv("FIREBASE_PROJECT_ID", "codescan-b61a0")
        })
        db = firestore.client()
        logger.info("Firebase & Firestore initialized successfully.")
    except Exception as e:
        logger.error(f"FATAL: Firebase Initialization Failed: {e}", exc_info=True)
        # In production you might want to exit(1) – here we continue with db=None
        # so that the app can still serve error responses.

# ─────────────────────────────────────────────
# Helper: Email → safe Firestore document ID
# ─────────────────────────────────────────────
def _email_to_doc_id(email: str) -> str:
    """Convert an email to a Firestore-safe document ID using SHA‑256."""
    return hashlib.sha256(email.lower().encode()).hexdigest()

# ─────────────────────────────────────────────
# Helper: Auth Guard
# ─────────────────────────────────────────────
def get_current_user():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    try:
        token = auth_header.split(" ", 1)[1]
        decoded = auth.verify_id_token(token)
        if decoded.get("firebase", {}).get("tenant") != TENANT_ID:
            logger.warning("Token tenant mismatch.")
            return None
        return decoded
    except Exception as e:
        logger.warning(f"Token verification failed: {e}")
        return None

def require_auth(f):
    """Decorator: Reject requests without a valid Firebase token."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({
                "status": "REJECTED",
                "error_code": "AUTH_FAILURE",
                "audit_summary": "Invalid or expired security token."
            }), 401
        return f(*args, user=user, **kwargs)
    return decorated

# ─────────────────────────────────────────────
# Helper: Input Validation
# ─────────────────────────────────────────────
EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')

def validate_email(email: str) -> bool:
    return bool(email and EMAIL_RE.match(email) and len(email) <= 254)

def validate_language_match(code: str, lang: str):
    code_lower = code.lower()
    if lang == "python":
        # Word boundaries prevent false positives like "reconst", "letter"
        if re.search(r'\bconst\b', code_lower) or re.search(r'\blet\b', code_lower) or "console.log" in code_lower:
            return False, "Snippet appears to be JavaScript/TypeScript, but environment is Python."
    if lang in ("javascript", "typescript"):
        if re.search(r'\bdef\b', code_lower) and ":" in code_lower:
            return False, "Snippet appears to be Python, but environment is set to JavaScript/TypeScript."
    return True, ""

# ─────────────────────────────────────────────
# MFA Routes (Now with hashed email doc IDs)
# ─────────────────────────────────────────────

@app.route('/mfa/setup', methods=['POST'])
@limiter.limit("5 per hour")
def mfa_setup():
    if not db:
        return jsonify({"error": "Database unavailable"}), 503

    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    if not validate_email(email):
        return jsonify({"error": "Invalid email"}), 400

    try:
        secret = pyotp.random_base32()
        doc_id = _email_to_doc_id(email)

        db.collection("users").document(doc_id).set({
            "email": email,
            "mfa_secret": secret,
            "mfa_enabled": False,
            "setup_timestamp": int(time.time())
        }, merge=True)

        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(name=email, issuer_name="SecureCodeScanner")
        img = qrcode.make(provisioning_uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()

        return jsonify({"qr_code": qr_b64})
    except Exception as e:
        logger.error(f"MFA Setup Error: {e}", exc_info=True)
        return jsonify({"error": "MFA provisioning failed"}), 500

@app.route('/mfa/verify', methods=['POST'])
@limiter.limit("10 per minute")
def mfa_verify():
    if not db:
        return jsonify({"success": False, "message": "Database unavailable"}), 503

    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    code = data.get("code", "").strip()

    if not validate_email(email):
        return jsonify({"success": False, "message": "Invalid email"}), 400
    if not re.fullmatch(r'\d{6}', code):
        return jsonify({"success": False, "message": "Code must be 6 digits"}), 400

    try:
        doc_id = _email_to_doc_id(email)
        user_doc = db.collection("users").document(doc_id).get()
        if not user_doc.exists:
            return jsonify({"success": False, "message": "Invalid code"}), 401

        user_data = user_doc.to_dict()
        secret = user_data.get("mfa_secret")
        if not secret:
            return jsonify({"success": False, "message": "MFA not configured"}), 400

        totp = pyotp.TOTP(secret)
        if totp.verify(code, valid_window=1):
            db.collection("users").document(doc_id).update({"mfa_enabled": True})
            return jsonify({"success": True})

        return jsonify({"success": False, "message": "Invalid security code"}), 401
    except Exception as e:
        logger.error(f"MFA Verify Error: {e}", exc_info=True)
        return jsonify({"success": False, "message": "Verification error"}), 500

@app.route('/mfa/status', methods=['POST'])
@limiter.limit("20 per minute")
def mfa_status():
    if not db:
        return jsonify({"enabled": False})

    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    if not validate_email(email):
        return jsonify({"enabled": False})

    try:
        doc_id = _email_to_doc_id(email)
        user_doc = db.collection("users").document(doc_id).get()
        if user_doc.exists and user_doc.to_dict().get("mfa_enabled"):
            return jsonify({"enabled": True})
    except Exception:
        pass
    return jsonify({"enabled": False})

# ─────────────────────────────────────────────
# Standard Routes
# ─────────────────────────────────────────────

@app.route("/")
def home():
    return redirect("/scanner")

@app.route("/scanner")
def scanner():
    return render_template("index.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/signup")
def signup_page():
    return render_template("signup.html")

@app.route("/reset-password")
def reset_password_page():
    return render_template("reset-password.html")

@app.route("/scan", methods=["POST"])
@limiter.limit("10 per minute")
@require_auth
def scan(user):
    try:
        language = request.form.get("language", "").strip().lower()
        code = request.form.get("code", "")

        ALLOWED_LANGUAGES = {
            "python", "javascript", "typescript", "java",
            "c", "cpp", "csharp", "go", "rust", "php", "ruby"
        }
        if language not in ALLOWED_LANGUAGES:
            return jsonify({
                "status": "REJECTED",
                "error_code": "INVALID_LANGUAGE",
                "audit_summary": "Unsupported language specified."
            }), 422

        if not code.strip():
            return jsonify({
                "status": "REJECTED",
                "error_code": "EMPTY_INPUT",
                "audit_summary": "No source code detected."
            }), 400

        if len(code) > MAX_CODE_SIZE:
            return jsonify({
                "status": "REJECTED",
                "error_code": "SIZE_EXCEEDED",
                "audit_summary": f"Payload exceeds limit of {MAX_CODE_SIZE} characters."
            }), 413

        is_match, msg = validate_language_match(code, language)
        if not is_match:
            return jsonify({
                "status": "REJECTED",
                "error_code": "LANGUAGE_MISMATCH",
                "audit_summary": msg
            }), 422

        # Call the new analyze_code that returns {status, vulnerabilities, most_critical}
        result = analyze_code(code, language)

        # Handle errors from the analysis engine
        if result.get("status") == "error":
            return jsonify({
                "status": "FAULT",
                "error_code": result.get("error_code", "UNKNOWN"),
                "audit_summary": result["most_critical"].get("details", "Scan failed.")
            }), 502

        # If no vulnerabilities found
        if not result.get("vulnerabilities"):
            return jsonify({
                "name": "No issues found",
                "severity": "N/A",
                "cwe": "N/A",
                "vulnerable_code": "N/A",
                "risk": "No security issues detected.",
                "fix": "N/A"
            })

        # Return the list of vulnerabilities to the frontend
        logger.info(f"Scan completed for uid={user.get('uid', 'unknown')} lang={language}")
        return jsonify({
            "vulnerabilities": result["vulnerabilities"],
            "total": len(result["vulnerabilities"])
        })

    except Exception as e:
        logger.error(f"CRITICAL ROUTE FAULT: {e}", exc_info=True)
        return jsonify({
            "status": "FAULT",
            "error_code": "SERVER_INTERNAL_ERROR",
            "audit_summary": "Internal logic error."
        }), 500

# ─────────────────────────────────────────────
# Error Handlers
# ─────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "Request too large"}), 413

@app.errorhandler(429)
def rate_limited(e):
    return jsonify({
        "status": "REJECTED",
        "error_code": "RATE_LIMITED",
        "audit_summary": "Too many requests. Please wait before retrying."
    }), 429

if __name__ == "__main__":
    app.run(debug=False, port=5000)
