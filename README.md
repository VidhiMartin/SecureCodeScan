# SecureCodeScan

# Secure Code Scanner — Production Security Reference
## Firestore Schema, Firebase Rules, Deployment & Environment Variables

---

## 1. Firestore Collection Schema

### `users/{uid}`
Keyed by Firebase UID (not email) for correctness and privacy.

```
users/{uid}
├── email              : string   — user's email address
├── mfa_enabled        : boolean  — true once TOTP is enrolled and verified
├── mfa_secret         : string   — base32 TOTP secret (active, post-enrolment)
├── mfa_pending        : string?  — temporary secret during setup flow (deleted on verify)
├── recovery_codes_hash: string[] — bcrypt hashes of 8 one-time recovery codes
├── enrolled_at        : timestamp
└── setup_started      : timestamp
```

### `mfa_lockout/{email}`
Per-email OTP failure counters.  Auto-expired after MFA_LOCKOUT_TTL (15 min).

```
mfa_lockout/{email}
├── failures  : number    — consecutive bad OTP count
└── locked_at : timestamp | null
```

### `otp_nonces/{sha256_hash}`
Anti-replay store.  Keys are SHA-256(email+otp_code).  TTL: 5 minutes.
Use a Cloud Scheduler / Firebase scheduled function to purge docs older than 5 min.

```
otp_nonces/{hash}
├── created_at : timestamp
└── email      : string   — for auditing
```

### `audit_log/{auto_id}`
Immutable append-only audit trail.  Never update or delete.

```
audit_log/{auto_id}
├── event     : string    — e.g. "SCAN_SUCCESS", "MFA_LOGIN_FAIL"
├── uid       : string
├── email     : string
├── ip        : string
├── timestamp : timestamp
└── extra     : map       — event-specific metadata
```

---

## 2. Firestore Security Rules

Paste this into Firebase Console → Firestore → Rules.

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    // ── users collection ──────────────────────────────────────────────
    // A user can read/write only their own document.
    // Fields mfa_secret, mfa_pending, recovery_codes_hash are NEVER
    // readable by the client — enforce in rules.
    match /users/{uid} {
      allow read: if request.auth != null
                  && request.auth.uid == uid
                  && !('mfa_secret'          in resource.data)  // block direct read of secret
                  && !('recovery_codes_hash' in resource.data);

      // Writes only via backend (Admin SDK bypasses rules), so deny all client writes.
      allow write: if false;
    }

    // ── mfa_lockout — backend-only ────────────────────────────────────
    match /mfa_lockout/{email} {
      allow read, write: if false;  // Admin SDK only
    }

    // ── otp_nonces — backend-only ─────────────────────────────────────
    match /otp_nonces/{hash} {
      allow read, write: if false;  // Admin SDK only
    }

    // ── audit_log — backend-only (append-only via Admin SDK) ──────────
    match /audit_log/{docId} {
      allow read:   if false;       // Never expose audit log to clients
      allow write:  if false;       // Admin SDK only
    }

    // Default deny
    match /{document=**} {
      allow read, write: if false;
    }
  }
}
```

> **Note**: The Admin SDK used by the Flask backend is not subject to Firestore
> security rules. These rules protect against direct client-side Firestore access.

---

## 3. Firebase Authentication Configuration

In Firebase Console → Authentication:

1. **Enable Email/Password** provider.
2. **Enable Multi-tenancy** and create a tenant (`Enterprise-Test-avvoo`).
   Set all users to that tenant.
3. **Set token expiry** to 1 hour (Settings → Session duration).
4. **Enable "Protect against account enumeration"** in Sign-in methods.
5. **Add your Vercel domain** to Authorized Domains.

---

## 4. Environment Variables

Set ALL of the following in Vercel Dashboard → Project → Settings → Environment Variables.

| Variable              | Required | Description                                                          |
|-----------------------|----------|----------------------------------------------------------------------|
| `FIREBASE_KEY`        | ✅ Yes   | Full Firebase service account JSON (paste as-is, newlines preserved) |
| `FIREBASE_PROJECT_ID` | ✅ Yes   | Firebase project ID, e.g. `code-scanner-91d48`                      |
| `FIREBASE_TENANT_ID`  | ✅ Yes   | Multi-tenant ID, e.g. `Enterprise-Test-avvoo`                       |
| `OPENROUTER_API_KEY`  | ✅ Yes   | OpenRouter API key for LLM access                                    |
| `SECRET_KEY`          | ✅ Yes   | 32+ byte random hex string for MFA JWT signing — generate below     |

**Generate SECRET_KEY (run once locally):**
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

For local development, create a `.env` file (never commit it):
```
FIREBASE_KEY={"type":"service_account","project_id":...}
FIREBASE_PROJECT_ID=code-scanner-91d48
FIREBASE_TENANT_ID=Enterprise-Test-avvoo
OPENROUTER_API_KEY=sk-or-...
SECRET_KEY=<output from above>
```

---

## 5. Deployment Instructions (Vercel)

### Prerequisites
- Vercel CLI: `npm install -g vercel`
- Python 3.11+ project

### Steps

```bash
# 1. Clone / navigate to project
cd secure-code-scanner

# 2. Log in to Vercel
vercel login

# 3. Set environment variables (one-time, or via dashboard)
vercel env add FIREBASE_KEY
vercel env add FIREBASE_PROJECT_ID
vercel env add FIREBASE_TENANT_ID
vercel env add OPENROUTER_API_KEY
vercel env add SECRET_KEY

# 4. Deploy to preview
vercel

# 5. Deploy to production
vercel --prod
```

### vercel.json reference variables
The `vercel.json` references secrets as `@variable_name`.
Create them via Vercel Dashboard → Project → Settings → Environment Variables,
or via CLI as shown above.

---

## 6. Frontend Integration Changes Required

The frontend must be updated to pass the **MFA session token** on every scan request.

After a successful `/mfa/login` or `/mfa/verify` call, store the returned
`mfa_token` in memory (not `localStorage` — XSS risk) and send it as:

```http
POST /scan
Authorization: Bearer <Firebase ID Token>
X-MFA-Token: <mfa_token from /mfa/login response>
Content-Type: application/x-www-form-urlencoded

language=python&code=...
```

**JavaScript example (in your existing scan handler):**
```javascript
// Store in closure/module scope, not localStorage
let mfaToken = null;

// After MFA login:
const mfaResp = await fetch('/mfa/login', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${firebaseIdToken}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ code: totpCode }),
});
const mfaData = await mfaResp.json();
if (mfaData.success) {
  mfaToken = mfaData.mfa_token;  // keep in memory only
}

// On scan:
const scanResp = await fetch('/scan', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${firebaseIdToken}`,
    'X-MFA-Token': mfaToken,
  },
  body: formData,
});
```

---

## 7. Recommended Firestore TTL Cleanup

Create a Firebase Scheduled Cloud Function to purge expired nonces and lockouts.
This keeps the collections from growing unboundedly on free tier.

```javascript
// functions/index.js
const functions = require('firebase-functions');
const admin = require('firebase-admin');
admin.initializeApp();

exports.cleanupExpiredDocs = functions.pubsub
  .schedule('every 10 minutes')
  .onRun(async () => {
    const db = admin.firestore();
    const cutoff5m  = new Date(Date.now() - 5  * 60 * 1000);
    const cutoff15m = new Date(Date.now() - 15 * 60 * 1000);

    // Purge OTP nonces older than 5 min
    const nonces = await db.collection('otp_nonces')
      .where('created_at', '<', cutoff5m).get();
    nonces.forEach(doc => doc.ref.delete());

    // Purge expired lockouts
    const lockouts = await db.collection('mfa_lockout')
      .where('locked_at', '<', cutoff15m).get();
    lockouts.forEach(doc => doc.ref.delete());
  });
```

Deploy: `firebase deploy --only functions`

---

## 8. Security Posture Summary

| Threat                   | Mitigation                                                         |
|--------------------------|--------------------------------------------------------------------|
| MFA bypass               | Every /scan requires valid X-MFA-Token JWT signed with SECRET_KEY |
| OTP replay               | SHA-256 nonce stored in Firestore; rejected within 5-min window   |
| Brute-force OTP          | 5-strike lockout per email; 15-min cooldown; rate limiter on route|
| Session hijacking        | MFA tokens are stateless JWTs with 1-hour TTL; no server cookies  |
| Firebase token abuse     | check_revoked=True; tenant assertion; max age 1h enforced         |
| Prompt injection         | Code is XML-escaped; system prompt warns model of adversarial input|
| XSS via scan result      | Bleach on all string input fields; CSP blocks inline scripts      |
| Clickjacking             | X-Frame-Options: DENY + frame-ancestors 'none' in CSP            |
| MIME sniffing            | X-Content-Type-Options: nosniff                                   |
| Downgrade attacks        | HSTS enforced with 1-year max-age + preload                       |
| Oversized payloads       | 50 KB hard limit with 413 response                                |
| Direct Firestore access  | Security rules deny all client reads/writes; Admin SDK bypasses   |
| Recovery code reuse      | Codes stored as bcrypt hashes; each hash deleted on first use     |
| Audit trail tampering    | audit_log is append-only via Admin SDK; rules deny all client ops |
