# Security design

The system handles confidential court data (NFR-01 Security, NFR-02 Privacy, NFR-09 Auditability), so security is built into every layer.

| Threat | Control | Where |
|---|---|---|
| Password theft from the database | Salted scrypt hashes; plain passwords never stored | `security.py` |
| Weak passwords | At least 10 characters with upper case, lower case, a digit and a symbol | `security.check_password_policy` |
| Password guessing (brute force) | Lock for 15 minutes after 5 failures; max 10 login attempts per IP per 5 minutes | `auth.py`, `app.py` |
| Discovering valid usernames | The same error message, and the same hashing cost, for unknown users and wrong passwords | `auth.py` |
| Stolen password | Optional TOTP two-factor login (RFC 6238) | `auth.py`, `/account` |
| Unauthorised actions | Protection Proxy with a role-permission table; **deny by default**; user re-checked on every call | `access_proxy.py` |
| Seeing other people's data | Lawyers see only their own cases; judges act only on their own hearings; vulnerability details masked for other roles | `facade.py` |
| Database file copied or leaked | Vulnerability details encrypted with Fernet (AES-128-CBC + HMAC-SHA256); key kept outside the database | `security.FieldCipher`, `repositories.py` |
| Hiding misuse by editing logs | Append-only audit log; each entry hashes the previous one (SHA-256 chain); "Verify integrity" detects any change or deletion | `repositories.AuditRepository` |
| SQL injection | Only parameterised queries (`?` placeholders) | `repositories.py` |
| Cross-site scripting (XSS) | Jinja2 auto-escaping; CSP `script-src 'self'`; no inline scripts | templates, `app.py` |
| Cross-site request forgery (CSRF) | Flask-WTF token on every form; SameSite=Strict cookie | `app.py` |
| Clickjacking | `frame-ancestors 'none'`, `X-Frame-Options: DENY` | `app.py` |
| Session hijacking or fixation | HttpOnly cookie; Secure flag over HTTPS; session cleared at login; 15-minute idle timeout | `app.py` |
| Information leakage | Debug off; generic error pages; `no-store` caching; secrets in environment or files outside git | `app.py`, `.gitignore` |
| Open redirect | Redirects go only to same-host referrers | `app.safe_back` |

## Security events recorded in the audit log

`LOGIN_SUCCESS`, `LOGIN_FAILED`, `ACCOUNT_LOCKED`, `LOGOUT` (including timeouts), `ACCESS_DENIED`, `PASSWORD_CHANGED`, `PASSWORD_RESET`, `USER_CREATED`, `USER_DEACTIVATED`, `ACCOUNT_UNLOCKED`, `TWO_FACTOR_ENABLED`, `TWO_FACTOR_RESET`, `AUDIT_VERIFIED`, `AUDIT_TAMPERING_DETECTED`.

## Showing tamper detection in the demo

```bash
python -c "import sqlite3; c=sqlite3.connect('instance/court.db'); c.execute(\"UPDATE audit_log SET user_name='Hacker' WHERE audit_id=3\"); c.commit()"
```

Then click **Audit Log → Verify integrity**. The system reports *TAMPERING DETECTED at entry #3*.

## Limitations (for a production deployment)

- Use a production WSGI server (for example waitress or gunicorn) behind HTTPS, and set `COURT_HTTPS=1`.
- Keep `COURT_SECRET_KEY` and `COURT_FIELD_KEY` in a secrets manager.
- The login rate limiter is in memory; a multi-server deployment needs a shared store.
