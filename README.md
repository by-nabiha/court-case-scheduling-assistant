# District Court Case Backlog Prioritization and Scheduling Assistant

An enterprise-grade judicial management platform that registers court cases, ranks the pending backlog by legal urgency, vulnerability, and waiting time, and generates conflict-free hearing schedules. A judge or court administrator must approve each hearing before it becomes official.

The system is structured around three core subsystems:

| Subsystem | Core Purpose | Design Patterns Applied |
|---|---|---|
| **Case Management** | Intake, validation, automated statutory urgency (Bail), lifecycle state engine | Factory, State |
| **Priority Engine** | Objective multi-factor scoring, deterministic tie-breaking, explainability | Strategy |
| **Hearing Scheduling & Approval** | 5-stage conflict chain, greedy slot allocation, judicial approval workflow | Chain of Responsibility, State |
| **Cross-Cutting / Security** | RBAC protection proxy, Fernet encryption at rest, tamper-evident audit ledger | Facade, Proxy, Observer, Singleton |

## Quick start

Requirements: **Python 3.10 or newer**.

**Windows:** double-click `run.bat`.
**macOS / Linux:** `./run.sh`

Or start it manually:

```bash
pip install -r requirements.txt
python seed.py --reset        # loads demo data (dates are relative to today)
python app.py
```

Then open **http://127.0.0.1:5000**.

### Demo accounts (password for all: `Court@2026!`)

| Username | Role |
|---|---|
| `clerk.sara` | Court Clerk |
| `lawyer.ali`, `lawyer.hina` | Lawyer (each sees only their own cases) |
| `judge.khan`, `judge.fatima`, `judge.raza` | Judge (approves only own hearings) |
| `admin.nabiha` | Court Administrator |
| `sysadmin` | System Administrator |

## Run the tests

```bash
python -m unittest discover tests -v
```

There are 67 tests covering each module, every design pattern and the security controls.

## Project structure

```
app.py                       Flask routes: presentation layer only
seed.py                      demo data
court/
  database.py                Singleton
  models.py                  classes from the Module 2 class diagram
  repositories.py            all SQL (parameterised); encryption of sensitive fields
  facade.py                  Facade: single entry point to modules A, B, C
  access_proxy.py            Proxy: role-based access control, deny by default
  auth.py                    login, lockout, two-factor
  security.py                hashing, password policy, encryption, audit hash chain, TOTP
  events.py                  Observer: audit log + notifications
  case_management/           Module A: case_factory.py (Factory), case_states.py (State)
  priority/                  Module B: strategies.py (Strategy)
  scheduling/                Module C: conflict_chain.py (CoR), schedule_states.py (State), scheduler.py
templates/, static/          user interface (no inline scripts, so the strict CSP applies)
tests/                       unit and web tests
docs/                        design patterns, security design, demo script
```

## Security features

- Salted password hashing (scrypt) and a strong password policy
- Account lockout after 5 failed attempts (15 minutes); per-IP login rate limit
- Optional two-factor authentication (TOTP: Google or Microsoft Authenticator)
- Role-based access control through the Proxy, which denies by default and re-checks the user on every call
- Data-level privacy: lawyers see only their own cases, judges act only on their own hearings
- Vulnerability details encrypted at rest (Fernet / AES) and never written to the audit log
- Tamper-evident audit log (SHA-256 hash chain) with a "Verify integrity" button
- CSRF tokens on every form; HttpOnly + SameSite=Strict cookies; 15-minute idle timeout
- Strict security headers (CSP, X-Frame-Options, nosniff); generic error pages; debug mode off

See [`docs/SECURITY.md`](docs/SECURITY.md) and [`docs/DESIGN_PATTERNS.md`](docs/DESIGN_PATTERNS.md).

## Configuration (optional)

| Variable | Purpose |
|---|---|
| `COURT_SECRET_KEY` | session-signing key (otherwise generated in `instance/secret.key`) |
| `COURT_FIELD_KEY` | encryption key for sensitive fields (otherwise `instance/field.key`) |
| `COURT_HTTPS=1` | sets the Secure cookie flag and HSTS when served over HTTPS |
| `COURT_INSTANCE` | folder for the database and keys (default `instance/`) |

The `instance/` folder holds the database and keys. It is listed in `.gitignore` and must never be committed.
