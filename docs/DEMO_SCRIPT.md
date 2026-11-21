# Demo recording script (about 8 minutes)

**Before recording:** run `python seed.py --reset`, then `python app.py`, and open http://127.0.0.1:5000.
Record with OBS Studio or Windows Game Bar (Win + G). Password for every account: `Court@2026!`

---

### 0. Introduction (30 s)
> "This is the District Court Case Backlog Prioritization and Scheduling Assistant. It provides end-to-end automation across Case Management, the Priority Engine, and Hearing Scheduling with human judicial approval, built using eight design patterns and strong defense-in-depth security."

### 1. Security at login (1 min): *Proxy, Observer*
- Log in as `clerk.sara` with a **wrong password**. Point out that the message is generic.
> "Passwords are stored as salted hashes. After 5 wrong attempts the account locks for 15 minutes, and every attempt is written to the audit log."
- Log in correctly.

### 2. Module A: Case Management (1.5 min): *Factory, State*
- **Register New Case**: type BAIL, ID `BA-2026-200`, today's date, parties `Ahmed vs State`, judge Fatima Noor.
> "The CaseFactory created a BailApplication object. Bail is urgent by court rule, so it was marked urgent automatically."
- Open **CR-2026-055** (parties missing) and click **Validate**.
> "The State pattern moved it to UPDATE REQUIRED because the parties are missing."
- Enter parties `State vs Tariq Mehmood` with a reason, save, and click **Validate** again. The case is now VALIDATED.
- Validate the new bail case and CV-2026-044 too.

### 3. Lawyer and privacy (1 min): *Proxy*
- Log out, then log in as `lawyer.ali`. Point out that only his own cases are shown.
- Open CV-2022-118 → **Vulnerable litigant** → Elderly (65+) → Save.
> "This detail is encrypted in the database and is never written into the audit log."
- Try opening `/schedule` and generating a schedule. The Generate form isn't shown. Type the address of an admin page such as `/users`: **Access denied**.

### 4. Module B: Priority Engine (1.5 min): *Strategy*
- Log in as `admin.nabiha` → **Priority Engine**.
- Open **"Why this score?"** on rank #1.
> "Every score is explained factor by factor. This is NFR-10, explainability."
- Switch to **First-Come-First-Served** (reason: "Comparison for review") → the oldest case jumps to #1.
- Switch to **Legal Urgency First** → urgent cases come first.
> "Each rule is a Strategy object. The engine swaps it at run time, and no other code changes."
- Switch back to **Weighted Factors**.

### 5. Module C: Scheduling (2 min): *Facade, Chain of Responsibility, State*
- **Hearing Schedule** → Generate (tomorrow, 14 days).
> "The facade first ranks the backlog, then gives each case the earliest slot that passes every check in the chain."
- Log in as `judge.fatima`. **Approve** CR-2026-012 and **Request changes** on another hearing.
- Click **Override / Reschedule** on a hearing, choose a time that is already taken, then **Check conflicts**. The chain lists the problems.
- Pick a free slot and apply it with a reason. The hearing goes back to *Pending Approval* (State pattern).
- As admin: **Availability** → remove one of Justice Fatima's days that has a hearing → **Conflicts → Run conflict scan** → a conflict appears → **Reschedule** the hearing → the conflict is resolved.

### 6. Audit and tamper detection (1 min): *Observer*
- As `admin.nabiha` → **Audit Log**. Show the logins, failed logins, ACCESS_DENIED and the case actions.
- Click **Verify integrity** → all entries intact.
- (Optional) Run the tamper command from `docs/SECURITY.md`, then verify again → **TAMPERING DETECTED**.

### 7. Two-factor and user management (30 s, optional)
- `sysadmin` → **User Management**: unlock a locked account, or disable a user.
- **My Account → Set up two-factor**: scan the QR code with an authenticator app.

### 8. Code and tests (30 s)
- Show the folders `case_management/`, `priority/` and `scheduling/`.
- Run `python -m unittest discover tests`. **67 tests pass.**
