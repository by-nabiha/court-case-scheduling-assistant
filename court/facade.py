"""
DESIGN PATTERN: Facade (Structural)
-----------------------------------
CourtSchedulingFacade is the ONE entry point to the three modules:

    Module A  Case Management       CaseFactory + Case State machine
    Module B  Priority Engine       PriorityEngine + PriorityStrategy
    Module C  Scheduling/Approval   HearingScheduler + conflict chain + Hearing State

It also coordinates the repositories and publishes events to the EventBus
(Observer).  The web layer never touches these subsystems directly; it only
talks to the facade - and only through the AccessControlProxy.

Every public method receives `actor` (the logged-in SystemUser) as its first
argument; the proxy supplies it automatically, so every action is attributed
in the audit trail.
"""
import json
import re
from datetime import date, datetime, timedelta

from .case_management.case_factory import CaseFactory
from .database import Database
from .events import AuditLogObserver, CourtEvent, EventBus, NotificationObserver
from .models import (AccessDeniedError, Availability, CourtError, NotFoundError, Role,
                     ValidationError)
from .priority.strategies import STRATEGIES, PriorityEngine, WeightedFactorStrategy, make_strategy
from .repositories import (AuditRepository, AvailabilityRepository, CaseRepository,
                           ConflictRepository, CourtroomRepository, HearingRepository,
                           JudgeRepository, NotificationRepository, SettingsRepository,
                           UserRepository)
from .scheduling.conflict_chain import SchedulingContext, SlotRequest, build_default_chain
from .scheduling.scheduler import HearingScheduler, _add_minutes
from .security import (FieldCipher, hash_password, new_totp_secret, totp_uri, verify_password,
                       verify_totp)

CASE_ID_RE = re.compile(r"^[A-Z]{2,5}-\d{4}-\d{1,5}$")
TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
VULNERABILITY_TYPES = ["Minor (under 18)", "Elderly (65+)", "Person with disability",
                       "Victim of violence", "Seriously ill"]
STAFF_ROLES = (Role.CLERK, Role.ADMIN, Role.JUDGE)


def _clean(text, field, max_len=200, required=True):
    text = (text or "").strip()
    if required and not text:
        raise ValidationError(f"{field} is required")
    if len(text) > max_len:
        raise ValidationError(f"{field} must be at most {max_len} characters")
    return text


def _parse_date(value, field="Date"):
    try:
        return date.fromisoformat((value or "").strip())
    except ValueError:
        raise ValidationError(f"{field} must be a valid date (YYYY-MM-DD)")


def _parse_time(value, field="Time"):
    value = (value or "").strip()
    if not TIME_RE.match(value):
        raise ValidationError(f"{field} must be in HH:MM (24-hour) format")
    return value


def _int_or_none(value):
    if value in (None, "", "None"):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"Invalid number '{value}'")


class CourtSchedulingFacade:
    def __init__(self, db: Database, cipher: FieldCipher, today=date.today):
        self.today = today
        self.users = UserRepository(db)
        self.judges_repo = JudgeRepository(db)
        self.courtrooms_repo = CourtroomRepository(db)
        self.availability_repo = AvailabilityRepository(db)
        self.cases = CaseRepository(db, cipher)
        self.hearings = HearingRepository(db)
        self.conflicts = ConflictRepository(db)
        self.settings = SettingsRepository(db)
        self.audit = AuditRepository(db)
        self.notifications_repo = NotificationRepository(db)

        # Observer wiring
        self.events = EventBus()
        self.events.subscribe(AuditLogObserver(self.audit))
        self.events.subscribe(NotificationObserver(self.notifications_repo))

        # Module C collaborators
        self.conflict_chain = build_default_chain()
        self.scheduler = HearingScheduler(self.conflict_chain, slot_minutes=60)

    # ================================================================ helpers
    def publish(self, actor, event_type, entity, entity_id, details="", reason=""):
        self.events.publish(CourtEvent(event_type, actor.name if actor else "SYSTEM",
                                       actor.role if actor else "SYSTEM", entity,
                                       str(entity_id), details, reason))

    def _case_visible(self, actor, case):
        """Data-level privacy (NFR-02): lawyers see only their own cases."""
        return actor.role != Role.LAWYER or case.lawyer_id == actor.user_id

    def _load_case(self, actor, case_id):
        case = self.cases.get(case_id)
        if not self._case_visible(actor, case):
            raise AccessDeniedError("You are not the counsel of record for this case.")
        return case

    def _mask(self, actor, case):
        """Sensitive vulnerability details are shown only to staff and own counsel."""
        if actor.role not in STAFF_ROLES and not (
                actor.role == Role.LAWYER and case.lawyer_id == actor.user_id):
            case.vulnerability_type = "•••• (restricted)" if case.vulnerable_party else ""
        return case

    def _context(self, exclude_ids=()):
        hearings = [h for h in self.hearings.active() if h.schedule_id not in exclude_ids]
        return SchedulingContext(self.judges_repo.all(), self.courtrooms_repo.all(),
                                 self.availability_repo.all(), hearings)

    def _check_judge_owns(self, actor, hearing):
        if actor.role == Role.JUDGE:
            judge = self.judges_repo.by_user(actor.user_id)
            if judge is None or judge.judge_id != hearing.judge_id:
                raise AccessDeniedError("Judges may act only on hearings assigned to them.")

    # ================================================ MODULE A: Case Management
    def case_types(self, actor):
        return CaseFactory.types()

    def vulnerability_types(self, actor):
        return VULNERABILITY_TYPES

    def list_cases(self, actor, status=None):
        lawyer = actor.user_id if actor.role == Role.LAWYER else None
        cases = self.cases.all(lawyer_id=lawyer)
        if status:
            cases = [c for c in cases if c.case_status == status]
        return [self._mask(actor, c) for c in cases]

    def get_case(self, actor, case_id):
        return self._mask(actor, self._load_case(actor, case_id))

    def case_history(self, actor, case_id):
        self._load_case(actor, case_id)
        return self.audit.recent(entity_id=case_id)

    def lawyers(self, actor):
        return self.users.by_role(Role.LAWYER)

    def register_case(self, actor, data):
        case_id = _clean(data.get("case_id"), "Case ID", 20).upper()
        if not CASE_ID_RE.match(case_id):
            raise ValidationError("Case ID must look like CR-2026-101 (letters-year-number)")
        if self.cases.exists(case_id):
            raise ValidationError(f"Case {case_id} is already registered")
        filing = _parse_date(data.get("filing_date"), "Filing date")
        if filing > self.today():
            raise ValidationError("Filing date cannot be in the future")
        judge_id = _int_or_none(data.get("judge_id"))
        if judge_id and not self.judges_repo.get(judge_id):
            raise ValidationError("Selected judge does not exist")
        lawyer_id = _int_or_none(data.get("lawyer_id"))
        if lawyer_id:
            lawyer = self.users.get(lawyer_id)
            if not lawyer or lawyer.role != Role.LAWYER:
                raise ValidationError("Selected lawyer does not exist")

        case = CaseFactory.create(
            data.get("case_type"), case_id=case_id,
            case_title=_clean(data.get("case_title"), "Case title"),
            filing_date=filing.isoformat(),
            parties=_clean(data.get("parties"), "Parties", required=False),
            judge_id=judge_id, lawyer_id=lawyer_id)
        if data.get("is_urgent") and not case.is_urgent:
            case.is_urgent = True
            case.urgency_reason = _clean(data.get("urgency_reason"), "Urgency reason")
        self.cases.add(case)
        details = f"{case.type_label}: {case.case_title}"
        if case.is_urgent:
            details += f" [URGENT - {case.urgency_reason}]"
        self.publish(actor, "CASE_REGISTERED", "Case", case_id, details)
        return case

    def update_case(self, actor, case_id, data, reason):
        case = self._load_case(actor, case_id)
        if not case.state.editable:
            raise CourtError(f"Case is {case.case_status} and can no longer be edited.")
        reason = _clean(reason, "Reason for change")
        changes = []
        for field, label in (("case_title", "Title"), ("parties", "Parties")):
            if field in data:
                new = _clean(data[field], label, required=(field == "case_title"))
                if new != getattr(case, field):
                    changes.append(f"{label}: '{getattr(case, field)}' -> '{new}'")
                    setattr(case, field, new)
        if "judge_id" in data and actor.role != Role.LAWYER:
            jid = _int_or_none(data["judge_id"])
            if jid and not self.judges_repo.get(jid):
                raise ValidationError("Selected judge does not exist")
            if jid != case.judge_id:
                changes.append(f"Judge: {case.judge_id} -> {jid}")
                case.judge_id = jid
        if not changes:
            raise ValidationError("No changes were made")
        self.cases.save(case)
        self.publish(actor, "CASE_UPDATED", "Case", case_id, "; ".join(changes), reason)
        return case

    def validate_case(self, actor, case_id):
        case = self._load_case(actor, case_id)
        problems = case.validate()               # State pattern decides legality
        self.cases.save(case)
        if problems:
            self.publish(actor, "CASE_NEEDS_CORRECTION", "Case", case_id, "; ".join(problems))
        else:
            self.publish(actor, "CASE_VALIDATED", "Case", case_id, "All required information present")
        return problems

    def request_correction(self, actor, case_id, reason):
        case = self._load_case(actor, case_id)
        reason = _clean(reason, "Reason")
        case.request_correction()
        self.cases.save(case)
        self.publish(actor, "CASE_NEEDS_CORRECTION", "Case", case_id, reason, reason)

    def mark_urgent(self, actor, case_id, urgent, reason):
        case = self._load_case(actor, case_id)
        if not case.state.editable:
            raise CourtError("A disposed case cannot be changed.")
        reason = _clean(reason, "Reason")
        if not urgent and case.urgent_by_rule:
            raise CourtError(f"{case.type_label} cases are urgent by court rule.")
        case.is_urgent = bool(urgent)
        case.urgency_reason = reason if urgent else ""
        self.cases.save(case)
        self.publish(actor, "CASE_MARKED_URGENT" if urgent else "CASE_URGENCY_REMOVED",
                     "Case", case_id, reason, reason)

    def record_vulnerability(self, actor, case_id, vulnerable, vulnerability_type, reason=""):
        case = self._load_case(actor, case_id)
        if not case.state.editable:
            raise CourtError("A disposed case cannot be changed.")
        if vulnerable and vulnerability_type not in VULNERABILITY_TYPES:
            raise ValidationError("Choose a vulnerability type from the list")
        case.vulnerable_party = bool(vulnerable)
        case.vulnerability_type = vulnerability_type if vulnerable else ""
        self.cases.save(case)
        # the audit log never stores the sensitive detail itself, only the fact
        self.publish(actor, "VULNERABILITY_RECORDED", "Case", case_id,
                     "Vulnerable litigant flagged" if vulnerable else "Vulnerability flag removed",
                     _clean(reason, "Reason", required=False))

    # ================================================== MODULE B: Priority Engine
    def _strategy(self):
        key = self.settings.get("priority_strategy", "WEIGHTED")
        weights = json.loads(self.settings.get("priority_weights", "{}"))
        return make_strategy(key, weights)

    def priority_settings(self, actor):
        s = self._strategy()
        weights = s.config() if isinstance(s, WeightedFactorStrategy) else \
            WeightedFactorStrategy(json.loads(self.settings.get("priority_weights", "{}"))).config()
        return {"active": s.key, "weights": weights,
                "strategies": [(k, v.name, v.description) for k, v in STRATEGIES.items()]}

    def set_priority_strategy(self, actor, key, weights=None, reason=""):
        if key not in STRATEGIES:
            raise ValidationError("Unknown priority strategy")
        reason = _clean(reason, "Reason for rule change")
        old = self.settings.get("priority_strategy", "WEIGHTED")
        if weights:
            clean = {}
            for k, v in weights.items():
                try:
                    num = float(v)
                except (TypeError, ValueError):
                    raise ValidationError(f"Weight '{k}' must be a number")
                if not 0 <= num <= 1000:
                    raise ValidationError(f"Weight '{k}' must be between 0 and 1000")
                clean[k] = num
            self.settings.set("priority_weights", json.dumps(clean))
        self.settings.set("priority_strategy", key)
        self.publish(actor, "PRIORITY_RULE_CHANGED", "PriorityRule", key,
                     f"{STRATEGIES.get(old, STRATEGIES['WEIGHTED']).name} -> {STRATEGIES[key].name}"
                     + (f" weights={json.dumps(weights)}" if weights else ""), reason)

    def prioritized_backlog(self, actor):
        """Rank (without saving) every validated case that is still pending."""
        engine = PriorityEngine(self._strategy())
        cases = self.cases.by_status("VALIDATED", "PRIORITIZED", "SCHEDULED", "HEARING_CONFIRMED")
        cases = [self._mask(actor, c) for c in cases if self._case_visible(actor, c)]
        return engine.rank(cases, self.today())

    def recalculate_priorities(self, actor, silent=False):
        engine = PriorityEngine(self._strategy())
        cases = self.cases.by_status("VALIDATED", "PRIORITIZED", "SCHEDULED", "HEARING_CONFIRMED")
        results = engine.rank(cases, self.today())
        for r in results:
            c = r.case
            c.priority_score, c.priority_level = r.score, r.level
            c.priority_explanation = r.explanation_text()
            c.prioritize()                       # VALIDATED -> PRIORITIZED (State)
            self.cases.save(c)
        if not silent:
            self.publish(actor, "PRIORITIES_RECALCULATED", "Backlog", "ALL",
                         f"{len(results)} cases ranked with {engine.strategy.name}")
        return results

    # ======================================= MODULE C: Scheduling and Approval
    def judges(self, actor):
        return self.judges_repo.all()

    def courtrooms(self, actor):
        return self.courtrooms_repo.all()

    def availability(self, actor):
        return self.availability_repo.all(from_date=self.today().isoformat())

    def add_availability(self, actor, resource_type, resource_id, on_date, start, end):
        if resource_type not in ("JUDGE", "COURTROOM"):
            raise ValidationError("Resource must be JUDGE or COURTROOM")
        rid = _int_or_none(resource_id)
        repo = self.judges_repo if resource_type == "JUDGE" else self.courtrooms_repo
        if not rid or not repo.get(rid):
            raise ValidationError("Selected judge/courtroom does not exist")
        d = _parse_date(on_date)
        if d < self.today():
            raise ValidationError("Availability cannot be added in the past")
        start, end = _parse_time(start, "Start time"), _parse_time(end, "End time")
        if start >= end:
            raise ValidationError("End time must be after start time")
        aid = self.availability_repo.add(Availability(None, resource_type, rid, d.isoformat(), start, end))
        self.publish(actor, "AVAILABILITY_ADDED", resource_type.title(), rid,
                     f"{d.isoformat()} {start}-{end}")
        return aid

    def remove_availability(self, actor, availability_id):
        a = self.availability_repo.get(_int_or_none(availability_id))
        if a is None:
            raise NotFoundError("Availability slot not found")
        self.availability_repo.delete(a.availability_id)
        self.publish(actor, "AVAILABILITY_REMOVED", a.resource_type.title(), a.resource_id,
                     f"{a.available_date} {a.start_time}-{a.end_time}")

    def set_courtroom_status(self, actor, courtroom_id, status, reason=""):
        if status not in ("ACTIVE", "UNDER_MAINTENANCE"):
            raise ValidationError("Invalid courtroom status")
        room = self.courtrooms_repo.get(_int_or_none(courtroom_id))
        if room is None:
            raise NotFoundError("Courtroom not found")
        self.courtrooms_repo.set_status(room.courtroom_id, status)
        self.publish(actor, "COURTROOM_STATUS_CHANGED", "Courtroom", room.courtroom_id,
                     f"{room.room_name}: {status}", _clean(reason, "Reason", required=False))

    def generate_schedule(self, actor, start_date, days):
        start = _parse_date(start_date, "Start date")
        if start < self.today():
            raise ValidationError("Schedule cannot start in the past")
        try:
            days = int(days)
        except (TypeError, ValueError):
            raise ValidationError("Number of days must be a number")
        if not 1 <= days <= 60:
            raise ValidationError("Number of days must be between 1 and 60")

        # <<include>> Prioritize Cases
        ranked = self.recalculate_priorities(actor, silent=True)
        busy = {h.case_id for h in self.hearings.active()}
        backlog = [r for r in ranked if r.case.state.schedulable and r.case.case_id not in busy]

        # <<include>> Check Judge / Courtroom Availability (inside the chain)
        rec = self.scheduler.recommend(backlog, self._context(), start, days, created_by=actor.name)
        for h in rec.proposed:
            h.status = "PENDING_APPROVAL"
            h.schedule_id = self.hearings.add(h)
            case = self.cases.get(h.case_id)
            case.schedule()                      # PRIORITIZED -> SCHEDULED (State)
            self.cases.save(case)
        self.publish(actor, "SCHEDULE_GENERATED", "Schedule", f"{start}+{days}d",
                     f"{len(rec.proposed)} hearings recommended, {len(rec.unscheduled)} could not be placed")
        return rec

    def list_hearings(self, actor, status=None):
        hearings = self.hearings.all()
        if actor.role == Role.LAWYER:
            own = {c.case_id for c in self.cases.all(lawyer_id=actor.user_id)}
            hearings = [h for h in hearings if h.case_id in own]
        if status:
            hearings = [h for h in hearings if h.status == status]
        return hearings

    def approve_hearing(self, actor, schedule_id):
        h = self.hearings.get(_int_or_none(schedule_id))
        self._check_judge_owns(actor, h)
        if self.conflicts.open_for(h.schedule_id):
            raise CourtError("This hearing has open scheduling conflicts. Resolve them first.")
        h.state.approve(h)                       # State pattern
        self.hearings.save(h)
        case = self.cases.get(h.case_id)
        case.confirm_hearing()
        self.cases.save(case)
        self.publish(actor, "HEARING_APPROVED", "Hearing", h.schedule_id,
                     f"Case {h.case_id} on {h.hearing_date} {h.hearing_time}")

    def request_changes(self, actor, schedule_id, reason):
        h = self.hearings.get(_int_or_none(schedule_id))
        self._check_judge_owns(actor, h)
        reason = _clean(reason, "Reason")
        h.state.request_changes(h)
        h.reason = reason
        self.hearings.save(h)
        self.publish(actor, "HEARING_CHANGES_REQUESTED", "Hearing", h.schedule_id,
                     f"Case {h.case_id}", reason)

    def check_slot(self, actor, schedule_id, on_date, start, courtroom_id):
        h = self.hearings.get(_int_or_none(schedule_id))
        d = _parse_date(on_date).isoformat()
        start = _parse_time(start)
        req = SlotRequest(h.case_id, h.judge_id, _int_or_none(courtroom_id), d, start,
                          _add_minutes(start, self.scheduler.slot_minutes),
                          exclude_schedule_id=h.schedule_id)
        return self.conflict_chain.handle(req, self._context(), [])

    def override_hearing(self, actor, schedule_id, on_date, start, courtroom_id, reason):
        """Manual override / rescheduling (FR-12, FR-14) - validated by the chain."""
        h = self.hearings.get(_int_or_none(schedule_id))
        self._check_judge_owns(actor, h)
        reason = _clean(reason, "Reason for change")
        d = _parse_date(on_date, "New date")
        if d < self.today():
            raise ValidationError("A hearing cannot be moved into the past")
        if not h.state.can("reschedule"):
            raise CourtError(f"Cannot reschedule a hearing that is {h.state.label}.")
        conflicts = self.check_slot(actor, schedule_id, on_date, start, courtroom_id)
        if conflicts:
            self.publish(actor, "OVERRIDE_REJECTED", "Hearing", h.schedule_id,
                         "; ".join(c.description for c in conflicts), reason)
            raise CourtError("Change rejected - conflicts found: " +
                             "; ".join(c.description for c in conflicts))
        old = f"{h.hearing_date} {h.hearing_time} room {h.courtroom_id}"
        h.hearing_date, h.hearing_time = d.isoformat(), _parse_time(start)
        h.end_time = _add_minutes(h.hearing_time, self.scheduler.slot_minutes)
        h.courtroom_id = _int_or_none(courtroom_id)
        h.state.reschedule(h)                    # -> PENDING_APPROVAL (needs re-approval)
        h.reason = reason
        self.hearings.save(h)
        case = self.cases.get(h.case_id)
        case.schedule()                          # HEARING_CONFIRMED -> SCHEDULED if needed
        self.cases.save(case)
        for c in self.conflicts.open_for(h.schedule_id):   # recheck succeeded
            self.conflicts.resolve(c.conflict_id, f"Hearing rescheduled by {actor.name}")
        self.publish(actor, "HEARING_RESCHEDULED", "Hearing", h.schedule_id,
                     f"Case {h.case_id}: {old} -> {h.hearing_date} {h.hearing_time} room {h.courtroom_id}",
                     reason)

    def complete_hearing(self, actor, schedule_id):
        h = self.hearings.get(_int_or_none(schedule_id))
        self._check_judge_owns(actor, h)
        h.state.complete(h)
        self.hearings.save(h)
        case = self.cases.get(h.case_id)
        case.dispose()
        self.cases.save(case)
        self.publish(actor, "HEARING_COMPLETED", "Hearing", h.schedule_id, f"Case {h.case_id} disposed")

    def cancel_hearing(self, actor, schedule_id, reason):
        h = self.hearings.get(_int_or_none(schedule_id))
        self._check_judge_owns(actor, h)
        reason = _clean(reason, "Reason")
        h.state.cancel(h)
        h.reason = reason
        self.hearings.save(h)
        case = self.cases.get(h.case_id)
        case.return_to_backlog()
        self.cases.save(case)
        for c in self.conflicts.open_for(h.schedule_id):
            self.conflicts.resolve(c.conflict_id, "Hearing cancelled")
        self.publish(actor, "HEARING_CANCELLED", "Hearing", h.schedule_id, f"Case {h.case_id}", reason)

    def scan_conflicts(self, actor):
        """Re-run the whole chain on every active hearing (e.g. after availability changed)."""
        ctx = self._context()
        found = []
        for h in ctx.hearings:
            req = SlotRequest(h.case_id, h.judge_id, h.courtroom_id, h.hearing_date,
                              h.hearing_time, h.end_time, exclude_schedule_id=h.schedule_id)
            for c in self.conflict_chain.handle(req, ctx, []):
                cid = self.conflicts.add(h.schedule_id, c.conflict_type, c.description)
                found.append((h, c, cid))
        self.publish(actor, "CONFLICT_DETECTED" if found else "CONFLICT_SCAN_CLEAN", "Schedule", "ALL",
                     f"{len(found)} conflict(s) found in {len(ctx.hearings)} active hearings")
        return found

    def list_conflicts(self, actor):
        return self.conflicts.all()

    def resolve_conflict(self, actor, conflict_id, note):
        c = self.conflicts.get(_int_or_none(conflict_id))
        note = _clean(note, "Resolution note")
        if c.resolution_status != "OPEN":
            raise CourtError("Conflict is already resolved")
        self.conflicts.resolve(c.conflict_id, note)
        self.publish(actor, "CONFLICT_RESOLVED", "Conflict", c.conflict_id, c.description, note)

    # ============================================ audit, notifications, users
    def audit_log(self, actor, limit=300):
        return self.audit.recent(limit)

    def verify_audit(self, actor):
        ok, bad, count = self.audit.verify()
        self.publish(actor, "AUDIT_VERIFIED" if ok else "AUDIT_TAMPERING_DETECTED", "AuditLog", "ALL",
                     f"{count} entries checked" + ("" if ok else f", chain broken at #{bad}"))
        return ok, bad, count

    def notifications(self, actor):
        return self.notifications_repo.for_role(actor.role)

    def dashboard(self, actor):
        cases = self.list_cases(actor)
        hearings = self.list_hearings(actor)
        pending = [c for c in cases if c.case_status != "DISPOSED"]
        today = self.today()
        return {
            "total": len(cases), "pending": len(pending),
            "urgent": sum(1 for c in pending if c.is_urgent),
            "vulnerable": sum(1 for c in pending if c.vulnerable_party),
            "awaiting_validation": sum(1 for c in cases if c.case_status in ("REGISTERED", "UPDATE_REQUIRED")),
            "pending_approval": sum(1 for h in hearings if h.status == "PENDING_APPROVAL"),
            "open_conflicts": sum(1 for c in self.conflicts.all() if c.resolution_status == "OPEN"),
            "avg_wait": round(sum(c.waiting_days(today) for c in pending) / len(pending)) if pending else 0,
            "upcoming": [h for h in hearings if h.is_active and h.hearing_date >= today.isoformat()][:6],
            "by_status": {s: sum(1 for c in cases if c.case_status == s) for s in
                          ("REGISTERED", "UPDATE_REQUIRED", "VALIDATED", "PRIORITIZED",
                           "SCHEDULED", "HEARING_CONFIRMED", "DISPOSED")},
        }

    # -- user administration (System Administrator) --------------------------
    def list_users(self, actor):
        return self.users.all()

    def create_user(self, actor, username, name, email, role, password):
        username = _clean(username, "Username", 30).lower()
        if not re.match(r"^[a-z0-9._]{3,30}$", username):
            raise ValidationError("Username: 3-30 letters, digits, dot or underscore")
        email = _clean(email, "Email", 100)
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
            raise ValidationError("Invalid email address")
        if role not in Role.LABELS:
            raise ValidationError("Invalid role")
        if self.users.by_username(username):
            raise ValidationError("Username already exists")
        uid = self.users.add(username, _clean(name, "Name", 80), email, role, hash_password(password))
        self.publish(actor, "USER_CREATED", "User", username, Role.LABELS[role])
        return uid

    def _get_user(self, user_id):
        user = self.users.get(_int_or_none(user_id))
        if user is None:
            raise NotFoundError("User not found")
        return user

    def set_user_active(self, actor, user_id, active):
        user = self._get_user(user_id)
        if user.user_id == actor.user_id:
            raise CourtError("You cannot deactivate your own account.")
        user.is_active = bool(active)
        self.users.update_security(user)
        self.publish(actor, "USER_ACTIVATED" if active else "USER_DEACTIVATED", "User", user.username)

    def unlock_user(self, actor, user_id):
        user = self._get_user(user_id)
        user.failed_attempts, user.locked_until = 0, ""
        self.users.update_security(user)
        self.publish(actor, "ACCOUNT_UNLOCKED", "User", user.username)

    def reset_password(self, actor, user_id, new_password):
        user = self._get_user(user_id)
        user.password_hash = hash_password(new_password)
        user.failed_attempts, user.locked_until = 0, ""
        self.users.update_security(user)
        self.publish(actor, "PASSWORD_RESET", "User", user.username)

    def reset_two_factor(self, actor, user_id):
        user = self._get_user(user_id)
        user.totp_secret, user.totp_enabled = "", False
        self.users.update_security(user)
        self.publish(actor, "TWO_FACTOR_RESET", "User", user.username)

    # -- self service (every logged-in user) ---------------------------------
    def change_own_password(self, actor, current, new):
        user = self._get_user(actor.user_id)
        if not verify_password(user.password_hash, current):
            raise ValidationError("Current password is incorrect")
        if current == new:
            raise ValidationError("New password must be different")
        user.password_hash = hash_password(new)
        self.users.update_security(user)
        self.publish(actor, "PASSWORD_CHANGED", "User", user.username)

    def begin_two_factor_setup(self, actor):
        user = self._get_user(actor.user_id)
        if user.totp_enabled:
            raise CourtError("Two-factor authentication is already enabled")
        user.totp_secret = new_totp_secret()
        self.users.update_security(user)
        return user.totp_secret, totp_uri(user.totp_secret, user.username)

    def confirm_two_factor_setup(self, actor, code):
        user = self._get_user(actor.user_id)
        if not verify_totp(user.totp_secret, code):
            raise ValidationError("The code is not correct. Check the time on your phone and try again.")
        user.totp_enabled = True
        self.users.update_security(user)
        self.publish(actor, "TWO_FACTOR_ENABLED", "User", user.username)
