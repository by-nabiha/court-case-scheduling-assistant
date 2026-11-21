"""
Domain classes taken from the Module#2 class diagram (Iteration 3):
SystemUser, Judge, Courtroom, Availability, Case, HearingSchedule,
SchedulingConflict, ScheduleRecommendation.

The concrete Case subclasses live in case_management/case_factory.py.
"""
from dataclasses import dataclass, field
from datetime import date
from typing import ClassVar, List, Optional


# --------------------------------------------------------------------- roles
class Role:
    CLERK = "COURT_CLERK"
    LAWYER = "LAWYER"
    JUDGE = "JUDGE"
    ADMIN = "COURT_ADMINISTRATOR"
    SYSADMIN = "SYSTEM_ADMINISTRATOR"

    LABELS = {
        CLERK: "Court Clerk",
        LAWYER: "Lawyer",
        JUDGE: "Judge",
        ADMIN: "Court Administrator",
        SYSADMIN: "System Administrator",
    }


# ---------------------------------------------------------------- exceptions
class CourtError(Exception):
    """Base class for all business-rule errors shown to the user."""


class AccessDeniedError(CourtError):
    pass


class InvalidTransitionError(CourtError):
    pass


class ValidationError(CourtError):
    pass


class NotFoundError(CourtError):
    pass


# -------------------------------------------------------------------- people
@dataclass
class SystemUser:
    user_id: int
    username: str
    name: str
    email: str
    role: str
    password_hash: str = ""
    is_active: bool = True
    failed_attempts: int = 0
    locked_until: str = ""
    totp_secret: str = ""
    totp_enabled: bool = False
    last_login: str = ""

    @property
    def role_label(self):
        return Role.LABELS.get(self.role, self.role)


@dataclass
class Judge:
    judge_id: int
    name: str
    court_name: str
    user_id: Optional[int] = None


# ----------------------------------------------------------------- resources
@dataclass
class Courtroom:
    courtroom_id: int
    room_name: str
    availability_status: str = "ACTIVE"   # ACTIVE | UNDER_MAINTENANCE


@dataclass
class Availability:
    availability_id: Optional[int]
    resource_type: str          # JUDGE | COURTROOM
    resource_id: int
    available_date: str         # YYYY-MM-DD
    start_time: str             # HH:MM
    end_time: str               # HH:MM

    def covers(self, on_date, start, end):
        return (self.available_date == on_date
                and self.start_time <= start and end <= self.end_time)


# ---------------------------------------------------------------------- case
CASE_STATUSES = ["REGISTERED", "UPDATE_REQUIRED", "VALIDATED", "PRIORITIZED",
                 "SCHEDULED", "HEARING_CONFIRMED", "DISPOSED"]


@dataclass
class Case:
    """Context object for the Case State pattern (see case_states.py)."""
    case_id: str
    case_title: str
    filing_date: str
    parties: str = ""
    judge_id: Optional[int] = None
    lawyer_id: Optional[int] = None
    case_status: str = "REGISTERED"
    is_urgent: bool = False
    urgency_reason: str = ""
    vulnerable_party: bool = False
    vulnerability_type: str = ""
    priority_score: float = 0.0
    priority_level: str = "UNASSESSED"
    priority_explanation: str = ""

    # Class-level attributes overridden by each concrete case type (Factory)
    case_type: ClassVar[str] = "GENERAL"
    type_label: ClassVar[str] = "General"
    type_weight: ClassVar[int] = 0
    urgent_by_rule: ClassVar[bool] = False
    rule_note: ClassVar[str] = ""

    # ---- derived information -------------------------------------------
    def waiting_days(self, today: Optional[date] = None) -> int:
        today = today or date.today()
        return max(0, (today - date.fromisoformat(self.filing_date)).days)

    def missing_fields(self) -> List[str]:
        """Rules used by 'Validate Case Information' (state diagram, iter. 3)."""
        problems = []
        if not self.case_title.strip():
            problems.append("Case title is required")
        if " vs " not in f" {self.parties.lower()} ":
            problems.append("Parties must be entered as 'Plaintiff vs Defendant'")
        try:
            if date.fromisoformat(self.filing_date) > date.today():
                problems.append("Filing date cannot be in the future")
        except ValueError:
            problems.append("Filing date is not a valid date")
        if self.judge_id is None:
            problems.append("An assigned judge is required")
        if self.vulnerable_party and not self.vulnerability_type:
            problems.append("Vulnerability type must be specified")
        return problems

    # ---- State pattern: the case delegates lifecycle events to its state --
    @property
    def state(self):
        from .case_management.case_states import state_for
        return state_for(self.case_status)

    def validate(self):
        return self.state.validate(self)

    def request_correction(self):
        self.state.request_correction(self)

    def prioritize(self):
        self.state.prioritize(self)

    def schedule(self):
        self.state.schedule(self)

    def confirm_hearing(self):
        self.state.confirm_hearing(self)

    def return_to_backlog(self):
        self.state.return_to_backlog(self)

    def dispose(self):
        self.state.dispose(self)


# ------------------------------------------------------------------ hearings
@dataclass
class HearingSchedule:
    """Context object for the Hearing State pattern (see schedule_states.py)."""
    schedule_id: Optional[int]
    case_id: str
    judge_id: int
    courtroom_id: int
    hearing_date: str
    hearing_time: str
    end_time: str
    status: str = "PENDING_APPROVAL"
    created_by: str = "SYSTEM"
    reason: str = ""

    @property
    def state(self):
        from .scheduling.schedule_states import hearing_state_for
        return hearing_state_for(self.status)

    @property
    def is_active(self):
        return self.status in ("PENDING_APPROVAL", "APPROVED", "CHANGES_REQUESTED")


@dataclass
class SchedulingConflict:
    conflict_id: Optional[int]
    schedule_id: Optional[int]
    conflict_type: str
    description: str
    resolution_status: str = "OPEN"
    detected_at: str = ""
    resolution_note: str = ""


@dataclass
class ScheduleRecommendation:
    """Output of the scheduling engine: hearings proposed + cases it could not fit."""
    proposed: List[HearingSchedule] = field(default_factory=list)
    unscheduled: List[tuple] = field(default_factory=list)   # (case_id, reason)
