"""
MODULE 1 - Case Management

DESIGN PATTERN: State (Behavioural)
-----------------------------------
Implements the Case state-machine diagram from Module#2 (Iteration 3):

  REGISTERED --validate--> VALIDATED --prioritize--> PRIORITIZED --schedule--> SCHEDULED
      |  ^                     |                          ^                       |
      v  | (correct & validate)|request_correction        | return_to_backlog     | confirm_hearing
  UPDATE_REQUIRED <-----------+                          +--------------------- HEARING_CONFIRMED --dispose--> DISPOSED

Every state is a class that decides which events are legal.  The Case object
(the *context*) simply forwards the event to its current state, so there are
no big if/else blocks on `case_status` anywhere in the code base, and an
illegal action (e.g. scheduling a case that was never validated) raises
InvalidTransitionError.
"""
from ..models import InvalidTransitionError


class CaseState:
    name = "ABSTRACT"
    description = ""
    editable = True          # may case information still be modified?
    schedulable = False      # may the scheduler pick this case?

    def _illegal(self, event):
        raise InvalidTransitionError(
            f"Cannot '{event}' a case that is in state {self.name}.")

    # Default behaviour: every event is illegal unless a state overrides it.
    def validate(self, case):
        self._illegal("validate")

    def request_correction(self, case):
        self._illegal("request correction for")

    def prioritize(self, case):
        self._illegal("prioritize")

    def schedule(self, case):
        self._illegal("schedule")

    def confirm_hearing(self, case):
        self._illegal("confirm a hearing for")

    def return_to_backlog(self, case):
        self._illegal("return to backlog")

    def dispose(self, case):
        self._illegal("dispose")

    def can(self, event):
        """True if this concrete state overrides (i.e. allows) the event."""
        return getattr(type(self), event) is not getattr(CaseState, event)


def _run_validation(case):
    problems = case.missing_fields()
    case.case_status = "UPDATE_REQUIRED" if problems else "VALIDATED"
    return problems


class Registered(CaseState):
    name = "REGISTERED"
    description = "Case entered by the clerk, waiting for validation."

    def validate(self, case):
        return _run_validation(case)

    def request_correction(self, case):
        case.case_status = "UPDATE_REQUIRED"


class UpdateRequired(CaseState):
    name = "UPDATE_REQUIRED"
    description = "Information is incomplete; clerk or lawyer must correct it."

    def validate(self, case):
        return _run_validation(case)


class Validated(CaseState):
    name = "VALIDATED"
    description = "Information verified; waiting for priority assessment."

    def prioritize(self, case):
        case.case_status = "PRIORITIZED"

    def request_correction(self, case):
        case.case_status = "UPDATE_REQUIRED"


class Prioritized(CaseState):
    name = "PRIORITIZED"
    description = "In the prioritised backlog, eligible for scheduling."
    schedulable = True

    def prioritize(self, case):
        pass                    # re-assessment keeps it in the backlog

    def schedule(self, case):
        case.case_status = "SCHEDULED"

    def request_correction(self, case):
        case.case_status = "UPDATE_REQUIRED"


class Scheduled(CaseState):
    name = "SCHEDULED"
    description = "A hearing has been recommended and awaits judicial approval."

    def prioritize(self, case):
        pass                    # score may be refreshed, state unchanged

    def schedule(self, case):
        pass                    # rescheduled within the same state

    def confirm_hearing(self, case):
        case.case_status = "HEARING_CONFIRMED"

    def return_to_backlog(self, case):
        case.case_status = "PRIORITIZED"


class HearingConfirmed(CaseState):
    name = "HEARING_CONFIRMED"
    description = "Hearing approved by the judge / administrator."

    def prioritize(self, case):
        pass

    def schedule(self, case):
        case.case_status = "SCHEDULED"      # rescheduling needs re-approval

    def return_to_backlog(self, case):
        case.case_status = "PRIORITIZED"

    def dispose(self, case):
        case.case_status = "DISPOSED"


class Disposed(CaseState):
    name = "DISPOSED"
    description = "Hearing completed and case disposed. Read-only."
    editable = False


_STATES = {cls.name: cls() for cls in
           (Registered, UpdateRequired, Validated, Prioritized,
            Scheduled, HearingConfirmed, Disposed)}


def state_for(status):
    try:
        return _STATES[status]
    except KeyError:
        raise InvalidTransitionError(f"Unknown case status '{status}'")
