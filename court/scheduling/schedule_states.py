"""
MODULE 3 - Hearing Scheduling / Approval

DESIGN PATTERN: State (Behavioural)
-----------------------------------
A HearingSchedule moves through the approval workflow described in the
swimlane diagram (Iteration 3) and DR-07 (human authorisation):

  PENDING_APPROVAL --approve--> APPROVED --complete--> COMPLETED
        |   ^                      |
        |   | reschedule           | reschedule (needs re-approval)
        v   |                      v
  CHANGES_REQUESTED  <--------  (back to PENDING_APPROVAL)
        any active state --cancel--> CANCELLED

Each state class only implements the events that are legal for it.
"""
from ..models import InvalidTransitionError


class HearingState:
    name = "ABSTRACT"
    label = ""

    def _illegal(self, event):
        raise InvalidTransitionError(f"Cannot {event} a hearing that is {self.label}.")

    def approve(self, h):
        self._illegal("approve")

    def request_changes(self, h):
        self._illegal("request changes to")

    def reschedule(self, h):
        self._illegal("reschedule")

    def complete(self, h):
        self._illegal("complete")

    def cancel(self, h):
        self._illegal("cancel")

    def can(self, event):
        return getattr(type(self), event) is not getattr(HearingState, event)


class PendingApproval(HearingState):
    name, label = "PENDING_APPROVAL", "pending approval"

    def approve(self, h):
        h.status = "APPROVED"

    def request_changes(self, h):
        h.status = "CHANGES_REQUESTED"

    def reschedule(self, h):
        h.status = "PENDING_APPROVAL"    # manual override stays pending

    def cancel(self, h):
        h.status = "CANCELLED"


class ChangesRequested(HearingState):
    name, label = "CHANGES_REQUESTED", "awaiting modification"

    def reschedule(self, h):
        h.status = "PENDING_APPROVAL"

    def cancel(self, h):
        h.status = "CANCELLED"


class Approved(HearingState):
    name, label = "APPROVED", "approved"

    def reschedule(self, h):
        h.status = "PENDING_APPROVAL"    # any change needs fresh approval

    def complete(self, h):
        h.status = "COMPLETED"

    def cancel(self, h):
        h.status = "CANCELLED"


class Completed(HearingState):
    name, label = "COMPLETED", "completed"


class Cancelled(HearingState):
    name, label = "CANCELLED", "cancelled"


_STATES = {c.name: c() for c in (PendingApproval, ChangesRequested, Approved,
                                 Completed, Cancelled)}


def hearing_state_for(status):
    try:
        return _STATES[status]
    except KeyError:
        raise InvalidTransitionError(f"Unknown hearing status '{status}'")
