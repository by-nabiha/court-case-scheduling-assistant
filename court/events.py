"""
Cross-cutting: auditing and notifications.

DESIGN PATTERN: Observer (Behavioural)
--------------------------------------
The facade publishes a CourtEvent whenever something important happens
(case registered, priority recalculated, hearing approved, conflict
detected ...).  It does NOT know who is interested.  Observers subscribe to
the EventBus:

  * AuditLogObserver      -> FR-15 / NFR-09 / DR-08 (who, what, when, why)
  * NotificationObserver  -> Increment 4 "Notifications" (role inboxes)

New reactions (e-mail, SMS, statistics) are added by subscribing another
observer - the business code is untouched (Open/Closed, low coupling).
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime

from .models import Role


@dataclass
class CourtEvent:
    event_type: str
    actor_name: str
    actor_role: str
    entity: str
    entity_id: str
    details: str = ""
    reason: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


class EventObserver(ABC):
    @abstractmethod
    def update(self, event: CourtEvent):
        ...


class EventBus:
    """Subject of the Observer pattern."""

    def __init__(self):
        self._observers = []

    def subscribe(self, observer: EventObserver):
        self._observers.append(observer)

    def unsubscribe(self, observer: EventObserver):
        self._observers.remove(observer)

    def publish(self, event: CourtEvent):
        for obs in list(self._observers):
            obs.update(event)


class AuditLogObserver(EventObserver):
    def __init__(self, audit_repo):
        self.repo = audit_repo

    def update(self, event):
        self.repo.add(event)


class NotificationObserver(EventObserver):
    """Routes selected events to the inbox of the roles that must react."""

    ROUTES = {
        "CASE_REGISTERED": [Role.ADMIN],
        "CASE_NEEDS_CORRECTION": [Role.CLERK, Role.LAWYER],
        "CASE_MARKED_URGENT": [Role.ADMIN, Role.JUDGE],
        "VULNERABILITY_RECORDED": [Role.CLERK],
        "PRIORITY_RULE_CHANGED": [Role.ADMIN, Role.JUDGE],
        "SCHEDULE_GENERATED": [Role.JUDGE],
        "HEARING_APPROVED": [Role.ADMIN, Role.CLERK, Role.LAWYER],
        "HEARING_CHANGES_REQUESTED": [Role.ADMIN],
        "HEARING_RESCHEDULED": [Role.JUDGE, Role.LAWYER, Role.CLERK],
        "HEARING_CANCELLED": [Role.LAWYER, Role.CLERK],
        "CONFLICT_DETECTED": [Role.ADMIN],
    }

    def __init__(self, notification_repo):
        self.repo = notification_repo

    def update(self, event):
        for role in self.ROUTES.get(event.event_type, []):
            msg = f"{event.event_type.replace('_', ' ').title()}: {event.entity} {event.entity_id}"
            if event.details:
                msg += f" - {event.details}"
            self.repo.add(role, msg, event.timestamp)
