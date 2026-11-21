"""
MODULE 3 - Hearing Scheduling

DESIGN PATTERN: Chain of Responsibility (Behavioural)
-----------------------------------------------------
FR-11 / DR-05 / DR-06 require several independent checks before a hearing
slot is accepted.  Each check is one handler; handlers are linked into a
chain and a SlotRequest travels down it.  Every handler appends the conflict
it finds (if any) and passes the request on, so the caller receives the
COMPLETE list of problems in one pass.

   JudgeAvailability -> CourtroomAvailability -> JudgeDoubleBooking
        -> CourtroomDoubleBooking -> CaseDoubleBooking

The same chain is reused by: automatic schedule generation, manual override
(FR-14), rescheduling (FR-12) and the "scan existing schedule" function.
Adding a new rule (e.g. "no hearings on public holidays") = one new handler,
no change to existing ones (Open/Closed, Single Responsibility).
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class SlotRequest:
    case_id: str
    judge_id: int
    courtroom_id: int
    hearing_date: str
    start: str
    end: str
    exclude_schedule_id: Optional[int] = None   # the hearing being moved


@dataclass
class ConflictDetail:
    conflict_type: str
    description: str


class SchedulingContext:
    """Read-only view of resources the handlers need (built by the facade)."""

    def __init__(self, judges, courtrooms, availability, hearings):
        self.judges = {j.judge_id: j for j in judges}
        self.courtrooms = {c.courtroom_id: c for c in courtrooms}
        self.availability = availability
        self.hearings = list(hearings)            # active hearings only

    def add_hearing(self, hearing):
        self.hearings.append(hearing)

    def overlapping(self, req: SlotRequest):
        for h in self.hearings:
            if h.schedule_id is not None and h.schedule_id == req.exclude_schedule_id:
                continue
            if h.hearing_date == req.hearing_date and h.hearing_time < req.end and req.start < h.end_time:
                yield h


class ConflictHandler(ABC):
    def __init__(self):
        self._next: Optional["ConflictHandler"] = None

    def set_next(self, handler: "ConflictHandler") -> "ConflictHandler":
        self._next = handler
        return handler          # allows a.set_next(b).set_next(c)

    def handle(self, req: SlotRequest, ctx: SchedulingContext,
               found: List[ConflictDetail]) -> List[ConflictDetail]:
        conflict = self.check(req, ctx)
        if conflict:
            found.append(conflict)
        if self._next:
            return self._next.handle(req, ctx, found)
        return found

    @abstractmethod
    def check(self, req, ctx) -> Optional[ConflictDetail]:
        ...


class JudgeAvailabilityHandler(ConflictHandler):
    def check(self, req, ctx):
        judge = ctx.judges.get(req.judge_id)
        if judge is None:
            return ConflictDetail("UNKNOWN_JUDGE", f"Judge #{req.judge_id} does not exist")
        ok = any(a.resource_type == "JUDGE" and a.resource_id == req.judge_id
                 and a.covers(req.hearing_date, req.start, req.end)
                 for a in ctx.availability)
        if not ok:
            return ConflictDetail("JUDGE_UNAVAILABLE",
                                  f"{judge.name} is not available on {req.hearing_date} "
                                  f"{req.start}-{req.end}")


class CourtroomAvailabilityHandler(ConflictHandler):
    def check(self, req, ctx):
        room = ctx.courtrooms.get(req.courtroom_id)
        if room is None:
            return ConflictDetail("UNKNOWN_COURTROOM", f"Courtroom #{req.courtroom_id} does not exist")
        if room.availability_status != "ACTIVE":
            return ConflictDetail("COURTROOM_UNAVAILABLE",
                                  f"{room.room_name} is {room.availability_status.replace('_', ' ').lower()}")
        ok = any(a.resource_type == "COURTROOM" and a.resource_id == req.courtroom_id
                 and a.covers(req.hearing_date, req.start, req.end)
                 for a in ctx.availability)
        if not ok:
            return ConflictDetail("COURTROOM_UNAVAILABLE",
                                  f"{room.room_name} is not open on {req.hearing_date} "
                                  f"{req.start}-{req.end}")


class JudgeDoubleBookingHandler(ConflictHandler):
    def check(self, req, ctx):
        for h in ctx.overlapping(req):
            if h.judge_id == req.judge_id:
                name = ctx.judges[req.judge_id].name if req.judge_id in ctx.judges else req.judge_id
                return ConflictDetail("JUDGE_DOUBLE_BOOKED",
                                      f"{name} already hears case {h.case_id} at "
                                      f"{h.hearing_time}-{h.end_time} on {h.hearing_date}")


class CourtroomDoubleBookingHandler(ConflictHandler):
    def check(self, req, ctx):
        for h in ctx.overlapping(req):
            if h.courtroom_id == req.courtroom_id:
                room = ctx.courtrooms.get(req.courtroom_id)
                return ConflictDetail("COURTROOM_DOUBLE_BOOKED",
                                      f"{room.room_name if room else req.courtroom_id} is already "
                                      f"used for case {h.case_id} at {h.hearing_time}-{h.end_time}")


class CaseDoubleBookingHandler(ConflictHandler):
    def check(self, req, ctx):
        for h in ctx.hearings:
            if h.case_id == req.case_id and h.schedule_id != req.exclude_schedule_id:
                return ConflictDetail("CASE_ALREADY_SCHEDULED",
                                      f"Case {req.case_id} already has an active hearing "
                                      f"on {h.hearing_date} {h.hearing_time}")


def build_default_chain() -> ConflictHandler:
    head = JudgeAvailabilityHandler()
    (head.set_next(CourtroomAvailabilityHandler())
         .set_next(JudgeDoubleBookingHandler())
         .set_next(CourtroomDoubleBookingHandler())
         .set_next(CaseDoubleBookingHandler()))
    return head
