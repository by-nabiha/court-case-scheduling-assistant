"""
MODULE 3 - Hearing Scheduling

HearingScheduler generates the recommended hearing schedule (FR-10):
it walks the prioritised backlog from Module 2 in rank order and gives each
case the EARLIEST slot that passes the whole conflict-check chain.
Because higher-priority cases are placed first, they receive the earliest
dates when judges/courtrooms are scarce (Stakeholder conflict #4).
"""
from datetime import date, datetime, timedelta

from ..models import HearingSchedule, ScheduleRecommendation
from .conflict_chain import SlotRequest


def _add_minutes(hhmm, minutes):
    t = datetime.strptime(hhmm, "%H:%M") + timedelta(minutes=minutes)
    return t.strftime("%H:%M")


class HearingScheduler:
    def __init__(self, conflict_chain, slot_minutes=60):
        self.chain = conflict_chain
        self.slot_minutes = slot_minutes

    def candidate_slots(self, ctx, judge_id, start_date, days):
        """Yield (date, start, end) inside the judge's availability windows."""
        end_date = start_date + timedelta(days=days - 1)
        windows = sorted(
            (a for a in ctx.availability
             if a.resource_type == "JUDGE" and a.resource_id == judge_id
             and start_date.isoformat() <= a.available_date <= end_date.isoformat()),
            key=lambda a: (a.available_date, a.start_time))
        for w in windows:
            start = w.start_time
            while _add_minutes(start, self.slot_minutes) <= w.end_time:
                yield w.available_date, start, _add_minutes(start, self.slot_minutes)
                start = _add_minutes(start, self.slot_minutes)

    def find_slot(self, ctx, case, start_date, days):
        """Earliest conflict-free (judge, courtroom, time) for this case."""
        judge_ids = [case.judge_id] if case.judge_id else sorted(ctx.judges)
        options = []
        for jid in judge_ids:
            found = None
            for d, s, e in self.candidate_slots(ctx, jid, start_date, days):
                for room_id in sorted(ctx.courtrooms):
                    req = SlotRequest(case.case_id, jid, room_id, d, s, e)
                    if not self.chain.handle(req, ctx, []):      # no conflicts
                        found = HearingSchedule(None, case.case_id, jid, room_id, d, s, e)
                        break
                if found:
                    break
            if found:
                options.append(found)
        return min(options, key=lambda h: (h.hearing_date, h.hearing_time, h.judge_id),
                   default=None)

    def recommend(self, ranked_results, ctx, start_date: date, days: int,
                  created_by="SYSTEM") -> ScheduleRecommendation:
        rec = ScheduleRecommendation()
        for result in ranked_results:
            case = result.case
            slot = self.find_slot(ctx, case, start_date, days)
            if slot is None:
                rec.unscheduled.append((case.case_id, "No judge/courtroom slot free in the period"))
                continue
            slot.created_by = created_by
            slot.reason = f"Rank #{result.rank} ({result.level}, score {result.score:g})"
            ctx.add_hearing(slot)          # later cases must not collide with it
            rec.proposed.append(slot)
        return rec
