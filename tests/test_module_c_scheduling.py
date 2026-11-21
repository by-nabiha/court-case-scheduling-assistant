"""Module C - Scheduling & Approval: Chain of Responsibility + State, FR-08 to FR-14."""
import unittest
from datetime import date, timedelta

from court.models import Availability, Courtroom, CourtError, HearingSchedule, InvalidTransitionError, Judge
from court.scheduling.conflict_chain import SchedulingContext, SlotRequest, build_default_chain
from tests.helpers import CourtTestCase

D = "2030-01-07"   # a Monday


def ctx(hearings=(), room_status="ACTIVE"):
    judges = [Judge(1, "Judge A", "Court"), Judge(2, "Judge B", "Court")]
    rooms = [Courtroom(1, "Room 1", room_status), Courtroom(2, "Room 2")]
    avail = [Availability(1, "JUDGE", 1, D, "09:00", "12:00"),
             Availability(2, "JUDGE", 2, D, "09:00", "12:00"),
             Availability(3, "COURTROOM", 1, D, "09:00", "16:00"),
             Availability(4, "COURTROOM", 2, D, "09:00", "16:00")]
    return SchedulingContext(judges, rooms, avail, hearings)


def types(conflicts):
    return {c.conflict_type for c in conflicts}


class ChainOfResponsibilityTests(unittest.TestCase):
    def setUp(self):
        self.chain = build_default_chain()

    def test_free_slot_has_no_conflicts(self):
        self.assertEqual(self.chain.handle(SlotRequest("X", 1, 1, D, "09:00", "10:00"), ctx(), []), [])

    def test_T11_outside_judge_availability(self):
        found = self.chain.handle(SlotRequest("X", 1, 1, D, "12:00", "13:00"), ctx(), [])
        self.assertIn("JUDGE_UNAVAILABLE", types(found))

    def test_T12_judge_double_booked(self):
        busy = [HearingSchedule(9, "Y", 1, 2, D, "09:00", "10:00")]
        found = self.chain.handle(SlotRequest("X", 1, 1, D, "09:30", "10:30"), ctx(busy), [])
        self.assertIn("JUDGE_DOUBLE_BOOKED", types(found))

    def test_courtroom_double_booked(self):
        busy = [HearingSchedule(9, "Y", 2, 1, D, "09:00", "10:00")]
        found = self.chain.handle(SlotRequest("X", 1, 1, D, "09:00", "10:00"), ctx(busy), [])
        self.assertEqual(types(found), {"COURTROOM_DOUBLE_BOOKED"})

    def test_T13_courtroom_under_maintenance(self):
        found = self.chain.handle(SlotRequest("X", 1, 1, D, "09:00", "10:00"), ctx(room_status="UNDER_MAINTENANCE"), [])
        self.assertIn("COURTROOM_UNAVAILABLE", types(found))

    def test_chain_reports_all_problems_at_once(self):
        busy = [HearingSchedule(9, "X", 1, 1, D, "09:00", "10:00")]
        found = self.chain.handle(SlotRequest("X", 1, 1, D, "09:00", "10:00"), ctx(busy), [])
        self.assertEqual(types(found), {"JUDGE_DOUBLE_BOOKED", "COURTROOM_DOUBLE_BOOKED", "CASE_ALREADY_SCHEDULED"})

    def test_moving_a_hearing_ignores_itself(self):
        own = [HearingSchedule(9, "X", 1, 1, D, "09:00", "10:00")]
        req = SlotRequest("X", 1, 1, D, "09:30", "10:30", exclude_schedule_id=9)
        self.assertEqual(self.chain.handle(req, ctx(own), []), [])


class HearingStateTests(unittest.TestCase):
    def h(self, status):
        return HearingSchedule(1, "X", 1, 1, D, "09:00", "10:00", status)

    def test_approve_then_complete(self):
        h = self.h("PENDING_APPROVAL"); h.state.approve(h); h.state.complete(h)
        self.assertEqual(h.status, "COMPLETED")

    def test_T15_completed_hearing_cannot_be_approved(self):
        h = self.h("COMPLETED")
        with self.assertRaises(InvalidTransitionError):
            h.state.approve(h)

    def test_T16_rescheduling_approved_hearing_needs_reapproval(self):
        h = self.h("APPROVED"); h.state.reschedule(h)
        self.assertEqual(h.status, "PENDING_APPROVAL")

    def test_changes_requested_cannot_be_approved_directly(self):
        h = self.h("CHANGES_REQUESTED")
        with self.assertRaises(InvalidTransitionError):
            h.state.approve(h)


class SchedulingServiceTests(CourtTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.as_user("admin.nabiha")
        self.start = (date.today() + timedelta(days=1)).isoformat()
        self.rec = self.admin.generate_schedule(self.start, 14)

    def test_T14_generated_schedule_has_no_conflicts_and_respects_priority(self):
        self.assertEqual(len(self.rec.proposed), 10)
        self.assertEqual(self.admin.scan_conflicts(), [])
        slot = {h.case_id: (h.hearing_date, h.hearing_time) for h in self.rec.proposed}
        # urgent cases on the same judge come before ordinary ones
        self.assertLess(slot["CR-2026-012"], slot["CR-2024-077"])
        self.assertLess(slot["BA-2026-031"], slot["CR-2024-077"])

    def test_all_hearings_wait_for_approval(self):
        self.assertTrue(all(h.status == "PENDING_APPROVAL" for h in self.facade.hearings.all()))
        self.assertEqual(self.facade.cases.get("CR-2026-012").case_status, "SCHEDULED")

    def test_judge_approves_own_hearing_only(self):
        fatima, khan = self.as_user("judge.fatima"), self.as_user("judge.khan")
        h = next(x for x in self.facade.hearings.all() if x.case_id == "CR-2026-012")   # Justice Fatima
        with self.assertRaises(CourtError):
            khan.approve_hearing(h.schedule_id)
        fatima.approve_hearing(h.schedule_id)
        self.assertEqual(self.facade.hearings.get(h.schedule_id).status, "APPROVED")
        self.assertEqual(self.facade.cases.get("CR-2026-012").case_status, "HEARING_CONFIRMED")

    def test_override_into_busy_slot_is_rejected(self):
        a, b = self.rec.proposed[0], self.rec.proposed[1]      # both Justice Fatima, Room 1
        with self.assertRaises(CourtError) as err:
            self.admin.override_hearing(b.schedule_id, a.hearing_date, a.hearing_time, a.courtroom_id, "test")
        self.assertIn("conflicts", str(err.exception))

    def test_removed_availability_is_detected_and_rescheduled(self):
        h = self.rec.proposed[0]
        slot = next(s for s in self.facade.availability_repo.all()
                    if s.resource_type == "JUDGE" and s.resource_id == h.judge_id and s.available_date == h.hearing_date)
        self.admin.remove_availability(slot.availability_id)
        found = self.admin.scan_conflicts()
        self.assertTrue(any(x[0].schedule_id == h.schedule_id for x in found))
        with self.assertRaises(CourtError):
            self.admin.approve_hearing(h.schedule_id)          # open conflict blocks approval
        later = next(s for s in self.facade.availability_repo.all()
                     if s.resource_type == "JUDGE" and s.resource_id == h.judge_id and s.available_date > h.hearing_date)
        self.admin.override_hearing(h.schedule_id, later.available_date, "12:00", 3, "Judge on leave")
        self.assertFalse(self.facade.conflicts.open_for(h.schedule_id))

    def test_T19_end_to_end_to_disposal(self):
        h = next(x for x in self.facade.hearings.all() if x.case_id == "CV-2022-118")
        self.admin.approve_hearing(h.schedule_id)
        self.admin.complete_hearing(h.schedule_id)
        self.assertEqual(self.facade.cases.get("CV-2022-118").case_status, "DISPOSED")
        actions = [r["action"] for r in self.facade.audit.recent(entity_id=str(h.schedule_id))]
        self.assertIn("HEARING_APPROVED", actions)
        self.assertIn("HEARING_COMPLETED", actions)

    def test_cancel_returns_case_to_backlog(self):
        h = self.rec.proposed[0]
        self.admin.cancel_hearing(h.schedule_id, "Parties settled")
        self.assertEqual(self.facade.cases.get(h.case_id).case_status, "PRIORITIZED")


if __name__ == "__main__":
    unittest.main()
