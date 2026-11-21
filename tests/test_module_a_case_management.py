"""Module A - Case Management: Factory and State patterns, FR-01 to FR-05."""
import unittest
from datetime import date, timedelta

from court.case_management.case_factory import BailApplication, CaseFactory, CivilCase
from court.models import CourtError, InvalidTransitionError, ValidationError
from tests.helpers import CourtTestCase

TODAY = date.today().isoformat()


class FactoryPatternTests(unittest.TestCase):
    def test_T01_bail_case_is_urgent_by_rule(self):
        case = CaseFactory.create("BAIL", case_id="BA-2026-1", case_title="Bail",
                                  filing_date=TODAY, parties="A vs State")
        self.assertIsInstance(case, BailApplication)
        self.assertTrue(case.is_urgent)
        self.assertIn("urgent by court rule", case.urgency_reason)

    def test_civil_case_is_not_urgent(self):
        case = CaseFactory.create("civil", case_id="CV-2026-1", case_title="Suit",
                                  filing_date=TODAY, parties="A vs B")
        self.assertIsInstance(case, CivilCase)
        self.assertFalse(case.is_urgent)

    def test_T02_unknown_type_rejected(self):
        with self.assertRaises(ValidationError):
            CaseFactory.create("TAX", case_id="TX-2026-1", case_title="x", filing_date=TODAY)

    def test_new_type_can_be_registered_without_changing_factory(self):
        @CaseFactory.register
        class TaxCase(CivilCase):
            case_type = "TAXTEST"
            type_label = "Tax"
        case = CaseFactory.create("TAXTEST", case_id="TX-2026-1", case_title="x", filing_date=TODAY)
        self.assertIsInstance(case, TaxCase)
        del CaseFactory._registry["TAXTEST"]


class StatePatternTests(unittest.TestCase):
    def make(self, **kw):
        data = dict(case_id="CV-2026-9", case_title="Suit", filing_date=TODAY,
                    parties="A vs B", judge_id=1)
        data.update(kw)
        return CaseFactory.create("CIVIL", **data)

    def test_T03_missing_parties_goes_to_update_required(self):
        case = self.make(parties="")
        problems = case.validate()
        self.assertEqual(case.case_status, "UPDATE_REQUIRED")
        self.assertTrue(any("Parties" in p for p in problems))

    def test_correction_then_validation_succeeds(self):
        case = self.make(parties="")
        case.validate()
        case.parties = "A vs B"
        self.assertEqual(case.validate(), [])
        self.assertEqual(case.case_status, "VALIDATED")

    def test_T04_cannot_schedule_registered_case(self):
        with self.assertRaises(InvalidTransitionError):
            self.make().schedule()

    def test_full_lifecycle(self):
        case = self.make()
        case.validate(); case.prioritize(); case.schedule(); case.confirm_hearing(); case.dispose()
        self.assertEqual(case.case_status, "DISPOSED")
        self.assertFalse(case.state.editable)

    def test_disposed_case_accepts_no_events(self):
        case = self.make(case_status="DISPOSED")
        for event in ("validate", "prioritize", "schedule", "dispose"):
            with self.assertRaises(InvalidTransitionError):
                getattr(case, event)()

    def test_waiting_days(self):
        case = self.make(filing_date=(date.today() - timedelta(days=100)).isoformat())
        self.assertEqual(case.waiting_days(), 100)


class CaseManagementServiceTests(CourtTestCase):
    def test_clerk_registers_case_and_it_is_audited(self):
        clerk = self.as_user("clerk.sara")
        case = clerk.register_case({"case_id": "cv-2026-500", "case_type": "CIVIL",
                                    "case_title": "Recovery suit", "filing_date": TODAY,
                                    "parties": "A vs B", "judge_id": "1"})
        self.assertEqual(case.case_id, "CV-2026-500")
        self.assertEqual(self.facade.audit.recent(entity_id="CV-2026-500")[0]["action"], "CASE_REGISTERED")

    def test_duplicate_and_future_dates_rejected(self):
        clerk = self.as_user("clerk.sara")
        with self.assertRaises(ValidationError):
            clerk.register_case({"case_id": "CV-2022-118", "case_type": "CIVIL",
                                 "case_title": "x", "filing_date": TODAY})
        with self.assertRaises(ValidationError):
            clerk.register_case({"case_id": "CV-2026-501", "case_type": "CIVIL", "case_title": "x",
                                 "filing_date": (date.today() + timedelta(days=3)).isoformat()})

    def test_update_requires_reason(self):
        clerk = self.as_user("clerk.sara")
        with self.assertRaises(ValidationError):
            clerk.update_case("CV-2026-044", {"case_title": "New title"}, "")

    def test_T05_disposed_case_cannot_be_edited(self):
        case = self.facade.cases.get("CV-2026-044")
        case.case_status = "DISPOSED"
        self.facade.cases.save(case)
        with self.assertRaises(CourtError):
            self.as_user("clerk.sara").update_case("CV-2026-044", {"case_title": "x"}, "typo")

    def test_bail_urgency_cannot_be_removed(self):
        with self.assertRaises(CourtError):
            self.as_user("clerk.sara").mark_urgent("BA-2026-031", False, "not urgent")

    def test_lawyer_records_vulnerability_on_own_case(self):
        lawyer = self.as_user("lawyer.ali")
        lawyer.record_vulnerability("CR-2024-077", True, "Elderly (65+)")
        self.assertEqual(self.facade.cases.get("CR-2024-077").vulnerability_type, "Elderly (65+)")


if __name__ == "__main__":
    unittest.main()
