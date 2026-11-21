"""Module B - Priority Engine: Strategy pattern, FR-06, FR-07, NFR-04, NFR-08, NFR-10."""
import unittest
from datetime import date, timedelta

from court.case_management.case_factory import CaseFactory
from court.models import ValidationError
from court.priority.strategies import (FirstComeFirstServedStrategy, LegalUrgencyFirstStrategy,
                                       PriorityEngine, WeightedFactorStrategy)
from tests.helpers import CourtTestCase


def case(cid, days_ago, ctype="CIVIL", **kw):
    return CaseFactory.create(ctype, case_id=cid, case_title=cid, parties="A vs B",
                              filing_date=(date.today() - timedelta(days=days_ago)).isoformat(), **kw)


class StrategyTests(unittest.TestCase):
    def setUp(self):
        self.old_ordinary = case("CV-2020-1", 2000)
        self.new_urgent = case("CV-2026-2", 5, is_urgent=True, urgency_reason="injunction")
        self.vulnerable = case("FM-2025-3", 200, "FAMILY", vulnerable_party=True,
                               vulnerability_type="Minor (under 18)")
        self.cases = [self.new_urgent, self.vulnerable, self.old_ordinary]

    def test_T06_fcfs_ranks_oldest_first(self):
        ranked = PriorityEngine(FirstComeFirstServedStrategy()).rank(self.cases)
        self.assertEqual(ranked[0].case.case_id, "CV-2020-1")

    def test_T07_weighted_ranks_urgent_case_above_old_case(self):
        ranked = PriorityEngine(WeightedFactorStrategy()).rank(self.cases)
        ids = [r.case.case_id for r in ranked]
        self.assertLess(ids.index("CV-2026-2"), ids.index("CV-2020-1"))

    def test_urgency_first_tiers(self):
        ranked = PriorityEngine(LegalUrgencyFirstStrategy()).rank(self.cases)
        self.assertEqual([r.case.case_id for r in ranked], ["CV-2026-2", "FM-2025-3", "CV-2020-1"])

    def test_T08_switching_strategy_changes_order(self):
        engine = PriorityEngine(FirstComeFirstServedStrategy())
        first = engine.rank(self.cases)[0].case.case_id
        engine.set_strategy(LegalUrgencyFirstStrategy())
        self.assertNotEqual(first, engine.rank(self.cases)[0].case.case_id)

    def test_T09_ranking_is_deterministic(self):
        a, b = case("CV-2024-1", 100), case("CV-2024-2", 100)
        engine = PriorityEngine(WeightedFactorStrategy())
        self.assertEqual([r.case.case_id for r in engine.rank([b, a])],
                         [r.case.case_id for r in engine.rank([a, b])])

    def test_T10_factors_explain_the_score(self):
        for strategy in (FirstComeFirstServedStrategy(), WeightedFactorStrategy(), LegalUrgencyFirstStrategy()):
            for r in PriorityEngine(strategy).rank(self.cases):
                self.assertAlmostEqual(sum(f.points for f in r.factors), r.score, places=1)
                self.assertTrue(r.factors)

    def test_weights_are_configurable(self):
        heavy = WeightedFactorStrategy({"vulnerability": 500})
        ranked = PriorityEngine(heavy).rank(self.cases)
        self.assertEqual(ranked[0].case.case_id, "FM-2025-3")


class PriorityServiceTests(CourtTestCase):
    def test_backlog_contains_only_validated_cases(self):
        ids = {r.case.case_id for r in self.as_user("admin.nabiha").prioritized_backlog()}
        self.assertNotIn("CR-2026-055", ids)          # still REGISTERED
        self.assertIn("CV-2022-118", ids)

    def test_recalculate_moves_cases_to_prioritized(self):
        self.as_user("admin.nabiha").recalculate_priorities()
        c = self.facade.cases.get("CV-2022-118")
        self.assertEqual(c.case_status, "PRIORITIZED")
        self.assertIn("Waiting time", c.priority_explanation)

    def test_admin_changes_rule_with_reason(self):
        admin = self.as_user("admin.nabiha")
        admin.set_priority_strategy("FCFS", None, "Court order on backlog")
        self.assertEqual(admin.priority_settings()["active"], "FCFS")
        self.assertEqual(admin.prioritized_backlog()[0].case.case_id, "CV-2022-118")
        with self.assertRaises(ValidationError):
            admin.set_priority_strategy("WEIGHTED", None, "")


if __name__ == "__main__":
    unittest.main()
