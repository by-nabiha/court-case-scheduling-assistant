"""
MODULE 2 - Priority Engine

DESIGN PATTERN: Strategy (Behavioural)
--------------------------------------
Module#1 lists "how case priority should be calculated" as a VOLATILE
requirement (FIFO first, maybe urgency/vulnerability later) and NFR-08 says
administrators must be able to change the rules.  Therefore every
prioritisation rule is a separate, interchangeable Strategy object:

    PriorityStrategy (interface)
      |- FirstComeFirstServedStrategy   pure filing order          (DR-03)
      |- WeightedFactorStrategy         configurable weights       (FR-06, NFR-08)
      |- LegalUrgencyFirstStrategy      urgent > vulnerable > FIFO (DR-02, DR-04)

PriorityEngine (the *context*) holds one strategy and can switch it at run
time; nothing else in the system changes when the rule changes.

Every strategy returns a PriorityResult with a list of PriorityFactor
objects, which is how NFR-10 (Explainability) is satisfied: the UI shows
exactly which factors produced each score.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import date
from typing import Dict, List


@dataclass
class PriorityFactor:
    name: str
    points: float
    explanation: str


@dataclass
class PriorityResult:
    case: object
    score: float
    level: str
    factors: List[PriorityFactor] = field(default_factory=list)
    rank: int = 0

    def explanation_text(self):
        return "; ".join(f"{f.name}: +{f.points:g} ({f.explanation})"
                         for f in self.factors if f.points)


class PriorityStrategy(ABC):
    key = ""
    name = ""
    description = ""

    @abstractmethod
    def compute(self, case, today: date) -> PriorityResult:
        ...

    @staticmethod
    def _level(score, high, medium):
        return "HIGH" if score >= high else "MEDIUM" if score >= medium else "LOW"

    def config(self) -> Dict:
        return {}


class FirstComeFirstServedStrategy(PriorityStrategy):
    key = "FCFS"
    name = "First-Come-First-Served"
    description = "Oldest filing first. Score = months waiting. Ignores urgency."

    def compute(self, case, today):
        days = case.waiting_days(today)
        score = round(days / 30, 1)
        factors = [PriorityFactor("Waiting time", score,
                                  f"{days} days since filing ({score:g} months)")]
        return PriorityResult(case, score, self._level(score, 24, 12), factors)


class WeightedFactorStrategy(PriorityStrategy):
    key = "WEIGHTED"
    name = "Weighted Factors"
    description = ("Score = urgency + vulnerability + case-type weight + waiting "
                   "time (points per year, capped). Weights are configurable.")

    DEFAULT_WEIGHTS = {"urgency": 40, "vulnerability": 25,
                       "waiting_per_year": 10, "waiting_cap": 30, "case_type": 1.0}

    def __init__(self, weights=None):
        self.weights = dict(self.DEFAULT_WEIGHTS)
        if weights:
            self.weights.update({k: float(v) for k, v in weights.items()
                                 if k in self.DEFAULT_WEIGHTS})

    def config(self):
        return dict(self.weights)

    def compute(self, case, today):
        w = self.weights
        factors = []
        if case.is_urgent:
            factors.append(PriorityFactor("Legal urgency", w["urgency"],
                                          case.urgency_reason or "Marked urgent"))
        if case.vulnerable_party:
            factors.append(PriorityFactor("Vulnerable litigant", w["vulnerability"],
                                          case.vulnerability_type or "Vulnerable party"))
        type_pts = round(case.type_weight * w["case_type"], 1)
        if type_pts:
            factors.append(PriorityFactor("Case type", type_pts,
                                          f"{case.type_label} weight {case.type_weight}"))
        days = case.waiting_days(today)
        wait_pts = round(min(w["waiting_cap"], days / 365 * w["waiting_per_year"]), 1)
        factors.append(PriorityFactor("Waiting time", wait_pts,
                                      f"{days} days pending (cap {w['waiting_cap']:g})"))
        score = round(sum(f.points for f in factors), 1)
        return PriorityResult(case, score, self._level(score, 60, 30), factors)


class LegalUrgencyFirstStrategy(PriorityStrategy):
    key = "URGENCY_FIRST"
    name = "Legal Urgency First"
    description = ("Strict tiers: urgent cases, then vulnerable litigants, then "
                   "everyone else; inside each tier, oldest filing first.")

    def compute(self, case, today):
        days = case.waiting_days(today)
        if case.is_urgent:
            tier, level, label = 2000, "HIGH", "Tier 1 - legally urgent"
        elif case.vulnerable_party:
            tier, level, label = 1000, "MEDIUM", "Tier 2 - vulnerable litigant"
        else:
            tier, level, label = 0, "LOW", "Tier 3 - ordinary"
        factors = [PriorityFactor("Priority tier", tier, label),
                   PriorityFactor("Waiting time (tie-break)", min(days, 999),
                                  f"{days} days since filing")]
        return PriorityResult(case, tier + min(days, 999), level, factors)


STRATEGIES = {s.key: s for s in (FirstComeFirstServedStrategy,
                                 WeightedFactorStrategy,
                                 LegalUrgencyFirstStrategy)}


def make_strategy(key, weights=None) -> PriorityStrategy:
    cls = STRATEGIES.get(key, WeightedFactorStrategy)
    return cls(weights) if cls is WeightedFactorStrategy else cls()


class PriorityEngine:
    """Context class of the Strategy pattern."""

    def __init__(self, strategy: PriorityStrategy):
        self._strategy = strategy

    @property
    def strategy(self):
        return self._strategy

    def set_strategy(self, strategy: PriorityStrategy):
        self._strategy = strategy

    def rank(self, cases, today=None) -> List[PriorityResult]:
        """Deterministic ranking (NFR-04): score desc, then filing date, then id."""
        today = today or date.today()
        results = [self._strategy.compute(c, today) for c in cases]
        results.sort(key=lambda r: (-r.score, r.case.filing_date, r.case.case_id))
        for i, r in enumerate(results, 1):
            r.rank = i
        return results
