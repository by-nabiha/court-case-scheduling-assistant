"""
MODULE 1 - Case Management

DESIGN PATTERN: Factory (Creational) with a self-registering product registry
------------------------------------------------------------------------------
Clients (the facade, the repository) never write `CriminalCase(...)`.
They ask `CaseFactory.create("CRIMINAL", **data)` and receive the right Case
subclass.  Each subclass carries the *court rules* for its type:
  * type_weight     -> used by the Priority Engine (Module 2)
  * urgent_by_rule  -> FR-04 "identify urgent case according to court rules"

Open/Closed Principle: a new case type (e.g. "TAX") is added by writing one
subclass decorated with @CaseFactory.register - no existing code changes.
"""
from ..models import Case, ValidationError


class CaseFactory:
    _registry = {}

    @classmethod
    def register(cls, case_class):
        """Class decorator that adds a concrete product to the factory."""
        cls._registry[case_class.case_type] = case_class
        return case_class

    @classmethod
    def create(cls, case_type, **data):
        case_class = cls._registry.get((case_type or "").upper())
        if case_class is None:
            raise ValidationError(f"Unknown case type '{case_type}'. "
                                  f"Allowed: {', '.join(cls._registry)}")
        case = case_class(**data)
        # Court rule: some case types are urgent by law (bail, custody of minors)
        if case_class.urgent_by_rule and not case.is_urgent:
            case.is_urgent = True
            case.urgency_reason = case.urgency_reason or case_class.rule_note
        return case

    @classmethod
    def types(cls):
        return [(k, v.type_label, v.rule_note) for k, v in cls._registry.items()]


@CaseFactory.register
class CriminalCase(Case):
    case_type = "CRIMINAL"
    type_label = "Criminal"
    type_weight = 15
    rule_note = "Criminal trials take precedence over ordinary civil matters."


@CaseFactory.register
class BailApplication(Case):
    case_type = "BAIL"
    type_label = "Bail Application"
    type_weight = 20
    urgent_by_rule = True
    rule_note = "Bail matters involve personal liberty and are urgent by court rule."


@CaseFactory.register
class FamilyCase(Case):
    case_type = "FAMILY"
    type_label = "Family / Custody"
    type_weight = 10
    rule_note = "Family and custody matters affecting minors receive preference."


@CaseFactory.register
class CivilCase(Case):
    case_type = "CIVIL"
    type_label = "Civil Suit"
    type_weight = 5
    rule_note = "Ordinary civil suits follow filing order."


@CaseFactory.register
class RentCase(Case):
    case_type = "RENT"
    type_label = "Rent / Tenancy"
    type_weight = 3
    rule_note = "Rent disputes follow filing order."
