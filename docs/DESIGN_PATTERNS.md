# Design patterns used

Eight classic GoF design patterns are used, covering all three categories (Creational, Structural, Behavioural) to provide clean separation of concerns and high architectural maintainability.

| # | Pattern | Category | File | Requirement |
|---|---|---|---|---|
| 1 | Singleton | Creational | `court/database.py` | One consistent data store for all modules |
| 2 | Factory | Creational | `court/case_management/case_factory.py` | FR-01, FR-04: case types with their own court rules |
| 3 | Facade | Structural | `court/facade.py` | One simple entry point; UI decoupled from subsystems |
| 4 | Proxy (protection) | Structural | `court/access_proxy.py` | NFR-01 security, NFR-02 privacy |
| 5 | Strategy | Behavioural | `court/priority/strategies.py` | FR-06, NFR-08: priority rules are a volatile requirement |
| 6 | State | Behavioural | `case_states.py`, `schedule_states.py` | Module 2 state diagrams; DR-07 approval |
| 7 | Chain of Responsibility | Behavioural | `court/scheduling/conflict_chain.py` | FR-11, DR-05, DR-06: conflict checks |
| 8 | Observer | Behavioural | `court/events.py` | FR-15 audit, notifications |

---

## 1. Singleton: `Database`
**Problem:** every module needs the same data, and parallel connections could write inconsistently.
**Solution:** `Database.get_instance()` creates the connection once (with double-checked locking) and always returns the same object. Calling the constructor a second time raises an error.

## 2. Factory: `CaseFactory`
**Problem:** case types follow different court rules. Bail is urgent by law, and criminal matters weigh more than rent disputes. Client code should not need a branch for every type.
**Solution:** `CaseFactory.create("BAIL", ...)` returns a `BailApplication`. Each subclass carries `type_weight`, `urgent_by_rule` and `rule_note`. New types register themselves with `@CaseFactory.register`, so the factory never changes (Open/Closed).
**Seen in the demo:** registering a bail case marks it urgent automatically. This implements *Identify Urgent Case «extend» Register Case*.

## 3. Facade: `CourtSchedulingFacade`
**Problem:** generating a schedule needs repositories, the priority engine, the scheduler, the conflict chain and the event bus.
**Solution:** one class offers simple operations such as `register_case`, `generate_schedule` and `approve_hearing`, and coordinates the subsystems behind them. `generate_schedule` implements the use case relationships *«include» Prioritize Cases* and *«include» Check Judge/Courtroom Availability*.

## 4. Proxy: `AccessControlProxy`
**Problem:** every operation must be authorised, and mixing security checks into business code breaks the Single Responsibility Principle.
**Solution:** the proxy offers the same interface as the facade. On each call it re-loads the user (so disabled accounts are refused immediately), checks the role in the `PERMISSIONS` table, **denies anything not listed**, publishes `ACCESS_DENIED`, and passes the current user to the facade.
**Seen in the demo:** a lawyer trying to generate a schedule gets "Access denied", and the attempt appears in the audit log.

## 5. Strategy: `PriorityStrategy` / `PriorityEngine`
**Problem:** Module 1 says *how priority is calculated* may change (FIFO first, then urgency and vulnerability), and NFR-08 says administrators must be able to change it.
**Solution:** `FirstComeFirstServedStrategy`, `WeightedFactorStrategy` (configurable weights) and `LegalUrgencyFirstStrategy` share the `compute(case)` method. `PriorityEngine.set_strategy()` swaps the rule at run time. Each result carries `PriorityFactor`s, which explain the score (NFR-10).

## 6. State: case lifecycle and hearing workflow
**Problem:** whether an action is allowed depends on status. For example, a case that was never validated must not be scheduled.
**Solution:** each status from the state diagrams is a class. `Case` and `HearingSchedule` delegate events to their current state object. Illegal events raise `InvalidTransitionError`.

```
Case:     REGISTERED → VALIDATED → PRIORITIZED → SCHEDULED → HEARING_CONFIRMED → DISPOSED
              ↘ UPDATE_REQUIRED ↗                   ↖──── cancelled ────┘
Hearing:  PENDING_APPROVAL → APPROVED → COMPLETED
              ↘ CHANGES_REQUESTED ↗ (reschedule)    any change → PENDING_APPROVAL again
```

## 7. Chain of Responsibility: conflict checks
**Problem:** a slot must pass several independent rules, and the same rules are needed in four places.
**Solution:** `JudgeAvailability → CourtroomAvailability → JudgeDoubleBooking → CourtroomDoubleBooking → CaseDoubleBooking`. Each handler records its problem and passes the request on, so the user sees **all** conflicts at once. The same chain is used by generation, manual override, rescheduling and the conflict scan.

## 8. Observer: `EventBus`
**Problem:** many actions must be audited and some must notify other roles, without the business code knowing who listens.
**Solution:** the facade publishes `CourtEvent`s. `AuditLogObserver` writes the hash-chained audit log, and `NotificationObserver` routes messages to role inboxes. Adding e-mail later is just one more observer.

---

## Design principles

- **Single Responsibility:** one handler checks one rule, the proxy only checks access, and repositories only persist data.
- **Open/Closed:** new case types, strategies, conflict rules and observers are new classes; existing code stays unchanged.
- **Liskov Substitution:** any strategy, handler or case subclass can replace another.
- **Interface Segregation:** small interfaces such as `compute()`, `check()` and `update()`.
- **Dependency Inversion:** the engine and scheduler depend on abstract strategy and handler types.
- **Layering and separation of concerns:** UI → Proxy → Facade → domain → repositories → database.
- **DRY:** one conflict chain serves four features.
