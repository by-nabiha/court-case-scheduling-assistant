"""
DESIGN PATTERN: Proxy - Protection Proxy (Structural)
-----------------------------------------------------
AccessControlProxy offers exactly the same methods as CourtSchedulingFacade
and stands in front of it.  On every call it:

  1. re-loads the user from the database (a deactivated or locked account
     loses access immediately, even in an open session);
  2. checks the method against the role-permission table (least privilege);
  3. DENIES BY DEFAULT any method not listed (fail-safe);
  4. records refused attempts as ACCESS_DENIED events (Observer -> audit log);
  5. injects the current user as `actor`, so the facade always knows who acted.

Security rules live here only (Single Responsibility); the facade contains
business logic only.  Data-level rules (a lawyer sees only own cases, a judge
acts only on own hearings) are enforced additionally inside the facade.
"""
from datetime import datetime

from .models import AccessDeniedError, Role

C, L, J, A, S = Role.CLERK, Role.LAWYER, Role.JUDGE, Role.ADMIN, Role.SYSADMIN
EVERYONE = {C, L, J, A, S}

PERMISSIONS = {
    # ---- shared / read ----------------------------------------------------
    "dashboard": EVERYONE, "notifications": EVERYONE, "case_types": EVERYONE,
    "vulnerability_types": EVERYONE, "judges": EVERYONE, "courtrooms": EVERYONE,
    "lawyers": {C, A, J}, "list_cases": {C, L, J, A}, "get_case": {C, L, J, A},
    "case_history": {C, L, J, A}, "list_hearings": {C, L, J, A},
    "change_own_password": EVERYONE, "begin_two_factor_setup": EVERYONE,
    "confirm_two_factor_setup": EVERYONE,
    # ---- Module A: Case Management ----------------------------------------
    "register_case": {C, A},
    "update_case": {C, L, A},
    "validate_case": {C, A},
    "request_correction": {C, A, J},
    "mark_urgent": {C, A},
    "record_vulnerability": {C, L, A},
    # ---- Module B: Priority Engine ----------------------------------------
    "priority_settings": {C, J, A, S},
    "prioritized_backlog": {C, J, A, S},
    "recalculate_priorities": {A},
    "set_priority_strategy": {A, S},
    # ---- Module C: Scheduling & Approval ----------------------------------
    "availability": {C, J, A},
    "add_availability": {A},
    "remove_availability": {A},
    "set_courtroom_status": {A},
    "generate_schedule": {A},
    "approve_hearing": {J, A},
    "request_changes": {J, A},
    "check_slot": {J, A},
    "override_hearing": {J, A},
    "complete_hearing": {J, A},
    "cancel_hearing": {J, A},
    "scan_conflicts": {A},
    "list_conflicts": {J, A},
    "resolve_conflict": {A},
    # ---- audit & user administration --------------------------------------
    "audit_log": {J, A, S},
    "verify_audit": {A, S},
    "list_users": {S},
    "create_user": {S},
    "set_user_active": {S},
    "unlock_user": {S},
    "reset_password": {S},
    "reset_two_factor": {S},
}


class AccessControlProxy:
    def __init__(self, facade, user):
        self._facade = facade
        self._user_id = user.user_id

    def _current_user(self):
        user = self._facade.users.get(self._user_id)
        if user is None or not user.is_active:
            raise AccessDeniedError("Your account is disabled. Contact the System Administrator.")
        if user.locked_until and user.locked_until > datetime.now().isoformat(timespec="seconds"):
            raise AccessDeniedError("Your account is locked.")
        return user

    @property
    def user(self):
        return self._current_user()

    def can(self, method_name):
        """Used by the templates to show only the buttons a role may use."""
        try:
            role = self._current_user().role
        except AccessDeniedError:
            return False
        return role in PERMISSIONS.get(method_name, set())

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        target = getattr(self._facade, name)          # AttributeError if unknown
        allowed = PERMISSIONS.get(name)               # None -> deny by default

        def guarded(*args, **kwargs):
            user = self._current_user()
            if allowed is None or user.role not in allowed:
                self._facade.publish(user, "ACCESS_DENIED", "Operation", name,
                                     f"{user.role_label} attempted '{name}'")
                raise AccessDeniedError(
                    f"Access denied: a {user.role_label} is not permitted to perform this action.")
            return target(user, *args, **kwargs)

        return guarded
