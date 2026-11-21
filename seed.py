"""
Loads demonstration data.   Usage:   python seed.py --reset

All dates are relative to *today*, so the demo works whenever it is run.
Demo password for every account:  Court@2026!
"""
import argparse
import os
from datetime import date, timedelta

from court.case_management.case_factory import CaseFactory
from court.database import Database
from court.models import Availability, Role
from court.repositories import (AvailabilityRepository, CaseRepository, CourtroomRepository,
                                JudgeRepository, SettingsRepository, UserRepository)
from court.security import FieldCipher, hash_password

DEMO_PASSWORD = "Court@2026!"

USERS = [
    ("clerk.sara", "Sara Ahmed", "sara.ahmed@districtcourt.pk", Role.CLERK),
    ("lawyer.ali", "Adv. Ali Raza", "ali.raza@lawfirm.pk", Role.LAWYER),
    ("lawyer.hina", "Adv. Hina Malik", "hina.malik@lawfirm.pk", Role.LAWYER),
    ("judge.khan", "Justice Imran Khan", "imran.khan@districtcourt.pk", Role.JUDGE),
    ("judge.fatima", "Justice Fatima Noor", "fatima.noor@districtcourt.pk", Role.JUDGE),
    ("judge.raza", "Justice Hamid Raza", "hamid.raza@districtcourt.pk", Role.JUDGE),
    ("admin.nabiha", "Nabiha Nasir", "nabiha.nasir@districtcourt.pk", Role.ADMIN),
    ("sysadmin", "Ayesha Khalid", "ayesha.khalid@districtcourt.pk", Role.SYSADMIN),
]


def seed(db, cipher, today=None):
    today = today or date.today()
    d = lambda days_ago: (today - timedelta(days=days_ago)).isoformat()

    users = UserRepository(db)
    pw = hash_password(DEMO_PASSWORD)
    ids = {u[0]: users.add(u[0], u[1], u[2], u[3], pw) for u in USERS}

    judges = JudgeRepository(db)
    j1 = judges.add("Justice Imran Khan", "Civil & Family Court-I", ids["judge.khan"])
    j2 = judges.add("Justice Fatima Noor", "Sessions Court-II", ids["judge.fatima"])
    j3 = judges.add("Justice Hamid Raza", "Civil Court-III", ids["judge.raza"])

    rooms = CourtroomRepository(db)
    r1, r2, r3 = rooms.add("Courtroom 1"), rooms.add("Courtroom 2"), rooms.add("Courtroom 3")

    # Availability: next 14 days, working days only
    avail = AvailabilityRepository(db)
    for offset in range(1, 15):
        day = today + timedelta(days=offset)
        if day.weekday() >= 5:
            continue
        ds = day.isoformat()
        avail.add(Availability(None, "JUDGE", j1, ds, "09:00", "12:00"))
        avail.add(Availability(None, "JUDGE", j2, ds, "09:00", "13:00"))
        if day.weekday() in (0, 2, 4):          # Justice Raza sits Mon/Wed/Fri
            avail.add(Availability(None, "JUDGE", j3, ds, "10:00", "13:00"))
        for r in (r1, r2):
            avail.add(Availability(None, "COURTROOM", r, ds, "09:00", "16:00"))
        if day.weekday() != 3:                   # Courtroom 3 closed on Thursdays
            avail.add(Availability(None, "COURTROOM", r3, ds, "09:00", "16:00"))

    cases = CaseRepository(db, cipher)
    L1, L2 = ids["lawyer.ali"], ids["lawyer.hina"]
    data = [
        # type,     id,             title,                                     filed, parties,                              judge, lawyer, status,       extra
        ("CIVIL",   "CV-2022-118", "Recovery of Rs. 2.5 million",               1180, "Akram Traders vs Bilal Enterprises",    j1, L1, "VALIDATED", {}),
        ("RENT",    "RN-2023-045", "Ejectment of tenant - Gulberg shop",        900,  "Shahid Mehmood vs Naveed Iqbal",       j3, L2, "VALIDATED", {}),
        ("CRIMINAL","CR-2024-077", "Theft under section 379 PPC",               640,  "State vs Kamran Ali",                  j2, L1, "VALIDATED", {}),
        ("FAMILY",  "FM-2025-019", "Custody of minor children",                 300,  "Sadia Bibi vs Asif Hussain",           j1, L2, "VALIDATED",
            {"vulnerable_party": True, "vulnerability_type": "Minor (under 18)"}),
        ("CIVIL",   "CV-2025-203", "Declaration of title - agricultural land",  250,  "Ghulam Rasool vs Province of Punjab",  j3, L1, "VALIDATED",
            {"vulnerable_party": True, "vulnerability_type": "Elderly (65+)"}),
        ("BAIL",    "BA-2026-031", "Post-arrest bail application",              12,   "Usman Tariq vs State",                 j2, L1, "VALIDATED", {}),
        ("CRIMINAL","CR-2026-012", "Domestic violence complaint",               40,   "State vs Rizwan Ahmed",                j2, L2, "VALIDATED",
            {"is_urgent": True, "urgency_reason": "Protection order requested by victim",
             "vulnerable_party": True, "vulnerability_type": "Victim of violence"}),
        ("CIVIL",   "CV-2023-310", "Specific performance of sale agreement",    780,  "Farooq Ahmed vs Zubair Khan",          j1, L2, "VALIDATED", {}),
        ("RENT",    "RN-2025-090", "Arrears of rent - residential flat",        200,  "Nasreen Akhtar vs Imtiaz Shah",        j3, L1, "VALIDATED", {}),
        ("FAMILY",  "FM-2024-150", "Maintenance allowance for wife",            420,  "Rubina Kausar vs Tahir Mahmood",       j1, L1, "VALIDATED", {}),
        ("CIVIL",   "CV-2026-044", "Permanent injunction - boundary wall",      20,   "Saleem Akhtar vs Javed Iqbal",         j3, L2, "REGISTERED", {}),
        ("CRIMINAL","CR-2026-055", "Cheque dishonour under section 489-F",      15,   "",                                     j2, L1, "REGISTERED", {}),
    ]
    for ctype, cid, title, filed, parties, jid, lid, status, extra in data:
        case = CaseFactory.create(ctype, case_id=cid, case_title=title, filing_date=d(filed),
                                  parties=parties, judge_id=jid, lawyer_id=lid,
                                  case_status=status, **extra)
        cases.add(case)

    SettingsRepository(db).set("priority_strategy", "WEIGHTED")


def main():
    ap = argparse.ArgumentParser(description="Load demo data")
    ap.add_argument("--reset", action="store_true", help="delete the existing database first")
    instance = os.environ.get("COURT_INSTANCE", "instance")
    ap.add_argument("--db", default=os.environ.get("COURT_DB", os.path.join(instance, "court.db")))
    args = ap.parse_args()
    os.makedirs(os.path.dirname(args.db) or ".", exist_ok=True)
    if args.reset and os.path.exists(args.db):
        os.remove(args.db)
    db = Database.get_instance(args.db)
    if db.query_one("SELECT COUNT(*) AS n FROM users")["n"]:
        print("Database already contains data. Use --reset to start again.")
        return
    seed(db, FieldCipher.from_environment(os.path.join(instance, "field.key")))
    print(f"Demo data loaded into {args.db}")
    print(f"Log in with any of these usernames and the password  {DEMO_PASSWORD}")
    for u in USERS:
        print(f"   {u[0]:<14} {Role.LABELS[u[3]]}")


if __name__ == "__main__":
    main()
