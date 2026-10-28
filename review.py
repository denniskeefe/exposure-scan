"""Analyst review gate: nothing reaches the report until a human signs off."""
from datetime import datetime, timezone

from models import CATEGORY_LABELS, Run


def pending(run: Run) -> list:
    return [f for f in run.findings if f.status == "pending"]


def auto_approve(run: Run, analyst: str) -> None:
    """Demo/testing only."""
    for f in pending(run):
        f.status = "approved"
    sign_off(run, analyst)


def sign_off(run: Run, analyst: str) -> None:
    if pending(run):
        raise ValueError(f"{len(pending(run))} findings still pending review")
    run.analyst = analyst
    run.reviewed_at = datetime.now(timezone.utc).strftime("%Y-%m-%d")


def interactive(run: Run, analyst: str) -> None:
    todo = pending(run)
    print(f"{len(todo)} findings to review for {run.subject.full_name}\n")
    for i, f in enumerate(todo, 1):
        while True:
            print(f"[{i}/{len(todo)}] {f.id} {CATEGORY_LABELS[f.category]} | {f.source} | severity {f.severity}")
            print(f"  {f.title}\n  {f.detail}\n  evidence: {f.evidence}")
            ans = input("  (a)pprove (r)eject (s)everity 1-5 (n)ote (q)uit-and-save > ").strip().lower()
            if ans == "a":
                f.status = "approved"; break
            if ans == "r":
                f.status = "rejected"
                f.analyst_note = f.analyst_note or input("  reason: ")
                break
            if ans == "s":
                v = input("  new severity: ").strip()
                if v in "12345" and v:
                    f.severity = int(v)
            elif ans == "n":
                f.analyst_note = input("  note: ")
            elif ans == "q":
                return
    sign_off(run, analyst)
