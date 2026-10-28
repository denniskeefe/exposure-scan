"""exposure-scan: automated scan -> analyst review -> 10-page PDF.

  python cli.py run [subject.json] [--demo]      (all steps in one go)
  python cli.py scan   --subject subject.json --out run.json [--demo]
  python cli.py review run.json --analyst "Name" [--auto-approve]
  python cli.py report run.json --out report.pdf
"""
import argparse
import json
import re
import subprocess
import sys
from dataclasses import asdict
from datetime import date

from models import Run, Subject
import review as rv
import report as rp
import scanners as sc


def cmd_scan(a):
    subj = Subject.load(a.subject)
    if not (subj.consent_attested and subj.consent_ref.strip()):
        sys.exit("Refusing to scan: subject must have consent_attested=true and a consent_ref.")
    demo = a.demo
    findings = sc.scan_breaches(subj, demo) + sc.scan_brokers(subj, demo) + sc.scan_social_search(subj, demo)
    notes = ["demo data" if demo else "live scan; broker results are unverified leads"]
    Run(subj, findings, date.today().isoformat(), "demo" if demo else "live", scan_notes=notes).save(a.out)
    print(f"{len(findings)} findings written to {a.out}")


def cmd_review(a):
    run = Run.load(a.run)
    if a.auto_approve:
        rv.auto_approve(run, a.analyst)
    else:
        rv.interactive(run, a.analyst)
    run.save(a.run)
    print("signed off" if run.analyst else "saved; review incomplete")


def cmd_report(a):
    pages = rp.build(Run.load(a.run), a.out)
    print(f"{pages}-page report written to {a.out}")


def ask_list(label):
    return [x.strip() for x in input(f"{label} (comma-separated, blank to skip): ").split(",") if x.strip()]


def prompt_subject():
    print("Enter the subject's details. Only scan yourself or someone who has agreed.\n")
    name = input("Full name: ").strip()
    subj = Subject(full_name=name, emails=ask_list("Emails"), phones=ask_list("Phones"),
                   usernames=ask_list("Usernames"), city=input("City: ").strip(),
                   state=input("State: ").strip())
    if input("Has this person consented to the scan? (yes/no): ").strip().lower() == "yes":
        subj.consent_attested = True
        subj.consent_ref = input("Consent reference (e.g. SELF-2026-10-28): ").strip()
    path = f"subject_{re.sub(r'[^a-z0-9]+', '_', name.lower()).strip('_')}.json"
    open(path, "w").write(json.dumps(asdict(subj), indent=2))
    print(f"Saved details to {path} (reuse it next time: python3 cli.py run {path})\n")
    return path


def cmd_run(a):
    """Scan -> review -> report, stopping cleanly if the review is not finished."""
    subject_path = a.subject or ("sample_subject.json" if a.demo else prompt_subject())
    stem = re.sub(r"\.json$", "", subject_path).replace("subject_", "")
    run_path, pdf_path = f"run_{stem}.json", f"report_{stem}.pdf"
    a.subject, a.out = subject_path, run_path
    cmd_scan(a)
    run = Run.load(run_path)
    if a.auto_approve:
        rv.auto_approve(run, a.analyst)
    else:
        a.analyst = a.analyst or input("Analyst name: ").strip()
        rv.interactive(run, a.analyst)
    run.save(run_path)
    if not run.analyst:
        sys.exit(f"Review not finished. Resume with: python3 cli.py review {run_path} --analyst \"{a.analyst}\"")
    rp.build(run, pdf_path)
    print(f"Report written to {pdf_path}")
    if sys.platform == "darwin":
        subprocess.run(["open", pdf_path])


p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
sub = p.add_subparsers(dest="cmd", required=True)
u = sub.add_parser("run", help="scan, review and build the report in one go")
u.add_argument("subject", nargs="?"); u.add_argument("--demo", action="store_true")
u.add_argument("--analyst"); u.add_argument("--auto-approve", action="store_true", help="demo/testing only")
u.set_defaults(fn=cmd_run)
s = sub.add_parser("scan"); s.add_argument("--subject", required=True); s.add_argument("--out", required=True)
s.add_argument("--demo", action="store_true"); s.set_defaults(fn=cmd_scan)
r = sub.add_parser("review"); r.add_argument("run"); r.add_argument("--analyst", required=True)
r.add_argument("--auto-approve", action="store_true", help="demo/testing only"); r.set_defaults(fn=cmd_review)
o = sub.add_parser("report"); o.add_argument("run"); o.add_argument("--out", required=True); o.set_defaults(fn=cmd_report)
args = p.parse_args()
args.fn(args)
