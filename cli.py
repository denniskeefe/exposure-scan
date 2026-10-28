"""exposure-scan: automated scan -> analyst review -> 10-page PDF.

  python cli.py scan   --subject subject.json --out run.json [--demo]
  python cli.py review run.json --analyst "Name" [--auto-approve]
  python cli.py report run.json --out report.pdf
"""
import argparse
import sys
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


p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
sub = p.add_subparsers(dest="cmd", required=True)
s = sub.add_parser("scan"); s.add_argument("--subject", required=True); s.add_argument("--out", required=True)
s.add_argument("--demo", action="store_true"); s.set_defaults(fn=cmd_scan)
r = sub.add_parser("review"); r.add_argument("run"); r.add_argument("--analyst", required=True)
r.add_argument("--auto-approve", action="store_true", help="demo/testing only"); r.set_defaults(fn=cmd_review)
o = sub.add_parser("report"); o.add_argument("run"); o.add_argument("--out", required=True); o.set_defaults(fn=cmd_report)
args = p.parse_args()
args.fn(args)
