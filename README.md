# exposure_scan

Automated scan plus analyst review that produces a fixed 10-page PDF covering
breach exposure, data broker listings, and social/search exposure.

## Requirements

- Python 3.10+
- `reportlab` (`pip install reportlab`)
- Live mode only:
  - `HIBP_API_KEY` for Have I Been Pwned (breaches)
  - `BRAVE_API_KEY` for Brave Search (social and search exposure)

## Workflow

```bash
# 1. Scan (use --demo for fictional sample data, no keys needed)
python3 cli.py scan --subject sample_subject.json --out run.json --demo

# 2. Analyst review: approve, reject, re-score, or annotate every finding
python3 cli.py review run.json --analyst "Your Name"

# 3. Build the report (blocked until every finding is reviewed and signed off)
python3 cli.py report run.json --out report.pdf
```

`review --auto-approve` approves everything and exists for demos and tests only.

## Subject file

See `sample_subject.json`. The scan refuses to run unless `consent_attested`
is `true` and `consent_ref` is non-empty (for example a signed engagement
form ID). Only scan yourself or people who have authorized it.

## Modules

| File | Role |
| --- | --- |
| `models.py` | `Subject`, `Finding`, `Run` dataclasses and JSON load/save |
| `scanners.py` | Breach, data broker, and social/search scanners plus demo fixtures |
| `review.py` | Analyst review loop and sign-off gate |
| `scoring.py` | Severity weights, per-category and overall score, risk bands |
| `report.py` | 10-page PDF builder (reportlab) |
| `cli.py` | `scan`, `review`, `report` commands |

## Scoring

Only approved findings count. Each finding adds a weight by severity
(1: 3, 2: 8, 3: 15, 4: 25, 5: 35), capped at 100 per category. Overall score is
breach 40%, brokers 30%, social/search 30%. Bands: Low (0-24), Moderate
(25-49), High (50-74), Critical (75+).

## Report pages

1. Cover
2. Executive summary
3. Scope, methodology, limitations
4. Breach exposure
5. Breach analysis
6. Data brokers
7. Social and search exposure
8. Risk register
9. Remediation plan (30/60/90 days)
10. Analyst sign-off and appendix

Each page is fitted into a single page frame, so the report is always exactly
10 pages. If a section has many findings, its text shrinks to fit rather than
adding pages.

## Limitations

- Live data broker checks are not automated. Broker sites block bots and change
  often, so live mode creates one unverified finding per site for the analyst to
  confirm or reject during review.
- Breach data covers publicly reported incidents only; dark web and private
  databases are out of scope.
- Search results are a sample, not a complete inventory.
- Live mode has not been run against the real APIs yet.
