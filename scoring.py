"""Risk scoring over analyst-approved findings only."""
from models import CATEGORIES, Finding

SEV_WEIGHT = {1: 3, 2: 8, 3: 15, 4: 25, 5: 35}
CAT_WEIGHT = {"breach": 0.4, "broker": 0.3, "social_search": 0.3}
BANDS = [(75, "Critical"), (50, "High"), (25, "Moderate"), (0, "Low")]


def band(score: float) -> str:
    return next(label for floor, label in BANDS if score >= floor)


def score(findings: list[Finding]) -> dict:
    approved = [f for f in findings if f.status == "approved"]
    cats = {c: min(100, sum(SEV_WEIGHT[f.severity] for f in approved if f.category == c))
            for c in CATEGORIES}
    overall = round(sum(cats[c] * CAT_WEIGHT[c] for c in CATEGORIES))
    return {"categories": cats, "overall": overall, "band": band(overall),
            "category_bands": {c: band(v) for c, v in cats.items()}}
