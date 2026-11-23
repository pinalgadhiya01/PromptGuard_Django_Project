"""
Main entry point of the detection engine.

    result = analyze_text("Ignore all previous instructions")

combines: ML prediction + rule matching + risk score + explanation.
"""
from . import classifier, scoring
from .explain import build_explanation
from .rules import BENIGN, find_matches


def analyze_text(text):
    text = (text or "").strip()

    ml_label, ml_conf, ml_probs = classifier.predict(text)
    matches = find_matches(text)

    # decide the final category
    if matches:
        best_rule = max(matches, key=lambda m: m["weight"])
        if ml_label != BENIGN and ml_conf >= 0.5:
            category = ml_label
        else:
            category = best_rule["category"]
    else:
        category = ml_label
        # ML alone is not enough to call something an attack if it is unsure
        if ml_label != BENIGN and ml_conf < 0.45:
            category = BENIGN

    score, level = scoring.calculate_score(ml_label, ml_conf, ml_probs, matches)

    # benign text with a tiny score should stay "Benign"
    if category != BENIGN and not matches and score <= 20:
        category = BENIGN

    explanation, recommendation = build_explanation(category, level, ml_conf, matches)

    return {
        "category": category,
        "risk_score": score,
        "risk_level": level,
        "ml_label": ml_label,
        "ml_confidence": round(ml_conf, 3),
        "matches": matches,
        "explanation": explanation,
        "recommendation": recommendation,
    }
