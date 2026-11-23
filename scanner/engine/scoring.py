"""
Risk scoring policy for PromptGuard (0-100).

NOTE: these thresholds are this project's own scoring policy,
they are not an industry / universal cybersecurity standard.

    0  - 20   Low
    21 - 40   Medium
    41 - 70   High
    71 - 100  Critical

Score is a mix of:
    * ML model       -> how sure the model is that the text is NOT benign (40 %)
    * Rule patterns  -> severity of the strongest indicator + a bonus
                        for every extra indicator found (60 %)
"""

ML_WEIGHT = 0.4
RULE_WEIGHT = 0.6


def risk_level(score):
    if score <= 20:
        return "Low"
    if score <= 40:
        return "Medium"
    if score <= 70:
        return "High"
    return "Critical"


def rule_score(matches):
    """Strongest indicator counts fully, the others add 15 % of their weight each."""
    if not matches:
        return 0
    weights = sorted((m["weight"] for m in matches), reverse=True)
    total = weights[0] + sum(0.15 * w for w in weights[1:])
    return min(100, total)


def calculate_score(ml_label, ml_confidence, ml_probs, matches):
    p_benign = ml_probs.get("Benign", 0)
    ml_risk = (1 - p_benign) * 100

    r_score = rule_score(matches)
    score = ML_WEIGHT * ml_risk + RULE_WEIGHT * r_score

    # if the rules found something serious, don't let a "benign" ML guess pull the score too low
    if matches and max(m["weight"] for m in matches) >= 70:
        score = max(score, 45)

    score = int(round(min(100, max(0, score))))
    return score, risk_level(score)
