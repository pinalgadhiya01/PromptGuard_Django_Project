"""
Explanation engine - turns the detection result into plain English.
"""
from .rules import (BENIGN, PROMPT_INJECTION, JAILBREAK, EXTRACTION, SENSITIVE, ROLE)

EXPLANATIONS = {
    PROMPT_INJECTION: (
        "The submitted text contains an instruction that tries to override or cancel "
        "the instructions the AI application was originally given.",
        "Treat this input as untrusted. Keep user content separate from trusted system "
        "instructions, and never let user text change the application's rules.",
    ),
    JAILBREAK: (
        "The submitted text tries to push the AI into dropping its safety rules, "
        "for example by asking it to bypass restrictions or enter an 'unrestricted' mode.",
        "Add output and input filtering, keep safety rules outside of the user's reach, "
        "and log repeated jailbreak attempts from the same user.",
    ),
    EXTRACTION: (
        "The submitted text tries to make the AI reveal its hidden system prompt or "
        "internal instructions.",
        "Do not put secrets inside the system prompt. Assume it can leak, and add "
        "checks that block responses which repeat the hidden instructions.",
    ),
    SENSITIVE: (
        "The submitted text asks the AI to disclose confidential data such as "
        "passwords, keys, credentials or other users' information.",
        "Never give the AI direct access to secrets. Apply access control on the "
        "server side and mask sensitive values before they reach the model.",
    ),
    ROLE: (
        "The submitted text tries to give the AI a new identity or higher privileges "
        "(for example 'you are now the administrator').",
        "Fix the AI's role on the server side and ignore role changes that come from "
        "user content. Do not grant extra permissions based on what the text claims.",
    ),
}

BENIGN_TEXT = (
    "No known attack patterns were found and the classifier considers this text normal.",
    "No action needed. Continue to treat all user input as untrusted as a general good practice.",
)


def build_explanation(category, level, ml_confidence, matches):
    """
    Returns (explanation, recommendation) as two strings.
    """
    if category == BENIGN:
        reason, rec = BENIGN_TEXT
        return f"Detected issue: None.\nReason: {reason}", rec

    reason, rec = EXPLANATIONS[category]
    lines = [
        f"Detected issue: {category}.",
        f"Reason: {reason}",
        f"Risk level: {level}.",
        f"The ML model was {round(ml_confidence * 100)}% confident about this category.",
    ]

    own = [m for m in matches if m["category"] == category]
    other = [m for m in matches if m["category"] != category]

    if own or other:
        lines.append("Suspicious patterns found:")
        for m in own + other:
            lines.append(f'- "{m["matched_text"]}" -> {m["description"]}')

    return "\n".join(lines), rec
