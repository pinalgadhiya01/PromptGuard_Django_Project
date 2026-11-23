"""
Keyword / pattern rules used by the detection engine.

Each rule is (regex, weight, short description).
weight = how severe that indicator is (0-100).
"""
import re

PROMPT_INJECTION = "Prompt Injection"
JAILBREAK = "Jailbreak Attempt"
EXTRACTION = "System Prompt Extraction"
SENSITIVE = "Sensitive Information Extraction"
ROLE = "Role Manipulation"
BENIGN = "Benign"

ATTACK_CATEGORIES = [PROMPT_INJECTION, JAILBREAK, EXTRACTION, SENSITIVE, ROLE]

RULES = {
    PROMPT_INJECTION: [
        (r"\bignore\b.{0,30}\b(previous|prior|above|earlier|original|all)\b.{0,20}\b(instruction|instructions|task|rules|prompt|guidelines)\b",
         85, "tries to make the AI ignore earlier instructions"),
        (r"\bdisregard\b.{0,30}\b(instruction|instructions|rules|prompt|guidelines|task)\b",
         80, "uses 'disregard' to cancel existing instructions"),
        (r"\bforget\b.{0,25}\b(everything|all|what)\b.{0,25}\b(told|said|instructed|before)\b",
         75, "asks the AI to forget what it was told"),
        (r"\boverride\b.{0,25}\b(instruction|instructions|rules|settings|prompt)\b",
         80, "tries to override existing instructions"),
        (r"\b(new|updated)\s+instructions?\s*:",
         55, "introduces 'new instructions' in the middle of the input"),
        (r"\bdo not follow\b.{0,25}\b(instruction|instructions|guidelines|rules)\b",
         70, "tells the AI not to follow its guidelines"),
        (r"\bstop following\b.{0,30}\b(instruction|instructions|rules|guidelines)\b",
         70, "tells the AI to stop following its rules"),
        (r"\bignore\b.{0,25}\b(the user|the original task|your task)\b",
         75, "tries to redirect the AI away from its original task"),
        (r"\bfrom now on\b.{0,40}\b(ignore|only|always|never)\b",
         45, "tries to change the AI's behaviour permanently ('from now on')"),
        (r"\b(end of (the )?(document|text|input))\b.{0,40}\b(now|then)\b",
         40, "fake 'end of document' marker followed by a new command"),
    ],
    JAILBREAK: [
        (r"\b(bypass|circumvent|get around|evade)\b.{0,25}\b(safety|restriction|restrictions|filter|filters|guardrail|guardrails|moderation|policy)\b",
         85, "asks the AI to bypass its safety controls"),
        (r"\bdan\s+mode\b|\bdo anything now\b",
         90, "mentions the well-known 'DAN / Do Anything Now' jailbreak"),
        (r"\bjailbreak(ed|ing)?\b",
         70, "directly mentions a jailbreak"),
        (r"\b(no|without|remove|disable|turn off)\b.{0,20}\b(restriction|restrictions|filters?|censorship|moderation|safeguards?|ethical (guidelines|restrictions)|content polic(y|ies)|safety guidelines)\b",
         75, "asks for the safety filters to be removed or disabled"),
        (r"\bdeveloper mode\b",
         65, "refers to a fake 'developer mode'"),
        (r"\bunfiltered\b|\buncensored\b|\bunrestricted\b",
         55, "asks for an unfiltered / unrestricted answer"),
        (r"\bnot bound by\b.{0,20}\b(rules|guidelines|restrictions|policies)\b",
         70, "says the AI is not bound by its rules"),
    ],
    EXTRACTION: [
        (r"\b(reveal|show|print|display|output|leak|repeat|tell me|give me|write out|reproduce|copy)\b.{0,40}\b(system prompt|system message|hidden prompt|initial prompt|initial instructions|hidden instructions|secret instructions|internal instructions|original instructions|developer message|prompt template|hidden rules)\b",
         85, "asks the AI to reveal its hidden system prompt / instructions"),
        (r"\bwhat (is|are|were)\b.{0,30}\b(your|the)\b.{0,15}\b(system prompt|instructions|rules)\b",
         50, "asks what the AI's hidden instructions are"),
        (r"\brepeat\b.{0,20}\b(everything|all|the text)\b.{0,20}\b(above|before)\b",
         70, "asks the AI to repeat everything above (common extraction trick)"),
        (r"\bword for word\b|\bverbatim\b",
         35, "asks for exact word-for-word output"),
        (r"\bsystem prompt\b",
         40, "mentions the 'system prompt'"),
    ],
    SENSITIVE: [
        (r"\b(password|passwords|passcode)\b",
         45, "asks about passwords"),
        (r"\b(api[\s_-]?keys?|secret keys?|access tokens?|private keys?|secret token)\b",
         70, "asks for API keys / tokens / private keys"),
        (r"\b(credit card|debit card|cvv|social security|ssn|aadhaar|bank account)\b",
         75, "asks for financial / identity numbers"),
        (r"\b(database credentials|connection string|login credentials|credentials)\b",
         70, "asks for credentials"),
        (r"\b(confidential|private|personal)\b.{0,25}\b(data|information|records|details)\b",
         50, "asks for confidential or personal data"),
        (r"\b(disclose|leak|expose|dump|send me)\b.{0,30}\b(confidential|secret|private|passwords?|data|records)\b",
         70, "asks the AI to disclose or leak private data"),
        (r"\b(other|all)\s+users?'?s?\b.{0,30}\b(email|emails|data|history|details|passwords?)\b",
         60, "asks for other users' data"),
    ],
    ROLE: [
        (r"\byou are now\b",
         55, "tries to assign the AI a new identity ('you are now...')"),
        (r"\bfrom now on you are\b",
         70, "permanently re-assigns the AI's role"),
        (r"\b(pretend|act|behave|roleplay|role-play)\b.{0,15}\b(to be|as|like)\b.{0,40}\b(admin|administrator|root|developer|system|hacker|evil|owner|creator|unrestricted|no restrictions)\b",
         75, "asks the AI to act as a privileged or malicious role"),
        (r"\b(i am|i'm)\b.{0,15}\b(your|the)\b.{0,10}\b(creator|developer|owner|admin|administrator|master)\b",
         60, "claims to be the AI's creator / admin to gain trust"),
        (r"\b(admin|administrator|root)\b.{0,20}\b(rights|access|privileges|mode)\b",
         55, "asks for admin / root privileges"),
        (r"\b(assume|take on)\b.{0,15}\b(the role|the persona)\b",
         45, "asks the AI to assume a different persona"),
        (r"\bswitch roles\b|\bchange your (identity|role)\b",
         55, "asks the AI to change its role or identity"),
    ],
}

# compile once when the module is imported
COMPILED = {
    cat: [(re.compile(p, re.IGNORECASE | re.DOTALL), w, d) for p, w, d in rules]
    for cat, rules in RULES.items()
}


def find_matches(text):
    """Return a list of dicts for every rule that matches the text."""
    found = []
    for category, rules in COMPILED.items():
        for regex, weight, desc in rules:
            m = regex.search(text)
            if m:
                found.append({
                    "category": category,
                    "weight": weight,
                    "description": desc,
                    "matched_text": m.group(0)[:120],
                })
    return found
