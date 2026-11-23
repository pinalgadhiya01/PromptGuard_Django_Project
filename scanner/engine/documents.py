"""
Document scanner - extracts text from PDF / TXT files and checks every
sentence for hidden instructions (indirect prompt injection).
"""
import re

from pypdf import PdfReader

from .analyzer import analyze_text
from .rules import BENIGN

MAX_PDF_PAGES = 30
MAX_CHARS = 20000  # we only scan the first 20k characters


def extract_text(uploaded_file):
    """Reads text out of an uploaded .pdf or .txt file."""
    name = uploaded_file.name.lower()

    if name.endswith(".txt"):
        raw = uploaded_file.read()
        return raw.decode("utf-8", errors="ignore")[:MAX_CHARS]

    if name.endswith(".pdf"):
        reader = PdfReader(uploaded_file)
        pieces = []
        for i, page in enumerate(reader.pages):
            if i >= MAX_PDF_PAGES:
                break
            pieces.append(page.extract_text() or "")
        return "\n".join(pieces)[:MAX_CHARS]

    raise ValueError("Only .pdf and .txt files are supported.")


def split_into_chunks(text):
    """Split the text into sentences / lines so each one can be checked."""
    parts = re.split(r"(?<=[.!?])\s+|\n+", text)
    return [p.strip() for p in parts if len(p.strip()) > 8]


def scan_document(text):
    """
    Analyses each chunk of the document.
    Returns (overall_result, findings)
    findings = list of flagged chunks (category, score, snippet, explanation)
    """
    findings = []
    for chunk in split_into_chunks(text):
        result = analyze_text(chunk)
        if result["category"] != BENIGN and result["risk_score"] > 20:
            findings.append({
                "snippet": chunk[:300],
                "category": result["category"],
                "risk_score": result["risk_score"],
                "risk_level": result["risk_level"],
                "reason": result["matches"][0]["description"] if result["matches"] else "flagged by the ML model",
            })

    # also run the whole text once, to catch attacks split across lines
    overall = analyze_text(text[:3000])

    if findings:
        top = max(findings, key=lambda f: f["risk_score"])
        if top["risk_score"] >= overall["risk_score"]:
            # use the worst chunk as the overall result
            overall = analyze_text(top["snippet"])

    return overall, findings
