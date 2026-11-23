from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Count
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from .engine.analyzer import analyze_text
from .engine.documents import extract_text, scan_document
from .forms import DocumentScanForm, PromptScanForm
from .models import Finding, Scan
from .report import build_report

LEVELS = ["Low", "Medium", "High", "Critical"]


def home(request):
    return render(request, "scanner/home.html")


@login_required
def scan_prompt(request):
    if request.method == "POST":
        form = PromptScanForm(request.POST)
        if form.is_valid():
            text = form.cleaned_data["prompt"]
            result = analyze_text(text)

            scan = Scan.objects.create(
                user=request.user,
                source_type="prompt",
                input_text=text,
                category=result["category"],
                risk_score=result["risk_score"],
                risk_level=result["risk_level"],
                ml_confidence=result["ml_confidence"],
                matched_patterns=result["matches"],
                explanation=result["explanation"],
                recommendation=result["recommendation"],
            )
            return redirect("scan_detail", pk=scan.pk)
    else:
        form = PromptScanForm()

    return render(request, "scanner/scan_prompt.html", {"form": form})


@login_required
def scan_document_view(request):
    if request.method == "POST":
        form = DocumentScanForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded = form.cleaned_data["document"]
            try:
                text = extract_text(uploaded)
            except Exception:
                messages.error(request, "Could not read that file. Is it a valid PDF/TXT?")
                return render(request, "scanner/scan_document.html", {"form": form})

            if not text.strip():
                messages.error(request, "No readable text was found in the file.")
                return render(request, "scanner/scan_document.html", {"form": form})

            overall, findings = scan_document(text)

            scan = Scan.objects.create(
                user=request.user,
                source_type="document",
                file_name=uploaded.name[:255],
                input_text=text[:5000],
                category=overall["category"],
                risk_score=overall["risk_score"],
                risk_level=overall["risk_level"],
                ml_confidence=overall["ml_confidence"],
                matched_patterns=overall["matches"],
                explanation=overall["explanation"],
                recommendation=overall["recommendation"],
            )
            for f in findings:
                Finding.objects.create(scan=scan, **f)

            return redirect("scan_detail", pk=scan.pk)
    else:
        form = DocumentScanForm()

    return render(request, "scanner/scan_document.html", {"form": form})


@login_required
def scan_detail(request, pk):
    # only the owner can open their own scan
    scan = get_object_or_404(Scan, pk=pk, user=request.user)
    return render(request, "scanner/scan_detail.html", {"scan": scan, "findings": scan.findings.all()})


@login_required
def history(request):
    scans = Scan.objects.filter(user=request.user)

    q = request.GET.get("q", "").strip()
    level = request.GET.get("level", "")
    if q:
        scans = scans.filter(input_text__icontains=q)
    if level in LEVELS:
        scans = scans.filter(risk_level=level)

    page = Paginator(scans, 10).get_page(request.GET.get("page"))
    return render(request, "scanner/history.html", {
        "page": page, "q": q, "level": level, "levels": LEVELS,
    })


@login_required
@require_POST
def delete_scan(request, pk):
    scan = get_object_or_404(Scan, pk=pk, user=request.user)
    scan.delete()
    messages.success(request, "Scan deleted.")
    return redirect("history")


@login_required
def dashboard(request):
    scans = Scan.objects.filter(user=request.user)
    total = scans.count()

    safe = scans.filter(category="Benign").count()
    suspicious = total - safe
    critical = scans.filter(risk_level="Critical").count()

    # attack categories (ignore benign)
    cat_rows = (
        scans.exclude(category="Benign")
        .values("category").annotate(n=Count("id")).order_by("-n")
    )
    max_cat = cat_rows[0]["n"] if cat_rows else 1
    categories = [
        {"name": r["category"], "count": r["n"], "percent": round(r["n"] / max_cat * 100)}
        for r in cat_rows
    ]

    # risk distribution
    level_counts = {lvl: scans.filter(risk_level=lvl).count() for lvl in LEVELS}
    distribution = []
    for lvl in LEVELS:
        pct = round(level_counts[lvl] / total * 100) if total else 0
        distribution.append({"level": lvl, "count": level_counts[lvl], "percent": pct})

    # conic-gradient for the donut chart (pure css, no internet needed)
    colors = {"Low": "#2e9e5b", "Medium": "#f2b01e", "High": "#ee7d24", "Critical": "#d93a3a"}
    stops, start = [], 0
    for d in distribution:
        if total and d["count"]:
            end = start + d["count"] / total * 100
            stops.append(f"{colors[d['level']]} {start:.2f}% {end:.2f}%")
            start = end
    donut = ", ".join(stops) if stops else "#2a3550 0% 100%"

    return render(request, "scanner/dashboard.html", {
        "total": total, "safe": safe, "suspicious": suspicious, "critical": critical,
        "categories": categories, "distribution": distribution, "donut": donut,
        "recent": scans[:6],
    })


@login_required
def download_report(request, pk):
    scan = get_object_or_404(Scan, pk=pk, user=request.user)
    pdf = build_report(scan)
    response = HttpResponse(pdf, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="promptguard_report_{scan.pk}.pdf"'
    return response
