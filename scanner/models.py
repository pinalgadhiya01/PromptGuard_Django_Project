from django.contrib.auth.models import User
from django.db import models


class Scan(models.Model):
    """One security analysis (either a typed prompt or an uploaded document)."""

    SOURCE_CHOICES = [
        ("prompt", "Prompt"),
        ("document", "Document"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="scans")
    source_type = models.CharField(max_length=10, choices=SOURCE_CHOICES, default="prompt")
    file_name = models.CharField(max_length=255, blank=True)
    input_text = models.TextField()

    category = models.CharField(max_length=50)
    risk_score = models.PositiveSmallIntegerField()
    risk_level = models.CharField(max_length=10)
    ml_confidence = models.FloatField(default=0)

    matched_patterns = models.JSONField(default=list, blank=True)
    explanation = models.TextField(blank=True)
    recommendation = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user.username} - {self.category} ({self.risk_score})"

    @property
    def short_text(self):
        t = self.input_text.replace("\n", " ")
        return t[:80] + "..." if len(t) > 80 else t

    @property
    def is_safe(self):
        return self.category == "Benign"


class Finding(models.Model):
    """A suspicious piece of text found inside an uploaded document."""

    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="findings")
    snippet = models.TextField()
    category = models.CharField(max_length=50)
    risk_score = models.PositiveSmallIntegerField()
    risk_level = models.CharField(max_length=10)
    reason = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["-risk_score"]

    def __str__(self):
        return f"{self.category} in scan {self.scan_id}"
