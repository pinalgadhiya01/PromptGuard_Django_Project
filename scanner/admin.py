from django.contrib import admin

from .models import Finding, Scan


class FindingInline(admin.TabularInline):
    model = Finding
    extra = 0


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "source_type", "category", "risk_score", "risk_level", "created_at")
    list_filter = ("category", "risk_level", "source_type")
    search_fields = ("input_text", "user__username")
    inlines = [FindingInline]


admin.site.register(Finding)
