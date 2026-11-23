from django.urls import path

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("scan/prompt/", views.scan_prompt, name="scan_prompt"),
    path("scan/document/", views.scan_document_view, name="scan_document"),
    path("scan/<int:pk>/", views.scan_detail, name="scan_detail"),
    path("scan/<int:pk>/report/", views.download_report, name="download_report"),
    path("scan/<int:pk>/delete/", views.delete_scan, name="delete_scan"),
    path("history/", views.history, name="history"),
]
