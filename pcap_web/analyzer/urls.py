# analyzer/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("upload/", views.upload_pcap, name="upload_pcap"),
    path("analysis/<int:analysis_id>/", views.analysis_detail, name="analysis_detail"),
    path(
        "analysis/<int:analysis_id>/status/",
        views.analysis_status,
        name="analysis_status",
    ),
    path(
        "analysis/<int:analysis_id>/delete/",
        views.delete_analysis,
        name="delete_analysis",
    ),
    path("list/", views.analysis_list, name="analysis_list"),
    # API endpoints
    path("api/upload/", views.api_upload_pcap, name="api_upload_pcap"),
]
