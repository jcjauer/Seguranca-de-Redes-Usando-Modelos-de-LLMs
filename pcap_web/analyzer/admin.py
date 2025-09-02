from django.contrib import admin
from .models import PCAPAnalysis


@admin.register(PCAPAnalysis)
class PCAPAnalysisAdmin(admin.ModelAdmin):
    """Configuração do admin para PCAPAnalysis"""

    list_display = [
        "original_filename",
        "status",
        "llm_model",
        "packet_count",
        "file_size_mb",
        "created_at",
        "analysis_duration",
    ]

    list_filter = ["status", "llm_model", "created_at"]

    search_fields = ["original_filename", "analysis_summary"]

    readonly_fields = ["created_at", "updated_at", "file_size_mb", "analysis_duration"]

    list_per_page = 20

    fieldsets = (
        (
            "Arquivo",
            {"fields": ("original_filename", "pcap_file", "file_size", "file_size_mb")},
        ),
        ("Configuração", {"fields": ("llm_model",)}),
        (
            "Resultados",
            {
                "fields": (
                    "status",
                    "packet_count",
                    "analysis_result",
                    "analysis_summary",
                    "error_message",
                )
            },
        ),
        (
            "Metadados",
            {
                "fields": ("created_at", "updated_at", "analysis_duration"),
                "classes": ("collapse",),
            },
        ),
    )
