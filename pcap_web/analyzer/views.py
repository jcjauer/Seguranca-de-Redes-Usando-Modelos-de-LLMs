# analyzer/views.py
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.core.files.storage import default_storage
from django.conf import settings
import json
import os
import time
import threading

from .models import PCAPAnalysis
from .forms import PCAPUploadForm
from .pcap_analyzer import analyze_pcap_with_llm, get_available_models


def index(request):
    """Página principal com upload e lista de análises"""
    if request.method == "POST":
        form = PCAPUploadForm(request.POST, request.FILES)
        if form.is_valid():
            # Criar registro de análise
            analysis = PCAPAnalysis(
                original_filename=request.FILES["pcap_file"].name,
                pcap_file=request.FILES["pcap_file"],
                file_size=request.FILES["pcap_file"].size,
                llm_model=form.cleaned_data["llm_model"],
                status="pending",
            )
            analysis.save()

            # Iniciar análise em background
            thread = threading.Thread(target=process_pcap_analysis, args=(analysis.id,))
            thread.daemon = True
            thread.start()

            messages.success(
                request,
                f"Arquivo {analysis.original_filename} carregado com sucesso! Análise iniciada.",
            )
            return redirect("analysis_detail", analysis_id=analysis.id)
    else:
        form = PCAPUploadForm()

    analyses = PCAPAnalysis.objects.all()[:10]  # Últimas 10 análises
    context = {
        "form": form,
        "available_models": get_available_models(),
        "analyses": analyses,
        "total_analyses": PCAPAnalysis.objects.count(),
        "completed_analyses": PCAPAnalysis.objects.filter(status="completed").count(),
        "pending_analyses": PCAPAnalysis.objects.filter(status="pending").count(),
    }
    return render(request, "analyzer/index.html", context)


def analysis_detail(request, analysis_id):
    """Detalhes de uma análise específica"""
    analysis = get_object_or_404(PCAPAnalysis, id=analysis_id)
    context = {
        "analysis": analysis,
    }
    return render(request, "analyzer/detail.html", context)


def analysis_list(request):
    """Lista todas as análises"""
    analyses = PCAPAnalysis.objects.all()
    context = {
        "analyses": analyses,
    }
    return render(request, "analyzer/list.html", context)


@require_http_methods(["GET"])
def analysis_status(request, analysis_id):
    """API endpoint para verificar status da análise"""
    analysis = get_object_or_404(PCAPAnalysis, id=analysis_id)

    data = {
        "id": analysis.id,
        "status": analysis.status,
        "packet_count": analysis.packet_count,
        "analysis_duration": analysis.analysis_duration,
        "has_result": bool(analysis.analysis_result),
        "error_message": analysis.error_message,
    }

    return JsonResponse(data)


@require_http_methods(["POST"])
def delete_analysis(request, analysis_id):
    """Deletar uma análise"""
    analysis = get_object_or_404(PCAPAnalysis, id=analysis_id)
    filename = analysis.original_filename
    analysis.delete()
    messages.success(request, f"Análise de {filename} deletada com sucesso.")
    return redirect("index")


def process_pcap_analysis(analysis_id):
    """Processa a análise PCAP em background"""
    analysis = None
    try:
        analysis = PCAPAnalysis.objects.get(id=analysis_id)
        analysis.status = "processing"
        analysis.save()

        start_time = time.time()

        # Realizar análise
        result = analyze_pcap_with_llm(analysis.pcap_file.path, analysis.llm_model)

        end_time = time.time()

        # Salvar resultados
        analysis.packet_count = result.get("packet_count", 0)
        analysis.analysis_result = result.get("analysis_text", "")
        analysis.analysis_summary = result.get("summary", "")
        analysis.analysis_duration = round(end_time - start_time, 2)
        analysis.status = "completed"
        analysis.save()

    except Exception as e:
        if analysis:
            analysis.status = "error"
            analysis.error_message = str(e)
            analysis.save()
        else:
            # Log error if analysis object couldn't be retrieved
            import logging

            logger = logging.getLogger("analyzer")
            logger.error(f"Failed to retrieve analysis {analysis_id}: {e}")
