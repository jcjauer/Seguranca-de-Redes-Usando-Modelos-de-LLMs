# analyzer/views.py
from django.views.decorators.http import require_POST
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
from . import context_processors


def index(request):
    """Página principal com upload e lista de análises"""
    # Obter status atual explicitamente (evita depender da ordem de execução do context processor durante render)
    try:
        ollama_status = context_processors.ollama_status_processor(request).get(
            "ollama_status"
        )
    except Exception:
        ollama_status = None
    if request.method == "POST":
        form = PCAPUploadForm(
            request.POST, request.FILES, request=request, ollama_status=ollama_status
        )
        if form.is_valid():
            # Criar registro de análise
            analysis = PCAPAnalysis(
                original_filename=request.FILES["pcap_file"].name,
                pcap_file=request.FILES["pcap_file"],
                file_size=request.FILES["pcap_file"].size,
                llm_model=form.cleaned_data["llm_model"],
                llm_host=form.cleaned_data.get("llm_host", None)
                or getattr(settings, "DEFAULT_LLM_HOST", "127.0.0.1"),
                llm_port=form.cleaned_data.get("llm_port", None)
                or getattr(settings, "DEFAULT_LLM_PORT", 11434),
                status="pending",
            )
            analysis.save()

            # Iniciar análise em background
            thread = threading.Thread(
                target=process_pcap_analysis,
                args=(analysis.id, analysis.llm_host, analysis.llm_port),
            )
            thread.daemon = True
            thread.start()

            messages.success(
                request,
                f"Arquivo {analysis.original_filename} carregado com sucesso! Análise iniciada.",
            )
            return redirect("analysis_detail", analysis_id=analysis.id)
    else:
        form = PCAPUploadForm(request=request, ollama_status=ollama_status)

    analyses = PCAPAnalysis.objects.all()[:10]  # Últimas 10 análises
    context = {
        "form": form,
        "available_models": get_available_models(),
        # ollama_status removido: agora fornecido via context processor global
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


def process_pcap_analysis(analysis_id, host=None, port=None):
    """Processa a análise PCAP em background com sistema de precisão avançado"""
    analysis = None
    try:
        analysis = PCAPAnalysis.objects.get(id=analysis_id)
        analysis.status = "processing"
        analysis.save()

        start_time = time.time()

        # Realizar análise avançada (passando host/port se fornecidos)
        result = analyze_pcap_with_llm(
            analysis.pcap_file.path, analysis.llm_model, host=host, port=port
        )

        end_time = time.time()

        # Salvar resultados básicos
        analysis.packet_count = result.get("packet_count", 0)
        analysis.analysis_result = result.get("analysis_text", "")
        analysis.analysis_summary = result.get("summary", "")
        analysis.analysis_duration = round(end_time - start_time, 2)

        # 🎯 NOVOS CAMPOS DE PRECISÃO - Salvar dados avançados
        analysis.malware_score = result.get("malware_score", 0)
        analysis.risk_level = result.get("risk_level", "MÍNIMO")
        analysis.threat_indicators = result.get("threat_indicators", [])
        analysis.network_patterns = result.get("network_patterns", {})
        analysis.malware_signatures = result.get("malware_signatures", {})
        analysis.temporal_analysis = result.get("temporal_analysis", {})
        analysis.threat_intelligence = result.get("threat_intelligence", {})

        analysis.status = "completed"
        analysis.save()

        print(
            f"✅ Análise {analysis_id} concluída com score {analysis.malware_score}/100 ({analysis.risk_level})"
        )

    except Exception as e:
        print(f"❌ Erro na análise {analysis_id}: {str(e)}")
        if analysis:
            analysis.status = "error"
            analysis.error_message = str(e)
            analysis.save()
        else:
            # Log error if analysis object couldn't be retrieved
            import logging

            logger = logging.getLogger("analyzer")
            logger.error(f"Failed to retrieve analysis {analysis_id}: {e}")


@require_POST
def update_ollama_config(request):
    """Atualiza host/port do Ollama; suporta resposta JSON para chamadas AJAX (fetch)."""
    clear = request.POST.get("clear", "") == "1"
    ajax = request.headers.get(
        "x-requested-with"
    ) == "XMLHttpRequest" or "application/json" in request.headers.get("Accept", "")

    if clear:
        request.session.pop("OLLAMA_HOST_OVERRIDE", None)
        request.session.pop("OLLAMA_PORT_OVERRIDE", None)
        if not ajax:
            messages.success(request, "Configuração Ollama restaurada para defaults.")
    else:
        host_input = request.POST.get("ollama_host", "").strip()
        port_input = request.POST.get("ollama_port", "").strip()
        host = host_input
        port = port_input
        if host and ":" in host and not port:
            possible_host, possible_port = host.rsplit(":", 1)
            if possible_port.isdigit():
                host = possible_host
                port = possible_port
        if host:
            request.session["OLLAMA_HOST_OVERRIDE"] = host
        if port:
            try:
                int(port)
            except ValueError:
                if ajax:
                    return JsonResponse(
                        {"status": "error", "error": "Porta inválida"}, status=400
                    )
                messages.error(request, "Porta inválida.")
                return redirect(request.META.get("HTTP_REFERER", "index"))
            request.session["OLLAMA_PORT_OVERRIDE"] = port
        if not ajax:
            messages.success(request, "Configuração Ollama atualizada.")

    # Limpar caches por host/port (pattern) + legacy key
    from django.core.cache import cache

    try:
        # Se armazenamos por chave padrao 'ollama_status::<host>:<port>' podemos invalidar a chave específica
        host = request.session.get("OLLAMA_HOST_OVERRIDE") or getattr(
            settings, "OLLAMA_HOST", "localhost"
        )
        port = request.session.get("OLLAMA_PORT_OVERRIDE") or getattr(
            settings, "OLLAMA_PORT", "11434"
        )
        cache.delete(f"ollama_status::{host}:{port}")
    except Exception:
        pass
    cache.delete("ollama_status_cache_v2")

    # Recalcular status atualizado
    try:
        fresh_status = context_processors.ollama_status_processor(request).get(
            "ollama_status"
        )
    except Exception:
        fresh_status = None

    if ajax:
        # Serializar somente campos necessários
        payload = {
            "status": "ok",
            "config": {
                "host": (
                    fresh_status.get("config", {}).get("host") if fresh_status else None
                ),
                "port": (
                    fresh_status.get("config", {}).get("port") if fresh_status else None
                ),
                "override": (
                    fresh_status.get("config", {}).get("override")
                    if fresh_status
                    else False
                ),
            },
            "ok": fresh_status.get("ok") if fresh_status else False,
            "model_count": fresh_status.get("model_count") if fresh_status else 0,
            "fallback": fresh_status.get("fallback") if fresh_status else "none",
        }
        return JsonResponse(payload)

    return redirect(request.META.get("HTTP_REFERER", "index"))
