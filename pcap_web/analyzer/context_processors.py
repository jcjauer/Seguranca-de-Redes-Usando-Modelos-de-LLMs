# analyzer/context_processors.py
from django.core.cache import cache
from django.conf import settings
import os
import requests

try:
    import ollama  # Cliente Python opcional
except ImportError:  # Se não instalado, seguimos sem ele
    ollama = None

try:
    from .utils import get_ollama_models as get_ollama_models_subprocess
except Exception:
    # Fallback defensivo caso utils não esteja acessível
    def get_ollama_models_subprocess():
        return []


def _normalize_models_list(raw_models):
    """Normaliza a lista de modelos em uma lista simples de nomes."""
    normalized = []
    for m in raw_models or []:
        if isinstance(m, dict):
            name = m.get('name') or m.get('model') or m.get('id')
            if name:
                normalized.append(name)
        else:
            normalized.append(str(m))
    return normalized


def _fetch_http_models(base_url: str, timeout: float = 1.5):
    """Tenta obter modelos via endpoint HTTP /api/tags do Ollama."""
    url = base_url.rstrip('/') + '/api/tags'
    try:
        resp = requests.get(url, timeout=timeout)
        if not resp.ok:
            return {'ok': False, 'error': f'HTTP {resp.status_code}'}
        payload = resp.json() if resp.content else {}
        raw_models = payload.get('models', [])
        models = _normalize_models_list(raw_models)
        return {'ok': True, 'models': len(models), 'raw': models}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def _fetch_python_client_models():
    """Fallback usando cliente Python ollama (se instalado)."""
    if not ollama:
        return {'ok': False, 'error': 'python_client_not_available'}
    try:
        resp = ollama.list()
        if isinstance(resp, dict) and 'models' in resp:
            raw_models = resp['models'] or []
        elif isinstance(resp, list):
            raw_models = resp
        else:
            raw_models = []
        models = _normalize_models_list(raw_models)
        if not models:
            # tentar subprocess se vazio
            sub = get_ollama_models_subprocess()
            return {'ok': True, 'models': len(sub), 'raw': sub}
        return {'ok': True, 'models': len(models), 'raw': models}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def _fetch_subprocess_models():
    """Último fallback: execução via subprocess utilitário customizado."""
    try:
        models = get_ollama_models_subprocess() or []
        return {'ok': True, 'models': len(models), 'raw': models}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def ollama_status_processor(request):
    """Injeta `ollama_status` em todos os templates com múltiplos fallbacks.

    Mudanças:
        * Cache agora é segmentado por host:port para não reutilizar estado anterior em overrides.
        * Se há override de sessão e a tentativa HTTP falhar, NÃO cai para outros fallbacks (mostra offline real daquele host).
        * Quando override está ativo, o cache é evitado (ou TTL mínimo) para refletir mudanças imediatas.

    Ordem de tentativa padrão (sem override):
        1. HTTP -> /api/tags
        2. Cliente Python
        3. Subprocess
    """

    # Resolver host/port/base_url (com overrides de sessão tendo maior prioridade)
    session_host = getattr(request, 'session', {}).get('OLLAMA_HOST_OVERRIDE') if hasattr(request, 'session') else None
    session_port = getattr(request, 'session', {}).get('OLLAMA_PORT_OVERRIDE') if hasattr(request, 'session') else None

    host = session_host or getattr(settings, 'OLLAMA_HOST', None) or os.environ.get('OLLAMA_HOST', 'localhost')
    port = session_port or getattr(settings, 'OLLAMA_PORT', None) or os.environ.get('OLLAMA_PORT', '11434')

    # Se por alguma versão anterior ficou salvo 'host:port' em host override, corrigir aqui
    if host and ':' in host:
        possible_host, possible_port = host.rsplit(':', 1)
        if possible_port.isdigit():
            host = possible_host
            # só sobrescreve port se não há override de port separado
            if not session_port:
                port = possible_port
                if hasattr(request, 'session'):
                    request.session['OLLAMA_HOST_OVERRIDE'] = host
                    request.session['OLLAMA_PORT_OVERRIDE'] = port
    base_url = (
        getattr(settings, 'OLLAMA_BASE_URL', None)
        or os.environ.get('OLLAMA_BASE_URL')
        or f'http://{host}:{port}'
    )

    # Define cache key específica por host:port
    hostport_key = f"{host}:{port}"
    base_cache_key = f"ollama_status::{hostport_key}"
    use_cache = True
    # Se override ativo, queremos estado mais imediato (desliga cache para refletir mudanças ou usa TTL curtíssimo)
    override_active = bool(session_host or session_port)
    if override_active:
        use_cache = False

    if use_cache:
        cached = cache.get(base_cache_key)
        if cached is not None:
            return {'ollama_status': cached}

    # 1) HTTP direto no host solicitado
    status_data = _fetch_http_models(base_url)
    if not status_data.get('ok'):
        http_error = status_data.get('error')
        if override_active:
            # Não mascarar erro com fallback: mostrar offline verdadeiro
            status_data = {
                'ok': False,
                'error': http_error or 'unreachable',
                'fallback': 'none',
            }
        else:
            # 2) Cliente Python
            py_status = _fetch_python_client_models()
            if py_status.get('ok'):
                status_data = py_status
                status_data['fallback'] = 'python_client'
                status_data['http_error'] = http_error
            else:
                # 3) Subprocess
                sub_status = _fetch_subprocess_models()
                if sub_status.get('ok'):
                    status_data = sub_status
                    status_data['fallback'] = 'subprocess'
                    status_data['http_error'] = http_error
                    status_data['python_error'] = py_status.get('error')
                else:
                    status_data = {
                        'ok': False,
                        'error': 'all_methods_failed',
                        'http_error': http_error,
                        'python_error': py_status.get('error'),
                        'subprocess_error': sub_status.get('error'),
                        'fallback': 'none'
                    }
    else:
        status_data['fallback'] = 'http'

    # Adicionar infos de origem para UI opcional
    status_data['config'] = {
        'host': host,
        'port': port,
        'display': f"{host}:{port}",
        'override': bool(session_host or session_port),
        'source': 'session' if (session_host or session_port) else 'settings/env'
    }

    # Cache somente quando não há override (estado estável). TTL 30s.
    if use_cache:
        cache.set(base_cache_key, status_data, 30)
    return {'ollama_status': status_data}
