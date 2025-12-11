# analyzer/forms.py
from django import forms
from .models import PCAPAnalysis
from .utils import get_ollama_models   # 🔹 agora importado daqui
from django.conf import settings


class PCAPUploadForm(forms.Form):
    """Formulário para upload de arquivos PCAP"""

    pcap_file = forms.FileField(
        label="Arquivo PCAP/CSV",
        help_text="Selecione um arquivo .pcap, .pcapng ou .csv para análise",
        widget=forms.FileInput(
            attrs={
                "class": "form-control",
                "accept": ".pcap,.pcapng,.csv",
                "id": "pcap-file-input",
            }
        ),
    )

    llm_model = forms.ChoiceField(
        label="Modelo LLM",
        choices=[],  # será preenchido no __init__
        widget=forms.Select(
            attrs={"class": "form-control", "id": "model-select"}),
    )

    llm_host = forms.CharField(
        label="Host LLM",
        required=False,
        widget=forms.TextInput(
            attrs={"class": "form-control", "placeholder": "127.0.0.1"}),
    )

    llm_port = forms.IntegerField(
        label="Porta LLM",
        required=False,
        initial=getattr(settings, 'DEFAULT_LLM_PORT', 11434),
        widget=forms.NumberInput(
            attrs={"class": "form-control", "placeholder": "11434"}),
    )

    analysis_mode = forms.ChoiceField(
        label="Modo de Análise",
        required=False,
        choices=[
            ("full", "🔬 Completo (YARA + LLM + Heurísticas) - Recomendado"),
            ("llm_heuristics", "🧠 LLM + Heurísticas (sem YARA)"),
            ("llm_yara", "🤖 LLM + YARA (sem detecções heurísticas)"),
            ("llm_only", "💬 Apenas LLM (análise básica de pacotes)"),
            ("yara_only", "🔍 Apenas YARA (sem análise LLM)"),
        ],
        initial="full",
        help_text="Escolha o nível de análise. Use modos simplificados para testar componentes individualmente.",
        widget=forms.Select(
            attrs={"class": "form-control", "id": "analysis-mode-select"}),
    )

    def __init__(self, *args, request=None, ollama_status=None, **kwargs):
        """Permite passar request para usar overrides de sessão no host/port e status atual.

        Se houver override de host/port e o status estiver offline (falha HTTP sem fallback), não exibimos modelos antigos.
        """
        super().__init__(*args, **kwargs)
        # Determinar se devemos listar modelos
        offline_override = False
        if ollama_status:
            cfg = ollama_status.get('config') or {}
            if cfg.get('override') and not ollama_status.get('ok') and ollama_status.get('fallback') == 'none':
                offline_override = True

        if offline_override:
            self.fields['llm_model'].choices = [("", "Ollama offline (override)")]
            self.fields['llm_model'].widget.attrs['disabled'] = 'disabled'
            self.fields['llm_model'].initial = ""
        else:
            models = get_ollama_models()
            if models:
                self.fields['llm_model'].choices = models
                self.fields['llm_model'].initial = models[0][0]
            else:
                self.fields['llm_model'].choices = [("", "Nenhum modelo encontrado")]
        # determine host/port defaults with session override precedence
        session_host = None
        session_port = None
        if request is not None and hasattr(request, 'session'):
            session_host = request.session.get('OLLAMA_HOST_OVERRIDE')
            session_port = request.session.get('OLLAMA_PORT_OVERRIDE')
        default_host = getattr(settings, 'DEFAULT_LLM_HOST', '127.0.0.1')
        default_port = getattr(settings, 'DEFAULT_LLM_PORT', 11434)
        self.fields['llm_host'].initial = session_host or default_host
        self.fields['llm_port'].initial = session_port or default_port

    def clean_pcap_file(self):
        """Validação do arquivo PCAP/CSV"""
        file = self.cleaned_data["pcap_file"]

        # Verificar extensão
        valid_extensions = [".pcap", ".pcapng", ".cap", ".csv"]
        if not any(file.name.lower().endswith(ext) for ext in valid_extensions):
            raise forms.ValidationError(
                "Arquivo deve ter extensão .pcap, .pcapng, .cap ou .csv"
            )

        # Verificar tamanho (máximo 50MB para PCAP, 100MB para CSV)
        is_csv = file.name.lower().endswith('.csv')
        max_size = 100 * 1024 * 1024 if is_csv else 50 * 1024 * 1024  # 100MB CSV, 50MB PCAP
        if file.size > max_size:
            raise forms.ValidationError(
                f"Arquivo muito grande. Tamanho máximo: {max_size/(1024*1024):.0f}MB. "
                f"Tamanho atual: {file.size / (1024*1024):.1f}MB"
            )

        # Verificar se não está vazio
        if file.size == 0:
            raise forms.ValidationError("Arquivo está vazio")

        return file

    def clean_llm_model(self):
        """Validação do modelo LLM"""
        model = self.cleaned_data.get("llm_model")
        # Se campo foi desabilitado (offline override), permitir vazio
        if self.fields['llm_model'].widget.attrs.get('disabled'):
            return model
        valid_models = [m[0] for m in get_ollama_models()]
        if model not in valid_models:
            raise forms.ValidationError(
                "Modelo LLM inválido ou não disponível no Ollama")
        return model


class AnalysisFilterForm(forms.Form):
    """Formulário para filtrar análises"""

    STATUS_CHOICES = [
        ("", "Todos os status"),
        ("pending", "Pendente"),
        ("processing", "Processando"),
        ("completed", "Concluída"),
        ("error", "Erro"),
    ]

    status = forms.ChoiceField(
        choices=STATUS_CHOICES,
        required=False,
        widget=forms.Select(attrs={"class": "form-control"}),
    )

    model = forms.ChoiceField(
        choices=[("", "Todos os modelos")] + get_ollama_models(),
        required=False,
        widget=forms.Select(attrs={"class": "form-control"}),
    )

    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(
            attrs={"class": "form-control", "type": "date"}),
    )

    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(
            attrs={"class": "form-control", "type": "date"}),
    )
