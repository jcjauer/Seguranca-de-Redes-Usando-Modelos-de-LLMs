# analyzer/forms.py
from django import forms
from .models import PCAPAnalysis
from .utils import get_ollama_models   # 🔹 agora importado daqui


class PCAPUploadForm(forms.Form):
    """Formulário para upload de arquivos PCAP"""

    pcap_file = forms.FileField(
        label="Arquivo PCAP",
        help_text="Selecione um arquivo .pcap ou .pcapng para análise",
        widget=forms.FileInput(
            attrs={
                "class": "form-control",
                "accept": ".pcap,.pcapng",
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

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        models = get_ollama_models()
        if models:
            self.fields['llm_model'].choices = models
            # primeiro modelo como padrão
            self.fields['llm_model'].initial = models[0][0]
        else:
            self.fields['llm_model'].choices = [
                ("", "Nenhum modelo encontrado")]

    def clean_pcap_file(self):
        """Validação do arquivo PCAP"""
        file = self.cleaned_data["pcap_file"]

        # Verificar extensão
        valid_extensions = [".pcap", ".pcapng", ".cap"]
        if not any(file.name.lower().endswith(ext) for ext in valid_extensions):
            raise forms.ValidationError(
                "Arquivo deve ter extensão .pcap, .pcapng ou .cap"
            )

        # Verificar tamanho (máximo 50MB)
        max_size = 50 * 1024 * 1024  # 50MB
        if file.size > max_size:
            raise forms.ValidationError(
                f"Arquivo muito grande. Tamanho máximo: 50MB. "
                f"Tamanho atual: {file.size / (1024*1024):.1f}MB"
            )

        # Verificar se não está vazio
        if file.size == 0:
            raise forms.ValidationError("Arquivo está vazio")

        return file

    def clean_llm_model(self):
        """Validação do modelo LLM"""
        model = self.cleaned_data["llm_model"]
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
