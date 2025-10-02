# analyzer/models.py
from django.db import models
from django.utils import timezone
import os


def pcap_upload_path(instance, filename):
    """Gera caminho para upload de arquivos PCAP"""
    return f'pcaps/{timezone.now().strftime("%Y/%m/%d")}/{filename}'


class PCAPAnalysis(models.Model):
    """Modelo para armazenar análises de PCAP"""

    # Informações do arquivo
    original_filename = models.CharField(max_length=255)
    pcap_file = models.FileField(upload_to=pcap_upload_path)
    file_size = models.BigIntegerField()

    # Configurações da análise
    llm_model = models.CharField(max_length=100, default="llama3")
    # Optional endpoint override for the LLM service
    llm_host = models.CharField(
        max_length=255, default="127.0.0.1", help_text="Host/IP do serviço LLM")
    llm_port = models.IntegerField(
        default=11434, help_text="Porta do serviço LLM")

    # Resultados da análise
    packet_count = models.IntegerField(null=True, blank=True)
    analysis_result = models.TextField(null=True, blank=True)
    analysis_summary = models.TextField(null=True, blank=True)

    # Metadados
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    analysis_duration = models.FloatField(null=True, blank=True)  # em segundos

    # Status da análise
    STATUS_CHOICES = [
        ("pending", "Pendente"),
        ("processing", "Processando"),
        ("completed", "Concluída"),
        ("error", "Erro"),
    ]
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="pending")
    error_message = models.TextField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Análise PCAP"
        verbose_name_plural = "Análises PCAP"

    def __str__(self):
        return f"{self.original_filename} - {self.get_status_display()}"

    def delete(self, *args, **kwargs):
        """Remove o arquivo físico ao deletar o registro"""
        if self.pcap_file and os.path.isfile(self.pcap_file.path):
            os.remove(self.pcap_file.path)
        super().delete(*args, **kwargs)

    @property
    def file_size_mb(self):
        """Retorna o tamanho do arquivo em MB"""
        return round(self.file_size / (1024 * 1024), 2)

    @property
    def is_completed(self):
        """Verifica se a análise foi concluída"""
        return self.status == "completed"

    @property
    def has_anomalies(self):
        """Verifica se foram detectadas anomalias"""
        if self.analysis_result:
            keywords = [
                "anomalia",
                "suspeito",
                "ataque",
                "malware",
                "scan",
                "ddos",
                "brute force",
            ]
            return any(keyword in self.analysis_result.lower() for keyword in keywords)
        return False
