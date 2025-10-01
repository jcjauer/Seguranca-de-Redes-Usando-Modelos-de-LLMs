from django.test import TestCase, Client, override_settings
from django.urls import reverse
from django.core.files.uploadedfile import SimpleUploadedFile
from django.contrib.auth.models import User
from unittest.mock import patch
from .models import PCAPAnalysis
from .forms import PCAPUploadForm
import tempfile
import os


class PCAPAnalysisModelTest(TestCase):
    """Testes para o modelo PCAPAnalysis"""

    def setUp(self):
        """Configuração inicial dos testes"""
        self.analysis = PCAPAnalysis.objects.create(
            original_filename="test.pcap",
            file_size=1024,
            llm_model="llama3",
            status="pending",
        )

    def test_string_representation(self):
        """Testa a representação string do modelo"""
        expected = "test.pcap - Pendente"
        self.assertEqual(str(self.analysis), expected)

    def test_file_size_mb_property(self):
        """Testa o cálculo do tamanho em MB"""
        self.assertEqual(self.analysis.file_size_mb, 0.0)  # 1024 bytes = 0.0 MB

    def test_is_completed_property(self):
        """Testa se a análise está completa"""
        self.assertFalse(self.analysis.is_completed)

        self.analysis.status = "completed"
        self.assertTrue(self.analysis.is_completed)

    def test_has_anomalies_property(self):
        """Testa detecção de anomalias"""
        self.assertFalse(self.analysis.has_anomalies)

        self.analysis.analysis_result = "Detectada anomalia suspeita no tráfego"
        self.assertTrue(self.analysis.has_anomalies)


class PCAPUploadFormTest(TestCase):
    """Testes para o formulário de upload"""

    def test_valid_form(self):
        """Testa formulário válido"""
        # Simula arquivo PCAP válido
        pcap_content = b"fake pcap content"
        uploaded_file = SimpleUploadedFile(
            "test.pcap", pcap_content, content_type="application/octet-stream"
        )

        # Usar o primeiro modelo disponível no sistema
        from analyzer.utils import get_ollama_models

        available_models = get_ollama_models()
        if available_models:
            model_choice = available_models[0][0]
        else:
            model_choice = "llama3"  # fallback

        form_data = {"llm_model": model_choice}
        form = PCAPUploadForm(form_data, {"pcap_file": uploaded_file})
        self.assertTrue(form.is_valid())

    def test_invalid_file_extension(self):
        """Testa arquivo com extensão inválida"""
        txt_content = b"not a pcap file"
        uploaded_file = SimpleUploadedFile(
            "test.txt", txt_content, content_type="text/plain"
        )

        form_data = {"llm_model": "llama3"}
        form = PCAPUploadForm(form_data, {"pcap_file": uploaded_file})
        self.assertFalse(form.is_valid())
        self.assertIn("pcap_file", form.errors)

    def test_file_too_large(self):
        """Testa arquivo muito grande"""
        # Simula arquivo de 60MB (acima do limite de 50MB)
        large_content = b"x" * (60 * 1024 * 1024)
        uploaded_file = SimpleUploadedFile(
            "large.pcap", large_content, content_type="application/octet-stream"
        )

        form_data = {"llm_model": "llama3"}
        form = PCAPUploadForm(form_data, {"pcap_file": uploaded_file})
        self.assertFalse(form.is_valid())
        self.assertIn("pcap_file", form.errors)


class ViewsTest(TestCase):
    """Testes para as views"""

    def setUp(self):
        """Configuração inicial"""
        self.client = Client()
        self.analysis = PCAPAnalysis.objects.create(
            original_filename="test.pcap",
            file_size=1024,
            llm_model="llama3",
            status="completed",
            packet_count=100,
            analysis_result="Tráfego normal detectado",
        )

    def test_index_view(self):
        """Testa a página inicial"""
        response = self.client.get(reverse("index"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Dashboard")

    def test_index_view_get(self):
        """Testa a página principal (GET)"""
        response = self.client.get(reverse("index"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Dashboard")

    def test_analysis_detail_view(self):
        """Testa a página de detalhes da análise"""
        response = self.client.get(reverse("analysis_detail", args=[self.analysis.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "test.pcap")

    def test_analysis_list_view(self):
        """Testa a página de lista de análises"""
        response = self.client.get(reverse("analysis_list"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "test.pcap")

    def test_analysis_status_api(self):
        """Testa a API de status"""
        response = self.client.get(reverse("analysis_status", args=[self.analysis.id]))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["packet_count"], 100)


class IntegrationTest(TestCase):
    """Testes de integração"""

    @patch("analyzer.views.threading.Thread")
    def test_full_upload_workflow(self, mock_thread):
        """Testa o fluxo completo de upload sem executar threading"""
        # Mock do thread para não executar em background durante teste
        mock_thread.return_value.start.return_value = None

        # Simula upload de arquivo
        pcap_content = b"fake pcap content"
        uploaded_file = SimpleUploadedFile(
            "integration_test.pcap",
            pcap_content,
            content_type="application/octet-stream",
        )

        # Usar o primeiro modelo disponível no sistema
        from analyzer.utils import get_ollama_models

        available_models = get_ollama_models()
        if available_models:
            model_choice = available_models[0][0]
        else:
            model_choice = "llama3"  # fallback

        response = self.client.post(
            reverse("index"), {"pcap_file": uploaded_file, "llm_model": model_choice}
        )

        # Deve redirecionar após upload bem-sucedido
        self.assertEqual(response.status_code, 302)

        # Verifica se a análise foi criada
        analysis = PCAPAnalysis.objects.last()
        self.assertEqual(analysis.original_filename, "integration_test.pcap")
        self.assertEqual(analysis.llm_model, model_choice)
        self.assertEqual(analysis.status, "pending")

        # Verifica se thread foi chamado (pode ser chamado múltiplas vezes devido a get_ollama_models)
        self.assertTrue(mock_thread.called)

    def test_process_pcap_analysis_error_handling(self):
        """Testa o tratamento de erro quando análise não existe"""
        from .views import process_pcap_analysis

        # Tentar processar análise que não existe
        process_pcap_analysis(99999)

        # Não deve haver erro - função deve lidar com isso graciosamente
        # Se chegou até aqui, o teste passou
        self.assertTrue(True)
