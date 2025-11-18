"""
Script de teste para verificar se o processamento está funcionando
"""
import os
import sys
import django

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pcap_web.settings')
django.setup()

from analyzer.models import PCAPAnalysis
from analyzer.pcap_analyzer import analyze_pcap_with_llm

# Pegar última análise
last = PCAPAnalysis.objects.order_by('-id').first()

if last:
    print(f"\n=== TESTANDO ANÁLISE ===")
    print(f"ID: {last.id}")
    print(f"Arquivo: {last.original_filename}")
    print(f"Caminho: {last.pcap_file.path}")
    print(f"Modo: {last.analysis_mode}")
    print(f"Modelo: {last.llm_model}")
    print()
    
    # Verificar se arquivo existe
    if not os.path.exists(last.pcap_file.path):
        print(f"❌ ERRO: Arquivo não encontrado: {last.pcap_file.path}")
    else:
        print(f"✅ Arquivo existe ({os.path.getsize(last.pcap_file.path)} bytes)")
        
        print("\n🚀 Iniciando análise de teste...")
        try:
            result = analyze_pcap_with_llm(
                last.pcap_file.path,
                last.llm_model,
                analysis_mode=last.analysis_mode
            )
            print("\n✅ SUCESSO!")
            print(f"Pacotes: {result.get('packet_count', 0)}")
            print(f"Score: {result.get('malware_score', 0)}")
            print(f"Risco: {result.get('risk_level', 'N/A')}")
        except Exception as e:
            print(f"\n❌ ERRO: {e}")
            import traceback
            traceback.print_exc()
else:
    print("❌ Nenhuma análise encontrada no banco")
