#!/usr/bin/env python3
"""
Script para testar a extração de streams TCP e detecção YARA no amostra.pcap
"""

import os
import sys
import subprocess
import glob

# Adiciona o caminho do Django
sys.path.append('pcap_web')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pcap_web.settings')

import django
django.setup()

from analyzer.pcap_analyzer import extrair_e_analisar_com_yara, extrair_tcp_streams

def testar_amostra_pcap():
    """
    Testa especificamente o arquivo amostra.pcap com diferentes métodos de extração
    """
    arquivo_pcap = "amostra.pcap"
    
    if not os.path.exists(arquivo_pcap):
        print(f"❌ Arquivo {arquivo_pcap} não encontrado!")
        return
    
    print(f"🔍 Testando análise do arquivo: {arquivo_pcap}")
    print("=" * 60)
    
    # 1. Teste com tshark (objetos de protocolos)
    print("\n1️⃣ TESTE: Extração de objetos com tshark")
    resultado_tshark = extrair_e_analisar_com_yara(arquivo_pcap, "teste_amostra_tshark")
    
    print(f"📊 Resultado tshark:")
    print(f"   - Arquivos extraídos: {resultado_tshark['total_arquivos']}")
    print(f"   - Detecções YARA: {resultado_tshark['total_deteccoes']}")
    print(f"   - Resumo: {resultado_tshark['resumo']}")
    
    # 2. Teste com TCP streams
    print("\n2️⃣ TESTE: Extração de streams TCP")
    streams_tcp = extrair_tcp_streams(arquivo_pcap, "teste_amostra_streams")
    
    print(f"📊 Resultado TCP streams:")
    print(f"   - Streams extraídos: {len(streams_tcp)}")
    
    # 3. Análise manual com tshark para ver o conteúdo do PCAP
    print("\n3️⃣ ANÁLISE: Informações detalhadas do PCAP")
    
    try:
        # Estatísticas básicas do PCAP
        result = subprocess.run([
            "tshark", "-r", arquivo_pcap, "-q", "-z", "conv,tcp"
        ], capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0 and result.stdout:
            print("📈 Conversações TCP encontradas:")
            linhas = result.stdout.split('\n')
            for linha in linhas:
                if '<->' in linha and 'Frames' in linha:
                    print(f"   {linha}")
        
        # Protocolos encontrados
        result = subprocess.run([
            "tshark", "-r", arquivo_pcap, "-q", "-z", "io,phs"
        ], capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0 and result.stdout:
            print("\n📦 Hierarquia de protocolos:")
            linhas = result.stdout.split('\n')
            for linha in linhas:
                if linha.strip() and not linha.startswith('='):
                    print(f"   {linha}")
                    
    except Exception as e:
        print(f"❌ Erro na análise detalhada: {e}")
    
    # 4. Verificar regras YARA carregadas
    print("\n4️⃣ VERIFICAÇÃO: Regras YARA disponíveis")
    yara_dir = "pcap_web/yara"
    if os.path.exists(yara_dir):
        yara_files = glob.glob(os.path.join(yara_dir, '**', '*.yara'), recursive=True)
        print(f"🎯 Regras YARA encontradas: {len(yara_files)}")
        for yara_file in yara_files:
            rel_path = os.path.relpath(yara_file, yara_dir)
            print(f"   - {rel_path}")
    else:
        print("❌ Diretório de regras YARA não encontrado")
    
    # 5. Teste manual de detecção com arquivos extraídos (se houver)
    print("\n5️⃣ TESTE: Detecção manual em arquivos extraídos")
    
    # Verifica pasta de extração tshark
    pasta_tshark = "teste_amostra_tshark"
    if os.path.exists(pasta_tshark):
        arquivos_extraidos = []
        for root, dirs, files in os.walk(pasta_tshark):
            for file in files:
                arquivos_extraidos.append(os.path.join(root, file))
        
        print(f"📁 Arquivos na pasta tshark: {len(arquivos_extraidos)}")
        for arquivo in arquivos_extraidos:
            tamanho = os.path.getsize(arquivo)
            rel_path = os.path.relpath(arquivo, pasta_tshark)
            print(f"   - {rel_path} ({tamanho} bytes)")
    
    # Verifica pasta de streams TCP
    pasta_streams = "teste_amostra_streams"
    if os.path.exists(pasta_streams):
        stream_files = glob.glob(os.path.join(pasta_streams, "*"))
        print(f"🌊 Arquivos de streams TCP: {len(stream_files)}")
        for stream_file in stream_files:
            tamanho = os.path.getsize(stream_file)
            nome = os.path.basename(stream_file)
            print(f"   - {nome} ({tamanho} bytes)")

if __name__ == "__main__":
    testar_amostra_pcap()