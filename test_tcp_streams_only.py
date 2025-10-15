#!/usr/bin/env python3
"""
Script para testar análise YARA APENAS em streams TCP (sem arquivos de protocolos)
"""

import sys
import os
sys.path.append('pcap_web')

from analyzer.pcap_analyzer import extrair_tcp_streams_e_analisar_com_yara

def main():
    if len(sys.argv) != 2:
        print("Uso: python test_tcp_streams_only.py <arquivo.pcap>")
        sys.exit(1)
    
    arquivo_pcap = sys.argv[1]
    
    if not os.path.exists(arquivo_pcap):
        print(f"❌ Arquivo não encontrado: {arquivo_pcap}")
        sys.exit(1)
    
    print("🌊 TESTANDO ANÁLISE YARA APENAS EM STREAMS TCP")
    print("=" * 60)
    print(f"📁 Arquivo: {arquivo_pcap}")
    print("=" * 60)
    
    # Executa análise APENAS em streams TCP  
    resultado = extrair_tcp_streams_e_analisar_com_yara(arquivo_pcap)
    
    print("\n" + "=" * 60)
    print("📊 RESUMO FINAL:")
    print("=" * 60)
    print(f"Streams TCP extraídos: {resultado['total_streams']}")
    print(f"Detecções YARA: {resultado['total_deteccoes']}")
    print(f"Streams limpos: {resultado['streams_limpos']}")
    print(f"Resumo: {resultado['resumo']}")
    
    if resultado['deteccoes_yara']:
        print("\n🚨 DETECÇÕES ENCONTRADAS:")
        print("-" * 40)
        for i, det in enumerate(resultado['deteccoes_yara'], 1):
            print(f"{i}. Regra: {det['regra']}")
            print(f"   Stream ID: {det['stream_id']}")
            print(f"   Tamanho: {det['tamanho_stream']} bytes")
            print(f"   Tags: {', '.join(det['tags']) if det['tags'] else 'Nenhuma'}")
            print()

if __name__ == "__main__":
    main()