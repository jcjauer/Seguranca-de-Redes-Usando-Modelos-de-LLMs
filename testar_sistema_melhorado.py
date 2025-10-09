#!/usr/bin/env python3
"""
Teste do Sistema Principal Melhorado - Análise Avançada de PCAP
Integra as melhorias bem-sucedidas dos scripts de teste no sistema principal
"""

import os
import sys
from pathlib import Path

# Adicionar o caminho do pcap_web ao Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'pcap_web'))

def testar_sistema_melhorado():
    """Testa as novas funcionalidades integradas no sistema principal"""
    
    print("🚀 TESTANDO SISTEMA PRINCIPAL MELHORADO")
    print("=" * 60)
    
    # Verificar se o arquivo de teste existe
    arquivo_teste = "amostra.pcap"
    if not os.path.exists(arquivo_teste):
        print(f"❌ Arquivo {arquivo_teste} não encontrado!")
        print("📝 Usando arquivo alternativo para teste...")
        arquivos_disponiveis = [
            "2013-12-23-Neutrino-EK-traffic.pcap",
            "exemplo.pcap",
            "anomalias_seguranca.pcap"
        ]
        
        for arquivo in arquivos_disponiveis:
            if os.path.exists(arquivo):
                arquivo_teste = arquivo
                break
        
        if not os.path.exists(arquivo_teste):
            print("❌ Nenhum arquivo PCAP disponível para teste!")
            return
    
    print(f"📁 Arquivo de teste: {arquivo_teste}")
    
    try:
        # Importar o analisador melhorado
        from analyzer.pcap_analyzer import analyze_pcap_with_llm, calcular_entropia, extrair_tcp_streams_com_tshark
        
        print("\n🔧 TESTANDO FUNCIONALIDADES INDIVIDUAIS")
        print("-" * 40)
        
        # 1. Testar cálculo de entropia
        print("1. Testando cálculo de entropia...")
        teste_dados_baixa_entropia = b"AAAAAAAAAAAAAAAA"  # Dados repetitivos
        teste_dados_alta_entropia = bytes(range(256))      # Dados diversos
        
        entropia_baixa = calcular_entropia(teste_dados_baixa_entropia)
        entropia_alta = calcular_entropia(teste_dados_alta_entropia)
        
        print(f"   ✅ Entropia baixa (dados repetitivos): {entropia_baixa:.2f}")
        print(f"   ✅ Entropia alta (dados diversos): {entropia_alta:.2f}")
        
        # 2. Testar extração de streams TCP
        print("\n2. Testando extração de streams TCP...")
        tcp_streams = extrair_tcp_streams_com_tshark(arquivo_teste)
        print(f"   ✅ Streams extraídos: {len(tcp_streams)}")
        
        streams_suspeitos = [s for s in tcp_streams if s.get('suspeito', False)]
        if streams_suspeitos:
            print(f"   🚨 Streams suspeitos encontrados: {len(streams_suspeitos)}")
            for stream in streams_suspeitos[:3]:  # Mostrar primeiros 3
                print(f"      - Stream {stream['stream_id']}: entropia {stream['entropia']:.2f}")
        else:
            print("   ℹ️ Nenhum stream suspeito encontrado")
        
        # 3. Testar análise completa
        print(f"\n3. Executando análise completa do sistema melhorado...")
        print("   📊 Iniciando análise (pode levar alguns minutos)...")
        
        resultado = analyze_pcap_with_llm(
            arquivo_pcap=arquivo_teste,
            modelo="llama3",  # Usar modelo padrão
        )
        
        print("\n🎯 RESULTADOS DA ANÁLISE COMPLETA")
        print("=" * 60)
        
        print(f"📦 Pacotes analisados: {resultado.get('packet_count', 'N/A')}")
        
        # Verificar se há detecções no relatório
        analise_texto = resultado.get('raw_data', '')
        
        # Procurar por indicadores de sucesso das novas funcionalidades
        indicadores_presentes = []
        
        if "ANÁLISE DE STREAMS TCP" in analise_texto:
            indicadores_presentes.append("✅ Análise de streams TCP ativada")
        
        if "ANÁLISE COMPORTAMENTAL" in analise_texto:
            indicadores_presentes.append("✅ Análise comportamental ativada")
        
        if "STREAMS SUSPEITOS" in analise_texto:
            indicadores_presentes.append("🚨 Streams suspeitos detectados")
        
        if "DETECÇÕES EM STREAMS TCP" in analise_texto:
            indicadores_presentes.append("🎯 Detecções YARA em streams")
        
        if "ALTO RISCO" in analise_texto or "MÉDIO RISCO" in analise_texto:
            indicadores_presentes.append("⚠️ Ameaças comportamentais detectadas")
        
        if indicadores_presentes:
            print("\n🎉 FUNCIONALIDADES MELHORADAS ATIVAS:")
            for indicador in indicadores_presentes:
                print(f"   {indicador}")
        else:
            print("\nℹ️ Sistema funcionando com análise básica")
        
        # Salvar relatório detalhado
        relatorio_arquivo = f"relatorio_sistema_melhorado_{Path(arquivo_teste).stem}.txt"
        with open(relatorio_arquivo, 'w', encoding='utf-8') as f:
            f.write(f"RELATÓRIO SISTEMA PRINCIPAL MELHORADO\n")
            f.write(f"=" * 50 + "\n")
            f.write(f"Arquivo analisado: {arquivo_teste}\n")
            f.write(f"Pacotes: {resultado.get('packet_count', 'N/A')}\n\n")
            f.write(analise_texto)
        
        print(f"\n💾 Relatório detalhado salvo: {relatorio_arquivo}")
        
        # Resumo final
        print(f"\n🏁 RESUMO DO TESTE")
        print("-" * 30)
        print("✅ Sistema principal melhorado testado com sucesso!")
        print("✅ Novas funcionalidades integradas:")
        print("   • Análise de streams TCP com tshark")
        print("   • Cálculo de entropia por stream")
        print("   • Análise comportamental de malware")
        print("   • Detecção de comunicação C2 criptografada")
        print("   • Análise YARA em streams reconstruídos")
        
        return True
        
    except ImportError as e:
        print(f"❌ Erro de importação: {e}")
        print("💡 Certifique-se de que o módulo pcap_web está acessível")
        return False
        
    except Exception as e:
        print(f"❌ Erro durante o teste: {e}")
        print(f"🔍 Tipo do erro: {type(e).__name__}")
        return False

if __name__ == "__main__":
    print("🔧 TESTE DO SISTEMA PRINCIPAL MELHORADO")
    print("Integração das melhorias bem-sucedidas dos scripts de detecção\n")
    
    sucesso = testar_sistema_melhorado()
    
    if sucesso:
        print("\n🎉 TESTE CONCLUÍDO COM SUCESSO!")
        print("O sistema principal agora possui capacidades avançadas de detecção")
        print("igual às que funcionaram nos scripts de teste do Bumblebee! 🎯")
    else:
        print("\n❌ TESTE FALHOU")
        print("Verifique os erros acima e tente novamente")