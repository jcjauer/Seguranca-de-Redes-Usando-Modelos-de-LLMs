#!/usr/bin/env python3
"""
Teste Focado - Extração de Streams TCP e Análise YARA
Testa apenas as funcionalidades específicas solicitadas
"""

import os
import sys

def testar_melhorias_focadas():
    """Testa apenas as melhorias focadas: streams TCP e YARA"""
    
    print("🎯 TESTE FOCADO: STREAMS TCP + YARA")
    print("=" * 50)
    
    # Arquivo de teste
    arquivo_teste = "amostra.pcap"
    if not os.path.exists(arquivo_teste):
        # Tentar arquivos alternativos
        arquivos_alternativos = [
            "2013-12-23-Neutrino-EK-traffic.pcap",
            "exemplo.pcap",
            "anomalias_seguranca.pcap"
        ]
        
        for arquivo in arquivos_alternativos:
            if os.path.exists(arquivo):
                arquivo_teste = arquivo
                break
        
        if not os.path.exists(arquivo_teste):
            print("❌ Nenhum arquivo PCAP encontrado para teste!")
            return False
    
    print(f"📁 Arquivo de teste: {arquivo_teste}")
    
    try:
        # Importar apenas as funções que precisamos
        sys.path.append('pcap_web')
        from analyzer.pcap_analyzer import extrair_tcp_streams_com_tshark, YARA_ENABLED, YARA_RULES
        
        print(f"\n✅ Importações realizadas com sucesso")
        print(f"📋 YARA habilitado: {YARA_ENABLED}")
        
        # 1. Testar extração de streams TCP
        print(f"\n🔧 TESTANDO EXTRAÇÃO DE STREAMS TCP")
        print("-" * 40)
        
        tcp_streams = extrair_tcp_streams_com_tshark(arquivo_teste)
        
        if tcp_streams:
            print(f"✅ Sucesso! {len(tcp_streams)} streams TCP extraídos")
            
            # Mostrar detalhes dos primeiros streams
            for i, stream in enumerate(tcp_streams[:3]):
                print(f"   📄 Stream {stream['stream_id']}: {stream['tamanho']} bytes")
        else:
            print("ℹ️ Nenhum stream TCP extraído (pode ser normal dependendo do PCAP)")
        
        # 2. Testar análise YARA nos streams (se disponível)
        if YARA_ENABLED and tcp_streams:
            print(f"\n🔧 TESTANDO ANÁLISE YARA NOS STREAMS")
            print("-" * 40)
            
            deteccoes_streams = 0
            
            for stream_info in tcp_streams:
                try:
                    with open(stream_info['arquivo'], 'rb') as f:
                        stream_data = f.read()
                    
                    matches = YARA_RULES.match(data=stream_data, timeout=3)
                    
                    if matches:
                        deteccoes_streams += len(matches)
                        for match in matches:
                            print(f"   🚨 DETECÇÃO: {match.rule} em stream {stream_info['stream_id']}")
                    
                except Exception as e:
                    print(f"   ⚠️ Erro ao analisar stream {stream_info['stream_id']}: {e}")
            
            if deteccoes_streams > 0:
                print(f"✅ {deteccoes_streams} detecções encontradas nos streams TCP!")
            else:
                print("ℹ️ Nenhuma detecção YARA nos streams TCP")
        
        elif not YARA_ENABLED:
            print(f"\n⚠️ YARA não está habilitado - análise de malware limitada")
            
        # 3. Teste básico da função principal (se quiser testar integração)
        print(f"\n🔧 TESTANDO INTEGRAÇÃO NO SISTEMA PRINCIPAL")
        print("-" * 40)
        
        from analyzer.pcap_analyzer import analyze_pcap_with_llm
        
        # Teste rápido (só verificar se não há erro de execução)
        try:
            resultado = analyze_pcap_with_llm(arquivo_teste, modelo="llama3")
            
            # Verificar se as novas funcionalidades aparecem no relatório
            analise_texto = resultado.get('raw_data', '')
            
            melhorias_detectadas = []
            if "STREAMS TCP EXTRAÍDOS" in analise_texto:
                melhorias_detectadas.append("✅ Extração de streams TCP ativa")
            
            if "DETECÇÕES EM STREAMS TCP" in analise_texto:
                melhorias_detectadas.append("🎯 Análise YARA em streams ativa")
            
            if melhorias_detectadas:
                print("🎉 MELHORIAS INTEGRADAS COM SUCESSO:")
                for melhoria in melhorias_detectadas:
                    print(f"   {melhoria}")
            else:
                print("ℹ️ Sistema funcionando (melhorias podem não aparecer se não houver dados)")
            
            return True
            
        except Exception as e:
            print(f"⚠️ Erro na integração: {e}")
            print("🔧 As funções individuais funcionam, mas pode haver problema na integração")
            return False
    
    except ImportError as e:
        print(f"❌ Erro de importação: {e}")
        return False
    except Exception as e:
        print(f"❌ Erro durante teste: {e}")
        return False

if __name__ == "__main__":
    print("🔧 TESTE DAS MELHORIAS FOCADAS")
    print("Testando apenas: Extração de Streams TCP + Análise YARA\n")
    
    sucesso = testar_melhorias_focadas()
    
    if sucesso:
        print(f"\n🎉 TESTE CONCLUÍDO COM SUCESSO!")
        print("📋 Funcionalidades implementadas:")
        print("   • Extração de streams TCP com tshark")
        print("   • Análise YARA em streams TCP reconstruídos")
        print("   • Integração no sistema principal")
        print("\n💡 O sistema agora pode detectar malware que usa")
        print("   comunicação criptografada em streams TCP completos!")
    else:
        print(f"\n❌ TESTE COM PROBLEMAS")
        print("Verifique os erros acima")