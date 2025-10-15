#!/usr/bin/env python3
"""
🚨 ANÁLISE DE TRÁFEGO NEUTRINO EK REAL 🚨
Análise do arquivo 2013-12-19-Neutrino-EK-traffic.pcap
com regras YARA aprimoradas para Neutrino EK
"""

import os
import sys
import subprocess
import yara
from pathlib import Path
import tempfile
import shutil

def criar_diretorio_analise():
    """Cria diretório para análise do Neutrino EK real"""
    pasta_analise = "neutrino_ek_real_analise"
    if os.path.exists(pasta_analise):
        shutil.rmtree(pasta_analise)
    os.makedirs(pasta_analise)
    return pasta_analise

def extrair_arquivos_tshark(pcap_file, pasta_destino):
    """Extrai arquivos do PCAP usando tshark"""
    print(f"🔍 EXTRAINDO ARQUIVOS DE: {pcap_file}")
    print("="*70)
    
    # Protocolos para extrair
    protocolos = ['http', 'smb', 'tftp', 'dicom', 'ftp', 'smtp', 'http2']
    total_arquivos = 0
    
    for protocolo in protocolos:
        print(f"[TSHARK] Extraindo protocolo: {protocolo}")
        pasta_protocolo = os.path.join(pasta_destino, protocolo)
        
        try:
            # Comando tshark para extrair objetos
            cmd = [
                'tshark', 
                '-r', pcap_file,
                '--export-objects', f'{protocolo},{pasta_protocolo}'
            ]
            
            resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if os.path.exists(pasta_protocolo):
                arquivos = os.listdir(pasta_protocolo)
                if arquivos:
                    print(f"[TSHARK] ✅ {len(arquivos)} arquivo(s) extraído(s) para {protocolo}")
                    for arquivo in arquivos[:5]:  # Mostrar apenas os primeiros 5
                        size = os.path.getsize(os.path.join(pasta_protocolo, arquivo))
                        print(f"[TSHARK]   📄 {arquivo} ({size} bytes)")
                    if len(arquivos) > 5:
                        print(f"[TSHARK]   ... e mais {len(arquivos) - 5} arquivo(s)")
                    total_arquivos += len(arquivos)
                else:
                    print(f"[TSHARK] ❌ Nenhum arquivo encontrado para {protocolo}")
            else:
                print(f"[TSHARK] ❌ Nenhum arquivo encontrado para {protocolo}")
                
        except subprocess.TimeoutExpired:
            print(f"[TSHARK] ⚠️ Timeout na extração de {protocolo}")
        except Exception as e:
            print(f"[TSHARK] ❌ Erro ao extrair {protocolo}: {e}")
    
    print(f"[TSHARK] 📊 Total de arquivos extraídos: {total_arquivos}")
    return total_arquivos

def carregar_regras_yara():
    """Carrega todas as regras YARA disponíveis (excluindo pastas archive)"""
    print("🔍 CARREGANDO REGRAS YARA")
    print("="*50)
    
    pasta_yara = "pcap_web/yara"
    regras_carregadas = []
    
    # Percorrer todas as subpastas, excluindo 'archive'
    for root, dirs, files in os.walk(pasta_yara):
        # Remover 'archive' da lista de diretórios para não percorrê-la
        if 'archive' in dirs:
            dirs.remove('archive')
        
        for file in files:
            if file.endswith('.yar') or file.endswith('.yara'):
                caminho_regra = os.path.join(root, file)
                try:
                    regra = yara.compile(caminho_regra)
                    regras_carregadas.append((caminho_regra, regra))
                    print(f"✅ Carregada: {caminho_regra}")
                except Exception as e:
                    print(f"❌ Erro ao carregar {caminho_regra}: {e}")
    
    print(f"📊 Total de regras carregadas: {len(regras_carregadas)}")
    return regras_carregadas

def analisar_arquivo_com_yara(arquivo_path, regras_yara):
    """Analisa um arquivo com todas as regras YARA"""
    deteccoes = []
    
    for nome_regra, regra_compilada in regras_yara:
        try:
            matches = regra_compilada.match(arquivo_path)
            if matches:
                for match in matches:
                    deteccoes.append({
                        'arquivo_regra': nome_regra,
                        'regra_nome': match.rule,
                        'strings': len(match.strings) if match.strings else 0,
                        'tags': match.tags
                    })
        except Exception as e:
            pass  # Ignorar erros de análise individual
    
    return deteccoes

def analisar_arquivos_extraidos(pasta_analise, regras_yara):
    """Analisa todos os arquivos extraídos com YARA"""
    print("🔍 ANÁLISE COM REGRAS YARA")
    print("="*50)
    
    total_deteccoes = 0
    deteccoes_importantes = []
    
    # Percorrer todos os arquivos extraídos
    for root, dirs, files in os.walk(pasta_analise):
        for file in files:
            arquivo_path = os.path.join(root, file)
            print(f"[YARA] 📄 Analisando: {file}")
            
            deteccoes = analisar_arquivo_com_yara(arquivo_path, regras_yara)
            
            if deteccoes:
                print(f"[YARA]   🚨 DETECÇÕES ENCONTRADAS ({len(deteccoes)}):")
                for det in deteccoes:
                    print(f"[YARA]      🎯 Regra: {det['regra_nome']}")
                    print(f"[YARA]         📁 Arquivo regra: {det['arquivo_regra']}")
                    print(f"[YARA]         🔍 Strings: {det['strings']} matches")
                    if det['tags']:
                        print(f"[YARA]         🏷️ Tags: {', '.join(det['tags'])}")
                    print()
                    
                    # Guardar detecções importantes (Neutrino, exploit kits, malware)
                    if any(keyword in det['regra_nome'].lower() or keyword in det['arquivo_regra'].lower() 
                           for keyword in ['neutrino', 'exploit', 'malware', 'trojan', 'backdoor']):
                        deteccoes_importantes.append({
                            'arquivo': file,
                            'caminho': arquivo_path,
                            'deteccao': det
                        })
                
                total_deteccoes += len(deteccoes)
            else:
                print(f"[YARA]   ✅ Nenhuma ameaça detectada")
    
    print(f"[YARA] 📊 Total de detecções: {total_deteccoes}")
    return total_deteccoes, deteccoes_importantes

def gerar_relatorio_detalhado(deteccoes_importantes, pasta_analise):
    """Gera relatório detalhado das detecções importantes"""
    if not deteccoes_importantes:
        print("\n📋 RELATÓRIO: Nenhuma detecção importante encontrada")
        return
    
    print("\n🚨 RELATÓRIO DE DETECÇÕES IMPORTANTES")
    print("="*60)
    
    # Agrupar por tipo de detecção
    neutrino_deteccoes = []
    exploit_deteccoes = []
    malware_deteccoes = []
    
    for det in deteccoes_importantes:
        nome_regra = det['deteccao']['regra_nome'].lower()
        arquivo_regra = det['deteccao']['arquivo_regra'].lower()
        
        if 'neutrino' in nome_regra or 'neutrino' in arquivo_regra:
            neutrino_deteccoes.append(det)
        elif 'exploit' in nome_regra or 'exploit' in arquivo_regra:
            exploit_deteccoes.append(det)
        else:
            malware_deteccoes.append(det)
    
    if neutrino_deteccoes:
        print("\n🎯 DETECÇÕES NEUTRINO EK:")
        for det in neutrino_deteccoes:
            print(f"   📄 Arquivo: {det['arquivo']}")
            print(f"   🚨 Regra: {det['deteccao']['regra_nome']}")
            print(f"   🔍 Matches: {det['deteccao']['strings']}")
            print()
    
    if exploit_deteccoes:
        print("\n💥 OUTRAS DETECÇÕES DE EXPLOIT:")
        for det in exploit_deteccoes:
            print(f"   📄 Arquivo: {det['arquivo']}")
            print(f"   🚨 Regra: {det['deteccao']['regra_nome']}")
            print(f"   🔍 Matches: {det['deteccao']['strings']}")
            print()
    
    if malware_deteccoes:
        print("\n🦠 OUTRAS DETECÇÕES DE MALWARE:")
        for det in malware_deteccoes:
            print(f"   📄 Arquivo: {det['arquivo']}")
            print(f"   🚨 Regra: {det['deteccao']['regra_nome']}")
            print(f"   🔍 Matches: {det['deteccao']['strings']}")
            print()

def main():
    print("🚨 ANÁLISE DE TRÁFEGO NEUTRINO EK REAL")
    print("="*70)
    
    pcap_file = "2013-12-19-Neutrino-EK-traffic.pcap"
    
    # Verificar se o arquivo existe
    if not os.path.exists(pcap_file):
        print(f"❌ Arquivo não encontrado: {pcap_file}")
        return
    
    print(f"📁 Analisando arquivo: {pcap_file}")
    size_mb = os.path.getsize(pcap_file) / (1024 * 1024)
    print(f"📊 Tamanho do arquivo: {size_mb:.2f} MB")
    print()
    
    # Criar diretório de análise
    pasta_analise = criar_diretorio_analise()
    
    # Extrair arquivos com tshark
    total_arquivos = extrair_arquivos_tshark(pcap_file, pasta_analise)
    
    if total_arquivos == 0:
        print("❌ Nenhum arquivo foi extraído. Análise interrompida.")
        return
    
    print()
    
    # Carregar regras YARA
    regras_yara = carregar_regras_yara()
    
    if not regras_yara:
        print("❌ Nenhuma regra YARA carregada. Análise interrompida.")
        return
    
    print()
    
    # Analisar arquivos extraídos
    total_deteccoes, deteccoes_importantes = analisar_arquivos_extraidos(pasta_analise, regras_yara)
    
    # Gerar relatório
    gerar_relatorio_detalhado(deteccoes_importantes, pasta_analise)
    
    print("\n📊 RESUMO FINAL:")
    print(f"   📁 Arquivos extraídos: {total_arquivos}")
    print(f"   🚨 Total de detecções: {total_deteccoes}")
    print(f"   🎯 Detecções importantes: {len(deteccoes_importantes)}")
    
    if deteccoes_importantes:
        print("\n🎉 SUCESSO: Neutrino EK detectado com as regras YARA!")
    else:
        print("\n⚠️ Nenhuma detecção importante de Neutrino EK encontrada.")
    
    print(f"\n📂 Arquivos extraídos salvos em: {pasta_analise}")
    print("="*70)

if __name__ == "__main__":
    main()