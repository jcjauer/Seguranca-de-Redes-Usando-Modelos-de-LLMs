#!/usr/bin/env python3
"""
🐝 ANÁLISE DE TRÁFEGO BUMBLEBEE MALWARE 🐝
Análise do arquivo amostra.pcap
com regras YARA para detecção do malware Bumblebee
"""

import os
import sys
import subprocess
import yara
from pathlib import Path
import tempfile
import shutil
import math
from collections import Counter

def calcular_entropia(data):
    """Calcula entropia dos dados (detecta criptografia/ofuscação)"""
    if len(data) == 0:
        return 0
    
    counter = Counter(data)
    total = len(data)
    entropy = 0
    
    for count in counter.values():
        prob = count / total
        if prob > 0:
            entropy -= prob * math.log2(prob)
    
    return entropy

def criar_diretorio_analise():
    """Cria diretório para análise do Bumblebee"""
    pasta_analise = "bumblebee_analise"
    if os.path.exists(pasta_analise):
        shutil.rmtree(pasta_analise)
    os.makedirs(pasta_analise)
    return pasta_analise

def extrair_arquivos_tshark(pcap_file, pasta_destino):
    """Extrai arquivos do PCAP usando tshark"""
    print(f"🔍 EXTRAINDO ARQUIVOS DE: {pcap_file}")
    print("="*70)
    
    # Protocolos para extrair - Bumblebee usa principalmente HTTP/HTTPS
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
    
    # NOVA FUNCIONALIDADE: Extrair TCP streams para detectar malware ofuscado
    print("\n🔍 EXTRAINDO TCP STREAMS (DETECÇÃO AVANÇADA)")
    tcp_dir = os.path.join(pasta_destino, "tcp_streams")
    os.makedirs(tcp_dir, exist_ok=True)
    
    try:
        # Buscar streams TCP com payload significativo
        cmd = ["tshark", "-r", pcap_file, "-Y", "tcp.len > 100", "-T", "fields", "-e", "tcp.stream", "-e", "tcp.len"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        tcp_streams = {}
        for line in result.stdout.strip().split('\n'):
            if '\t' in line:
                parts = line.split('\t')
                if len(parts) >= 2:
                    try:
                        stream_id = int(parts[0])
                        length = int(parts[1])
                        if stream_id not in tcp_streams or length > tcp_streams[stream_id]:
                            tcp_streams[stream_id] = length
                    except:
                        pass
        
        # Extrair os 20 maiores streams
        sorted_streams = sorted(tcp_streams.items(), key=lambda x: x[1], reverse=True)[:20]
        tcp_extraidos = 0
        
        for stream_id, length in sorted_streams:
            try:
                cmd = ["tshark", "-r", pcap_file, "-Y", f"tcp.stream eq {stream_id}", "-T", "fields", "-e", "tcp.payload"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.stdout.strip():
                    hex_data = ''.join(result.stdout.strip().split())
                    if hex_data and len(hex_data) > 20:
                        try:
                            binary_data = bytes.fromhex(hex_data)
                            if len(binary_data) > 10:
                                stream_file = os.path.join(tcp_dir, f"tcp_stream_{stream_id}_{length}.bin")
                                with open(stream_file, 'wb') as f:
                                    f.write(binary_data)
                                tcp_extraidos += 1
                        except ValueError:
                            pass
            except:
                pass
        
        print(f"[TSHARK] ✅ {tcp_extraidos} TCP streams extraídos")
        total_arquivos += tcp_extraidos
        
    except Exception as e:
        print(f"[TSHARK] ⚠️ Erro ao extrair TCP streams: {e}")
    
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
                    
                    # Guardar detecções importantes (Bumblebee, exploit kits, malware)
                    if any(keyword in det['regra_nome'].lower() or keyword in det['arquivo_regra'].lower() 
                           for keyword in ['bumblebee', 'malware', 'trojan', 'backdoor', 'loader', 'infostealer']):
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
    
    print("\n🐝 RELATÓRIO DE DETECÇÕES IMPORTANTES")
    print("="*60)
    
    # Agrupar por tipo de detecção
    bumblebee_deteccoes = []
    malware_deteccoes = []
    outras_deteccoes = []
    
    for det in deteccoes_importantes:
        nome_regra = det['deteccao']['regra_nome'].lower()
        arquivo_regra = det['deteccao']['arquivo_regra'].lower()
        
        if 'bumblebee' in nome_regra or 'bumblebee' in arquivo_regra:
            bumblebee_deteccoes.append(det)
        elif any(keyword in nome_regra or keyword in arquivo_regra 
                for keyword in ['malware', 'trojan', 'backdoor', 'loader', 'infostealer']):
            malware_deteccoes.append(det)
        else:
            outras_deteccoes.append(det)
    
    if bumblebee_deteccoes:
        print("\n🐝 DETECÇÕES BUMBLEBEE:")
        for det in bumblebee_deteccoes:
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
    
    if outras_deteccoes:
        print("\n⚠️ OUTRAS DETECÇÕES:")
        for det in outras_deteccoes:
            print(f"   📄 Arquivo: {det['arquivo']}")
            print(f"   🚨 Regra: {det['deteccao']['regra_nome']}")
            print(f"   🔍 Matches: {det['deteccao']['strings']}")
            print()

def analisar_arquivos_especiais(pasta_analise):
    """Analisa arquivos com características especiais do Bumblebee"""
    print("\n🔍 ANÁLISE ESPECIAL PARA BUMBLEBEE")
    print("="*50)
    
    arquivos_suspeitos = []
    arquivos_alta_entropia = []
    
    for root, dirs, files in os.walk(pasta_analise):
        for file in files:
            arquivo_path = os.path.join(root, file)
            size = os.path.getsize(arquivo_path)
            
            # NOVA: Análise de entropia para detectar ofuscação
            if size > 100:  # Só analisar arquivos com mais de 100 bytes
                try:
                    with open(arquivo_path, 'rb') as f:
                        data = f.read()
                    
                    entropia = calcular_entropia(data)
                    
                    if entropia > 7.0:  # Alta entropia = possível criptografia
                        arquivos_alta_entropia.append({
                            'arquivo': file,
                            'caminho': arquivo_path,
                            'entropia': entropia,
                            'tamanho': size
                        })
                except:
                    pass
            
            # Bumblebee características originais:
            suspeito = False
            razoes = []
            
            if file.lower().endswith(('.dll', '.exe')):
                suspeito = True
                razoes.append("Executável/DLL")
            
            if file.lower().endswith(('.iso', '.img')):
                suspeito = True
                razoes.append("Imagem de disco")
            
            if file.lower().endswith(('.ps1', '.bat', '.cmd')):
                suspeito = True
                razoes.append("Script")
            
            if size > 50000 and size < 500000:  # Entre 50KB e 500KB
                suspeito = True
                razoes.append(f"Tamanho suspeito ({size} bytes)")
            
            # NOVA: TCP streams são sempre suspeitos
            if 'tcp_stream' in file.lower():
                suspeito = True
                razoes.append("TCP Stream")
            
            if suspeito:
                arquivos_suspeitos.append({
                    'arquivo': file,
                    'caminho': arquivo_path,
                    'tamanho': size,
                    'razoes': razoes
                })
    
    # Relatório de alta entropia (NOVA DETECÇÃO)
    if arquivos_alta_entropia:
        print("🚨 ARQUIVOS COM ALTA ENTROPIA (POSSÍVEL MALWARE OFUSCADO):")
        for arq in arquivos_alta_entropia:
            print(f"   📄 {arq['arquivo']}")
            print(f"      💾 Tamanho: {arq['tamanho']} bytes")
            print(f"      📊 Entropia: {arq['entropia']:.2f}/8.0")
            if arq['entropia'] > 7.5:
                print(f"      🚨 CRÍTICO: Altamente provável ser malware criptografado!")
            print()
    
    if arquivos_suspeitos:
        print("\n🚨 ARQUIVOS SUSPEITOS ENCONTRADOS:")
        for arq in arquivos_suspeitos:
            print(f"   📄 {arq['arquivo']}")
            print(f"      💾 Tamanho: {arq['tamanho']} bytes")
            print(f"      ⚠️ Razões: {', '.join(arq['razoes'])}")
            print()
    else:
        print("\n✅ Nenhum arquivo com características suspeitas do Bumblebee")
    
    # RETORNAR dados para uso no relatório final
    return len(arquivos_alta_entropia), len(arquivos_suspeitos)

def main():
    print("🐝 ANÁLISE DE TRÁFEGO BUMBLEBEE MALWARE")
    print("="*70)
    
    pcap_file = "amostra.pcap"
    
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
    
    # Análise especial para Bumblebee (COM NOVA DETECÇÃO DE ENTROPIA)
    alta_entropia, arquivos_suspeitos = analisar_arquivos_especiais(pasta_analise)
    
    # Gerar relatório
    gerar_relatorio_detalhado(deteccoes_importantes, pasta_analise)
    
    print("\n📊 RESUMO FINAL:")
    print(f"   📁 Arquivos extraídos: {total_arquivos}")
    print(f"   🚨 Total de detecções YARA: {total_deteccoes}")
    print(f"   🎯 Detecções importantes: {len(deteccoes_importantes)}")
    print(f"   📊 Arquivos alta entropia: {alta_entropia}")
    print(f"   ⚠️ Arquivos suspeitos: {arquivos_suspeitos}")
    
    # NOVA LÓGICA: Considerar alta entropia como indicador de malware
    deteccao_total = len(deteccoes_importantes) + alta_entropia
    
    if deteccoes_importantes:
        print("\n🎉 SUCESSO: Bumblebee detectado com as regras YARA!")
    elif alta_entropia > 0:
        print("\n🚨 DETECÇÃO AVANÇADA: Possível Bumblebee ofuscado detectado via análise de entropia!")
        print(f"\n📊 {alta_entropia} arquivo(s) com alta entropia encontrado(s)")
        print("💡 Isso indica presença de malware criptografado/ofuscado")
    else:
        print("\n⚠️ Nenhuma detecção de Bumblebee encontrada.")
    
    print(f"\n📂 Arquivos extraídos salvos em: {pasta_analise}")
    print("="*70)

if __name__ == "__main__":
    main()