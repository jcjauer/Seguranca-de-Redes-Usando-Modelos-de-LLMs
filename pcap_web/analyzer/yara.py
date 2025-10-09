# analyzer/yara.py
"""
Módulo dedicado para análise YARA - ACESSO EXCLUSIVO
Este módulo tem acesso completo às extrações de arquivos e regras YARA
O LLM NÃO tem acesso a este módulo, apenas recebe o relatório final
"""

import math
import os
import sys
import time
import tempfile
import shutil
from pathlib import Path
from collections import defaultdict

# Adicionar path do projeto principal para importar módulos
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))
sys.path.append(parent_dir)

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, Raw, DNS, DNSQR, ARP, Ether
    import yara
    YARA_DEPENDENCIES_OK = True
except ImportError as e:
    print(f"[YARA] ❌ Erro ao importar dependências YARA: {e}")
    print("[YARA] Certifique-se de que scapy e yara-python estão instalados")
    YARA_DEPENDENCIES_OK = False

# --- CARREGAMENTO AUTOMÁTICO DAS REGRAS YARA ---
YARA_RULES = None
YARA_ENABLED = False

try:
    pasta_yara = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "yara")
    rule_files = []
    for root, dirs, files in os.walk(pasta_yara):
        for file in files:
            if file.endswith('.yar') or file.endswith('.yara'):
                rule_files.append(os.path.join(root, file))
    
    rules_dict = {os.path.splitext(os.path.basename(f))[0]: f for f in rule_files}
    if rules_dict:
        YARA_RULES = yara.compile(filepaths=rules_dict)
        YARA_ENABLED = True
        print(f"[YARA] ✅ {len(rule_files)} regras carregadas")
    else:
        print("[YARA] ⚠️ Nenhuma regra YARA encontrada")
        
except Exception as e:
    print(f"[YARA] ❌ Erro ao carregar regras YARA: {e}")
    YARA_ENABLED = False

def calcular_entropia(data):
    """Calcula a entropia Shannon de dados binários"""
    if not data:
        return 0.0

    ocorrencias = {}
    for byte in data:
        ocorrencias[byte] = ocorrencias.get(byte, 0) + 1

    entropia = 0
    for count in ocorrencias.values():
        p_x = count / len(data)
        entropia -= p_x * math.log2(p_x)

    return entropia

def extrair_tcp_streams_com_scapy(arquivo_pcap, pasta_base="tcp_streams_yara"):
    """Extrai TCP streams usando Scapy - EXCLUSIVO PARA YARA"""
    if not os.path.exists(pasta_base):
        os.makedirs(pasta_base)
    
    print(f"[YARA-TCP] 🔍 Extraindo TCP streams do PCAP: {arquivo_pcap}")
    
    try:
        pacotes = rdpcap(arquivo_pcap)
        
        # Agrupar pacotes por stream TCP (4-tuple)
        streams_tcp = defaultdict(list)
        
        for pkt in pacotes:
            if TCP in pkt and IP in pkt:
                # Criar chave única para o stream (src_ip, src_port, dst_ip, dst_port)
                stream_key = (
                    pkt[IP].src, pkt[TCP].sport,
                    pkt[IP].dst, pkt[TCP].dport
                )
                streams_tcp[stream_key].append(pkt)
        
        streams_extraidos = []
        stream_id = 0
        
        for stream_key, pacotes_stream in streams_tcp.items():
            if len(pacotes_stream) < 2:  # Ignorar streams muito pequenos
                continue
                
            # Extrair payloads TCP
            payload_total = b""
            for pkt in pacotes_stream:
                if Raw in pkt:
                    payload_total += bytes(pkt[Raw].load)
            
            if len(payload_total) > 100:  # Só streams com payload significativo
                arquivo_stream = os.path.join(pasta_base, f"tcp_stream_{stream_id}.bin")
                with open(arquivo_stream, 'wb') as f:
                    f.write(payload_total)
                
                streams_extraidos.append({
                    'stream_id': stream_id,
                    'arquivo': arquivo_stream,
                    'tamanho': len(payload_total),
                    'pacotes': len(pacotes_stream),
                    'src': f"{stream_key[0]}:{stream_key[1]}",
                    'dst': f"{stream_key[2]}:{stream_key[3]}",
                    'tipo': 'TCP Stream'
                })
                
                print(f"[YARA-TCP]   📄 Stream {stream_id}: {len(payload_total)} bytes extraídos")
                stream_id += 1
        
        # Ordenar por tamanho e pegar os 10 maiores
        streams_extraidos.sort(key=lambda x: x['tamanho'], reverse=True)
        streams_extraidos = streams_extraidos[:10]
        
        print(f"[YARA-TCP] 📊 Total de {len(streams_extraidos)} streams TCP extraídos")
        return streams_extraidos
        
    except Exception as e:
        print(f"[YARA-TCP] ❌ Erro ao extrair streams: {e}")
        return []

def extrair_http_payloads_com_scapy(arquivo_pcap, pasta_base="http_files_yara"):
    """Extrai HTTP payloads usando Scapy - EXCLUSIVO PARA YARA"""
    if not os.path.exists(pasta_base):
        os.makedirs(pasta_base)
    
    print(f"[YARA-HTTP] 🌐 Extraindo HTTP payloads do PCAP: {arquivo_pcap}")
    
    try:
        pacotes = rdpcap(arquivo_pcap)
        arquivos_extraidos = []
        request_count = 0
        response_count = 0
        
        for pkt in pacotes:
            if Raw in pkt and TCP in pkt:
                payload = bytes(pkt[Raw].load)
                
                # Detectar HTTP requests
                if any(method in payload[:100] for method in [b'GET ', b'POST ', b'PUT ', b'DELETE ']):
                    if len(payload) > 50:
                        arquivo_http = os.path.join(pasta_base, f"http_request_{request_count}.bin")
                        with open(arquivo_http, 'wb') as f:
                            f.write(payload)
                        
                        arquivos_extraidos.append({
                            'arquivo': arquivo_http,
                            'tamanho': len(payload),
                            'tipo': 'HTTP Request',
                            'porta': pkt[TCP].dport
                        })
                        
                        request_count += 1
                        if request_count >= 20:  # Limitar requests
                            break
                
                # Detectar HTTP responses
                elif payload.startswith(b'HTTP/1.'):
                    if len(payload) > 50:
                        arquivo_http = os.path.join(pasta_base, f"http_response_{response_count}.bin")
                        with open(arquivo_http, 'wb') as f:
                            f.write(payload)
                        
                        arquivos_extraidos.append({
                            'arquivo': arquivo_http,
                            'tamanho': len(payload),
                            'tipo': 'HTTP Response',
                            'porta': pkt[TCP].sport
                        })
                        
                        response_count += 1
                        if response_count >= 20:  # Limitar responses
                            break
        
        print(f"[YARA-HTTP] 📊 Total de {len(arquivos_extraidos)} HTTP payloads extraídos")
        return arquivos_extraidos
        
    except Exception as e:
        print(f"[YARA-HTTP] ❌ Erro ao extrair HTTP: {e}")
        return []

def extrair_payloads_suspeitos_com_scapy(arquivo_pcap, pasta_base="suspicious_yara"):
    """Extrai payloads suspeitos (alta entropia, portas não padrão) usando Scapy - EXCLUSIVO PARA YARA"""
    if not os.path.exists(pasta_base):
        os.makedirs(pasta_base)
    
    print(f"[YARA-SUSP] 🚨 Extraindo payloads suspeitos do PCAP: {arquivo_pcap}")
    
    try:
        pacotes = rdpcap(arquivo_pcap)
        arquivos_extraidos = []
        contador = 0
        
        for pkt in pacotes:
            if Raw in pkt and TCP in pkt:
                payload = bytes(pkt[Raw].load)
                
                if len(payload) > 20:
                    # Calcular entropia
                    entropia = calcular_entropia(payload)
                    porta_dst = pkt[TCP].dport
                    
                    # Critérios de suspeita
                    suspeito = False
                    razoes = []
                    
                    if entropia > 7.0:  # Alta entropia
                        suspeito = True
                        razoes.append(f"Alta entropia ({entropia:.2f})")
                    
                    if porta_dst > 1024 and porta_dst not in [8080, 8443, 3389]:  # Porta não padrão
                        suspeito = True
                        razoes.append(f"Porta suspeita ({porta_dst})")
                    
                    if len(payload) > 50000:  # Payload muito grande
                        suspeito = True
                        razoes.append(f"Payload grande ({len(payload)} bytes)")
                    
                    if suspeito:
                        arquivo_susp = os.path.join(pasta_base, f"suspicious_{contador}.bin")
                        with open(arquivo_susp, 'wb') as f:
                            f.write(payload)
                        
                        arquivos_extraidos.append({
                            'arquivo': arquivo_susp,
                            'tamanho': len(payload),
                            'entropia': entropia,
                            'porta': porta_dst,
                            'razoes': razoes,
                            'tipo': 'Payload Suspeito'
                        })
                        
                        contador += 1
                        if contador >= 15:  # Limitar
                            break
        
        print(f"[YARA-SUSP] 📊 Total de {len(arquivos_extraidos)} payloads suspeitos extraídos")
        return arquivos_extraidos
        
    except Exception as e:
        print(f"[YARA-SUSP] ❌ Erro ao extrair suspeitos: {e}")
        return []

def analisar_arquivos_com_yara(arquivos_extraidos):
    """Analisa arquivos extraídos com YARA - ACESSO EXCLUSIVO ÀS REGRAS"""
    global YARA_RULES, YARA_ENABLED
    
    if not YARA_ENABLED or not YARA_RULES:
        print("[YARA] ❌ Regras YARA não disponíveis")
        return []
    
    print(f"[YARA] 🔍 Analisando {len(arquivos_extraidos)} arquivo(s) extraído(s)")
    deteccoes = []
    
    for arquivo_info in arquivos_extraidos:
        arquivo_path = arquivo_info['arquivo']
        
        try:
            matches = YARA_RULES.match(arquivo_path, timeout=5)
            
            if matches:
                for match in matches:
                    deteccoes.append({
                        'arquivo': os.path.basename(arquivo_path),
                        'arquivo_completo': arquivo_path,
                        'regra': match.rule,
                        'meta': dict(match.meta),
                        'tags': match.tags,
                        'strings': [str(string) for string in match.strings],
                        'tamanho_arquivo': arquivo_info.get('tamanho', 0),
                        'tipo_fonte': arquivo_info.get('tipo', 'desconhecido')
                    })
                    
                    print(f"[YARA] 🚨 DETECÇÃO: {match.rule} em {os.path.basename(arquivo_path)}")
            
        except Exception as e:
            print(f"[YARA] ⚠️ Erro ao analisar {arquivo_path}: {e}")
            continue
    
    print(f"[YARA] 📊 Total de {len(deteccoes)} detecções encontradas")
    return deteccoes

def gerar_relatorio_yara(deteccoes_yara):
    """Gera relatório YARA formatado para o LLM - ÚNICA INTERFACE EXTERNA"""
    
    if not deteccoes_yara:
        return {
            'status': 'limpo',
            'total_deteccoes': 0,
            'relatorio_texto': "✅ Nenhuma detecção YARA encontrada nos arquivos extraídos.",
            'deteccoes': []
        }
    
    # Criar relatório estruturado
    relatorio_texto = f"🚨 RELATÓRIO YARA - {len(deteccoes_yara)} DETECÇÕES DE MALWARE:\n\n"
    
    # Agrupar por regra
    deteccoes_por_regra = defaultdict(list)
    for det in deteccoes_yara:
        deteccoes_por_regra[det['regra']].append(det)
    
    # Relatório detalhado
    for i, (regra, deteccoes_regra) in enumerate(deteccoes_por_regra.items(), 1):
        relatorio_texto += f"{i}. REGRA: {regra}\n"
        relatorio_texto += f"   ARQUIVOS INFECTADOS: {len(deteccoes_regra)}\n"
        
        # Mostrar até 3 arquivos por regra
        for j, det in enumerate(deteccoes_regra[:3], 1):
            relatorio_texto += f"   {j}) {det['arquivo']} ({det['tamanho_arquivo']} bytes, {det['tipo_fonte']})\n"
            if det.get('tags'):
                relatorio_texto += f"      Tags: {', '.join(det['tags'])}\n"
            if det.get('strings'):
                relatorio_texto += f"      Strings detectadas: {len(det['strings'])}\n"
        
        if len(deteccoes_regra) > 3:
            relatorio_texto += f"   ... e mais {len(deteccoes_regra) - 3} arquivo(s)\n"
        relatorio_texto += "\n"
    
    # Estatísticas
    tipos_fonte = defaultdict(int)
    for det in deteccoes_yara:
        tipos_fonte[det['tipo_fonte']] += 1
    
    relatorio_texto += "📊 ESTATÍSTICAS DAS DETECÇÕES:\n"
    for tipo, count in tipos_fonte.items():
        relatorio_texto += f"   - {tipo}: {count} detecção(ões)\n"
    
    return {
        'status': 'infectado',
        'total_deteccoes': len(deteccoes_yara),
        'regras_ativadas': len(deteccoes_por_regra),
        'relatorio_texto': relatorio_texto,
        'deteccoes': deteccoes_yara[:10]  # Top 10 para detalhes
    }

def executar_analise_yara_completa(arquivo_pcap):
    """Executa análise YARA completa - FUNÇÃO PRINCIPAL DO MÓDULO YARA"""
    
    if not YARA_DEPENDENCIES_OK:
        return {
            'status': 'erro',
            'erro': 'Dependências YARA não disponíveis',
            'relatorio_texto': '❌ Análise YARA não pôde ser executada - dependências não instaladas'
        }
    
    print(f"[YARA] 🚀 Iniciando análise YARA completa de: {arquivo_pcap}")
    
    try:
        # Criar pasta temporária do sistema para extrações
        with tempfile.TemporaryDirectory(prefix="yara_extraction_") as pasta_temp:
            print(f"[YARA] 📁 Usando pasta temporária: {pasta_temp}")
            
            # 1. Extrair TCP streams
            streams_tcp = extrair_tcp_streams_com_scapy(arquivo_pcap, f"{pasta_temp}/tcp")
            
            # 2. Extrair HTTP payloads  
            payloads_http = extrair_http_payloads_com_scapy(arquivo_pcap, f"{pasta_temp}/http")
            
            # 3. Extrair payloads suspeitos
            payloads_suspeitos = extrair_payloads_suspeitos_com_scapy(arquivo_pcap, f"{pasta_temp}/suspicious")
        
            # 4. Combinar todos os arquivos
            todos_arquivos = streams_tcp + payloads_http + payloads_suspeitos
            
            if not todos_arquivos:
                return {
                    'status': 'sem_arquivos',
                    'total_deteccoes': 0,
                    'relatorio_texto': '⚠️ Nenhum arquivo foi extraído do PCAP para análise YARA'
                }
            
            # 5. Analisar com YARA
            deteccoes = analisar_arquivos_com_yara(todos_arquivos)
            
            # 6. Gerar relatório final
            relatorio = gerar_relatorio_yara(deteccoes)
            relatorio['arquivos_extraidos'] = len(todos_arquivos)
            relatorio['pasta_extracao'] = 'temporaria_removida_automaticamente'
            
            print(f"[YARA] ✅ Análise completa finalizada: {len(deteccoes)} detecções")
            print("[YARA] 🗑️ Pasta temporária será removida automaticamente")
            
            return relatorio
        # Pasta temporária é removida automaticamente aqui
        
    except Exception as e:
        print(f"[YARA] ❌ Erro na análise completa: {e}")
        return {
            'status': 'erro',
            'erro': str(e),
            'relatorio_texto': f'❌ Erro durante análise YARA: {str(e)}'
        }

# Função de teste (apenas para desenvolvimento)
if __name__ == "__main__":
    print("[YARA] 🧪 Testando módulo YARA...")
    print(f"[YARA] Status: {'✅ Ativo' if YARA_ENABLED else '❌ Inativo'}")
    
    if len(sys.argv) > 1:
        arquivo_teste = sys.argv[1]
        print(f"[YARA] Testando com arquivo: {arquivo_teste}")
        resultado = executar_analise_yara_completa(arquivo_teste)
        print(f"[YARA] Resultado: {resultado['status']}")
        print(resultado['relatorio_texto'])