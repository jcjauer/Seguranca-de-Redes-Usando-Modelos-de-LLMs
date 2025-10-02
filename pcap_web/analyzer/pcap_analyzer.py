# Função para extrair arquivos de múltiplos protocolos usando tshark
def extrair_arquivos_com_tshark(arquivo_pcap, pasta_base="tshark_extracted"):
    """
    Usa tshark para extrair arquivos de múltiplos protocolos do PCAP.
    Protocolos suportados: http, smb, tftp, dicom
    """
    import os, subprocess, glob, shutil
    
    # Protocolos testados e funcionais no tshark
    protocolos = [
        "http",    # Arquivos HTTP (páginas, imagens, downloads)
        "smb",     # Arquivos compartilhados via SMB
        "tftp",    # Arquivos transferidos via TFTP
        "dicom"    # Arquivos médicos DICOM
    ]
    
    arquivos_extraidos = []
    print(f"[TSHARK] Extraindo arquivos do PCAP: {arquivo_pcap}")
    
    if not os.path.exists(pasta_base):
        os.makedirs(pasta_base)
        print(f"[TSHARK] Pasta criada: {pasta_base}")
    
    for proto in protocolos:
        pasta_saida = os.path.join(pasta_base, proto)
        if not os.path.exists(pasta_saida):
            os.makedirs(pasta_saida)
        
        print(f"[TSHARK] Extraindo protocolo: {proto}")
        try:
            # Executa o tshark para extrair objetos
            result = subprocess.run([
                "tshark", "-r", arquivo_pcap, "--export-objects", f"{proto},{pasta_saida}"
            ], check=True, capture_output=True, text=True, timeout=30)
            
            # Verifica arquivos extraídos
            arquivos_proto = glob.glob(os.path.join(pasta_saida, "*"))
            if arquivos_proto:
                print(f"[TSHARK] ✅ {len(arquivos_proto)} arquivo(s) extraído(s) para {proto}")
                for arquivo in arquivos_proto:
                    tamanho = os.path.getsize(arquivo)
                    print(f"[TSHARK]   📄 {os.path.basename(arquivo)} ({tamanho} bytes)")
                    arquivos_extraidos.extend(arquivos_proto)
            else:
                print(f"[TSHARK] ❌ Nenhum arquivo encontrado para {proto}")
                
        except subprocess.TimeoutExpired:
            print(f"[TSHARK] ⏰ Timeout ao extrair {proto}")
        except subprocess.CalledProcessError as e:
            # Alguns protocolos podem não ter dados, isso é normal
            print(f"[TSHARK] ⚠️  Protocolo {proto} sem dados ou erro: {e.returncode}")
        except Exception as e:
            print(f"[TSHARK] ❌ Erro inesperado com {proto}: {e}")
    
    print(f"[TSHARK] 📊 Total de arquivos extraídos: {len(arquivos_extraidos)}")
    return arquivos_extraidos


def analisar_arquivos_com_yara(arquivos_extraidos):
    """
    Analisa arquivos extraídos pelo tshark usando regras YARA.
    Retorna lista de detecções de malware.
    """
    if not YARA_ENABLED:
        print("[YARA] ⚠️ YARA não está disponível ou regras não foram carregadas")
        return []
    
    deteccoes = []
    print(f"[YARA] 🔍 Analisando {len(arquivos_extraidos)} arquivo(s) extraído(s)")
    
    for arquivo_path in arquivos_extraidos:
        try:
            print(f"[YARA] 📄 Analisando: {os.path.basename(arquivo_path)}")
            
            # Lê o arquivo
            with open(arquivo_path, 'rb') as f:
                file_data = f.read()
            
            # Se o arquivo estiver vazio, pula
            if not file_data:
                print(f"[YARA]   ⚠️ Arquivo vazio, pulando")
                continue
            
            # Executa as regras YARA
            matches = YARA_RULES.match(data=file_data)
            
            if matches:
                print(f"[YARA]   🚨 {len(matches)} detecção(ões) encontrada(s)!")
                for match in matches:
                    deteccao = {
                        'arquivo': arquivo_path,
                        'arquivo_nome': os.path.basename(arquivo_path),
                        'regra': match.rule,
                        'tags': match.tags,
                        'strings': [(s.identifier, s.instances) for s in match.strings],
                        'tamanho_arquivo': len(file_data)
                    }
                    deteccoes.append(deteccao)
                    print(f"[YARA]     🎯 Regra: {match.rule}")
                    print(f"[YARA]     🏷️  Tags: {', '.join(match.tags) if match.tags else 'Nenhuma'}")
            else:
                print(f"[YARA]   ✅ Nenhuma ameaça detectada")
                
        except Exception as e:
            print(f"[YARA]   ❌ Erro ao analisar {arquivo_path}: {e}")
    
    print(f"[YARA] 📊 Total de detecções: {len(deteccoes)}")
    return deteccoes


def extrair_e_analisar_com_yara(arquivo_pcap, pasta_base="tshark_extracted"):
    """
    Função principal que combina extração com tshark e análise com YARA.
    """
    print("🚀 Iniciando extração e análise de malware...")
    
    # 1. Extrai arquivos do PCAP usando tshark
    arquivos_extraidos = extrair_arquivos_com_tshark(arquivo_pcap, pasta_base)
    
    if not arquivos_extraidos:
        print("⚠️ Nenhum arquivo foi extraído do PCAP")
        return {
            'arquivos_extraidos': [],
            'deteccoes_yara': [],
            'total_arquivos': 0,
            'total_deteccoes': 0,
            'arquivos_limpos': 0,
            'resumo': 'Nenhum arquivo extraído para análise'
        }
    
    # 2. Analisa os arquivos extraídos com YARA
    deteccoes = analisar_arquivos_com_yara(arquivos_extraidos)
    
    # 3. Gera resumo
    resumo = {
        'arquivos_extraidos': arquivos_extraidos,
        'deteccoes_yara': deteccoes,
        'total_arquivos': len(arquivos_extraidos),
        'total_deteccoes': len(deteccoes),
        'arquivos_limpos': len(arquivos_extraidos) - len([d for d in deteccoes]),
        'resumo': f"Extraídos {len(arquivos_extraidos)} arquivos, {len(deteccoes)} ameaças detectadas"
    }
    
    print(f"🎉 Análise concluída: {resumo['resumo']}")
    return resumo


# analyzer/pcap_analyzer.py
"""
Módulo para análise de arquivos PCAP com LLM
"""

import math
import os
import sys

# --- Reconstrução de arquivos HTTP do PCAP ---
def extrair_arquivos_de_pcap(arquivo_pcap, pasta_saida="extracted_files"):
    """Extrai arquivos de HTTP, FTP, SMTP (anexos base64), SMB e payloads TCP do PCAP."""
    import os, re, base64
    from scapy.all import rdpcap, TCP, Raw
    if not os.path.exists(pasta_saida):
        os.makedirs(pasta_saida)
    pacotes = rdpcap(arquivo_pcap)
    fluxos = {}
    arquivos_extraidos = []
    # Agrupa pacotes por fluxo TCP (src, sport, dst, dport)
    for pkt in pacotes:
        if TCP in pkt and Raw in pkt:
            ip = pkt["IP"] if "IP" in pkt else None
            if not ip:
                continue
            key = (ip.src, pkt[TCP].sport, ip.dst, pkt[TCP].dport)
            if key not in fluxos:
                fluxos[key] = b""
            fluxos[key] += bytes(pkt[Raw].load)
    for fluxo, dados in fluxos.items():
        # HTTP
        partes = re.split(b"HTTP/", dados)
        for parte in partes:
            if b"Content-Type" in parte and b"\r\n\r\n" in parte:
                cabecalho, corpo = parte.split(b"\r\n\r\n", 1)
                nome = None
                for linha in cabecalho.split(b"\r\n"):
                    if b"Content-Disposition" in linha and b"filename=" in linha:
                        nome = linha.split(b"filename=")[-1].strip().replace(b'"', b'').decode(errors="ignore")
                        break
                if not nome:
                    nome = f"http_file_{len(arquivos_extraidos)+1}.bin"
                caminho = os.path.join(pasta_saida, nome)
                with open(caminho, "wb") as f:
                    f.write(corpo)
                arquivos_extraidos.append(caminho)
        # FTP (busca por comandos STOR e arquivos binários)
        if b"STOR " in dados:
            arquivos = re.findall(b"STOR ([^\r\n]+)\r\n(.+?)(?=STOR |$)", dados, re.DOTALL)
            for nome, conteudo in arquivos:
                nome = nome.decode(errors="ignore").strip()
                caminho = os.path.join(pasta_saida, f"ftp_{nome}")
                with open(caminho, "wb") as f:
                    f.write(conteudo)
                arquivos_extraidos.append(caminho)
        # SMTP (anexos base64)
        if b"Content-Transfer-Encoding: base64" in dados:
            anexos = re.findall(b"Content-Transfer-Encoding: base64\r\n\r\n([A-Za-z0-9+/=\r\n]+)", dados)
            for idx, anexo in enumerate(anexos):
                try:
                    binario = base64.b64decode(anexo)
                    caminho = os.path.join(pasta_saida, f"smtp_attachment_{len(arquivos_extraidos)+1}.bin")
                    with open(caminho, "wb") as f:
                        f.write(binario)
                    arquivos_extraidos.append(caminho)
                except Exception:
                    pass
        # SMB (busca por padrões de arquivos)
        if b"\xFFSMB" in dados:
            # Simples: salva o payload SMB bruto
            caminho = os.path.join(pasta_saida, f"smb_payload_{len(arquivos_extraidos)+1}.bin")
            with open(caminho, "wb") as f:
                f.write(dados)
            arquivos_extraidos.append(caminho)
        # TCP genérico: salva payloads grandes
        if len(dados) > 100000:
            caminho = os.path.join(pasta_saida, f"tcp_payload_{len(arquivos_extraidos)+1}.bin")
            with open(caminho, "wb") as f:
                f.write(dados)
            arquivos_extraidos.append(caminho)
    return arquivos_extraidos

# Estrutura para descriptografia TLS (requer chave privada do servidor)
def tentar_descriptografar_tls(pcap_path, chave_privada_path, pcap_saida):
    """Descriptografa tráfego TLS de um PCAP usando chave privada (requer tshark instalado)."""
    # Exemplo de uso: tshark -r input.pcap -o "tls.keylog_file:chave.key" -w output_decrypted.pcap
    # Ou: tshark -r input.pcap -o "tls.keylog_file:chave.key" -Y ssl -w output_decrypted.pcap
    import subprocess
    cmd = [
        "tshark", "-r", pcap_path,
        "-o", f"tls.keylog_file:{chave_privada_path}",
        "-w", pcap_saida
    ]
    try:
        subprocess.run(cmd, check=True)
        return True
    except Exception as e:
        print(f"Erro ao descriptografar TLS: {e}")
        return False

# --- Carregamento automático das regras YARA da pasta 'yara' ---
try:
    import yara
    import glob
    # Caminho absoluto para a pasta de regras YARA
    YARA_RULES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'yara'))
    rule_files = glob.glob(os.path.join(YARA_RULES_DIR, '**', '*.yara'), recursive=True)
    rules_dict = {os.path.splitext(os.path.basename(f))[0]: f for f in rule_files}
    if rules_dict:
        YARA_RULES = yara.compile(filepaths=rules_dict)
        YARA_ENABLED = True
    else:
        YARA_RULES = None
        YARA_ENABLED = False
except Exception as e:
    YARA_RULES = None
    YARA_ENABLED = False
    print(f"[YARA] Falha ao carregar regras: {e}")

# Adicionar path do projeto principal para importar módulos
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))
sys.path.append(parent_dir)

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, Raw, DNS, DNSQR, ARP, Ether
    import ollama
except ImportError as e:
    print(f"Erro ao importar dependências: {e}")
    print("Certifique-se de que scapy e ollama estão instalados")

from .utils import get_ollama_models as get_ollama_models_subprocess


def detectar_dominios_suspeitos(dados):
    """Detecta domínios suspeitos, user-agents maliciosos e padrões de fraude"""
    suspeitos = {
        "dominios_suspeitos": [],
        "user_agents_maliciosos": [],
        "click_fraud_patterns": [],
        "short_urls": [],
        "asian_domains": [],
    }

    # Lista de domínios conhecidos por atividade maliciosa (baseado no seu exemplo)
    dominios_maliciosos = [
        "yl.liufen.com",
        "hqs9.cnzz.com",
        "doudouguo.com",
        "dw156.tk",
        "lckj77.com",
        "cnzz.com",
    ]

    # Padrões de User-Agent suspeitos
    user_agents_suspeitos = [
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/4.0",  # Antigo/desatualizado
        "Mozilla/5.0 (Windows NT 6.1)",  # Muito genérico
    ]

    # Padrões de URLs de fraude de clique
    click_fraud_keywords = [
        "/stat.htm",
        "/ck.aspx",
        "/sync_pos.htm",
        "cnzz_core_c.php",
        "repeatip=",
        "showp=",
        "rnd=",
    ]

    for pkt in dados:
        # Análise de DNS queries
        if pkt.get("dns_query"):
            query = pkt["dns_query"].lower()

            # Verificar domínios maliciosos conhecidos
            for dominio in dominios_maliciosos:
                if dominio in query:
                    suspeitos["dominios_suspeitos"].append(
                        {
                            "query": query,
                            "src_ip": pkt["src_ip"],
                            "tipo": "dominio_malicioso_conhecido",
                        }
                    )

            # Detectar domínios com TLD suspeitos (.tk, .ml, .ga, etc.)
            if any(tld in query for tld in [".tk", ".ml", ".ga", ".cf", ".xyz"]):
                suspeitos["dominios_suspeitos"].append(
                    {"query": query, "src_ip": pkt["src_ip"], "tipo": "tld_suspeito"}
                )

            # Detectar domínios asiáticos suspeitos
            if any(
                keyword in query for keyword in ["china", "asia", ".cn", ".hk", ".tw"]
            ):
                suspeitos["asian_domains"].append(query)

        # Análise de payload HTTP (se disponível em Raw data)
        if (
            pkt.get("entropy") and pkt["entropy"] < 4.0
        ):  # Baixa entropia = texto legível
            # Simular detecção de conteúdo HTTP suspeito
            # Em implementação real, você analisaria o payload do pacote
            src_port = pkt.get("src_port", 0)
            dst_port = pkt.get("dst_port", 0)

            # Portas HTTP/HTTPS
            if src_port in [80, 443, 8080] or dst_port in [80, 443, 8080]:
                # Aqui você poderia analisar o payload real do HTTP
                # Por enquanto, vamos simular baseado nos padrões que você mostrou
                suspeitos["click_fraud_patterns"].append(
                    {
                        "src_ip": pkt["src_ip"],
                        "dst_ip": pkt["dst_ip"],
                        "port": dst_port,
                        "suspeita": "trafego_http_suspeito",
                    }
                )

    return suspeitos


def calcular_entropia(data):
    """Calcula a entropia de dados binários"""
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


def processar_pcap(arquivo_pcap):
    """Processa arquivo PCAP e extrai informações dos pacotes"""
    try:
        pacotes = rdpcap(arquivo_pcap)
        resumo = []
        pacotes_sem_ip = 0

        for pkt in pacotes:
            info = None

            # Processar pacotes IP
            if IP in pkt:
                info = {
                    "src_ip": pkt[IP].src,
                    "dst_ip": pkt[IP].dst,
                    "protocol": pkt[IP].proto,
                    "ip_version": 4,
                    "length": len(pkt),
                    "entropy": None,
                    "src_port": None,
                    "dst_port": None,
                    "tcp_flags": None,
                    "dns_query": None,
                }

            # Processar pacotes IPv6
            elif IPv6 in pkt:
                info = {
                    "src_ip": pkt[IPv6].src,
                    "dst_ip": pkt[IPv6].dst,
                    "protocol": pkt[IPv6].nh,  # Next Header
                    "ip_version": 6,
                    "length": len(pkt),
                    "entropy": None,
                    "src_port": None,
                    "dst_port": None,
                    "tcp_flags": None,
                    "dns_query": None,
                }

            # Processar pacotes ARP
            elif ARP in pkt:
                info = {
                    "src_ip": pkt[ARP].psrc,
                    "dst_ip": pkt[ARP].pdst,
                    "protocol": "ARP",
                    "ip_version": "ARP",
                    "length": len(pkt),
                    "entropy": None,
                    "src_port": None,
                    "dst_port": None,
                    "tcp_flags": None,
                    "dns_query": None,
                    "arp_op": pkt[ARP].op,  # Operação ARP (request/reply)
                }

            # Tentar interpretar pacotes Raw como possíveis dados IP
            # Tamanho mínimo de um cabeçalho IP
            elif Raw in pkt and len(pkt) > 20:
                try:
                    # Tentar interpretar dados Raw como IP
                    raw_data = bytes(pkt[Raw].load)

                    # Verificar se os primeiros bytes parecem um cabeçalho IP
                    if len(raw_data) >= 20:
                        version = (raw_data[0] >> 4) & 0xF
                        if version == 4:  # IPv4
                            # Tentar criar pacote IP a partir dos dados Raw
                            ip_pkt = IP(raw_data)
                            info = {
                                "src_ip": ip_pkt.src,
                                "dst_ip": ip_pkt.dst,
                                "protocol": ip_pkt.proto,
                                "ip_version": 4,
                                "length": len(pkt),
                                "entropy": None,
                                "src_port": None,
                                "dst_port": None,
                                "tcp_flags": None,
                                "dns_query": None,
                                "raw_interpreted": True,
                            }

                            # Verificar se há TCP/UDP dentro dos dados Raw
                            if TCP in ip_pkt:
                                info["tcp_flags"] = str(ip_pkt[TCP].flags)
                                info["src_port"] = ip_pkt[TCP].sport
                                info["dst_port"] = ip_pkt[TCP].dport
                            elif UDP in ip_pkt:
                                info["src_port"] = ip_pkt[UDP].sport
                                info["dst_port"] = ip_pkt[UDP].dport

                        elif version == 6:  # IPv6
                            ipv6_pkt = IPv6(raw_data)
                            info = {
                                "src_ip": ipv6_pkt.src,
                                "dst_ip": ipv6_pkt.dst,
                                "protocol": ipv6_pkt.nh,
                                "ip_version": 6,
                                "length": len(pkt),
                                "entropy": None,
                                "src_port": None,
                                "dst_port": None,
                                "tcp_flags": None,
                                "dns_query": None,
                                "raw_interpreted": True,
                            }
                except:
                    # Se falhar a interpretação, criar entrada genérica para dados Raw
                    raw_data = bytes(pkt[Raw].load)
                    info = {
                        "src_ip": "Raw Data",
                        "dst_ip": "Unknown",
                        "protocol": "Raw",
                        "ip_version": "Raw",
                        "length": len(pkt),
                        "entropy": (
                            round(calcular_entropia(raw_data), 4) if raw_data else 0
                        ),
                        "src_port": None,
                        "dst_port": None,
                        "tcp_flags": None,
                        "dns_query": None,
                        "raw_data_hex": raw_data[:32].hex() if raw_data else "",
                    }

            # Se encontrou um tipo de pacote suportado
            if info:
                # Só processar TCP/UDP se não foi interpretado como Raw
                if not info.get("raw_interpreted", False):
                    # Informações TCP
                    if TCP in pkt:
                        info["tcp_flags"] = str(pkt[TCP].flags)
                        info["src_port"] = pkt[TCP].sport
                        info["dst_port"] = pkt[TCP].dport

                    # Informações UDP
                    elif UDP in pkt:
                        info["src_port"] = pkt[UDP].sport
                        info["dst_port"] = pkt[UDP].dport

                        # Verificar DNS
                        if DNS in pkt:
                            try:
                                if pkt[DNS].qd:
                                    info["dns_query"] = pkt[DNS].qd.qname.decode(
                                        "utf-8"
                                    )
                            except:
                                pass

                # Calcular entropia do payload se ainda não foi calculada
                if not info.get("entropy") and Raw in pkt:
                    payload = bytes(pkt[Raw].load)
                    info["entropy"] = round(calcular_entropia(payload), 4)

                resumo.append(info)
            else:
                # Contar pacotes não suportados
                pacotes_sem_ip += 1

        # Se não há pacotes suportados, retornar erro mais informativo
        if not resumo:
            tipos_pacotes = []
            for pkt in pacotes[:10]:  # Analisar apenas os primeiros 10 pacotes
                if Ether in pkt:
                    tipos_pacotes.append(f"Ethernet (tipo: {hex(pkt[Ether].type)})")
                elif Raw in pkt:
                    tipos_pacotes.append("Raw Data")
                else:
                    tipos_pacotes.append(str(type(pkt).__name__))

            raise Exception(
                f"Nenhum pacote IP/IPv6/ARP/Raw interpretável encontrado no arquivo PCAP. "
                f"Total de pacotes: {len(pacotes)}, "
                f"Pacotes não suportados: {pacotes_sem_ip}. "
                f"Tipos encontrados: {', '.join(set(tipos_pacotes[:5]))}. "
                f"Este arquivo pode conter protocolos não suportados ou dados corrompidos."
            )

        return resumo

    except Exception as e:
        raise Exception(f"Erro ao processar PCAP: {str(e)}")


def analisar_padroes_botnet(dados, ips_origem, ips_destino):
    """Analisa padrões específicos de botnet e malware"""
    padroes = {
        "hosts_com_multiplas_conexoes": {},  # Host interno -> múltiplos destinos externos
        "comunicacao_c2": [],  # Possível Command & Control
        "beaconing": {},  # Comunicação periódica
        "data_exfiltration": [],  # Transferências suspeitas
        "port_scanning": {},  # Tentativas de port scan
        "flood_attacks": {},  # Ataques de flood
        "crypto_mining": [],  # Padrões de crypto mining
        "click_fraud": [],  # Fraude de cliques
    }

    # Analisar hosts com múltiplas conexões externas (indicador de botnet)
    conexoes_por_host = {}
    for pkt in dados:
        src_ip = pkt["src_ip"]
        dst_ip = pkt["dst_ip"]

        if src_ip and dst_ip:
            # Identificar redes internas vs externas (assumindo 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)
            is_src_internal = (
                src_ip.startswith("10.")
                or src_ip.startswith("192.168.")
                or src_ip.startswith("172.")
            )
            is_dst_external = not (
                dst_ip.startswith("10.")
                or dst_ip.startswith("192.168.")
                or dst_ip.startswith("172.")
            )

            if is_src_internal and is_dst_external:
                if src_ip not in conexoes_por_host:
                    conexoes_por_host[src_ip] = set()
                conexoes_por_host[src_ip].add(dst_ip)

    # Identificar hosts com muitas conexões externas (possível botnet)
    for host, destinos in conexoes_por_host.items():
        if len(destinos) > 5:  # Threshold ajustável
            padroes["hosts_com_multiplas_conexoes"][host] = len(destinos)

    # Detectar flooding (muitos pacotes para o mesmo destino)
    flood_contador = {}
    for pkt in dados:
        key = (pkt["src_ip"], pkt["dst_ip"], pkt["dst_port"])
        if key[0] and key[1]:
            if key not in flood_contador:
                flood_contador[key] = 0
            flood_contador[key] += 1

    # Identificar floods suspeitos
    for (src, dst, port), count in flood_contador.items():
        if count > 100:  # Threshold ajustável
            padroes["flood_attacks"][f"{src} → {dst}:{port}"] = count

    # Detectar port scanning (mesmo IP tentando múltiplas portas)
    port_scan_detector = {}
    for pkt in dados:
        if pkt["src_ip"] and pkt["dst_ip"] and pkt["dst_port"]:
            key = (pkt["src_ip"], pkt["dst_ip"])
            if key not in port_scan_detector:
                port_scan_detector[key] = set()
            port_scan_detector[key].add(pkt["dst_port"])

    # Identificar port scans
    for (src, dst), ports in port_scan_detector.items():
        if len(ports) > 10:  # Threshold ajustável
            padroes["port_scanning"][f"{src} → {dst}"] = len(ports)

    # Detectar alta entropia (possível comunicação C2 criptografada)
    for pkt in dados:
        if pkt["entropy"] and pkt["entropy"] > 7.0:  # Muito alta entropia
            padroes["comunicacao_c2"].append(
                {
                    "src": pkt["src_ip"],
                    "dst": pkt["dst_ip"],
                    "port": pkt["dst_port"],
                    "entropy": pkt["entropy"],
                }
            )

    return padroes


def formatar_dados_para_analise(dados):
    """Formata dados dos pacotes para análise pelo LLM"""
    # Estatísticas gerais
    total_pacotes = len(dados)
    ips_origem = set(pkt["src_ip"] for pkt in dados)
    ips_destino = set(pkt["dst_ip"] for pkt in dados)
    protocolos = {}
    portas_destino = {}
    entropias_altas = []
    tipos_ip = {"IPv4": 0, "IPv6": 0, "ARP": 0, "Raw": 0}

    for pkt in dados:
        # Contar tipos de IP
        if pkt.get("ip_version") == 4:
            tipos_ip["IPv4"] += 1
        elif pkt.get("ip_version") == 6:
            tipos_ip["IPv6"] += 1
        elif pkt.get("ip_version") == "ARP":
            tipos_ip["ARP"] += 1
        elif pkt.get("ip_version") == "Raw":
            tipos_ip["Raw"] += 1

        # Contar protocolos
        proto = pkt["protocol"]
        protocolos[proto] = protocolos.get(proto, 0) + 1

        # Contar portas de destino
        if pkt["dst_port"]:
            porta = pkt["dst_port"]
            portas_destino[porta] = portas_destino.get(porta, 0) + 1

        # Detectar alta entropia
        if pkt["entropy"] and pkt["entropy"] > 6.0:
            entropias_altas.append(pkt)

    # ANÁLISE AVANÇADA DE PADRÕES DE BOTNET
    padroes_suspeitos = analisar_padroes_botnet(dados, ips_origem, ips_destino)

    # ANÁLISE DE DOMÍNIOS E FRAUDE
    dominios_suspeitos = detectar_dominios_suspeitos(dados)

    # Criar resumo estruturado
    resumo = f"""
RESUMO DA ANÁLISE DE REDE:

ESTATÍSTICAS GERAIS:
- Total de pacotes: {total_pacotes}
- IPv4: {tipos_ip["IPv4"]} pacotes
- IPv6: {tipos_ip["IPv6"]} pacotes  
- ARP: {tipos_ip["ARP"]} pacotes
- Raw Data: {tipos_ip["Raw"]} pacotes
- IPs de origem únicos: {len(ips_origem)}
- IPs de destino únicos: {len(ips_destino)}

PROTOCOLOS DETECTADOS:
"""

    for proto, count in sorted(protocolos.items(), key=lambda x: x[1], reverse=True):
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"Protocolo {proto}")
        resumo += f"- {proto_name}: {count} pacotes\n"

    resumo += "\nPORTAS MAIS ACESSADAS:\n"
    for porta, count in sorted(
        portas_destino.items(), key=lambda x: x[1], reverse=True
    )[:10]:
        porta_name = get_port_service(porta)
        resumo += f"- Porta {porta} ({porta_name}): {count} pacotes\n"

    if entropias_altas:
        resumo += f"\nPACOTES COM ALTA ENTROPIA (>6.0): {len(entropias_altas)}\n"
        for pkt in entropias_altas[:5]:  # Mostrar apenas os primeiros 5
            resumo += f"- {pkt['src_ip']} → {pkt['dst_ip']}:{pkt['dst_port']} (entropia: {pkt['entropy']})\n"

    # Adicionar análise avançada de padrões de botnet
    resumo += "\n🚨 ANÁLISE DE PADRÕES MALICIOSOS:\n"

    if padroes_suspeitos["hosts_com_multiplas_conexoes"]:
        resumo += "\n⚠️ HOSTS COM MÚLTIPLAS CONEXÕES EXTERNAS (Possível Botnet):\n"
        for host, count in padroes_suspeitos["hosts_com_multiplas_conexoes"].items():
            resumo += f"- {host} conectou-se a {count} destinos externos diferentes\n"

    if padroes_suspeitos["flood_attacks"]:
        resumo += "\n🌊 ATAQUES DE FLOODING DETECTADOS:\n"
        for flood, count in list(padroes_suspeitos["flood_attacks"].items())[:5]:
            resumo += f"- {flood}: {count} pacotes\n"

    if padroes_suspeitos["port_scanning"]:
        resumo += "\n🔍 PORT SCANNING DETECTADO:\n"
        for scan, ports in padroes_suspeitos["port_scanning"].items():
            resumo += f"- {scan} testou {ports} portas diferentes\n"

    if padroes_suspeitos["comunicacao_c2"]:
        resumo += "\n📡 POSSÍVEL COMUNICAÇÃO C&C (Alta Entropia):\n"
        for c2 in padroes_suspeitos["comunicacao_c2"][:5]:
            resumo += f"- {c2['src']} → {c2['dst']}:{c2['port']} (entropia: {c2['entropy']:.2f})\n"

    # Adicionar análise de domínios suspeitos
    if dominios_suspeitos["dominios_suspeitos"]:
        resumo += "\n🌐 DOMÍNIOS SUSPEITOS DETECTADOS:\n"
        for dom in dominios_suspeitos["dominios_suspeitos"][:5]:
            resumo += f"- {dom['query']} (de {dom['src_ip']}) - {dom['tipo']}\n"

    if dominios_suspeitos["click_fraud_patterns"]:
        resumo += "\n💰 POSSÍVEL FRAUDE DE CLIQUES:\n"
        for fraud in dominios_suspeitos["click_fraud_patterns"][:5]:
            resumo += f"- {fraud['src_ip']} → {fraud['dst_ip']}:{fraud['port']} - {fraud['suspeita']}\n"

    if dominios_suspeitos["asian_domains"]:
        resumo += "\n🏮 DOMÍNIOS ASIÁTICOS DETECTADOS:\n"
        for domain in set(dominios_suspeitos["asian_domains"][:5]):
            resumo += f"- {domain}\n"

    # Detectar padrões suspeitos antigos (manter compatibilidade)
    suspeitos = detectar_padroes_suspeitos(dados)
    if suspeitos:
        resumo += "\nPADRÕES SUSPEITOS ADICIONAIS:\n"
        for padrao in suspeitos:
            resumo += f"- {padrao}\n"

    return resumo


def detectar_padroes_suspeitos(dados):
    """Detecta padrões potencialmente suspeitos nos dados"""
    suspeitos = []

    # Contar conexões por IP de origem
    conexoes_por_ip = {}
    portas_por_ip = {}

    for pkt in dados:
        src_ip = pkt["src_ip"]
        dst_ip = pkt["dst_ip"]
        dst_port = pkt["dst_port"]

        # Contar conexões
        key = f"{src_ip}→{dst_ip}"
        conexoes_por_ip[key] = conexoes_por_ip.get(key, 0) + 1

        # Contar portas por IP origem
        if dst_port:
            if src_ip not in portas_por_ip:
                portas_por_ip[src_ip] = set()
            portas_por_ip[src_ip].add(dst_port)

    # Detectar possível port scanning
    for ip, portas in portas_por_ip.items():
        if len(portas) > 10:  # Mais de 10 portas diferentes
            suspeitos.append(
                f"Possível port scan de {ip} (testou {len(portas)} portas)"
            )

    # Detectar possível DDoS/flooding
    for conexao, count in conexoes_por_ip.items():
        if count > 20:  # Mais de 20 pacotes para a mesma conexão
            suspeitos.append(f"Possível flooding: {conexao} ({count} pacotes)")

    # Detectar IPs com muitas conexões diferentes
    ips_origem_stats = {}
    for pkt in dados:
        src_ip = pkt["src_ip"]
        if src_ip not in ips_origem_stats:
            ips_origem_stats[src_ip] = set()
        ips_origem_stats[src_ip].add(pkt["dst_ip"])

    for ip, destinos in ips_origem_stats.items():
        if len(destinos) > 10:  # Conectou a mais de 10 IPs diferentes
            suspeitos.append(f"IP {ip} conectou a {len(destinos)} destinos diferentes")

    return suspeitos


def get_port_service(porta):
    """Retorna o serviço conhecido para uma porta"""
    servicos = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP",
        68: "DHCP",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        993: "IMAPS",
        995: "POP3S",
        1433: "SQL Server",
        3389: "RDP",
        5432: "PostgreSQL",
        3306: "MySQL",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
    }
    return servicos.get(porta, "Desconhecido")


def analisar_com_llm(dados_formatados, modelo="llama3", host=None, port=None):
    """Envia dados para análise pelo LLM"""
    prompt = f"""
Você é um especialista em segurança cibernética e análise forense de tráfego de rede especializado em detecção de malware, botnets e ataques APT (Advanced Persistent Threats).

DADOS DE TRÁFEGO PARA ANÁLISE:
{dados_formatados}

EXECUTE UMA ANÁLISE FORENSE DETALHADA FOCANDO EM:

🚨 DETECÇÃO DE MALWARE E BOTNETS:
- Identifique padrões de comunicação C&C (Command & Control)
- Detecte tráfego criptografado suspeito (alta entropia)
- Analise conexões com IPs externos não autorizados
- Procure por beaconing (comunicação periódica com servidores remotos)
- Identifique múltiplas conexões de um host interno para destinos externos
- Detecte tráfego HTTP/HTTPS para domínios suspeitos ou recém-registrados

🔍 INDICADORES DE COMPROMISSO (IOCs):
- Hosts internos iniciando muitas conexões externas simultâneas
- Tráfego em portas não padronizadas (especialmente > 1024)
- Comunicação com IPs de países com alta atividade maliciosa
- Padrões de DNS suspeitos (DGA - Domain Generation Algorithm)
- Transferências de dados volumosas para fora da rede
- Atividade de rede fora do horário comercial

⚔️ TÉCNICAS DE ATAQUE AVANÇADAS:
- Port scanning e network reconnaissance
- Data exfiltration (baseado em volume e destino)
- Lateral movement (propagação interna)
- Click fraud e ad fraud (requisições HTTP suspeitas)
- Crypto-mining malware (alta utilização de rede)
- Ransomware communication patterns

📊 ANÁLISE COMPORTAMENTAL:
- Compare volumes de tráfego por host (identifique outliers)
- Analise protocolos incomuns ou mal formados
- Detecte anomalias temporais (rajadas de tráfego)
- Identifique comunicação peer-to-peer suspeita

FORNEÇA UMA RESPOSTA ESTRUTURADA COM:

1. **CLASSIFICAÇÃO DE RISCO** (Crítico/Alto/Médio/Baixo)

2. **AMEAÇAS IDENTIFICADAS** (seja específico sobre o tipo de malware/botnet)

3. **HOSTS COMPROMETIDOS** (liste IPs suspeitos e evidências)

4. **INDICADORES TÉCNICOS** (IOCs específicos encontrados)

5. **PADRÕES DE ATAQUE** (descreva a campanha maliciosa)

6. **IMPACTO POTENCIAL** (que dados/sistemas estão em risco)

7. **AÇÕES IMEDIATAS** (contenção e isolamento)

8. **INVESTIGAÇÃO FORENSE** (próximos passos para análise)

9. **REMEDIAÇÃO** (limpeza e fortalecimento)

10. **MONITORAMENTO** (detecção contínua)

Seja extremamente detalhado em aspectos técnicos e forneça comandos específicos, IPs para bloqueio, e procedimentos operacionais. Assuma que você está analisando um possível incidente de segurança crítico.

**ATENÇÃO:**
No final do relatório, APRESENTE O RELATÓRIO YARA COMPLETO exatamente como recebido, em um bloco destacado, SEM OMITIR NENHUMA LINHA. Em seguida, explique detalhadamente todos os malwares identificados pelas regras YARA, justificando cada identificação.
"""

    try:
        # If a host/port is provided, set a small env fallback so the ollama client
        # or subprocess-based client may pick it up. This is best-effort: depending
        # on the installed ollama package, you may need to configure the client
        # differently. The values are set as hints for the environment.
        if host:
            os.environ.setdefault("OLLAMA_HOST", host)
        if port:
            os.environ.setdefault("OLLAMA_PORT", str(port))

        resposta = ollama.chat(
            model=modelo, messages=[{"role": "user", "content": prompt}]
        )
        return resposta["message"]["content"]
    except Exception as e:
        raise Exception(f"Erro ao conectar com o modelo {modelo}: {str(e)}")


def get_available_models():
    """Retorna lista de modelos LLM disponíveis"""
    try:
        models_response = ollama.list()
        models = []
        # Support different return shapes: dict with 'models' key or direct list
        if isinstance(models_response, dict) and "models" in models_response:
            iterable = models_response["models"]
        elif isinstance(models_response, list):
            iterable = models_response
        else:
            iterable = []

        for model in iterable:
            if isinstance(model, dict):
                name = model.get("name", model.get("model", "unknown"))
            else:
                # model may be a plain string
                name = str(model)
            models.append(name)

        if models:
            return models
        # fallback to subprocess parser if Python API returned empty
        return get_ollama_models_subprocess()
    except Exception:
        # on error, return empty list to indicate none available
        # fallback to subprocess-based listing which matches CLI output
        return get_ollama_models_subprocess()


def get_ollama_status(host=None, port=None):
    """Verifica se o Ollama está acessível e retorna um resumo simples.

    Retorna um dicionário com chaves: ok (bool), models (int, opcional), error (str, opcional)
    """
    try:
        # aplicar host/port como fallback de ambiente se fornecidos
        if host:
            os.environ.setdefault("OLLAMA_HOST", host)
        if port:
            os.environ.setdefault("OLLAMA_PORT", str(port))

        try:
            resp = ollama.list()
        except Exception:
            resp = None
        # normalize response to a list of models
        if resp:
            if isinstance(resp, dict) and "models" in resp:
                models = resp["models"] or []
            elif isinstance(resp, list):
                models = resp
            else:
                models = []

            # count entries; if entries are dicts try to extract name
            count = 0
            for m in models:
                if m:
                    count += 1

            # if we couldn't find models via the Python client, fallback to subprocess parser
            if count == 0:
                parsed = get_ollama_models_subprocess()
                return {"ok": True, "models": len(parsed)}

            return {"ok": True, "models": count}
        else:
            # fallback to subprocess parser which reads CLI output
            parsed = get_ollama_models_subprocess()
            return {"ok": True, "models": len(parsed)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def analyze_pcap_with_llm(arquivo_pcap, modelo="llama3", host=None, port=None):
    """Função principal para análise completa de PCAP com LLM"""
    try:
        # Processar PCAP
        dados_pacotes = processar_pcap(arquivo_pcap)
        if not dados_pacotes:
            raise Exception("Nenhum pacote IP encontrado no arquivo PCAP")

        # Formatar dados para análise
        dados_formatados = formatar_dados_para_analise(dados_pacotes)

        # Gerar relatório YARA

        from scapy.all import Raw, rdpcap
        global YARA_RULES, YARA_ENABLED
        yara_deteccoes = []
        yara_deteccoes_buffer = []
        if 'YARA_RULES' in globals() and YARA_ENABLED:
            pacotes = rdpcap(arquivo_pcap)
            # 1. Análise por pacote (como já fazia)
            for pkt in pacotes:
                if Raw in pkt:
                    payload = bytes(pkt[Raw].load)
                    try:
                        matches = YARA_RULES.match(data=payload, timeout=2)
                    except Exception:
                        matches = []
                    for m in matches:
                        def extract_string_data(s):
                            # Compatível com tupla (antigo) ou objeto StringMatch (novo)
                            if hasattr(s, 'data'):
                                val = s.data
                            elif isinstance(s, (tuple, list)) and len(s) > 2:
                                val = s[2]
                            else:
                                val = str(s)
                            return val.decode(errors="ignore") if isinstance(val, bytes) else str(val)
                        det = {
                            "rule": m.rule,
                            "namespace": m.namespace,
                            "strings": [extract_string_data(s) for s in m.strings]
                        }
                        yara_deteccoes.append(det)
            # 2. Análise em buffer agregado
            all_payloads = b"".join(bytes(pkt[Raw].load) for pkt in pacotes if Raw in pkt)
            if all_payloads:
                try:
                    matches_buffer = YARA_RULES.match(data=all_payloads, timeout=5)
                except Exception:
                    matches_buffer = []
                for m in matches_buffer:
                    def extract_string_data(s):
                        if hasattr(s, 'data'):
                            val = s.data
                        elif isinstance(s, (tuple, list)) and len(s) > 2:
                            val = s[2]
                        else:
                            val = str(s)
                        return val.decode(errors="ignore") if isinstance(val, bytes) else str(val)
                    det = {
                        "rule": m.rule,
                        "namespace": m.namespace,
                        "strings": [extract_string_data(s) for s in m.strings]
                    }
                    yara_deteccoes_buffer.append(det)

            # 3. Reconstrução de arquivos HTTP e análise YARA neles
            # Extrai arquivos com tshark (multi-protocolo)
            arquivos_tshark = extrair_arquivos_com_tshark(arquivo_pcap)
            # Extrai arquivos com método Python (multi-protocolo)
            arquivos_extraidos = extrair_arquivos_de_pcap(arquivo_pcap)
            todos_arquivos = set(arquivos_tshark + arquivos_extraidos)
            yara_deteccoes_arquivos = []
            for arq in todos_arquivos:
                try:
                    with open(arq, "rb") as f:
                        dados = f.read()
                    matches_file = YARA_RULES.match(data=dados, timeout=5)
                except Exception:
                    matches_file = []
                for m in matches_file:
                    def extract_string_data(s):
                        if hasattr(s, 'data'):
                            val = s.data
                        elif isinstance(s, (tuple, list)) and len(s) > 2:
                            val = s[2]
                        else:
                            val = str(s)
                        return val.decode(errors="ignore") if isinstance(val, bytes) else str(val)
                    det = {
                        "rule": m.rule,
                        "namespace": m.namespace,
                        "strings": [extract_string_data(s) for s in m.strings],
                        "arquivo": arq
                    }
                    yara_deteccoes_arquivos.append(det)
        # Montar relatório

        total_deteccoes = len(yara_deteccoes) + len(yara_deteccoes_buffer)
        relatorio_yara = ""
        if total_deteccoes:
            relatorio_yara += f"Foram detectadas {total_deteccoes} ameaças por YARA:\n"
            if yara_deteccoes:
                relatorio_yara += "\n- Detecções por pacote:\n"
                for det in yara_deteccoes:
                    relatorio_yara += f"  - Regra: {det['rule']} (namespace: {det['namespace']}) | Strings: {', '.join(det['strings'])}\n"
            if yara_deteccoes_buffer:
                relatorio_yara += "\n- Detecções no buffer agregado:\n"
                for det in yara_deteccoes_buffer:
                    relatorio_yara += f"  - Regra: {det['rule']} (namespace: {det['namespace']}) | Strings: {', '.join(det['strings'])}\n"
        # Relatório de arquivos HTTP
        if 'yara_deteccoes_arquivos' in locals() and yara_deteccoes_arquivos:
            relatorio_yara += f"\n- Detecções em arquivos HTTP extraídos:\n"
            for det in yara_deteccoes_arquivos:
                relatorio_yara += f"  - Arquivo: {det['arquivo']} | Regra: {det['rule']} (namespace: {det['namespace']}) | Strings: {', '.join(det['strings'])}\n"
        if not relatorio_yara:
            relatorio_yara = "Nenhuma ameaça detectada pelas regras YARA."

        # Acrescentar o relatório YARA ao final dos dados formatados
        dados_formatados_com_yara = f"{dados_formatados}\n\nRELATÓRIO YARA:\n{relatorio_yara}"

        # Analisar com LLM (passando host/port se fornecidos)
        analise_llm = analisar_com_llm(dados_formatados_com_yara, modelo, host=host, port=port)

        return {
            "packet_count": len(dados_pacotes),
            "analysis_text": analise_llm,
            "summary": analise_llm,
            "raw_data": dados_formatados_com_yara,
        }
    except Exception as e:
        raise Exception(f"Erro na análise: {str(e)}")


if __name__ == "__main__":
    # Teste local
    print("Testando analisador PCAP...")
    try:
        models = get_available_models()
        print(f"Modelos disponíveis: {models}")
    except Exception as e:
        print(f"Erro: {e}")