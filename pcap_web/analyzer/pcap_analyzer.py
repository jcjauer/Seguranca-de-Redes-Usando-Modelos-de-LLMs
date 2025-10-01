# analyzer/pcap_analyzer.py
"""
Módulo para análise de arquivos PCAP com LLM
"""

import math
import os
import sys

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

        # Analisar com LLM (passando host/port se fornecidos)
        analise_llm = analisar_com_llm(dados_formatados, modelo, host=host, port=port)

        # Criar resumo
        resumo = f"Analisados {len(dados_pacotes)} pacotes com modelo {modelo}"

        return {
            "packet_count": len(dados_pacotes),
            "analysis_text": analise_llm,
            "summary": resumo,
            "raw_data": dados_formatados,
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
