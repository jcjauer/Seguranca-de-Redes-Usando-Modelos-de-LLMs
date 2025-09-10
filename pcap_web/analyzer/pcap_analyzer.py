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
                            round(calcular_entropia(raw_data),
                                  4) if raw_data else 0
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
                    tipos_pacotes.append(
                        f"Ethernet (tipo: {hex(pkt[Ether].type)})")
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
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(
            proto, f"Protocolo {proto}")
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

    # Detectar padrões suspeitos
    suspeitos = detectar_padroes_suspeitos(dados)
    if suspeitos:
        resumo += "\nPADRÕES SUSPEITOS DETECTADOS:\n"
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
            suspeitos.append(
                f"IP {ip} conectou a {len(destinos)} destinos diferentes")

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
Você é um especialista em segurança cibernética e análise de tráfego de rede. 
Analise os seguintes dados de rede e forneça uma análise detalhada sobre possíveis 
ameaças, anomalias e recomendações de segurança.

{dados_formatados}

ANÁLISE SOLICITADA:
1. Identifique possíveis ameaças e ataques
2. Classifique o nível de risco (Baixo/Médio/Alto)
3. Explique os indicadores suspeitos encontrados
4. Forneça recomendações de mitigação
5. Resumo executivo da situação de segurança

Seja específico e técnico, mas também didático para que um administrador 
de rede possa entender e agir.
"""

    try:
        # If a host/port is provided, set a small env fallback so the ollama client
        # or subprocess-based client may pick it up. This is best-effort: depending
        # on the installed ollama package, you may need to configure the client
        # differently. The values are set as hints for the environment.
        if host:
            os.environ.setdefault('OLLAMA_HOST', host)
        if port:
            os.environ.setdefault('OLLAMA_PORT', str(port))

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
        for model in models_response["models"]:
            name = model.get("name", model.get("model", "unknown"))
            models.append(name)
        return models if models else ["llama3"]
    except Exception:
        return ["llama3", "mistral", "gemma", "codellama"]


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
        analise_llm = analisar_com_llm(
            dados_formatados, modelo, host=host, port=port
        )

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
