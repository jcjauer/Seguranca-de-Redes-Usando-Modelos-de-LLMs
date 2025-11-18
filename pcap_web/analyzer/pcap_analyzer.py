# analyzer/pcap_analyzer.py
"""
Módulo para análise de arquivos PCAP com LLM
"""

import math
import os
import sys
import logging
import struct
import csv
from collections import defaultdict

# Configurar o logger
# Nível INFO: logger.info(), Nível AVISO: logger.warning(), Nível ERRO: logger.error()
logger = logging.getLogger(__name__)

# Adicionar path do projeto principal para importar módulos (APENAS PARA TESTE LOCAL)
# Esta lógica foi movida para o bloco __main__ para não sujar o escopo global
# current_dir = os.path.dirname(os.path.abspath(__file__))
# parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))
# sys.path.append(parent_dir)

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, Raw, DNS, ARP, Ether
    import ollama

    DEPENDENCIES_OK = True
except ImportError as e:
    logger.critical(f"Erro ao importar dependências: {e}")
    logger.critical("Certifique-se de que scapy e ollama estão instalados")
    DEPENDENCIES_OK = False

# Importação condicional para evitar erro quando executado diretamente
try:
    from .utils import get_ollama_models as get_ollama_models_subprocess
    from .yara_detector import (
        executar_analise_yara_completa,
    )  # INTEGRAÇÃO COM MÓDULO YARA
except ImportError:
    # Fallback quando executado diretamente
    logger.warning(
        "Executando em modo 'standalone'. Módulos .utils e .yara_detector não carregados."
    )

    def get_ollama_models_subprocess():
        return ["llama3", "llama3.1", "qwen2.5"]

    def executar_analise_yara_completa(arquivo_pcap):
        return {
            "status": "erro",
            "relatorio_texto": "❌ Módulo YARA não disponível (modo standalone)",
        }


################################################################################
# 1. CENTRAL DE CONFIGURAÇÃO E INDICADORES DE COMPROMETIMENTO (IOCs)
################################################################################


class Config:
    """Central de configuração para thresholds e scores"""

    # === Thresholds de Detecção ===
    # Múltiplas Conexões (Botnet)
    BOTNET_CONNECTIONS_LOW = 20
    BOTNET_CONNECTIONS_MEDIUM = 30
    BOTNET_CONNECTIONS_HIGH = 50
    BOTNET_CONNECTIONS_CRITICAL = 100

    # Port Scanning
    PORT_SCAN_LOW = 30
    PORT_SCAN_MEDIUM = 50
    PORT_SCAN_HIGH = 100
    PORT_SCAN_CRITICAL = 200

    # Flooding
    FLOOD_LOW = 1000
    FLOOD_MEDIUM = 2000
    FLOOD_HIGH = 5000
    FLOOD_CRITICAL = 10000

    # DDoS Específico
    SYN_FLOOD_MIN_PACKETS = 100
    SYN_FLOOD_ACK_RATIO = 0.1  # < 10% de ACKs indica SYN Flood
    UDP_FLOOD_THRESHOLD = 500
    UDP_FLOOD_DNS_THRESHOLD = 1000
    ICMP_FLOOD_LOW = 200
    ICMP_FLOOD_HIGH = 1000
    ACK_FLOOD_THRESHOLD = 300
    HTTP_SLOWLORIS_CONNECTIONS = 50
    ARP_SPOOFING_THRESHOLD = 50
    DNS_AMPLIFICATION_MIN_SIZE = 512  # bytes
    DNS_AMPLIFICATION_MIN_COUNT = 10
    DNS_AMPLIFICATION_MIN_BYTES = 10000
    FRAGMENT_ATTACK_SMALL_PKT_SIZE = 100
    FRAGMENT_ATTACK_THRESHOLD = 500
    DDOS_DISTRIBUTED_SOURCES = 10  # Número mínimo de fontes para DDoS distribuído
    
    # Anomalias de Tráfego
    SPIKE_MULTIPLIER = 10  # Tráfego 10x acima da média é spike
    BANDWIDTH_THRESHOLD_MBPS = 100  # 100 Mbps é alto
    CONNECTION_TIMEOUT_SECONDS = 300  # 5 minutos sem atividade
    PACKET_SIZE_ANOMALY_MIN = 64  # Menor que MTU suspeito
    PACKET_SIZE_ANOMALY_MAX = 1500  # Maior que MTU padrão

    # Comunicação C2
    C2_MIN_ENTROPY = 7.5  # Mais restritivo
    C2_COUNT_LOW = 5
    C2_COUNT_MEDIUM = 10
    C2_COUNT_HIGH = 20

    # Domínios
    DOMAINS_SUSPICIOUS_COUNT = 3
    DOMAINS_MALICIOUS_COUNT_MEDIUM = 1
    DOMAINS_MALICIOUS_COUNT_HIGH = 5

    # Domínios Asiáticos
    ASIAN_DOMAIN_COUNT = 5

    # === Scores de Risco (de 100) ===
    # O score total é limitado a 100
    SCORE_DDoS_CRITICAL = 30
    SCORE_DDoS_HIGH = 25
    SCORE_DDoS_MEDIUM = 15

    SCORE_BOTNET_CRITICAL = 25
    SCORE_BOTNET_HIGH = 20
    SCORE_BOTNET_MEDIUM = 15
    SCORE_BOTNET_LOW = 10

    SCORE_PORTSCAN_CRITICAL = 20
    SCORE_PORTSCAN_HIGH = 15
    SCORE_PORTSCAN_MEDIUM = 10
    SCORE_PORTSCAN_LOW = 5

    SCORE_FLOOD_CRITICAL = 15
    SCORE_FLOOD_HIGH = 12
    SCORE_FLOOD_MEDIUM = 8
    SCORE_FLOOD_LOW = 5

    SCORE_C2_HIGH = 20
    SCORE_C2_MEDIUM = 15
    SCORE_C2_LOW = 10
    SCORE_C2_MINIMAL = 5

    SCORE_DOMAINS_MALICIOUS_HIGH = 10
    SCORE_DOMAINS_MALICIOUS_MEDIUM = 8
    SCORE_DOMAINS_SUSPICIOUS = 5

    SCORE_ASIAN_DOMAINS_HIGH = 5
    SCORE_ASIAN_DOMAINS_LOW = 2


# === Listas de IOCs Globais ===
GLOBAL_MALICIOUS_DOMAINS = [
    "yl.liufen.com",
    "hqs9.cnzz.com",
    "doudouguo.com",
    "dw156.tk",
    "lckj77.com",
    "cnzz.com",
]

GLOBAL_SUSPICIOUS_TLDS = [
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".xyz",
]

GLOBAL_ASIAN_DOMAIN_KEYWORDS = [
    "china",
    "asia",
    ".cn",
    ".hk",
    ".tw",
]

GLOBAL_MALICIOUS_IPS = {
    "185.220.101.23": "Tor exit node",
    "60.221.254.19": "Known C2 server (from sample)",
    "125.43.78.107": "Suspicious IP range",
    "1.2.3.4": "Known botnet IP",
    "5.6.7.8": "Malware distribution",
}

GLOBAL_SUSPICIOUS_COUNTRY_PREFIXES = [
    "60.",
    "125.",
    "185.",  # Simulação de geolocalização
]

GLOBAL_SUSPICIOUS_COUNTRIES = [
    "CN",
    "RU",
    "KP",
    "IR",  # Países com alta atividade maliciosa
]


################################################################################
# 2. MÓDULOS DE HEURÍSTICA E ANÁLISE
################################################################################


def analisar_iocs_e_dominios(dados):
    """Analisa IOCs, domínios suspeitos e threat intelligence em uma única passagem
    *** OTIMIZADO: Unifica detectar_dominios_suspeitos + verificar_threat_intelligence ***
    """
    # Usar listas de IOCs globais
    dominios_maliciosos = GLOBAL_MALICIOUS_DOMAINS
    suspicious_tlds = GLOBAL_SUSPICIOUS_TLDS
    asian_keywords = GLOBAL_ASIAN_DOMAIN_KEYWORDS
    malicious_ips = GLOBAL_MALICIOUS_IPS
    suspicious_prefixes = GLOBAL_SUSPICIOUS_COUNTRY_PREFIXES
    
    resultado = {
        # Domínios
        "dominios_suspeitos": [],
        "user_agents_maliciosos": [],
        "short_urls": [],
        "asian_domains": [],
        # Threat Intelligence
        "malicious_ips": [],
        "malicious_domains": [],
        "suspicious_countries": [],
        "tor_nodes": [],
        "confidence_scores": {},
    }

    for pkt in dados:
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        dns_query = pkt.get("dns_query")
        
        # Análise de DNS queries
        if dns_query:
            query = dns_query.lower()

            # Verificar domínios maliciosos conhecidos
            for dominio in dominios_maliciosos:
                if dominio in query:
                    resultado["dominios_suspeitos"].append({
                        "query": query,
                        "src_ip": src_ip,
                        "tipo": "dominio_malicioso_conhecido",
                    })
                    resultado["malicious_domains"].append({
                        "domain": query,
                        "src": src_ip,
                        "categoria": "Malware/Click fraud",
                        "confidence": 0.85,
                    })

            # Detectar domínios com TLD suspeitos
            if any(tld in query for tld in suspicious_tlds):
                resultado["dominios_suspeitos"].append({
                    "query": query,
                    "src_ip": src_ip,
                    "tipo": "tld_suspeito"
                })

            # Detectar domínios asiáticos suspeitos
            if any(keyword in query for keyword in asian_keywords):
                resultado["asian_domains"].append(query)
        
        # Análise de IPs maliciosos
        if dst_ip and dst_ip in malicious_ips:
            resultado["malicious_ips"].append({
                "ip": dst_ip,
                "src": src_ip,
                "categoria": malicious_ips[dst_ip],
                "confidence": 0.9,
            })
        
        # Verificar ranges de IP suspeitos
        if dst_ip and any(dst_ip.startswith(prefix) for prefix in suspicious_prefixes):
            resultado["suspicious_countries"].append({
                "ip": dst_ip,
                "country": "Suspicious region",
                "confidence": 0.6
            })

    return resultado


def calcular_score_malware(dados, padroes_suspeitos, iocs_e_dominios):
    """Calcula score de probabilidade de malware (0-100) baseado em evidências e thresholds do Config
    *** ATUALIZADO: Usa iocs_e_dominios unificado ***
    """
    score = 0
    evidencias = []

    # SCORING POR CATEGORIA
    cfg = Config  # Atalho para a classe de configuração

    # 0. PRIORIDADE: Ataques DDoS (Score Máximo: SCORE_DDoS_CRITICAL)
    if padroes_suspeitos.get("ddos_attacks"):
        for attack_key, attack_info in padroes_suspeitos["ddos_attacks"].items():
            if isinstance(attack_info, dict):
                severity = attack_info.get("severity", "MÉDIO")
                attack_type = attack_info.get("type", "DDoS")

                if severity == "CRÍTICO":
                    score += cfg.SCORE_DDoS_CRITICAL
                    evidencias.append(
                        f"CRÍTICO: {attack_type} detectado - "
                        f"Alvo: {attack_info.get('target')}:{attack_info.get('port')} "
                        f"({attack_info.get('num_attackers', 'N/A')} atacantes)"
                    )
                elif severity == "ALTO":
                    score += cfg.SCORE_DDoS_HIGH
                    evidencias.append(
                        f"ALTO: {attack_type} - "
                        f"Atacante: {attack_info.get('attacker')} → "
                        f"Vítima: {attack_info.get('target')}:{attack_info.get('port')} "
                        f"({attack_info.get('syn_packets', 0)} pacotes SYN)"
                    )
                elif severity == "MÉDIO":
                    score += cfg.SCORE_DDoS_MEDIUM
                    evidencias.append(
                        f"MÉDIO: {attack_type} - "
                        f"{attack_info.get('attacker')} → {attack_info.get('target')}"
                    )

    # 1. Múltiplas conexões externas (Score Máximo: SCORE_BOTNET_CRITICAL)
    if padroes_suspeitos.get("hosts_com_multiplas_conexoes"):
        for host, count in padroes_suspeitos.get("hosts_com_multiplas_conexoes", {}).items():
            if count > cfg.BOTNET_CONNECTIONS_CRITICAL:
                score += cfg.SCORE_BOTNET_CRITICAL
                evidencias.append(
                    f"CRÍTICO: {host} conectou a {count} destinos externos (botnet massiva)"
                )
            elif count > cfg.BOTNET_CONNECTIONS_HIGH:
                score += cfg.SCORE_BOTNET_HIGH
                evidencias.append(
                    f"ALTO: {host} conectou a {count} destinos externos (botnet)"
                )
            elif count > cfg.BOTNET_CONNECTIONS_MEDIUM:
                score += cfg.SCORE_BOTNET_MEDIUM
                evidencias.append(f"ALTO: {host} conectou a {count} destinos externos")
            elif count > cfg.BOTNET_CONNECTIONS_LOW:
                score += cfg.SCORE_BOTNET_LOW
                evidencias.append(f"MÉDIO: {host} conectou a {count} destinos externos")

    # 2. Port scanning (Score Máximo: SCORE_PORTSCAN_CRITICAL)
    if padroes_suspeitos.get("port_scanning"):
        for scan, ports in padroes_suspeitos.get("port_scanning", {}).items():
            if ports > cfg.PORT_SCAN_CRITICAL:
                score += cfg.SCORE_PORTSCAN_CRITICAL
                evidencias.append(f"CRÍTICO: Port scan massivo {scan} ({ports} portas)")
            elif ports > cfg.PORT_SCAN_HIGH:
                score += cfg.SCORE_PORTSCAN_HIGH
                evidencias.append(f"ALTO: Port scan extenso {scan} ({ports} portas)")
            elif ports > cfg.PORT_SCAN_MEDIUM:
                score += cfg.SCORE_PORTSCAN_MEDIUM
                evidencias.append(f"MÉDIO: Port scan {scan} ({ports} portas)")
            elif ports > cfg.PORT_SCAN_LOW:
                score += cfg.SCORE_PORTSCAN_LOW
                evidencias.append(f"BAIXO: Port scan {scan} ({ports} portas)")

    # 3. Comunicação C2 (Score Máximo: SCORE_C2_HIGH)
    if padroes_suspeitos.get("comunicacao_c2"):
        high_entropy_count = len(
            [
                c
                for c in padroes_suspeitos.get("comunicacao_c2", [])
                if c["entropy"] > cfg.C2_MIN_ENTROPY
            ]
        )
        total_c2 = len(padroes_suspeitos.get("comunicacao_c2", []))

        if high_entropy_count > cfg.C2_COUNT_HIGH:
            score += cfg.SCORE_C2_HIGH
            evidencias.append(
                f"CRÍTICO: {high_entropy_count} conexões C2 de alta entropia"
            )
        elif high_entropy_count > cfg.C2_COUNT_MEDIUM:
            score += cfg.SCORE_C2_MEDIUM
            evidencias.append(f"ALTO: {high_entropy_count} conexões C2 suspeitas")
        elif total_c2 > cfg.C2_COUNT_LOW:
            score += cfg.SCORE_C2_LOW
            evidencias.append(
                f"MÉDIO: {total_c2} comunicações criptografadas suspeitas"
            )
        else:
            score += cfg.SCORE_C2_MINIMAL
            evidencias.append(f"BAIXO: Comunicação criptografada detectada")

    # 5. Domínios maliciosos (Score Máximo: SCORE_DOMAINS_MALICIOUS_HIGH)
    if iocs_e_dominios.get("dominios_suspeitos"):
        malicious_domains = len(
            [
                d
                for d in iocs_e_dominios.get("dominios_suspeitos", [])
                if d["tipo"] == "dominio_malicioso_conhecido"
            ]
        )
        total_suspicious = len(iocs_e_dominios.get("dominios_suspeitos", []))

        if malicious_domains > cfg.DOMAINS_MALICIOUS_COUNT_HIGH:
            score += cfg.SCORE_DOMAINS_MALICIOUS_HIGH
            evidencias.append(
                f"CRÍTICO: {malicious_domains} domínios maliciosos conhecidos"
            )
        elif malicious_domains >= cfg.DOMAINS_MALICIOUS_COUNT_MEDIUM:
            score += cfg.SCORE_DOMAINS_MALICIOUS_MEDIUM
            evidencias.append(
                f"ALTO: {malicious_domains} domínios maliciosos conhecidos"
            )
        elif total_suspicious > cfg.DOMAINS_SUSPICIOUS_COUNT:
            score += cfg.SCORE_DOMAINS_SUSPICIOUS
            evidencias.append(f"MÉDIO: {total_suspicious} domínios suspeitos")

    # 6. Domínios asiáticos suspeitos (Score Máximo: SCORE_ASIAN_DOMAINS_HIGH)
    if iocs_e_dominios.get("asian_domains"):
        asian_count = len(set(iocs_e_dominios.get("asian_domains", [])))
        if asian_count > cfg.ASIAN_DOMAIN_COUNT:
            score += cfg.SCORE_ASIAN_DOMAINS_HIGH
            evidencias.append(f"MÉDIO: {asian_count} domínios asiáticos suspeitos")
        else:
            score += cfg.SCORE_ASIAN_DOMAINS_LOW
            evidencias.append(f"BAIXO: {asian_count} domínios asiáticos detectados")

    # 8. Anomalias de tráfego (Score Máximo: 10)
    if padroes_suspeitos.get("anomalias_trafego"):
        anomaly_count = len(padroes_suspeitos["anomalias_trafego"])
        if anomaly_count > 5:
            score += 10
            evidencias.append(f"MÉDIO: {anomaly_count} anomalias de tráfego detectadas")
        else:
            score += 5
            evidencias.append(f"BAIXO: {anomaly_count} anomalias de tráfego")

    # 9. Vazamento de dados (Score Máximo: 15)
    if padroes_suspeitos.get("data_leakage"):
        total_leaked = sum(leak["total_bytes"] for leak in padroes_suspeitos.get("data_leakage", []))
        mb_leaked = total_leaked / (1024 * 1024)
        if mb_leaked > 100:  # > 100 MB
            score += 15
            evidencias.append(f"CRÍTICO: {mb_leaked:.2f} MB enviados externamente")
        elif mb_leaked > 50:
            score += 10
            evidencias.append(f"ALTO: {mb_leaked:.2f} MB enviados externamente")
        else:
            score += 5
            evidencias.append(f"MÉDIO: {mb_leaked:.2f} MB enviados externamente")

    # 10. Conexões suspeitas (Score Máximo: 8)
    if padroes_suspeitos.get("conexoes_suspeitas"):
        susp_conn_count = len(padroes_suspeitos.get("conexoes_suspeitas", []))
        if susp_conn_count > 10:
            score += 8
            evidencias.append(f"MÉDIO: {susp_conn_count} conexões a portas não-padrão")
        else:
            score += 4
            evidencias.append(f"BAIXO: {susp_conn_count} conexões suspeitas")

    # Limitar score máximo
    score = min(score, 100)

    return {"score": score, "nivel": get_risk_level(score), "evidencias": evidencias}


def get_risk_level(score):
    """Converte score em nível de risco"""
    if score >= 80:
        return "CRÍTICO"
    elif score >= 60:
        return "ALTO"
    elif score >= 40:
        return "MÉDIO"
    elif score >= 20:
        return "BAIXO"
    else:
        return "MÍNIMO"


def analisar_comportamento_temporal(dados):
    """
    Analisa padrões temporais suspeitos e comportamentos de beaconing.
    *** CORRIGIDO: Agora usa timestamps reais em vez de índices. ***
    """
    comportamentos = {
        "beaconing_intervals": [],
        "burst_patterns": [],
        "periodic_communication": [],
        "time_based_anomalies": [],
    }

    # Agrupar por conexão (src_ip, dst_ip, dst_port)
    conexoes = defaultdict(list)
    for pkt in dados:
        # Validar timestamp > 0 para evitar falsos positivos com timestamps inválidos
        timestamp = pkt.get("timestamp", 0)
        if pkt["src_ip"] and pkt["dst_ip"] and timestamp > 0:
            key = (pkt["src_ip"], pkt["dst_ip"], pkt["dst_port"])
            conexoes[key].append(timestamp)

    # Detectar beaconing (comunicação periódica característica de malware)
    for conexao, timestamps in conexoes.items():
        # Validar e filtrar timestamps válidos
        timestamps = [t for t in timestamps if isinstance(t, (int, float)) and t > 0]
        
        if len(timestamps) >= 5:  # Pelo menos 5 comunicações
            # Ordenar timestamps para garantir
            timestamps.sort()
            intervalos = [
                timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)
            ]

            # Verificar se intervalos são consistentes (indicativo de beaconing)
            if len(intervalos) > 0:
                media_intervalo = sum(intervalos) / len(intervalos)
                # Calcular variância. Baixa variância = intervalos consistentes
                variancia = sum((x - media_intervalo) ** 2 for x in intervalos) / len(
                    intervalos
                )

                # Se a variância for baixa (< 1.0s) e houver pacotes suficientes
                if variancia < 1.0 and len(timestamps) >= 10:
                    comportamentos["beaconing_intervals"].append(
                        {
                            "conexao": f"{conexao[0]}→{conexao[1]}:{conexao[2]}",
                            "intervalo_medio_s": round(media_intervalo, 2),
                            "variancia_s2": round(variancia, 2),
                            "count": len(timestamps),
                            "suspeita": "beaconing_malware_consistente",
                        }
                    )

            # Detectar burst patterns (rajadas de comunicação)
            if len(timestamps) > 50:
                duracao = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0.1
                # Se a duração for muito curta (ex: > 50 pacotes em < 2 segundos)
                if duracao < 2.0:
                    comportamentos["burst_patterns"].append(
                        {
                            "conexao": f"{conexao[0]}→{conexao[1]}:{conexao[2]}",
                            "total_packets": len(timestamps),
                            "duracao_s": round(duracao, 2),
                            "suspeita": "burst_ddos_or_data_exfiltration",
                        }
                    )

    return comportamentos




def calcular_entropia(data):
    """Calcula a entropia de dados binários"""
    if not data:
        return 0.0
    
    data_len = len(data)
    if data_len == 0:
        return 0.0

    ocorrencias = {}
    for byte in data:
        ocorrencias[byte] = ocorrencias.get(byte, 0) + 1

    entropia = 0
    for count in ocorrencias.values():
        p_x = count / data_len
        entropia -= p_x * math.log2(p_x)

    return entropia


################################################################################
# 3. PROCESSADOR DE PACOTES (PARSER)
################################################################################


def processar_csv(arquivo_csv):
    """
    Processa arquivo CSV exportado de ferramentas de rede (Wireshark, tcpdump, etc)
    Formatos suportados:
    - Wireshark: Export Packet Dissections > As CSV
    - Colunas mínimas: No., Time, Source, Destination, Protocol, Length, Info
    - Colunas opcionais: Source Port, Destination Port, TCP Flags
    
    Retorna lista de dicts no mesmo formato de processar_pcap()
    """
    resumo = []
    
    try:
        with open(arquivo_csv, 'r', encoding='utf-8', errors='ignore') as f:
            # Detectar delimitador (vírgula, ponto-e-vírgula, tab)
            sample = f.read(1024)
            f.seek(0)
            
            delimiter = ','
            if sample.count(';') > sample.count(','):
                delimiter = ';'
            elif sample.count('\t') > sample.count(','):
                delimiter = '\t'
            
            reader = csv.DictReader(f, delimiter=delimiter)
            
            # Mapear nomes de colunas comuns (case-insensitive)
            for row in reader:
                # Normalizar keys para lowercase
                row_lower = {k.lower().strip(): v for k, v in row.items()}
                
                # Extrair campos principais (tentar variações de nomes)
                timestamp = 0.0
                for time_key in ['time', 'timestamp', 'time_relative', 'frame.time_relative']:
                    if time_key in row_lower and row_lower[time_key]:
                        try:
                            timestamp = float(row_lower[time_key])
                            break
                        except (ValueError, TypeError):
                            continue
                
                src_ip = None
                for src_key in ['source', 'src', 'ip.src', 'source address']:
                    if src_key in row_lower and row_lower[src_key]:
                        src_ip = row_lower[src_key].strip()
                        break
                
                dst_ip = None
                for dst_key in ['destination', 'dst', 'ip.dst', 'destination address']:
                    if dst_key in row_lower and row_lower[dst_key]:
                        dst_ip = row_lower[dst_key].strip()
                        break
                
                protocol = None
                for proto_key in ['protocol', 'proto', '_ws.col.protocol']:
                    if proto_key in row_lower and row_lower[proto_key]:
                        protocol = row_lower[proto_key].strip().upper()
                        break
                
                length = 0
                for len_key in ['length', 'len', 'frame.len', 'packet length']:
                    if len_key in row_lower and row_lower[len_key]:
                        try:
                            length = int(row_lower[len_key])
                            break
                        except (ValueError, TypeError):
                            continue
                
                # Portas (opcional)
                src_port = None
                for sport_key in ['source port', 'src port', 'tcp.srcport', 'udp.srcport']:
                    if sport_key in row_lower and row_lower[sport_key]:
                        try:
                            src_port = int(row_lower[sport_key])
                            break
                        except (ValueError, TypeError):
                            continue
                
                dst_port = None
                for dport_key in ['destination port', 'dst port', 'tcp.dstport', 'udp.dstport']:
                    if dport_key in row_lower and row_lower[dport_key]:
                        try:
                            dst_port = int(row_lower[dport_key])
                            break
                        except (ValueError, TypeError):
                            continue
                
                # Info/DNS query
                dns_query = None
                info = row_lower.get('info', row_lower.get('_ws.col.info', ''))
                if info and 'dns' in protocol.lower() if protocol else False:
                    # Extrair query do campo Info
                    if 'query' in info.lower():
                        dns_query = info.strip()
                
                # TCP Flags (opcional)
                tcp_flags = None
                for flag_key in ['tcp flags', 'tcp.flags', 'flags']:
                    if flag_key in row_lower and row_lower[flag_key]:
                        tcp_flags = row_lower[flag_key].strip()
                        break
                
                # Converter protocolo para número (aproximado)
                proto_num = None
                if protocol:
                    proto_map = {
                        'TCP': 6,
                        'UDP': 17,
                        'ICMP': 1,
                        'ICMPv6': 58,
                        'ARP': 'ARP',
                        'DNS': 17,  # DNS usa UDP
                        'HTTP': 6,  # HTTP usa TCP
                        'HTTPS': 6,
                        'TLS': 6,
                        'SSL': 6,
                    }
                    proto_num = proto_map.get(protocol, protocol)
                
                # Criar registro no formato padrão
                if src_ip and dst_ip:  # Mínimo necessário
                    info_dict = {
                        'timestamp': timestamp,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'protocol': proto_num or 'Unknown',
                        'ip_version': 4 if '.' in src_ip else (6 if ':' in src_ip else 'Unknown'),
                        'length': length,
                        'entropy': None,  # CSV não tem payload para calcular entropia
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'tcp_flags': tcp_flags,
                        'dns_query': dns_query,
                    }
                    resumo.append(info_dict)
        
        logger.info(f"✅ CSV processado: {len(resumo)} registros válidos")
        return resumo
        
    except Exception as e:
        logger.error(f"Erro ao processar CSV: {e}")
        raise Exception(f"Erro ao processar arquivo CSV: {str(e)}")


def processar_pcap(arquivo_pcap):
    """
    Processa arquivo PCAP e extrai informações dos pacotes
    *** CORRIGIDO: Adicionado 'timestamp' a todos os pacotes ***
    """
    try:
        pacotes = rdpcap(arquivo_pcap)
        resumo = []
        pacotes_sem_ip = 0

        for pkt in pacotes:
            info = None
            try:
                timestamp = float(pkt.time) if hasattr(pkt, 'time') else 0.0
            except (ValueError, TypeError, AttributeError):
                timestamp = 0.0

            # Processar pacotes IP
            if IP in pkt:
                info = {
                    "timestamp": timestamp,  # <-- CORREÇÃO
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
                    "timestamp": timestamp,  # <-- CORREÇÃO
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
                    "timestamp": timestamp,  # <-- CORREÇÃO
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
            elif Raw in pkt and len(pkt) > 20:
                try:
                    raw_data = bytes(pkt[Raw].load)
                    if len(raw_data) >= 20:
                        version = (raw_data[0] >> 4) & 0xF
                        if version == 4:  # IPv4
                            try:
                                ip_pkt = IP(raw_data)
                                info = {
                                    "timestamp": timestamp,
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
                                if TCP in ip_pkt:
                                    info["tcp_flags"] = str(ip_pkt[TCP].flags)
                                    info["src_port"] = ip_pkt[TCP].sport
                                    info["dst_port"] = ip_pkt[TCP].dport
                                elif UDP in ip_pkt:
                                    info["src_port"] = ip_pkt[UDP].sport
                                    info["dst_port"] = ip_pkt[UDP].dport
                            except Exception:
                                logger.debug(f"Raw IPv4 inválido ou malformado")
                                info = None

                        elif version == 6:  # IPv6
                            try:
                                ipv6_pkt = IPv6(raw_data)
                                info = {
                                    "timestamp": timestamp,
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
                            except Exception:
                                logger.debug(f"Raw IPv6 inválido ou malformado")
                                info = None
                except (ValueError, IndexError, AttributeError, struct.error) as e_raw:
                    logger.debug(f"Falha ao interpretar Raw data: {e_raw}")
                    # Se falhar a interpretação, criar entrada genérica para dados Raw
                    raw_data = bytes(pkt[Raw].load)
                    info = {
                        "timestamp": timestamp,  # <-- CORREÇÃO
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
                    if TCP in pkt:
                        info["tcp_flags"] = str(pkt[TCP].flags)
                        info["src_port"] = pkt[TCP].sport
                        info["dst_port"] = pkt[TCP].dport
                    elif UDP in pkt:
                        info["src_port"] = pkt[UDP].sport
                        info["dst_port"] = pkt[UDP].dport
                        if DNS in pkt:
                            try:
                                if pkt[DNS].qd:
                                    info["dns_query"] = pkt[DNS].qd.qname.decode(
                                        "utf-8"
                                    )
                            except (AttributeError, UnicodeDecodeError, IndexError):
                                pass

                # Calcular entropia do payload se ainda não foi calculada
                if not info.get("entropy") and Raw in pkt:
                    payload = bytes(pkt[Raw].load)
                    info["entropy"] = round(calcular_entropia(payload), 4)

                resumo.append(info)
            else:
                pacotes_sem_ip += 1

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
        logger.error(f"Erro fatal ao processar PCAP: {str(e)}")
        raise Exception(f"Erro ao processar PCAP: {str(e)}")


def analisar_padroes_botnet(dados, ips_origem, ips_destino):
    """
    Analisa padrões específicos de botnet e malware
    *** OTIMIZADO: Loop único consolidado com validação consistente ***
    """
    padroes = {
        "hosts_com_multiplas_conexoes": {},
        "comunicacao_c2": [],
        "port_scanning": {},
        "ddos_attacks": {},
        "anomalias_trafego": [],
        "conexoes_suspeitas": [],
        "data_leakage": [],
    }

    cfg = Config

    # Inicializar detectores
    conexoes_por_host = defaultdict(set)
    ddos_detector = defaultdict(lambda: {"syn": 0, "ack": 0, "rst": 0, "total": 0})
    syn_sources = defaultdict(set)
    udp_flood_detector = defaultdict(int)
    udp_sources = defaultdict(set)
    icmp_flood_detector = defaultdict(int)
    ack_flood_detector = defaultdict(int)
    http_connections = defaultdict(int)
    arp_table = defaultdict(int)
    dns_responses = defaultdict(lambda: {"count": 0, "total_size": 0})
    fragmented_packets = defaultdict(int)
    port_scan_detector = defaultdict(set)
    portas_suspeitas = defaultdict(int)
    uploads = defaultdict(int)
    traffic_by_hour = defaultdict(int)
    protocol_count = defaultdict(int)
    tiny_packets = 0
    jumbo_packets = 0
    high_entropy_packets = []
    
    portas_conhecidas = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443}

    # ======== LOOP ÚNICO CONSOLIDADO ========
    for pkt in dados:
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        src_port = pkt.get("src_port")
        dst_port = pkt.get("dst_port")
        protocol = pkt.get("protocol")
        tcp_flags = pkt.get("tcp_flags")
        length = pkt.get("length", 0)
        entropy = pkt.get("entropy")
        timestamp = pkt.get("timestamp", 0)
        ip_version = pkt.get("ip_version")

        # Validação de IP consistente
        ip_valid = src_ip and dst_ip and src_ip not in ["Raw Data", "Unknown"] and dst_ip not in ["Raw Data", "Unknown"]
        
        # 1. Hosts com múltiplas conexões (apenas IPs válidos)
        if ip_valid:
            is_src_internal = src_ip.startswith(("10.", "192.168.", "172."))
            is_dst_external = not dst_ip.startswith(("10.", "192.168.", "172."))
            
            if is_src_internal and is_dst_external:
                conexoes_por_host[src_ip].add(dst_ip)
                uploads[src_ip] += length  # 2. Data leakage tracking
        
        # 3. DDoS SYN Flood detection
        if ip_valid and dst_port and tcp_flags:
            key = (src_ip, dst_ip, dst_port)
            ddos_detector[key]["total"] += 1
            
            if "S" in tcp_flags and "A" not in tcp_flags:
                ddos_detector[key]["syn"] += 1
                syn_sources[dst_ip].add(src_ip)
            elif "A" in tcp_flags:
                ddos_detector[key]["ack"] += 1
            elif "R" in tcp_flags:
                ddos_detector[key]["rst"] += 1
            
            # 4. ACK Flood detection
            if "A" in tcp_flags and "S" not in tcp_flags and "F" not in tcp_flags:
                ack_flood_detector[key] += 1
            
            # 5. Slowloris detection
            if dst_port in [80, 443, 8080] and "S" in tcp_flags:
                http_connections[(src_ip, dst_ip)] += 1
        
        # 6. UDP Flood detection
        if ip_valid and dst_port and protocol == 17:
            key = (src_ip, dst_ip, dst_port)
            udp_flood_detector[key] += 1
            udp_sources[dst_ip].add(src_ip)
        
        # 7. ICMP Flood detection
        if ip_valid and protocol == 1:
            icmp_flood_detector[(src_ip, dst_ip)] += 1
        
        # 8. ARP Spoofing
        if ip_version == "ARP" and src_ip:
            arp_table[src_ip] += 1
        
        # 9. DNS Amplification
        if src_port == 53 and length > cfg.DNS_AMPLIFICATION_MIN_SIZE and src_ip:
            dns_responses[src_ip]["count"] += 1
            dns_responses[src_ip]["total_size"] += length
        
        # 10. Fragmentação IP
        if ip_valid and length < cfg.FRAGMENT_ATTACK_SMALL_PKT_SIZE:
            fragmented_packets[src_ip] += 1
        
        # 11. Port scanning (incluindo portas >1024 comuns)
        if ip_valid and dst_port:
            # Detectar scan em portas relevantes (não apenas <1024)
            if dst_port not in portas_conhecidas and dst_port < 49152:
                port_scan_detector[(src_ip, dst_ip)].add(dst_port)
                # 12. Conexões suspeitas
                portas_suspeitas[f"{src_ip} → {dst_ip}:{dst_port}"] += 1
        
        # 13. Alta entropia (C2)
        if ip_valid and entropy and entropy > cfg.C2_MIN_ENTROPY:
            high_entropy_packets.append(pkt)
        
        # 14. Tráfego por hora
        if timestamp > 0:
            from datetime import datetime
            try:
                hour = datetime.fromtimestamp(timestamp).hour
                traffic_by_hour[hour] += 1
            except (ValueError, OSError):
                pass
        
        # 15. Protocolos incomuns
        if protocol not in [1, 6, 17]:
            protocol_count[protocol] += 1
        
        # 16. Tamanhos anômalos
        if length < cfg.PACKET_SIZE_ANOMALY_MIN:
            tiny_packets += 1
        elif length > cfg.PACKET_SIZE_ANOMALY_MAX:
            jumbo_packets += 1
    
    # ======== PROCESSAMENTO PÓS-LOOP ========
    
    # Processar DDoS SYN Flood
    for (src, dst, port), flags in ddos_detector.items():
        syn_count = flags["syn"]
        ack_count = flags["ack"]
        total = flags["total"]
        
        if syn_count > cfg.SYN_FLOOD_MIN_PACKETS and (ack_count / max(syn_count, 1)) < cfg.SYN_FLOOD_ACK_RATIO:
            num_sources = len(syn_sources.get(dst, set()))
            if num_sources > cfg.DDOS_DISTRIBUTED_SOURCES:
                padroes["ddos_attacks"][f"SYN_FLOOD_DISTRIBUTED: {dst}:{port}"] = {
                    "type": "SYN Flood Distribuído",
                    "target": dst,
                    "port": port,
                    "syn_packets": syn_count,
                    "num_attackers": num_sources,
                    "severity": "CRÍTICO",
                }
            else:
                padroes["ddos_attacks"][f"SYN_FLOOD: {src} → {dst}:{port}"] = {
                    "type": "SYN Flood",
                    "attacker": src,
                    "target": dst,
                    "port": port,
                    "syn_packets": syn_count,
                    "ack_packets": ack_count,
                    "num_attackers": 1,
                    "severity": "ALTO",
                }
    
    # Processar UDP Flood
    for (src, dst, port), count in udp_flood_detector.items():
        threshold = cfg.UDP_FLOOD_DNS_THRESHOLD if port == 53 else cfg.UDP_FLOOD_THRESHOLD
        if count > threshold:
            num_sources = len(udp_sources.get(dst, set()))
            attack_type = "DNS Amplification/Flood" if port == 53 else "UDP Flood"
            
            if num_sources > cfg.DDOS_DISTRIBUTED_SOURCES:
                padroes["ddos_attacks"][f"UDP_FLOOD_DISTRIBUTED: {dst}:{port}"] = {
                    "type": f"{attack_type} Distribuído",
                    "target": dst,
                    "port": port,
                    "udp_packets": count,
                    "num_attackers": num_sources,
                    "severity": "CRÍTICO",
                }
            else:
                padroes["ddos_attacks"][f"UDP_FLOOD: {src} → {dst}:{port}"] = {
                    "type": attack_type,
                    "attacker": src,
                    "target": dst,
                    "port": port,
                    "udp_packets": count,
                    "num_attackers": 1,
                    "severity": "ALTO",
                }
    
    # Processar ICMP Flood
    for (src, dst), count in icmp_flood_detector.items():
        if count > cfg.ICMP_FLOOD_LOW:
            severity = "ALTO" if count > cfg.ICMP_FLOOD_HIGH else "MÉDIO"
            padroes["ddos_attacks"][f"ICMP_FLOOD: {src} → {dst}"] = {
                "type": "ICMP Flood (Ping Flood)",
                "attacker": src,
                "target": dst,
                "icmp_packets": count,
                "num_attackers": 1,
                "severity": severity,
            }
    
    # Processar ACK Flood
    for (src, dst, port), count in ack_flood_detector.items():
        if count > cfg.ACK_FLOOD_THRESHOLD:
            padroes["ddos_attacks"][f"ACK_FLOOD: {src} → {dst}:{port}"] = {
                "type": "ACK Flood",
                "attacker": src,
                "target": dst,
                "port": port,
                "ack_packets": count,
                "num_attackers": 1,
                "severity": "ALTO",
            }
    
    # Processar Slowloris
    for (src, dst), count in http_connections.items():
        if count > cfg.HTTP_SLOWLORIS_CONNECTIONS:
            padroes["ddos_attacks"][f"SLOWLORIS: {src} → {dst}"] = {
                "type": "Slowloris (HTTP Slow)",
                "attacker": src,
                "target": dst,
                "http_connections": count,
                "num_attackers": 1,
                "severity": "ALTO",
            }
    
    # Processar ARP Spoofing
    for src_ip, count in arp_table.items():
        if count > cfg.ARP_SPOOFING_THRESHOLD:
            padroes["ddos_attacks"][f"ARP_SPOOFING: {src_ip}"] = {
                "type": "ARP Spoofing",
                "attacker": src_ip,
                "arp_packets": count,
                "num_attackers": 1,
                "severity": "ALTO",
            }
    
    # Processar DNS Amplification
    for src_ip, stats in dns_responses.items():
        if stats["count"] > cfg.DNS_AMPLIFICATION_MIN_COUNT and stats["total_size"] > cfg.DNS_AMPLIFICATION_MIN_BYTES:
            padroes["ddos_attacks"][f"DNS_AMPLIFICATION: {src_ip}"] = {
                "type": "DNS Amplification",
                "amplifier": src_ip,
                "large_responses": stats["count"],
                "total_bytes": stats["total_size"],
                "num_attackers": 1,
                "severity": "CRÍTICO",
            }
    
    # Processar Fragmentação IP
    for src_ip, count in fragmented_packets.items():
        if count > cfg.FRAGMENT_ATTACK_THRESHOLD:
            padroes["ddos_attacks"][f"FRAGMENTATION_ATTACK: {src_ip}"] = {
                "type": "Ataque de Fragmentação IP",
                "attacker": src_ip,
                "small_packets": count,
                "num_attackers": 1,
                "severity": "MÉDIO",
            }
    
    # Processar Port Scanning
    for (src, dst), ports in port_scan_detector.items():
        if len(ports) > cfg.PORT_SCAN_LOW:
            padroes["port_scanning"][f"{src} → {dst}"] = len(ports)
    
    # Processar hosts com múltiplas conexões (excluir atacantes DDoS)
    ddos_ips = set()
    for attack_info in padroes["ddos_attacks"].values():
        if isinstance(attack_info, dict):
            if attack_info.get("attacker"):
                ddos_ips.add(attack_info["attacker"])
            if attack_info.get("target"):
                ddos_ips.add(attack_info["target"])
    
    for host, destinos in conexoes_por_host.items():
        if host not in ddos_ips and len(destinos) > cfg.BOTNET_CONNECTIONS_LOW:
            padroes["hosts_com_multiplas_conexoes"][host] = len(destinos)
    
    # Processar alta entropia (C2) - excluir IPs DDoS
    for pkt in high_entropy_packets:
        src_ip = pkt["src_ip"]
        dst_ip = pkt["dst_ip"]
        if src_ip not in ddos_ips and dst_ip not in ddos_ips:
            padroes["comunicacao_c2"].append({
                "src": src_ip,
                "dst": dst_ip,
                "port": pkt["dst_port"],
                "entropy": pkt["entropy"],
            })
    
    # Processar conexões suspeitas
    for conexao, count in portas_suspeitas.items():
        if count > 50:
            padroes["conexoes_suspeitas"].append({
                "conexao": conexao,
                "count": count,
                "tipo": "porta_nao_padrao_alta_frequencia"
            })
    
    # Processar data leakage
    for src_ip, total_bytes in uploads.items():
        if total_bytes > 10 * 1024 * 1024:
            padroes["data_leakage"].append({
                "src_ip": src_ip,
                "total_bytes": total_bytes,
                "tipo": "upload_massivo_externo"
            })
    
    # Processar tráfego por hora
    if traffic_by_hour:
        avg_traffic = sum(traffic_by_hour.values()) / max(len(traffic_by_hour), 1)
        for hour, count in traffic_by_hour.items():
            if count > avg_traffic * cfg.SPIKE_MULTIPLIER and hour in range(0, 6):
                padroes["anomalias_trafego"].append({
                    "hora": hour,
                    "pacotes": count,
                    "media": int(avg_traffic),
                    "tipo": "spike_horario_incomum"
                })
    
    # Processar protocolos incomuns
    for protocol, count in protocol_count.items():
        if count > 100:
            padroes["anomalias_trafego"].append({
                "protocolo": protocol,
                "pacotes": count,
                "tipo": "protocolo_incomum"
            })
    
    # Processar tamanhos anômalos
    if tiny_packets > 1000:
        padroes["anomalias_trafego"].append({
            "tipo": "pacotes_muito_pequenos",
            "count": tiny_packets,
            "tamanho": f"< {cfg.PACKET_SIZE_ANOMALY_MIN} bytes"
        })
    
    if jumbo_packets > 100:
        padroes["anomalias_trafego"].append({
            "tipo": "pacotes_jumbo",
            "count": jumbo_packets,
            "tamanho": f"> {cfg.PACKET_SIZE_ANOMALY_MAX} bytes"
        })

    return padroes


def formatar_dados_para_analise(dados, padroes_suspeitos, iocs_e_dominios):
    """Formata dados dos pacotes para análise pelo LLM
    *** OTIMIZADO: Recebe padrões já calculados para evitar dupla execução ***
    """
    total_pacotes = len(dados)
    ips_origem = set(pkt["src_ip"] for pkt in dados if pkt["src_ip"])
    ips_destino = set(pkt["dst_ip"] for pkt in dados if pkt["dst_ip"])
    protocolos = defaultdict(int)
    portas_destino = defaultdict(int)
    entropias_altas = []
    tipos_ip = {"IPv4": 0, "IPv6": 0, "ARP": 0, "Raw": 0}

    for pkt in dados:
        ip_ver = pkt.get("ip_version", "Raw")
        if ip_ver in tipos_ip:
            tipos_ip[ip_ver] += 1

        protocolos[pkt["protocol"]] += 1

        if pkt["dst_port"]:
            portas_destino[pkt["dst_port"]] += 1

        if (
            pkt["entropy"] and pkt["entropy"] > 6.0
        ):  # Manter 6.0 para logging, 7.5 para scoring
            entropias_altas.append(pkt)

    resumo = f"""
RESUMO DA ANÁLISE DE REDE:

ESTATÍSTICAS GERAIS:
- Total de pacotes: {total_pacotes}
- IPv4: {tipos_ip["IPv4"]} | IPv6: {tipos_ip["IPv6"]} | ARP: {tipos_ip["ARP"]} | Raw: {tipos_ip["Raw"]}
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
        for pkt in entropias_altas[:5]:
            resumo += f"- {pkt['src_ip']} → {pkt['dst_ip']}:{pkt['dst_port']} (entropia: {pkt['entropy']})\n"

    resumo += "\n🚨 ANÁLISE DE PADRÕES MALICIOSOS:\n"

    if padroes_suspeitos.get("ddos_attacks"):
        resumo += "\n🔴 ATAQUES DDoS DETECTADOS (CRÍTICO):\n"
        for attack_key, attack_info in padroes_suspeitos["ddos_attacks"].items():
            if isinstance(attack_info, dict):
                resumo += f"- {attack_info.get('type', 'DDoS')} (Severidade: {attack_info.get('severity', 'MÉDIO')})\n"
                resumo += (
                    f"  L Alvo: {attack_info.get('target')}:{attack_info.get('port')}\n"
                )
                if attack_info.get("attacker"):
                    resumo += f"  L Atacante: {attack_info.get('attacker')}\n"
                if attack_info.get("num_attackers"):
                    resumo += f"  L Fontes: {attack_info['num_attackers']} IPs\n"

    if padroes_suspeitos.get("hosts_com_multiplas_conexoes"):
        resumo += "\n⚠️ HOSTS COM MÚLTIPLAS CONEXÕES EXTERNAS (Possível Botnet):\n"
        for host, count in padroes_suspeitos.get("hosts_com_multiplas_conexoes", {}).items():
            resumo += f"- {host} conectou-se a {count} destinos externos diferentes\n"

    if padroes_suspeitos.get("port_scanning"):
        resumo += "\n🔍 PORT SCANNING DETECTADO:\n"
        for scan, ports in padroes_suspeitos.get("port_scanning", {}).items():
            resumo += f"- {scan} testou {ports} portas diferentes\n"

    if padroes_suspeitos.get("comunicacao_c2"):
        resumo += "\n📡 POSSÍVEL COMUNICAÇÃO C&C (Alta Entropia):\n"
        for c2 in padroes_suspeitos.get("comunicacao_c2", [])[:5]:
            resumo += f"- {c2['src']} → {c2['dst']}:{c2['port']} (entropia: {c2['entropy']:.2f})\n"

    if iocs_e_dominios.get("dominios_suspeitos"):
        resumo += "\n🌐 DOMÍNIOS SUSPEITOS DETECTADOS:\n"
        for dom in iocs_e_dominios.get("dominios_suspeitos", [])[:5]:
            resumo += f"- {dom['query']} (de {dom['src_ip']}) - {dom['tipo']}\n"

    if padroes_suspeitos.get("anomalias_trafego"):
        resumo += "\n⚠️ ANOMALIAS DE TRÁFEGO:\n"
        for anomalia in padroes_suspeitos.get("anomalias_trafego", [])[:5]:
            resumo += f"- {anomalia.get('tipo', 'anomalia')}: {anomalia}\n"

    if padroes_suspeitos.get("conexoes_suspeitas"):
        resumo += "\n🔌 CONEXÕES SUSPEITAS:\n"
        for conexao in padroes_suspeitos.get("conexoes_suspeitas", [])[:5]:
            resumo += f"- {conexao['conexao']}: {conexao['count']} pacotes (porta não-padrão)\n"

    if padroes_suspeitos.get("data_leakage"):
        resumo += "\n📤 POSSÍVEL VAZAMENTO DE DADOS:\n"
        for leak in padroes_suspeitos.get("data_leakage", [])[:5]:
            mb = leak['total_bytes'] / (1024 * 1024)
            resumo += f"- {leak['src_ip']}: {mb:.2f} MB enviados externamente\n"

    return resumo


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
        135: "RPC",
        137: "NetBIOS",
        138: "NetBIOS",
        139: "NetBIOS",
        143: "IMAP",
        161: "SNMP",
        162: "SNMP-Trap",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        514: "Syslog",
        587: "SMTP-MSA",
        636: "LDAPS",
        993: "IMAPS",
        995: "POP3S",
        1433: "SQL Server",
        1521: "Oracle DB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        9200: "Elasticsearch",
        27017: "MongoDB",
    }
    return servicos.get(porta, "Desconhecido")


################################################################################
# 4. INTERAÇÃO COM O LLM (OLLAMA)
################################################################################


def analisar_com_llm_hibrido(
    dados_formatados, relatorio_yara, modelo="llama3", host=None, port=None
):
    """Análise híbrida: LLM para comportamento + YARA como evidência complementar"""

    prompt = f"""
Você é um especialista em análise forense de tráfego de rede e detecção de ameaças cibernéticas.

**IMPORTANTE**: As detecções heurísticas são EVIDÊNCIAS, não vereditos finais. 
Interprete o CONTEXTO completo antes de classificar:
- DDoS entre IPs internos (192.168.x.x) pode ser diagnóstico legítimo
- YARA detectando "Nmap" + port scan = ferramenta de segurança, não ataque
- Alta entropia em HTTPS/TLS = NORMAL (criptografia legítima)
- Correlacione YARA + Tráfego + Origem/Destino para evitar falsos positivos

DADOS DE TRÁFEGO:
{dados_formatados}

RELATÓRIO YARA:
{relatorio_yara}

INSTRUÇÕES DE ANÁLISE:

1. INTERPRETAÇÃO DE DETECÇÕES:
   - DDoS Externo (Internet → Rede) = Ataque confirmado
   - DDoS Interno (LAN → LAN) = Possível diagnóstico/teste
   - Port Scanning + YARA (Nmap/Masscan) = Ferramenta de segurança
   - Port Scanning sem YARA = Reconhecimento suspeito

2. CORRELAÇÃO YARA + TRÁFEGO:
   - YARA (malware) + tráfego suspeito = Compromisso CONFIRMADO
   - YARA (ferramenta) + atividade = Uso legítimo de ferramentas
   - Sem YARA + DDoS = Ataque de rede (não malware)

3. DIFERENCIAÇÃO CRÍTICA (EVITAR CONTRADIÇÕES):
   - DDoS: Identifique ATACANTE(S) e VÍTIMA separadamente
     * ATACANTE = IP(s) enviando flood (SYN/UDP/ICMP)
     * VÍTIMA = IP recebendo flood excessivo
     * Um host NÃO pode ser atacante E vítima simultaneamente no mesmo ataque
   - Botnet: Host → MUITOS destinos externos (>100 IPs distintos)
   - Normal: HTTPS/DNS legítimo em portas padrão
   - Tráfego para IPs Google (142.250.x.x, 172.217.x.x) = Geralmente LEGÍTIMO

4. ANÁLISE DE PORTAS:
   - Portas de Serviço (0-1023): SSH(22), DNS(53), HTTP(80), HTTPS(443)
   - Portas Registradas (1024-49151): Aplicações específicas
   - Portas Efêmeras (49152-65535): NORMAIS em conexões TCP/UDP cliente
   - SUSPEITO: Servidores escutando em portas efêmeras ou portas incomuns
   - NORMAL: Cliente usando portas efêmeras (ex: 192.168.x.x:51234 → google.com:443)

5. ANOMALIAS A CONSIDERAR:
   - Vazamento de dados: Uploads >10MB para IPs externos (excluindo Google/CDNs)
   - Portas suspeitas: Servidor em porta efêmera OU porta incomum (<1024 não-padrão)
   - Tráfego em horários incomuns (0h-6h) em redes corporativas
   - Protocolos raros: Não TCP/UDP/ICMP/DNS/ARP

6. ANÁLISE DE ENTROPIA:
   - Entropia >7.5 em HTTPS/TLS (porta 443) = **NORMAL** (SSL/TLS legítimo)
   - Entropia >7.5 em DNS/HTTP (portas 53/80) = **SUSPEITO** (malware/tunelamento)
   - Entropia >7.5 para Google/Cloudflare/AWS = Tráfego web normal
   - Contexto: Sempre mencione o protocolo e porta ao analisar entropia

RESPOSTA ESTRUTURADA (8 SEÇÕES):

1. **CLASSIFICAÇÃO DE RISCO** (Crítico/Alto/Médio/Baixo/Normal)
   - Justifique baseado em evidências concretas

2. **CORRELAÇÃO YARA-TRÁFEGO**
   - Se YARA não detectou nada, mencione explicitamente

3. **AMEAÇAS IDENTIFICADAS** (tipo específico: "SYN Flood DDoS", "Botnet Emotet", etc)
   - Liste apenas ameaças confirmadas ou altamente prováveis

4. **HOSTS COMPROMETIDOS**
   - VÍTIMAS: IPs que RECEBEM ataque (flooding, port scan)
   - ATACANTES: IPs que ENVIAM ataque
   - COMPROMETIDOS: IPs com comportamento de botnet/malware
   - SEJA CONSISTENTE - não liste o mesmo IP em categorias contraditórias

5. **PADRÕES DE ATAQUE**
   - **OBRIGATÓRIO**: Inclua números específicos dos dados fornecidos
   - Formato: "Técnica: [números concretos]"
   - Exemplos:
     * "SYN Flood: 15.234 pacotes SYN enviados em 30 segundos"
     * "DNS Amplification: 50 queries gerando 2.5MB de resposta"
     * "Port Scan: 500 portas distintas escaneadas em 10 segundos"
     * "Exfiltração: 50MB enviados para IP externo em conexão única"
   - NÃO use descrições genéricas - SEMPRE cite os números do relatório

6. **AÇÕES IMEDIATAS** (bloquear atacante, isolar vítima, etc)
   - Priorize ações baseadas na severidade
   - Seja específico: "Bloquear IP X.X.X.X" não "Bloquear atacante"

7. **INVESTIGAÇÃO FORENSE** (logs, memória, etc)
   - Sugira passos concretos e priorizados
   - Exemplo: "1. Coletar logs de firewall dos últimos 24h, 2. Analisar memória do host X"

8. **REMEDIAÇÃO** (mitigação, limpeza, fortalecimento)
   - Diferencie mitigação imediata vs fortalecimento de longo prazo
   - Exemplo: "Imediato: Rate limiting DNS. Longo prazo: Implementar BCP38"

**REGRAS CRÍTICAS**:
- NÃO contradiga informações entre seções
- NÃO classifique tráfego HTTPS legítimo como exfiltração sem evidência adicional
- NÃO liste um IP como vítima E atacante no mesmo contexto
- NÃO classifique portas efêmeras (>49152) como suspeitas se usadas por cliente
- NÃO mencione "alta entropia" sem especificar protocolo e porta
- SE não há YARA, NÃO invente detecções de malware
- SEMPRE inclua números específicos em "PADRÕES DE ATAQUE"

Seja PRECISO, CONSISTENTE e CONTEXTUAL.
"""

    try:
        # Define variáveis de ambiente para o cliente ollama (API antiga)
        if host:
            os.environ.setdefault("OLLAMA_HOST", host)
        if port:
            os.environ.setdefault("OLLAMA_PORT", str(port))

        resposta = ollama.chat(
            model=modelo, messages=[{"role": "user", "content": prompt}]
        )
        return resposta["message"]["content"]
    except Exception as e:
        logger.error(f"Erro na análise LLM híbrida: {str(e)}")
        return f"Erro na análise LLM híbrida: {str(e)}"


# FUNÇÃO analisar_com_llm (antiga) REMOVIDA.


def get_available_models():
    """Retorna lista de modelos LLM disponíveis"""
    try:
        models_response = ollama.list()
        models = []
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
                name = str(model)
            models.append(name)

        if models:
            return models
        return get_ollama_models_subprocess()
    except Exception:
        return get_ollama_models_subprocess()


def get_ollama_status(host=None, port=None):
    """Verifica se o Ollama está acessível e retorna um resumo simples."""
    try:
        if host:
            os.environ.setdefault("OLLAMA_HOST", host)
        if port:
            os.environ.setdefault("OLLAMA_PORT", str(port))

        try:
            resp = ollama.list()
        except Exception:
            resp = None

        if resp:
            if isinstance(resp, dict) and "models" in resp:
                models = resp["models"] or []
            elif isinstance(resp, list):
                models = resp
            else:
                models = []

            count = sum(1 for m in models if m)

            if count == 0:
                parsed = get_ollama_models_subprocess()
                return {"ok": True, "models": len(parsed)}
            return {"ok": True, "models": count}
        else:
            parsed = get_ollama_models_subprocess()
            return {"ok": True, "models": len(parsed)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


################################################################################
# 5. ORQUESTRADOR PRINCIPAL
################################################################################


def analyze_pcap_with_llm(arquivo_pcap, modelo="llama3", host=None, port=None, analysis_mode="full"):
    """
    Função principal para análise completa de PCAP/CSV com LLM + YARA (híbrida)
    *** ATUALIZADO: Suporte para CSV + Modos de análise configuráveis ***
    
    Formatos suportados:
    - .pcap, .pcapng: Análise completa com YARA
    - .csv: Análise comportamental (sem YARA, pois não há payload)
    
    Modos de análise:
    - 'full': Análise completa (YARA + LLM + Heurísticas) - PADRÃO
    - 'llm_heuristics': LLM + Heurísticas (sem YARA)
    - 'llm_yara': LLM + YARA (sem detecções heurísticas)
    - 'llm_only': Apenas LLM com dados básicos de pacotes
    - 'yara_only': Apenas análise YARA (sem LLM)
    """
    try:
        # Detectar tipo de arquivo
        arquivo_lower = arquivo_pcap.lower()
        is_csv = arquivo_lower.endswith('.csv')
        
        logger.info(
            f"[MAIN] 🚀 Iniciando análise de: {arquivo_pcap} (Tipo: {'CSV' if is_csv else 'PCAP'}, Modo: {analysis_mode.upper()})"
        )

        # 1. ANÁLISE COMPORTAMENTAL (para LLM)
        logger.info("[MAIN] 📊 Processando pacotes para análise comportamental...")
        
        if is_csv:
            dados_pacotes = processar_csv(arquivo_pcap)
        else:
            dados_pacotes = processar_pcap(arquivo_pcap)

        if not dados_pacotes:
            raise Exception("Nenhum pacote IP encontrado no arquivo")

        # Determinar quais componentes executar baseado no modo
        run_heuristics = analysis_mode in ['full', 'llm_heuristics']
        run_yara = analysis_mode in ['full', 'llm_yara', 'yara_only'] and not is_csv
        run_llm = analysis_mode in ['full', 'llm_heuristics', 'llm_yara', 'llm_only']
        
        # Inicializar variáveis padrão
        padroes_suspeitos = {}
        iocs_e_dominios = {}
        scoring_result = {"score": 0, "nivel_risco": "MÍNIMO", "evidencias": []}
        comportamento_temporal = {}
        
        # FASE 2: Análises especializadas (apenas se heurísticas ativadas)
        if run_heuristics:
            logger.info("🔍 Iniciando análise heurística especializada...")
            ips_origem = set(pkt["src_ip"] for pkt in dados_pacotes if pkt["src_ip"])
            ips_destino = set(pkt["dst_ip"] for pkt in dados_pacotes if pkt["dst_ip"])

            padroes_suspeitos = analisar_padroes_botnet(
                dados_pacotes, ips_origem, ips_destino
            )
            iocs_e_dominios = analisar_iocs_e_dominios(dados_pacotes)

            # FASE 3: Sistema de scoring avançado
            logger.info("📊 Calculando score de malware...")
            scoring_result = calcular_score_malware(
                dados_pacotes, padroes_suspeitos, iocs_e_dominios
            )

            # FASE 5: Análise comportamental temporal
            logger.info("⏱️ Analisando comportamento temporal (com timestamps reais)...")
            comportamento_temporal = analisar_comportamento_temporal(dados_pacotes)
        else:
            logger.info("⏭️ Modo '{analysis_mode}': Pulando análises heurísticas")

        # FASE 6: Formatar dados para análise LLM (usando padrões já calculados ou vazios)
        if run_llm:
            dados_formatados = formatar_dados_para_analise(dados_pacotes, padroes_suspeitos, iocs_e_dominios)
        else:
            dados_formatados = "Análise LLM desativada neste modo"

        # FASE 8: ANÁLISE YARA COMPLETA (baseado no modo selecionado)
        if run_yara:
            logger.info("🔍 Executando análise YARA...")
            if is_csv:
                logger.warning("⚠️ Arquivos CSV não suportam análise YARA (sem payload). Análise apenas comportamental.")
                relatorio_yara_texto = "⚠️ Análise YARA não aplicável para arquivos CSV (sem payload binário)"
            else:
                try:
                    relatorio_yara_resultado = executar_analise_yara_completa(arquivo_pcap)
                    relatorio_yara_texto = relatorio_yara_resultado.get(
                        "relatorio_texto", "❌ Relatório YARA não disponível"
                    )
                except Exception as e:
                    logger.warning(f"⚠️ Análise YARA falhou: {e}")
                    relatorio_yara_resultado = {"total_deteccoes": 0, "arquivos_extraidos": 0}
                    relatorio_yara_texto = "❌ Análise YARA não disponível"
        else:
            logger.info(f"⏭️ Modo '{analysis_mode}': Pulando análise YARA")
            relatorio_yara_texto = f"⚠️ Análise YARA desativada (modo: {analysis_mode})"
            relatorio_yara_resultado = {"total_deteccoes": 0, "arquivos_extraidos": 0}

        # Adicionar contexto avançado para o LLM (sem assinaturas)
        contexto_avancado = f"""
ANÁLISE DE SEGURANÇA AVANÇADA - Score: {scoring_result.get('score', 0)}/100 ({scoring_result.get('nivel_risco', 'MÍNIMO')})

RESUMO EXECUTIVO:
- Total de pacotes: {len(dados_pacotes)}
- Score de malware: {scoring_result.get('score', 0)}/100
- Nível de risco: {scoring_result.get('nivel_risco', 'MÍNIMO')}

EVIDÊNCIAS ENCONTRADAS:
{chr(10).join(f"• {evidencia}" for evidencia in scoring_result.get('evidencias', []))}

THREAT INTELLIGENCE:
- IPs maliciosos: {len(iocs_e_dominios.get('malicious_ips', []))}
- Domínios suspeitos: {len(iocs_e_dominios.get('malicious_domains', []))}
- Regiões suspeitas: {len(iocs_e_dominios.get('suspicious_countries', []))}

ANÁLISE COMPORTAMENTAL:
- Beaconing detectado: {len(comportamento_temporal.get('beaconing_intervals', []))} padrões
- Burst patterns: {len(comportamento_temporal.get('burst_patterns', []))} eventos

ANÁLISE YARA:
{relatorio_yara_texto}

Por favor, analise estes dados considerando o contexto de segurança avançado fornecido.
"""

        # FASE 9: ANÁLISE LLM HÍBRIDA (apenas se ativado)
        if run_llm:
            logger.info("🤖 Executando análise híbrida com LLM...")
            try:
                analise_llm = analisar_com_llm_hibrido(
                    dados_formatados, relatorio_yara_texto, modelo, host=host, port=port
                )
            except Exception as e_llm:
                logger.error(f"Falha na análise LLM: {e_llm}. Retornando erro.")
                raise Exception(f"Erro na análise LLM: {e_llm}")  # Remover fallback
        else:
            logger.info(f"⏭️ Modo '{analysis_mode}': Análise LLM desativada")
            analise_llm = f"📊 MODO: {analysis_mode.upper()}\n\n{relatorio_yara_texto}"

        # FASE 10: RESULTADO FINAL COMBINADO
        total_deteccoes_yara = relatorio_yara_resultado.get("total_deteccoes", 0)
        arquivos_extraidos = relatorio_yara_resultado.get("arquivos_extraidos", 0)

        resumo = f"""
📋 ANÁLISE COMPLETA FINALIZADA
├─ Pacotes analisados: {len(dados_pacotes)}
├─ Score de malware: {scoring_result.get('score', 0)}/100 ({scoring_result.get('nivel_risco', 'MÍNIMO')})
├─ IOCs encontrados: {len(iocs_e_dominios.get('malicious_ips', [])) + len(iocs_e_dominios.get('malicious_domains', []))}
├─ Detecções YARA: {total_deteccoes_yara}
├─ Arquivos extraídos: {arquivos_extraidos}
└─ Modelo LLM: {modelo}
"""

        logger.info(
            f"✅ Análise híbrida concluída: Score {scoring_result.get('score', 0)}/100 | {total_deteccoes_yara} detecções YARA"
        )

        network_patterns = {
            "ddos_attacks": len(padroes_suspeitos.get("ddos_attacks", {})),
            "conexoes_multiplas": len(
                padroes_suspeitos.get("hosts_com_multiplas_conexoes", {})
            ),
            "port_scanning": len(padroes_suspeitos.get("port_scanning", {})),
            "comunicacao_c2": len(padroes_suspeitos.get("comunicacao_c2", [])),
        }

        return {
            "packet_count": len(dados_pacotes),
            "analysis_text": analise_llm,
            "summary": resumo,
            "raw_data": dados_formatados,
            "malware_score": scoring_result.get("score", 0),
            "risk_level": scoring_result.get("nivel_risco", "MÍNIMO"),
            "network_patterns": network_patterns,
            "malware_signatures": {},  # Removido
            "temporal_analysis": {
                "beaconing_count": len(comportamento_temporal.get("beaconing_intervals", [])),
                "burst_count": len(comportamento_temporal.get("burst_patterns", [])),
                "periodic_patterns": len(
                    comportamento_temporal.get("periodic_communication", [])
                ),
            },
            "threat_intelligence": {
                "malicious_ips_count": len(iocs_e_dominios.get("malicious_ips", [])),
                "malicious_domains_count": len(iocs_e_dominios.get("malicious_domains", [])),
                "suspicious_countries_count": len(iocs_e_dominios.get("suspicious_countries", [])),
                "top_threats": iocs_e_dominios.get("malicious_ips", [])[:10],
            },
            "yara_detections": total_deteccoes_yara,
            "extracted_files": arquivos_extraidos,
            "yara_report": relatorio_yara_texto,
        }

    except Exception as e:
        logger.error(f"❌ Erro na análise: {str(e)}")
        raise Exception(f"Erro na análise avançada: {str(e)}")


################################################################################
# 6. BLOCO DE TESTE LOCAL
################################################################################

if __name__ == "__main__":
    # Configuração de logging para aparecer no console durante o teste
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )

    # Hack de path para permitir a execução local e encontrar os módulos
    # no diretório pai (como .utils e .yara_detector)
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(
            current_dir
        )  # Assumindo que .utils está em parent_dir
        sys.path.append(parent_dir)

        # Tentar re-importar com o novo path
        from utils import get_ollama_models as get_ollama_models_subprocess
        from yara_detector import executar_analise_yara_completa

        logger.info("Módulos .utils e .yara_detector recarregados para teste local.")
    except ImportError as e:
        logger.warning(f"Não foi possível carregar módulos locais para teste: {e}")
        # Manter os fallbacks definidos no início do script

    print("\n--- Testando analisador PCAP (execução local) ---")
    try:
        status = get_ollama_status()
        if status["ok"]:
            print(f"✅ Status Ollama: OK ({status['models']} modelos encontrados)")
            models = get_available_models()
            print(f"   Modelos disponíveis: {models}")

            # Para testar, crie um arquivo 'dummy.pcap' ou aponte para um PCAP real
            TEST_PCAP = "exemplo.pcap"  # Mude isso
            if not os.path.exists(TEST_PCAP):
                print(
                    f"⚠️  Arquivo de teste '{TEST_PCAP}' não encontrado. Pulando teste de análise."
                )
            else:
                print(f"\n🚀 Iniciando análise de '{TEST_PCAP}'...")
                resultado = analyze_pcap_with_llm(
                    TEST_PCAP, modelo=models[0] if models else "llama3"
                )
                print("\n--- RESUMO DA ANÁLISE ---")
                print(resultado["summary"])
                print("\n--- ANÁLISE DO LLM ---")
                print(resultado["analysis_text"])
                print("-------------------------")

        else:
            print(f"❌ Status Ollama: ERRO ({status['error']})")

    except Exception as e:
        print(f"❌ Erro no teste local: {e}")
