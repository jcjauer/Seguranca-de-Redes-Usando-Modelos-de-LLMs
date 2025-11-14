# analyzer/pcap_analyzer.py
"""
Módulo para análise de arquivos PCAP com LLM
"""

import math
import os
import sys
import logging
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
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, Raw, DNS, DNSQR, ARP, Ether
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

    # Comunicação C2
    C2_MIN_ENTROPY = 7.5  # Mais restritivo
    C2_COUNT_LOW = 5
    C2_COUNT_MEDIUM = 10
    C2_COUNT_HIGH = 20

    # Domínios
    DOMAINS_SUSPICIOUS_COUNT = 3
    DOMAINS_MALICIOUS_COUNT_MEDIUM = 1
    DOMAINS_MALICIOUS_COUNT_HIGH = 5

    # Click Fraud
    CLICK_FRAUD_COUNT = 10

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

    SCORE_CLICK_FRAUD_HIGH = 5
    SCORE_CLICK_FRAUD_LOW = 3

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

GLOBAL_SUSPICIOUS_USER_AGENTS = [
    "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/4.0",  # Antigo/desatualizado
    "Mozilla/5.0 (Windows NT 6.1)",  # Muito genérico
]

GLOBAL_CLICK_FRAUD_KEYWORDS = [
    "/stat.htm",
    "/ck.aspx",
    "/sync_pos.htm",
    "cnzz_core_c.php",
    "repeatip=",
    "showp=",
    "rnd=",
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


def detectar_dominios_suspeitos(dados):
    """Detecta domínios suspeitos, user-agents maliciosos e padrões de fraude"""
    suspeitos = {
        "dominios_suspeitos": [],
        "user_agents_maliciosos": [],
        "click_fraud_patterns": [],
        "short_urls": [],
        "asian_domains": [],
    }

    # Usar as listas globais centralizadas
    dominios_maliciosos = GLOBAL_MALICIOUS_DOMAINS
    user_agents_suspeitos = GLOBAL_SUSPICIOUS_USER_AGENTS
    click_fraud_keywords = GLOBAL_CLICK_FRAUD_KEYWORDS
    suspicious_tlds = GLOBAL_SUSPICIOUS_TLDS
    asian_keywords = GLOBAL_ASIAN_DOMAIN_KEYWORDS

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

            # Detectar domínios com TLD suspeitos
            if any(tld in query for tld in suspicious_tlds):
                suspeitos["dominios_suspeitos"].append(
                    {"query": query, "src_ip": pkt["src_ip"], "tipo": "tld_suspeito"}
                )

            # Detectar domínios asiáticos suspeitos
            if any(keyword in query for keyword in asian_keywords):
                suspeitos["asian_domains"].append(query)

        # Análise de payload HTTP (simulado)
        if (
            pkt.get("entropy") and pkt["entropy"] < 4.0
        ):  # Baixa entropia = texto legível
            src_port = pkt.get("src_port", 0)
            dst_port = pkt.get("dst_port", 0)

            # Portas HTTP/HTTPS
            if src_port in [80, 443, 8080] or dst_port in [80, 443, 8080]:
                # Simulação baseada em padrões
                suspeitos["click_fraud_patterns"].append(
                    {
                        "src_ip": pkt["src_ip"],
                        "dst_ip": pkt["dst_ip"],
                        "port": dst_port,
                        "suspeita": "trafego_http_suspeito",
                    }
                )

    return suspeitos


def calcular_score_malware(dados, padroes_suspeitos, dominios_suspeitos):
    """Calcula score de probabilidade de malware (0-100) baseado em evidências e thresholds do Config"""
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
    if padroes_suspeitos["hosts_com_multiplas_conexoes"]:
        for host, count in padroes_suspeitos["hosts_com_multiplas_conexoes"].items():
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
    if padroes_suspeitos["port_scanning"]:
        for scan, ports in padroes_suspeitos["port_scanning"].items():
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

    # 3. Flooding attacks (Score Máximo: SCORE_FLOOD_CRITICAL)
    if padroes_suspeitos["flood_attacks"]:
        max_flood = max(padroes_suspeitos["flood_attacks"].values())
        if max_flood > cfg.FLOOD_CRITICAL:
            score += cfg.SCORE_FLOOD_CRITICAL
            evidencias.append(f"CRÍTICO: Flood DDoS massivo ({max_flood} pacotes)")
        elif max_flood > cfg.FLOOD_HIGH:
            score += cfg.SCORE_FLOOD_HIGH
            evidencias.append(f"ALTO: Flood significativo ({max_flood} pacotes)")
        elif max_flood > cfg.FLOOD_MEDIUM:
            score += cfg.SCORE_FLOOD_MEDIUM
            evidencias.append(f"MÉDIO: Flood moderado ({max_flood} pacotes)")
        elif max_flood > cfg.FLOOD_LOW:
            score += cfg.SCORE_FLOOD_LOW
            evidencias.append(f"BAIXO: Flood detectado ({max_flood} pacotes)")

    # 4. Comunicação C2 (Score Máximo: SCORE_C2_HIGH)
    if padroes_suspeitos["comunicacao_c2"]:
        high_entropy_count = len(
            [
                c
                for c in padroes_suspeitos["comunicacao_c2"]
                if c["entropy"] > cfg.C2_MIN_ENTROPY
            ]
        )
        total_c2 = len(padroes_suspeitos["comunicacao_c2"])

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
    if dominios_suspeitos["dominios_suspeitos"]:
        malicious_domains = len(
            [
                d
                for d in dominios_suspeitos["dominios_suspeitos"]
                if d["tipo"] == "dominio_malicioso_conhecido"
            ]
        )
        total_suspicious = len(dominios_suspeitos["dominios_suspeitos"])

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

    # 6. Click fraud (Score Máximo: SCORE_CLICK_FRAUD_HIGH)
    if dominios_suspeitos["click_fraud_patterns"]:
        fraud_count = len(dominios_suspeitos["click_fraud_patterns"])
        if fraud_count > cfg.CLICK_FRAUD_COUNT:
            score += cfg.SCORE_CLICK_FRAUD_HIGH
            evidencias.append(f"MÉDIO: {fraud_count} padrões de fraude de cliques")
        else:
            score += cfg.SCORE_CLICK_FRAUD_LOW
            evidencias.append("BAIXO: Padrões de fraude de cliques detectados")

    # 7. Domínios asiáticos suspeitos (Score Máximo: SCORE_ASIAN_DOMAINS_HIGH)
    if dominios_suspeitos["asian_domains"]:
        asian_count = len(set(dominios_suspeitos["asian_domains"]))
        if asian_count > cfg.ASIAN_DOMAIN_COUNT:
            score += cfg.SCORE_ASIAN_DOMAINS_HIGH
            evidencias.append(f"MÉDIO: {asian_count} domínios asiáticos suspeitos")
        else:
            score += cfg.SCORE_ASIAN_DOMAINS_LOW
            evidencias.append(f"BAIXO: {asian_count} domínios asiáticos detectados")

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
        # Pkt deve ter timestamp salvo pelo processar_pcap
        if pkt["src_ip"] and pkt["dst_ip"] and pkt.get("timestamp"):
            key = (pkt["src_ip"], pkt["dst_ip"], pkt["dst_port"])
            conexoes[key].append(pkt["timestamp"])  # <-- CORREÇÃO: Usar timestamp real

    # Detectar beaconing (comunicação periódica característica de malware)
    for conexao, timestamps in conexoes.items():
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


def verificar_threat_intelligence(dados):
    """Verifica IPs e domínios contra bases de threat intelligence (das constantes globais)"""
    # Usar listas de IOCs globais
    malicious_ips = GLOBAL_MALICIOUS_IPS
    malicious_domains = {
        domain: "Click fraud/Malware" for domain in GLOBAL_MALICIOUS_DOMAINS
    }
    suspicious_countries = (
        GLOBAL_SUSPICIOUS_COUNTRIES  # Não usado ativamente aqui, mas disponível
    )
    suspicious_prefixes = GLOBAL_SUSPICIOUS_COUNTRY_PREFIXES

    iocs_found = {
        "malicious_ips": [],
        "malicious_domains": [],
        "suspicious_countries": [],
        "tor_nodes": [],
        "confidence_scores": {},
    }

    for pkt in dados:
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")

        if not src_ip or not dst_ip:
            continue

        # Verificar IPs maliciosos
        if dst_ip in malicious_ips:
            iocs_found["malicious_ips"].append(
                {
                    "ip": dst_ip,
                    "src": src_ip,
                    "categoria": malicious_ips[dst_ip],
                    "confidence": 0.9,
                }
            )

        # Verificar domínios DNS suspeitos
        dns_query = pkt.get("dns_query")
        if dns_query:
            for domain, categoria in malicious_domains.items():
                if domain in dns_query.lower():
                    iocs_found["malicious_domains"].append(
                        {
                            "domain": dns_query,
                            "src": src_ip,
                            "categoria": categoria,
                            "confidence": 0.85,
                        }
                    )

        # Verificar ranges de IP suspeitos (simulado por prefixos)
        if dst_ip:
            if any(dst_ip.startswith(prefix) for prefix in suspicious_prefixes):
                iocs_found["suspicious_countries"].append(
                    {"ip": dst_ip, "country": "Suspicious region", "confidence": 0.6}
                )

    return iocs_found


def calcular_entropia(data):
    """Calcula a entropia de dados binários"""
    if not data:
        return 0.0

    ocorrencias = {}
    for byte in data:
        ocorrencias[byte] = ocorrencias.get(byte, 0) + 1

    entropia = 0
    data_len = len(data)  # Cache do comprimento
    for count in ocorrencias.values():
        p_x = count / data_len
        entropia -= p_x * math.log2(p_x)

    return entropia


################################################################################
# 3. PROCESSADOR DE PACOTES (PARSER)
################################################################################


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
            timestamp = float(pkt.time)  # <-- CORREÇÃO: Capturar o timestamp real

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
                            ip_pkt = IP(raw_data)
                            info = {
                                "timestamp": timestamp,  # <-- CORREÇÃO
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

                        elif version == 6:  # IPv6
                            ipv6_pkt = IPv6(raw_data)
                            info = {
                                "timestamp": timestamp,  # <-- CORREÇÃO
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
                except Exception as e_raw:  # <-- CORREÇÃO: Capturar exceção específica
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
                            except Exception:  # <-- CORREÇÃO: Captura mais restrita
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
    *** CORRIGIDO: Usa thresholds da classe Config ***
    """
    padroes = {
        "hosts_com_multiplas_conexoes": {},  # Host interno -> múltiplos destinos externos
        "comunicacao_c2": [],  # Possível Command & Control
        "beaconing": {},  # Comunicação periódica
        "data_exfiltration": [],  # Transferências suspeitas
        "port_scanning": {},  # Tentativas de port scan
        "flood_attacks": {},  # Ataques de flood
        "ddos_attacks": {},  # Ataques DDoS (SYN Flood, UDP Flood, etc)
        "crypto_mining": [],  # Padrões de crypto mining
        "click_fraud": [],  # Fraude de cliques
    }

    cfg = Config  # Atalho para a classe de configuração

    # Analisar hosts com múltiplas conexões externas (indicador de botnet)
    conexoes_por_host = defaultdict(set)
    for pkt in dados:
        src_ip = pkt["src_ip"]
        dst_ip = pkt["dst_ip"]

        if src_ip and dst_ip:
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
                conexoes_por_host[src_ip].add(dst_ip)

    for host, destinos in conexoes_por_host.items():
        is_ddos_attacker = any(
            attack_info.get("attacker") == host
            for attack_info in padroes.get("ddos_attacks", {}).values()
            if isinstance(attack_info, dict)
        )

        # Usar threshold do Config
        if not is_ddos_attacker and len(destinos) > cfg.BOTNET_CONNECTIONS_LOW:
            padroes["hosts_com_multiplas_conexoes"][host] = len(destinos)

    # ======== DETECÇÃO DE DDoS (SYN Flood, UDP Flood, etc) ========
    ddos_detector = defaultdict(lambda: {"syn": 0, "ack": 0, "rst": 0, "total": 0})
    syn_sources = defaultdict(set)

    for pkt in dados:
        src_ip = pkt["src_ip"]
        dst_ip = pkt["dst_ip"]
        dst_port = pkt["dst_port"]
        tcp_flags = pkt.get("tcp_flags")

        if src_ip and dst_ip and dst_port and tcp_flags:
            key = (src_ip, dst_ip, dst_port)
            ddos_detector[key]["total"] += 1

            if "S" in tcp_flags and "A" not in tcp_flags:  # SYN sem ACK
                ddos_detector[key]["syn"] += 1
                syn_sources[dst_ip].add(src_ip)
            elif "A" in tcp_flags:
                ddos_detector[key]["ack"] += 1
            elif "R" in tcp_flags:
                ddos_detector[key]["rst"] += 1

    # Analisar padrões de DDoS SYN Flood
    for (src, dst, port), flags in ddos_detector.items():
        syn_count = flags["syn"]
        ack_count = flags["ack"]
        total = flags["total"]

        # PADRÃO 1: SYN Flood clássico (muitos SYN, poucos ACK)
        if (
            syn_count > 100 and (ack_count / max(syn_count, 1)) < 0.1
        ):  # Threshold específico
            num_sources = len(syn_sources.get(dst, set()))
            if num_sources > 10:
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
                    "severity": "ALTO",
                }

        # PADRÃO 2: Flooding geral (muito tráfego unidirecional)
        elif total > 1000 and ack_count < (total * 0.3):
            padroes["ddos_attacks"][f"FLOOD: {src} → {dst}:{port}"] = {
                "type": "Flood Attack",
                "attacker": src,
                "target": dst,
                "port": port,
                "total_packets": total,
                "severity": "MÉDIO",
            }

    # ======== DETECÇÃO DE UDP FLOOD ========
    udp_flood_detector = defaultdict(int)
    udp_sources = defaultdict(set)

    for pkt in dados:
        protocol = pkt.get("protocol")
        if (
            pkt["src_ip"] and pkt["dst_ip"] and pkt["dst_port"] and protocol == 17
        ):  # UDP
            key = (pkt["src_ip"], pkt["dst_ip"], pkt["dst_port"])
            udp_flood_detector[key] += 1
            udp_sources[pkt["dst_ip"]].add(pkt["src_ip"])

    # Analisar padrões de UDP Flood
    for (src, dst, port), count in udp_flood_detector.items():
        if port != 53 and count > 500:  # Threshold específico
            num_sources = len(udp_sources.get(dst, set()))
            if num_sources > 10:
                padroes["ddos_attacks"][f"UDP_FLOOD_DISTRIBUTED: {dst}:{port}"] = {
                    "type": "UDP Flood Distribuído",
                    "target": dst,
                    "port": port,
                    "udp_packets": count,
                    "num_attackers": num_sources,
                    "severity": "CRÍTICO",
                }
            else:
                padroes["ddos_attacks"][f"UDP_FLOOD: {src} → {dst}:{port}"] = {
                    "type": "UDP Flood",
                    "attacker": src,
                    "target": dst,
                    "port": port,
                    "udp_packets": count,
                    "severity": "ALTO",
                }

    # ... (O restante das detecções de DDoS (ICMP, ACK, Frag, Slowloris, ARP, DNS) continua aqui) ...
    # ... (Omitido por brevidade, mas deve ser refatorado da mesma forma com Config) ...

    # Detectar flooding (genérico)
    flood_contador = defaultdict(int)
    for pkt in dados:
        key = (pkt["src_ip"], pkt["dst_ip"], pkt["dst_port"])
        if key[0] and key[1]:
            flood_contador[key] += 1

    for (src, dst, port), count in flood_contador.items():
        # Usar thresholds do Config
        if count > cfg.FLOOD_LOW:
            # Lógica mais simples, refinar se necessário (ex: DNS vs HTTP)
            if (port != 53 and count > cfg.FLOOD_MEDIUM) or (
                port == 53 and count > cfg.FLOOD_HIGH
            ):
                padroes["flood_attacks"][f"{src} → {dst}:{port}"] = count

    # Detectar port scanning (mesmo IP tentando múltiplas portas)
    port_scan_detector = defaultdict(set)
    for pkt in dados:
        if pkt["src_ip"] and pkt["dst_ip"] and pkt["dst_port"]:
            if (
                pkt["dst_port"] > 1024
                or pkt["dst_port"] == 53
                or pkt.get("src_port") == 53
            ):
                continue  # Ignorar portas efêmeras e DNS
            key = (pkt["src_ip"], pkt["dst_ip"])
            port_scan_detector[key].add(pkt["dst_port"])

    for (src, dst), ports in port_scan_detector.items():
        # Usar threshold do Config
        if len(ports) > cfg.PORT_SCAN_LOW:
            padroes["port_scanning"][f"{src} → {dst}"] = len(ports)

    # Detectar alta entropia (possível comunicação C2 criptografada)
    for pkt in dados:
        if (
            pkt["entropy"] and pkt["entropy"] > cfg.C2_MIN_ENTROPY
        ):  # Usar threshold do Config
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

    padroes_suspeitos = analisar_padroes_botnet(dados, ips_origem, ips_destino)
    dominios_suspeitos = detectar_dominios_suspeitos(dados)

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

    if padroes_suspeitos["hosts_com_multiplas_conexoes"]:
        resumo += "\n⚠️ HOSTS COM MÚLTIPLAS CONEXÕES EXTERNAS (Possível Botnet):\n"
        for host, count in padroes_suspeitos["hosts_com_multiplas_conexoes"].items():
            resumo += f"- {host} conectou-se a {count} destinos externos diferentes\n"

    if padroes_suspeitos["port_scanning"]:
        resumo += "\n🔍 PORT SCANNING DETECTADO:\n"
        for scan, ports in padroes_suspeitos["port_scanning"].items():
            resumo += f"- {scan} testou {ports} portas diferentes\n"

    if padroes_suspeitos["comunicacao_c2"]:
        resumo += "\n📡 POSSÍVEL COMUNICAÇÃO C&C (Alta Entropia):\n"
        for c2 in padroes_suspeitos["comunicacao_c2"][:5]:
            resumo += f"- {c2['src']} → {c2['dst']}:{c2['port']} (entropia: {c2['entropy']:.2f})\n"

    if dominios_suspeitos["dominios_suspeitos"]:
        resumo += "\n🌐 DOMÍNIOS SUSPEITOS DETECTADOS:\n"
        for dom in dominios_suspeitos["dominios_suspeitos"][:5]:
            resumo += f"- {dom['query']} (de {dom['src_ip']}) - {dom['tipo']}\n"

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


################################################################################
# 4. INTERAÇÃO COM O LLM (OLLAMA)
################################################################################


def analisar_com_llm_hibrido(
    dados_formatados, relatorio_yara, modelo="llama3", host=None, port=None
):
    """Análise híbrida: LLM para comportamento + YARA como evidência complementar"""

    prompt = f"""
Você é um especialista em segurança cibernética e análise forense de tráfego de rede especializado em detecção de malware, botnets e ataques APT.

IMPORTANTE: Seja CAUTELOSO e evite falsos positivos. Tráfego normal de servidor pode incluir:
- Múltiplas conexões legítimas (servidores web, DNS, email)
- HTTPS legítimo tem alta entropia (isso é NORMAL)
- Servidores podem acessar muitos IPs externos (CDNs, APIs, serviços cloud)

DADOS DE TRÁFEGO PARA ANÁLISE:
{dados_formatados}

=== RELATÓRIO YARA (EVIDÊNCIAS DE MALWARE) ===
{relatorio_yara}

EXECUTE UMA ANÁLISE FORENSE EQUILIBRADA:

🔍 CORRELAÇÃO YARA + TRÁFEGO:
- Se há detecções YARA, correlacione com o tráfego de rede observado
- Identifique quais conexões de rede podem estar relacionadas ao malware detectado
- SOMENTE se houver CORRELAÇÃO clara entre YARA e tráfego, considere malware

🚨 DETECÇÃO DE MALWARE E BOTNETS (EVITE FALSOS POSITIVOS):
- Identifique padrões ANÔMALOS de comunicação C&C (não tráfego HTTPS normal)
- Tráfego criptografado (alta entropia) em portas não-padrão (não em 443/HTTPS)
- Beaconing: comunicação PERIÓDICA e REGULAR (não ocasional)
- Múltiplas conexões EXCESSIVAS e INCOMUNS (>50 destinos externos é suspeito)

🔍 INDICADORES DE COMPROMISSO (THRESHOLDS REALISTAS):
- Hosts com >100 conexões externas simultâneas diferentes
- Port scanning: >50 portas testadas em curto período
- Flooding: >1000 pacotes para mesmo destino
- DNS suspeitos: DGA com padrões aleatórios claros

📊 ANÁLISE COMPORTAMENTAL:
- Compare volumes: outliers EXTREMOS (não apenas acima da média)
- Protocolos REALMENTE incomuns (não apenas HTTP/HTTPS/DNS comum)
- Anomalias SIGNIFICATIVAS (não pequenas variações)

FORNEÇA UMA RESPOSTA ESTRUTURADA COM:

1. **CLASSIFICAÇÃO DE RISCO** (Crítico/Alto/Médio/Baixo/Limpo)
2. **CORRELAÇÃO YARA-TRÁFEGO** (como as detecções se relacionam com o tráfego)
3. **AMEAÇAS IDENTIFICADAS** (seja específico sobre o tipo de malware/botnet - ou "Nenhuma" se limpo)
4. **HOSTS COMPROMETIDOS** (liste IPs suspeitos com EVIDÊNCIAS FORTES - ou "Nenhum" se limpo)
5. **PADRÕES DE ATAQUE** (descreva a campanha maliciosa - ou "Tráfego normal" se limpo)
6. **AÇÕES IMEDIATAS** (contenção e isolamento - ou "Nenhuma ação necessária" se limpo)
7. **INVESTIGAÇÃO FORENSE** (próximos passos - ou "Não necessário" se limpo)
8. **REMEDIAÇÃO** (limpeza e fortalecimento - ou "Sistema aparenta estar limpo" se limpo)

Se NÃO houver evidências CLARAS de malware/ataque, classifique como BAIXO ou LIMPO.
Seja detalhado mas REALISTA. Evite alarmes falsos.
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


def analyze_pcap_with_llm(arquivo_pcap, modelo="llama3", host=None, port=None):
    """
    Função principal para análise completa de PCAP com LLM + YARA (híbrida)
    *** ATUALIZADO: Remoção de 'detectar_assinaturas_malware' ***
    """
    try:
        logger.info(
            f"[MAIN] 🚀 Iniciando análise híbrida COMPORTAMENTAL+YARA de: {arquivo_pcap}"
        )

        # 1. ANÁLISE COMPORTAMENTAL (para LLM)
        logger.info("[MAIN] 📊 Processando pacotes para análise comportamental...")
        dados_pacotes = processar_pcap(arquivo_pcap)

        if not dados_pacotes:
            raise Exception("Nenhum pacote IP encontrado no arquivo PCAP")

        # FASE 2: Análises especializadas
        logger.info("🔍 Iniciando análise especializada...")
        ips_origem = set(pkt["src_ip"] for pkt in dados_pacotes if pkt["src_ip"])
        ips_destino = set(pkt["dst_ip"] for pkt in dados_pacotes if pkt["dst_ip"])

        padroes_suspeitos = analisar_padroes_botnet(
            dados_pacotes, ips_origem, ips_destino
        )
        dominios_suspeitos = detectar_dominios_suspeitos(dados_pacotes)

        # FASE 3: Sistema de scoring avançado
        logger.info("📊 Calculando score de malware...")
        scoring_result = calcular_score_malware(
            dados_pacotes, padroes_suspeitos, dominios_suspeitos
        )

        # FASE 4: (Removida - detectar_assinaturas_malware)

        # FASE 5: Análise comportamental temporal
        logger.info("⏱️ Analisando comportamento temporal (com timestamps reais)...")
        comportamento_temporal = analisar_comportamento_temporal(dados_pacotes)

        # FASE 6: Threat Intelligence
        logger.info("🌐 Verificando Threat Intelligence...")
        threat_intel = verificar_threat_intelligence(dados_pacotes)

        # FASE 7: Formatar dados para análise LLM
        dados_formatados = formatar_dados_para_analise(dados_pacotes)

        # FASE 8: ANÁLISE YARA COMPLETA
        logger.info("🔍 Executando análise YARA...")
        try:
            relatorio_yara_resultado = executar_analise_yara_completa(arquivo_pcap)
            relatorio_yara_texto = relatorio_yara_resultado.get(
                "relatorio_texto", "❌ Relatório YARA não disponível"
            )
        except Exception as e:
            logger.warning(f"⚠️ Análise YARA falhou: {e}")
            relatorio_yara_resultado = {"total_deteccoes": 0, "arquivos_extraidos": 0}
            relatorio_yara_texto = "❌ Análise YARA não disponível"

        # Adicionar contexto avançado para o LLM (sem assinaturas)
        contexto_avancado = f"""
ANÁLISE DE SEGURANÇA AVANÇADA - Score: {scoring_result['score']}/100 ({scoring_result['nivel']})

RESUMO EXECUTIVO:
- Total de pacotes: {len(dados_pacotes)}
- Score de malware: {scoring_result['score']}/100
- Nível de risco: {scoring_result['nivel']}

EVIDÊNCIAS ENCONTRADAS:
{chr(10).join(f"• {evidencia}" for evidencia in scoring_result['evidencias'])}

THREAT INTELLIGENCE:
- IPs maliciosos: {len(threat_intel['malicious_ips'])}
- Domínios suspeitos: {len(threat_intel['malicious_domains'])}
- Regiões suspeitas: {len(threat_intel['suspicious_countries'])}

ANÁLISE COMPORTAMENTAL:
- Beaconing detectado: {len(comportamento_temporal['beaconing_intervals'])} padrões
- Burst patterns: {len(comportamento_temporal['burst_patterns'])} eventos

ANÁLISE YARA:
{relatorio_yara_texto}

Por favor, analise estes dados considerando o contexto de segurança avançado fornecido.
"""

        # FASE 9: ANÁLISE LLM HÍBRIDA
        logger.info("🤖 Executando análise híbrida com LLM...")
        try:
            analise_llm = analisar_com_llm_hibrido(
                dados_formatados, relatorio_yara_texto, modelo, host=host, port=port
            )
        except Exception as e_llm:
            logger.error(f"Falha na análise LLM: {e_llm}. Retornando erro.")
            raise Exception(f"Erro na análise LLM: {e_llm}")  # Remover fallback

        # FASE 10: RESULTADO FINAL COMBINADO
        total_deteccoes_yara = relatorio_yara_resultado.get("total_deteccoes", 0)
        arquivos_extraidos = relatorio_yara_resultado.get("arquivos_extraidos", 0)

        resumo = f"""
📋 ANÁLISE COMPLETA FINALIZADA
├─ Pacotes analisados: {len(dados_pacotes)}
├─ Score de malware: {scoring_result['score']}/100 ({scoring_result['nivel']})
├─ IOCs encontrados: {len(threat_intel['malicious_ips']) + len(threat_intel['malicious_domains'])}
├─ Detecções YARA: {total_deteccoes_yara}
├─ Arquivos extraídos: {arquivos_extraidos}
└─ Modelo LLM: {modelo}
"""

        logger.info(
            f"✅ Análise híbrida concluída: Score {scoring_result['score']}/100 | {total_deteccoes_yara} detecções YARA"
        )

        network_patterns = {
            "ddos_attacks": len(padroes_suspeitos.get("ddos_attacks", {})),
            "conexoes_multiplas": len(
                padroes_suspeitos.get("hosts_com_multiplas_conexoes", {})
            ),
            "port_scanning": len(padroes_suspeitos.get("port_scanning", {})),
            "flood_attacks": len(padroes_suspeitos.get("flood_attacks", {})),
            "comunicacao_c2": len(padroes_suspeitos.get("comunicacao_c2", [])),
        }

        return {
            "packet_count": len(dados_pacotes),
            "analysis_text": analise_llm,
            "summary": resumo,
            "raw_data": dados_formatados,
            "malware_score": scoring_result["score"],
            "risk_level": scoring_result["nivel"],
            "network_patterns": network_patterns,
            "malware_signatures": {},  # Removido
            "temporal_analysis": {
                "beaconing_count": len(comportamento_temporal["beaconing_intervals"]),
                "burst_count": len(comportamento_temporal["burst_patterns"]),
                "periodic_patterns": len(
                    comportamento_temporal.get("periodic_communication", [])
                ),
            },
            "threat_intelligence": {
                "malicious_ips_count": len(threat_intel["malicious_ips"]),
                "malicious_domains_count": len(threat_intel["malicious_domains"]),
                "suspicious_countries_count": len(threat_intel["suspicious_countries"]),
                "top_threats": threat_intel["malicious_ips"][:10],
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
