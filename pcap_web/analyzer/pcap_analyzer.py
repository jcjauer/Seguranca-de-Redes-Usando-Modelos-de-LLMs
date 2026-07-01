# analyzer/pcap_analyzer.py
"""
Módulo para análise de arquivos PCAP com LLM

NOTA DE CÓDIGO:
- Variáveis técnicas (src_ip, dst_ip, timestamp) mantidas em inglês (padrão RFC/Scapy)
- Variáveis de negócio (resumo, dominios_consultados) em português (legibilidade)
- TODO: Padronizar para inglês completo em versão futura para internacionalização
"""

import math
import os
import sys
import logging
import struct
import csv
from uuid import uuid4
from collections import defaultdict
from datetime import datetime

# Configurar o logger
# Nível INFO: logger.info(), Nível AVISO: logger.warning(), Nível ERRO: logger.error()
logger = logging.getLogger(__name__)

# Adicionar path do projeto principal para importar módulos (APENAS PARA TESTE LOCAL)
# Esta lógica foi movida para o bloco __main__ para não sujar o escopo global
# current_dir = os.path.dirname(os.path.abspath(__file__))
# parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))
# sys.path.append(parent_dir)

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, Raw, DNS, ARP, Ether, conf
    import ollama

    # HARDENING: Proteção contra PCAPs maliciosos (RCE)
    # Desabilitar dissectors que podem executar código arbitrário
    conf.layers.filter([Ether, IP, IPv6, TCP, UDP, DNS, ARP, Raw])
    
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
        YARA_RULESET_VERSION as YARA_RULESET_VERSION_SUBPROCESS,
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

    YARA_RULESET_VERSION_SUBPROCESS = "desconhecida"


ANALYSIS_PIPELINE_VERSION = "2026.05.05-analysis-v2"


################################################################################
# 1. CENTRAL DE CONFIGURAÇÃO E INDICADORES DE COMPROMETIMENTO (IOCs)
################################################################################


class Config:
    """
    Central de configuração para thresholds e scores
    
    ⚠️ MANUTENIBILIDADE: Configurações hardcoded no código
    Problema: Alterar thresholds requer editar código-fonte e redeploy
    
    TODO: Migrar para arquivo externo (config.yaml ou .env)
    Exemplo:
        config.yaml:
            detection:
              syn_flood_min_packets: 2000
              syn_flood_ack_ratio: 0.02
              port_scan_threshold: 100
            scoring:
              ddos_critical: 30
              botnet_high: 20
    
    Benefícios: Hot-reload, ambientes diferentes (dev/prod), auditoria de mudanças
    """

    # === Thresholds de Detecção ===
    # Múltiplas Conexões (Botnet)
    BOTNET_CONNECTIONS_LOW = 50
    BOTNET_CONNECTIONS_MEDIUM = 100
    BOTNET_CONNECTIONS_HIGH = 200
    BOTNET_CONNECTIONS_CRITICAL = 500

    # Port Scanning
    PORT_SCAN_LOW = 100
    PORT_SCAN_MEDIUM = 200
    PORT_SCAN_HIGH = 500
    PORT_SCAN_CRITICAL = 1000

    # Flooding
    FLOOD_LOW = 500
    FLOOD_MEDIUM = 1000
    FLOOD_HIGH = 3000
    FLOOD_CRITICAL = 8000

    # DDoS Específico -  DETECTAR ATAQUES REAIS
    SYN_FLOOD_MIN_PACKETS = 300       
    SYN_FLOOD_ACK_RATIO = 0.1         
    UDP_FLOOD_THRESHOLD = 1000        
    UDP_FLOOD_DNS_THRESHOLD = 500      
    ICMP_FLOOD_LOW = 500              
    ICMP_FLOOD_HIGH = 2000
    ACK_FLOOD_THRESHOLD = 1000
    ARP_SPOOFING_THRESHOLD = 100       # Pacotes ARP de um mesmo IP
    FRAGMENT_ATTACK_THRESHOLD = 100    # Fragmentos IP para um mesmo alvo
    
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


################################################################################
# WHITELISTS DE IPs CONHECIDOS (Previne Falsos Positivos Críticos)
################################################################################

# CRÍTICO: LLMs locais (llama3, qwen, gemma) NÃO têm conhecimento atualizado de ASNs
# Eles inventam ASNs, confundem 8.8.8.8 com malware, acham 1.1.1.1 suspeito
# Whitelists previnem falsos positivos em tráfego legítimo (YouTube, Netflix, etc)

# ⚠️ LIMITAÇÃO CONHECIDA: Whitelists estáticas podem gerar falsos negativos
# IPs de nuvem (AWS, Azure, GCP) são reciclados constantemente
# Atacantes podem alugar IPs whitelistados para evasão
# TODO: Migrar para consulta DNS reversa (PTR) ou base GeoIP/ASN atualizável

KNOWN_GOOD_IPS = {
    # Google DNS e serviços
    "8.8.8.8", "8.8.4.4",
    # Cloudflare DNS
    "1.1.1.1", "1.0.0.1",
    # OpenDNS
    "208.67.222.222", "208.67.220.220",
}

# Prefixos de ranges conhecidos (matching parcial para performance)
KNOWN_GOOD_PREFIXES = [
    # Google LLC (AS15169)
    "142.250.", "142.251.", "172.217.", "172.253.", "74.125.", "216.58.",
    # Cloudflare (AS13335)
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
    "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
    "162.158.", "172.64.", "172.65.", "172.66.", "172.67.", "173.245.",
    # Amazon AWS (AS16509, AS14618)
    "52.", "54.", "18.", "3.", "13.", "34.", "35.",
    # Microsoft Azure (AS8075)
    "40.", "13.", "20.", "23.", "51.", "52.", "104.",
    # Akamai (AS20940)
    "23.0.", "23.1.", "23.2.", "23.32.", "23.33.", "23.34.", "23.35.",
    "23.192.", "23.193.", "23.194.", "23.195.", "23.196.",
    "104.64.", "104.65.", "104.66.", "104.67.", "104.68.", "104.69.",
    # Fastly CDN (AS54113)
    "151.101.",
]

# Domínios conhecidos legítimos
KNOWN_GOOD_DOMAINS = [
    # Big Tech
    "google.com", "youtube.com", "googleapis.com", "gstatic.com", "ggpht.com",
    "facebook.com", "fbcdn.net", "whatsapp.com", "instagram.com",
    "microsoft.com", "windows.com", "live.com", "outlook.com", "office.com",
    "apple.com", "icloud.com", "cdn-apple.com",
    "amazon.com", "amazonaws.com", "cloudfront.net",
    # CDNs
    "cloudflare.com", "akamai.com", "akamaihd.net", "fastly.net",
    # Streaming
    "netflix.com", "nflxvideo.net", "nflxext.com", "nflximg.com",
    "spotify.com", "twitch.tv", "ttvnw.net",
    # Outros
    "wikipedia.org", "wikimedia.org",
]

def is_known_good_ip(ip):
    """Verifica se IP pertence a provedor conhecido legítimo"""
    if ip in KNOWN_GOOD_IPS:
        return True
    for prefix in KNOWN_GOOD_PREFIXES:
        if ip.startswith(prefix):
            return True
    return False

def is_known_good_domain(domain):
    """Verifica se domínio é de provedor conhecido legítimo"""
    domain_lower = domain.lower().strip(".")
    for good_domain in KNOWN_GOOD_DOMAINS:
        if domain_lower == good_domain or domain_lower.endswith("." + good_domain):
            return True
    return False

def is_local_ip(ip):
    """Verifica se IP é local/privado (RFC1918, IPv6 link-local, loopback)"""
    if not ip:
        return False
    
    # IPv4 privado (RFC1918)
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        # 172.16.0.0 - 172.31.255.255
        if ip.startswith("172."):
            try:
                second_octet = int(ip.split(".")[1])
                if 16 <= second_octet <= 31:
                    return True
            except (ValueError, IndexError):
                pass
        else:
            return True
    
    # Loopback
    if ip.startswith("127.") or ip == "::1":
        return True
    
    # IPv6 link-local (fe80::/10)
    if ip.startswith("fe80:") or ip.startswith("fe80::"):
        return True
    
    # IPv6 ULA (Unique Local Address - fc00::/7)
    if ip.startswith("fc") or ip.startswith("fd"):
        return True
    
    # IPv6 multicast (ff00::/8)
    if ip.startswith("ff"):
        return True
    
    return False


################################################################################
# 2. MÓDULOS DE HEURÍSTICA E ANÁLISE
################################################################################


def analisar_iocs_e_dominios(dados):
    """
    Coleta domínios e IPs acessados para análise pela IA
    Separa IPs/domínios conhecidos (whitelist) de desconhecidos (análise IA)
    """
    
    resultado = {
        # Lista de todos os domínios DNS vistos
        "dominios_consultados": [],
        # IPs únicos de destino (FILTRADOS: sem IPs conhecidos legítimos)
        "ips_destino_unicos": set(),
        # IPs conhecidos legítimos (para relatório)
        "ips_legitimos": set(),
        # Domínios conhecidos legítimos (para relatório)
        "dominios_legitimos": [],
        # Campos mantidos para compatibilidade
        "dominios_suspeitos": [],
        "malicious_ips": [],
        "malicious_domains": [],
        "suspicious_countries": [],
        "asian_domains": [],
    }

    for pkt in dados:
        dst_ip = pkt.get("dst_ip")
        src_ip = pkt.get("src_ip")
        dns_query = pkt.get("dns_query")
        
        # Coletar domínios DNS (separar conhecidos de desconhecidos)
        if dns_query:
            query = dns_query.lower().strip('.')
            if query:
                # Verificar se é domínio conhecido legítimo
                if is_known_good_domain(query):
                    if query not in resultado["dominios_legitimos"]:
                        resultado["dominios_legitimos"].append(query)
                else:
                    # Domínio desconhecido - enviar para IA analisar
                    if not any(d["dominio"] == query for d in resultado["dominios_consultados"]):
                        resultado["dominios_consultados"].append({
                            "dominio": query,
                            "src_ip": src_ip,
                            "timestamp": pkt.get("timestamp", 0),
                        })
        
        # Coletar IPs de destino (separar conhecidos de desconhecidos)
        if dst_ip and dst_ip not in ["Raw Data", "Unknown"]:
            if is_known_good_ip(dst_ip):
                resultado["ips_legitimos"].add(dst_ip)
            else:
                resultado["ips_destino_unicos"].add(dst_ip)
        
        # Verificar IP de origem também
        if src_ip and src_ip not in ["Raw Data", "Unknown"]:
            if is_known_good_ip(src_ip):
                resultado["ips_legitimos"].add(src_ip)

    # Converter sets para listas para serialização
    resultado["ips_destino_unicos"] = list(resultado["ips_destino_unicos"])
    resultado["ips_legitimos"] = list(resultado["ips_legitimos"])
    
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
    Processa arquivo PCAP em streaming (evita OOM em arquivos grandes)
    Usa PcapReader para ler pacote por pacote sem carregar tudo na RAM
    """
    from scapy.utils import PcapReader
    
    try:
        resumo = []
        pacotes_sem_ip = 0

        with PcapReader(arquivo_pcap) as pcap_reader:
            for pkt in pcap_reader:
                info = None
                try:
                    timestamp = float(pkt.time) if hasattr(pkt, 'time') else 0.0
                except (ValueError, TypeError, AttributeError):
                    timestamp = 0.0

                # Processar pacotes IP
                if IP in pkt:
                    info = {
                        "timestamp": timestamp,
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
                        "timestamp": timestamp,
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

                # Processar pacotes ARP (coletar MAC para detecção de spoofing)
                elif ARP in pkt:
                    info = {
                        "timestamp": timestamp,
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
                        "arp_op": pkt[ARP].op,
                        "src_mac": pkt[ARP].hwsrc if hasattr(pkt[ARP], 'hwsrc') else None,
                        "dst_mac": pkt[ARP].hwdst if hasattr(pkt[ARP], 'hwdst') else None,
                    }

                # Pacotes não-IP (Raw/Unknown): ignorar
                # Se Scapy não parseou, provavelmente é camada 2 ou corrupto
                else:
                    pacotes_sem_ip += 1
                    info = None

                # Se encontrou um tipo de pacote suportado
                if info:
                    # Processar TCP/UDP
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
                                    info["dns_query"] = pkt[DNS].qd.qname.decode("utf-8")
                            except (AttributeError, UnicodeDecodeError, IndexError):
                                pass

                    # Calcular entropia do payload
                    # 🚀 OTIMIZAÇÃO: Amostragem para evitar cálculo em milhões de pacotes
                    # Problema: PCAP de 5GB → milhões de cálculos de entropia → horas
                    # Solução: Amostrar apenas 1 em cada 100 pacotes + limitar payload a 1KB
                    if Raw in pkt and len(resumo) % 100 == 0:  # Amostragem 1%
                        try:
                            payload = bytes(pkt[Raw].load)
                            # Limitar a primeiros 1024 bytes (evita processar payloads gigantes)
                            if len(payload) > 1024:
                                payload = payload[:1024]
                            info["entropy"] = round(calcular_entropia(payload), 4)
                        except Exception:
                            info["entropy"] = None

                    resumo.append(info)
                else:
                    pacotes_sem_ip += 1

        if not resumo:
            raise Exception(
                f"Nenhum pacote IP/IPv6/ARP encontrado no arquivo PCAP. "
                f"Pacotes processados: {pacotes_sem_ip + len(resumo)}, "
                f"Pacotes não-IP: {pacotes_sem_ip}. "
                f"Este arquivo pode conter protocolos não suportados ou dados corrompidos."
            )

        logger.info(f"✅ PCAP processado: {len(resumo)} pacotes válidos, {pacotes_sem_ip} não-IP ignorados")
        return resumo

    except Exception as e:
        logger.error(f"Erro fatal ao processar PCAP: {str(e)}")
        raise Exception(f"Erro ao processar PCAP: {str(e)}")


def analisar_padroes_botnet(dados, ips_origem, ips_destino):
    """
    Analisa padrões específicos de botnet e malware
    *** OTIMIZADO: Loop único consolidado com validação consistente ***
    
    ⚠️ REFATORAÇÃO NECESSÁRIA (God Method Anti-Pattern):
    Esta função mistura múltiplas responsabilidades (DDoS, port scan, C2, vazamento de dados)
    em um único loop gigante, tornando testes unitários e manutenção difíceis.
    
    TODO: Separar em módulos especializados:
    - detect_ddos_patterns()
    - detect_port_scans()
    - detect_c2_communication()
    - detect_data_exfiltration()
    - detect_traffic_anomalies()
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
    # ===================================================================
    # CORRELAÇÃO BIDIRECIONAL: Rastreia handshake TCP completo (SYN + SYN-ACK)
    # Chave: (IP_CLIENTE, IP_SERVIDOR, PORTA_SERVIDOR)
    # SYN (ida): Cliente → Servidor => chave = (src, dst, dst_port)
    # SYN-ACK (volta): Servidor → Cliente => INVERTE para chave = (dst, src, src_port)
    # ===================================================================
    tcp_handshakes = defaultdict(lambda: {"syn": 0, "synack": 0, "sources": set()})
    
    # Volume por ALVO (para detectar DDoS distribuído)
    udp_target_volume = defaultdict(lambda: {"count": 0, "sources": set()})
    icmp_target_volume = defaultdict(int)
    ack_flood_target = defaultdict(int)
    fragmented_by_target = defaultdict(int)

    # Contadores auxiliares
    conexoes_por_host = defaultdict(set)
    port_scan_detector = defaultdict(set)
    portas_suspeitas = defaultdict(int)
    uploads = defaultdict(int)
    high_entropy_packets = []
    MAX_ENTROPY_SAMPLES = 1000  # Limite para prevenir OOM em PCAPs grandes
    traffic_by_hour = defaultdict(int)
    invalid_timestamps = 0  # Contador para debug
    protocol_count = defaultdict(int)
    tiny_packets = 0
    jumbo_packets = 0
    arp_table = defaultdict(int)
    arp_ip_to_mac = defaultdict(set)
    
    portas_conhecidas = {20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443}

    # ======== LOOP ÚNICO CONSOLIDADO ========
    # 🚀 OTIMIZAÇÃO: Adicionar contador para amostrar operações pesadas
    packet_counter = 0
    for pkt in dados:
        packet_counter += 1
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

        # Validação de IP consistente - Early return para performance
        ip_valid = src_ip and dst_ip and src_ip not in ["Raw Data", "Unknown"] and dst_ip not in ["Raw Data", "Unknown"]
        
        # Early return: ignora pacotes sem IPs válidos (ARP sem IP, raw data)
        if not ip_valid:
            continue
        
        # 1. Hosts com múltiplas conexões
        is_src_internal = src_ip.startswith(("10.", "192.168.", "172."))
        is_dst_external = not dst_ip.startswith(("10.", "192.168.", "172."))
        
        if is_src_internal and is_dst_external:
                conexoes_por_host[src_ip].add(dst_ip)
                uploads[src_ip] += length  # 2. Data leakage tracking
        
        # Ignorar tráfego legítimo conhecido (evita falsos positivos)
        if is_known_good_ip(dst_ip) or is_known_good_ip(src_ip):
            continue  # ← IMPORTANTE: não contar ataques contra Google, Cloudflare, etc.

        # 2. TCP: Correlação bidirecional (SYN + SYN-ACK)
        if protocol == 6 and tcp_flags and src_port and dst_port:
            flags_str = str(tcp_flags)
            
            # Cenário 1: Cliente enviando SYN (Ida) - Cliente → Servidor
            if "S" in flags_str and "A" not in flags_str:
                # Chave: (Cliente, Servidor, Porta_Servidor)
                key = (src_ip, dst_ip, dst_port)
                tcp_handshakes[key]["syn"] += 1
                tcp_handshakes[key]["sources"].add(src_ip)
                
                # Port scan detection (ignora portas efêmeras)
                if dst_port < 10000:
                    port_scan_detector[(src_ip, dst_ip)].add(dst_port)
            
            # Cenário 2: Servidor respondendo SYN-ACK (Volta) - Servidor → Cliente
            elif "S" in flags_str and "A" in flags_str:
                # INVERSÃO DA CHAVE: Servidor é src agora, mas na chave ele é dst
                # Chave reversa: (Cliente, Servidor, Porta_Servidor)
                key_reverse = (dst_ip, src_ip, src_port)
                
                # Só contabiliza se já vimos o SYN de ida (evita ruído)
                if key_reverse in tcp_handshakes:
                    tcp_handshakes[key_reverse]["synack"] += 1

            # ACK Flood: APENAS ACKs órfãos (sem SYN prévio)
            # ACKs normais de conexões estabelecidas são legítimos
            if "A" in flags_str and "S" not in flags_str and "F" not in flags_str:
                # Verificar se existe handshake estabelecido (SYN foi visto)
                key_forward = (src_ip, dst_ip, dst_port)
                key_reverse = (dst_ip, src_ip, src_port if src_port else 0)
                
                # Só conta como flood se NÃO existe SYN anterior (ACK órfão)
                if key_forward not in tcp_handshakes and key_reverse not in tcp_handshakes:
                    ack_flood_target[(dst_ip, dst_port)] += 1

        # 3. UDP Flood: agregado por alvo (detecta DDoS distribuído)
        if protocol == 17:  # UDP não requer dst_port (pode ser fragmentado)
            udp_target_volume[dst_ip]["count"] += 1
            if src_ip:  # Adiciona source apenas se válido
                udp_target_volume[dst_ip]["sources"].add(src_ip)

        # 4. ICMP Flood
        if protocol == 1:
            icmp_target_volume[dst_ip] += 1
        
        # 8. ARP Spoofing (CORRIGIDO: detectar conflitos de MAC)
        if ip_version == "ARP" and src_ip:
            arp_table[src_ip] += 1
            # Rastrear múltiplos MACs para mesmo IP (spoofing)
            src_mac = pkt.get("src_mac")
            if src_mac:
                arp_ip_to_mac[src_ip].add(src_mac)
        
        # 9. Fragmentação IP (conta por ALVO) - Suporta dict e Scapy Packet
        if isinstance(pkt, dict) and pkt.get("fragmented"):
            fragmented_by_target[dst_ip] += 1
        elif hasattr(pkt, "haslayer") and pkt.haslayer(IP):
            ip_layer = pkt[IP]
            is_fragmented = bool(ip_layer.flags & 0x1) or ip_layer.frag > 0
            if is_fragmented:
                fragmented_by_target[dst_ip] += 1
            
        # 12. Conexões suspeitas (portas não-padrão)
        if dst_port and dst_port not in portas_conhecidas and dst_port < 49152:
            portas_suspeitas[f"{src_ip} → {dst_ip}:{dst_port}"] += 1
        
        # 13. Alta entropia (C2) - ignora TLS/HTTPS e IPs conhecidos
        # ⚠️ LIMITAÇÃO: Binários comprimidos (ZIP, JPG, vídeos) geram falsos positivos
        if entropy and entropy > cfg.C2_MIN_ENTROPY:
            portas_tls = {443, 8443, 465, 587, 993, 995, 636, 989, 990, 992, 5061, 853}
            eh_tls = dst_port in portas_tls or src_port in portas_tls
            
            # Filtrar: NÃO alertar se porta TLS OU IP conhecido
            if not eh_tls and not is_known_good_ip(src_ip) and not is_known_good_ip(dst_ip):
                # Limite: armazena até MAX_ENTROPY_SAMPLES (previne OOM)
                if len(high_entropy_packets) < MAX_ENTROPY_SAMPLES:
                    high_entropy_packets.append(pkt)
                # Amostragem após limite (reservoir sampling)
                elif packet_counter % 100 == 0:  # 1% dos pacotes após limite
                    import random
                    idx = random.randint(0, MAX_ENTROPY_SAMPLES - 1)
                    high_entropy_packets[idx] = pkt
        
        # 14. Tráfego por hora
        if timestamp > 0:
            try:
                hour = datetime.fromtimestamp(timestamp).hour
                traffic_by_hour[hour] += 1
            except (ValueError, OSError) as e:
                invalid_timestamps += 1
                if invalid_timestamps <= 5:  # Log primeiros 5 erros
                    logger.warning(f"Timestamp inválido ignorado: {timestamp} - {e}")
        
        # 15. Protocolos incomuns
        if protocol not in [1, 6, 17]:
            protocol_count[protocol] += 1
        
        # 16. Tamanhos anômalos
        if length < cfg.PACKET_SIZE_ANOMALY_MIN:
            tiny_packets += 1
        elif length > cfg.PACKET_SIZE_ANOMALY_MAX:
            jumbo_packets += 1
    
    # ======== PÓS-PROCESSAMENTO: DETECÇÃO FINAL DE DDoS ========
    cfg = Config

    # ===================================================================
    # PROTEÇÃO CONTRA FALSOS POSITIVOS EM TRÁFEGO NORMAL (OBRIGATÓRIO!)
    # ===================================================================
    
    # Calcular duração total do PCAP (em segundos)
    timestamps = [pkt["timestamp"] for pkt in dados if pkt.get("timestamp", 0) > 0]
    if len(timestamps) < 2:
        duracao_segundos = 1
    else:
        duracao_segundos = max(timestamps) - min(timestamps)
        if duracao_segundos < 1:
            duracao_segundos = 1
    
    # Calcular PPS médio
    pps_medio = len(dados) / duracao_segundos
    
    # Regras anti-falso-positivo (se não passar, IGNORA o ataque)
    def is_trafego_normal_legitimo(target_ip, port, syn_count=None, synack_count=None, udp_count=None):
        # 1. IP da vítima é conhecido (Google, Cloudflare, etc) → nunca é alvo real
        if is_known_good_ip(target_ip):
            return True
        
        # 1b. IP local/privado → mas PERMITE se volume muito alto (ataques internos/labs)
        # Deixar cada detector decidir baseado no volume
        
        # 2. PPS muito baixo = não é flood (independente da porta)
        if pps_medio < 50:  # menos de 50 pacotes/segundo = tráfego humano
            return True
        
        # 3. Muitos SYN mas com SYN-ACK alto = navegação normal
        # CRÍTICO: Só considera "normal" se RATIO ALTO (>70% resposta)
        if syn_count and synack_count and syn_count > 100:
            ratio = synack_count / max(syn_count, 1)
            if ratio > 0.7:  # mais de 70% dos SYN têm resposta → navegação normal
                return True
        
        return False

    # 1. Analisar SYN Flood - AGREGAÇÃO POR ALVO primeiro, depois análise
    syn_flood_by_target = defaultdict(lambda: {"syn": 0, "synack": 0, "sources": set(), "connections": []})
    
    # ETAPA 1: Agregar todas as conexões por alvo
    for (attacker, target, port), metrics in tcp_handshakes.items():
        target_key = (target, port)
        syn_flood_by_target[target_key]["syn"] += metrics["syn"]
        syn_flood_by_target[target_key]["synack"] += metrics["synack"]
        syn_flood_by_target[target_key]["sources"].add(attacker)
        syn_flood_by_target[target_key]["connections"].append({
            "attacker": attacker,
            "syns": metrics["syn"],
            "synacks": metrics["synack"]
        })
    
    # ETAPA 2: Analisar volume agregado por alvo
    for (target, port), aggregated in syn_flood_by_target.items():
        total_syns = aggregated["syn"]
        total_synacks = aggregated["synack"]
        num_sources = len(aggregated["sources"])
        
        # Threshold AGREGADO (não por conexão individual)
        if total_syns < cfg.SYN_FLOOD_MIN_PACKETS:  # Ex: 300 SYNs TOTAIS
            continue
        
        # Calcular ratio agregado
        ratio = total_synacks / (total_syns + 1)
        
        # Se ratio baixo = servidor não consegue responder = flood
        if ratio < cfg.SYN_FLOOD_ACK_RATIO:  # Ex: <10% resposta
            # PROTEÇÃO CONTRA FALSO POSITIVO (mas com exceção para volume alto)
            # Se volume muito alto (>1000 SYNs), detecta mesmo se IP local
            if total_syns < 1000 and is_trafego_normal_legitimo(target, port, total_syns, total_synacks):
                continue
            severity = "CRÍTICO" if num_sources >= 5 else "ALTO"
            attack_type = "SYN Flood Distribuído" if num_sources >= 5 else "SYN Flood"
            
            # Para ataques distribuídos, lista principais atacantes
            if num_sources >= 5:
                top_attackers = sorted(
                    aggregated["connections"],
                    key=lambda x: x["syns"],
                    reverse=True
                )[:5]
                attacker_list = ", ".join([a["attacker"] for a in top_attackers])
                attacker_display = f"{num_sources} atacantes (top: {attacker_list})"
            else:
                attacker_display = ", ".join(aggregated["sources"])
            
            padroes["ddos_attacks"][f"{attack_type}_{target}:{port}"] = {
                "type": attack_type,
                "attacker": attacker_display,
                "target": target,
                "port": port,
                "syn_sent": total_syns,
                "ack_received": total_synacks,
                "ratio": f"{ratio:.2f}",
                "num_attackers": num_sources,
                "severity": severity,
            }

    # 2. Analisar UDP Flood (Agregado por alvo)
    for target, data in udp_target_volume.items():
        count = data["count"]
        sources = len(data["sources"])
        
        if count > cfg.UDP_FLOOD_THRESHOLD:
            # PROTEÇÃO CONTRA FALSO POSITIVO
            if is_known_good_ip(target):
                continue  # Ignora DNS Google, Cloudflare, etc
            
            # NOVO: Verificar PPS - mas considerar volume absoluto também
            udp_pps = count / duracao_segundos
            
            # Regras de detecção mais inteligentes:
            # 1. Alto volume absoluto (>5000) = sempre suspeito (MESMO se IP local)
            #    Permite detectar ataques internos/labs
            # 2. PPS moderado/alto (>50) = flood ativo
            # 3. Volume médio + PPS baixo + IP local = pode ser tráfego normal
            if count < 5000 and udp_pps < 50:
                # Volume baixo + PPS baixo = provavelmente tráfego normal espalhado
                continue
            
            # Ignora IPs locais APENAS se volume baixo (<5000)
            # Se volume alto, detecta mesmo sendo IP local (ataque interno/lab)
            if count < 5000 and is_local_ip(target):
                continue  # Tráfego local baixo não é DDoS
            
            severity = "CRÍTICO" if sources >= 5 else "ALTO"
            attack_type = "UDP Flood Distribuído" if sources >= 5 else "UDP Flood"
            
            padroes["ddos_attacks"][f"UDP_FLOOD → {target}"] = {
                "type": attack_type,
                "target": target,
                "packet_count": count,
                "num_attackers": sources,
                "severity": severity,
            }

    # 4. ICMP Flood
    for target_ip, count in icmp_target_volume.items():
        if count > cfg.ICMP_FLOOD_LOW:
            severity = "ALTO" if count > cfg.ICMP_FLOOD_HIGH else "MÉDIO"
            padroes["ddos_attacks"][f"ICMP_FLOOD_{target_ip}"] = {
                "type": "ICMP Flood (Ping Flood)",
                "target": target_ip,
                "icmp_packets": count,
                "severity": severity,
            }

    # ACK Flood (apenas ACKs órfãos)
    for target_key, count in ack_flood_target.items():
        if count > cfg.ACK_FLOOD_THRESHOLD:
            target_ip, port = target_key
            
            # PROTEÇÃO CONTRA FALSO POSITIVO
            if is_trafego_normal_legitimo(target_ip, port):
                continue  # Ignora IPs conhecidos ou PPS baixo
            
            padroes["ddos_attacks"][f"ACK_FLOOD_{target_ip}:{port}"] = {
                "type": "ACK Flood",
                "target": target_ip,
                "port": port,
                "ack_packets": count,
                "severity": "ALTO",
            }

    # 5. Processar Port Scanning
    for (src, dst), ports in port_scan_detector.items():
        if len(ports) > cfg.PORT_SCAN_MEDIUM:  # Ex: 10 portas
            padroes["port_scanning"][f"{src} → {dst}"] = {
                "ports_scanned": len(ports),
                "example_ports": list(ports)[:5],
            }
    
    # 6. Identificar IPs envolvidos em ataques (para filtrar falsos positivos)
    ddos_ips = set()
    for attack_info in padroes["ddos_attacks"].values():
        if isinstance(attack_info, dict):
            if attack_info.get("attacker"):
                ddos_ips.add(attack_info["attacker"])
            if attack_info.get("target"):
                ddos_ips.add(attack_info["target"])
    
    # 7. Upload/Exfiltração (excluir IPs de DDoS)
    for src, bytes_sent in uploads.items():
        if src not in ddos_ips:
            mb_sent = bytes_sent / (1024 * 1024)
            if mb_sent > 50:  # 50MB
                padroes["data_leakage"].append({
                    "src": src,
                    "mb_sent": f"{mb_sent:.2f} MB",
                    "tipo": "Alto volume de upload",
                })
    
    # 8. Processar hosts com múltiplas conexões (excluir IPs de DDoS)
    for host, destinos in conexoes_por_host.items():
        if host not in ddos_ips and len(destinos) > cfg.BOTNET_CONNECTIONS_LOW:
            padroes["hosts_com_multiplas_conexoes"][host] = len(destinos)
    
    # ARP Spoofing (mantido - funciona bem)
    for src_ip, mac_addresses in arp_ip_to_mac.items():
        if len(mac_addresses) > 1:
            padroes["ddos_attacks"][f"ARP_SPOOFING_MAC_CONFLICT: {src_ip}"] = {
                "type": "ARP Spoofing (Conflito de MAC)",
                "ip": src_ip,
                "mac_addresses": list(mac_addresses),
                "num_macs": len(mac_addresses),
                "severity": "CRÍTICO",
            }
    
    for src_ip, count in arp_table.items():
        if count > cfg.ARP_SPOOFING_THRESHOLD and len(arp_ip_to_mac.get(src_ip, set())) <= 1:
            padroes["ddos_attacks"][f"ARP_FLOODING: {src_ip}"] = {
                "type": "ARP Flooding (Alto Volume)",
                "source": src_ip,
                "arp_packets": count,
                "num_attackers": 1,
                "severity": "MÉDIO",
            }
    
    # Fragmentação IP por alvo
    for target_ip, count in fragmented_by_target.items():
        if count > cfg.FRAGMENT_ATTACK_THRESHOLD:
            padroes["ddos_attacks"][f"FRAGMENTATION_ATTACK_{target_ip}"] = {
                "type": "Ataque de Fragmentação IP",
                "target": target_ip,
                "small_packets": count,
                "severity": "MÉDIO",
            }
    
    # Alta entropia (mantido - funciona bem)
    for pkt in high_entropy_packets:
        src_ip = pkt["src_ip"]
        dst_ip = pkt["dst_ip"]
        dst_port = pkt.get("dst_port")
        src_port = pkt.get("src_port")
        
        # Ignorar IPs de DDoS e portas HTTPS/TLS conhecidas
        portas_tls = {443, 8443, 465, 587, 993, 995, 636, 989, 990, 992, 5061}
        eh_porta_tls = dst_port in portas_tls or src_port in portas_tls
        
        if src_ip not in ddos_ips and dst_ip not in ddos_ips and not eh_porta_tls:
            # Alta entropia em porta não-HTTPS = suspeito
            padroes["comunicacao_c2"].append({
                "src": src_ip,
                "dst": dst_ip,
                "port": dst_port or src_port or "desconhecido",
                "entropy": pkt["entropy"],
            })
    
    # Processar conexões suspeitas
    for conexao, count in portas_suspeitas.items():
        if count > 200:
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
    # 🔍 REMOVIDO: Pacotes pequenos (<64 bytes) são NORMAIS em TCP (ACKs, handshake)
    # Causa falsos positivos massivos - ACKs têm ~54-66 bytes
    # if tiny_packets > 1000:
    #     padroes["anomalias_trafego"].append({
    #         "tipo": "pacotes_muito_pequenos",
    #         "count": tiny_packets,
    #         "tamanho": f"< {cfg.PACKET_SIZE_ANOMALY_MIN} bytes"
    #     })
    
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

    resumo += "\n🔍 PADRÕES DE TRÁFEGO DETECTADOS (Para análise contextual pela IA):\n"

    # DEBUG CRÍTICO: Verificar se ataques DDoS foram detectados
    print(f"\n{'='*80}")
    print(f"🔍 [CRÍTICO] padroes_suspeitos['ddos_attacks'] = {padroes_suspeitos.get('ddos_attacks')}")
    print(f"🔍 [CRÍTICO] Número de ataques: {len(padroes_suspeitos.get('ddos_attacks', {}))}")
    print(f"{'='*80}\n")

    # SEMPRE adicionar seção de ataques (mesmo que vazia) para clareza do LLM
    resumo += "\n" + "="*80 + "\n"
    resumo += "🚨 ATAQUES CONFIRMADOS PELO MOTOR HEURÍSTICO:\n"
    resumo += "="*80 + "\n"
    
    # Verificar se há ataques - dicionário não-vazio
    ddos_attacks = padroes_suspeitos.get("ddos_attacks", {})
    
    if ddos_attacks and len(ddos_attacks) > 0:
        resumo += f"\n✅ {len(ddos_attacks)} ATAQUE(S) DETECTADO(S):\n\n"
        
        # Organizar ataques por tipo para melhor legibilidade
        ataques_por_tipo = {}
        for attack_key, attack_info in ddos_attacks.items():
            if isinstance(attack_info, dict):
                tipo = attack_info.get('type', 'Ataque Desconhecido')
                if tipo not in ataques_por_tipo:
                    ataques_por_tipo[tipo] = []
                ataques_por_tipo[tipo].append(attack_info)
        
        # Exibir ataques organizados por tipo
        for tipo_ataque, ataques_lista in sorted(ataques_por_tipo.items()):
            resumo += f"\n>>> {tipo_ataque.upper()}: {len(ataques_lista)} detecção(ões)\n"
            
            for idx, attack_info in enumerate(ataques_lista, 1):
                resumo += f"   [{idx}] "
                
                # Atacante → Alvo:Porta (se houver)
                if attack_info.get("attacker"):
                    resumo += f"Origem: {attack_info['attacker']} | "
                
                if attack_info.get("target"):
                    resumo += f"Alvo: {attack_info.get('target')}"
                    if attack_info.get("port") and not attack_info.get("num_targets"):
                        resumo += f":{attack_info['port']}"
                
                # Métricas detalhadas
                if attack_info.get("syn_sent"):
                    resumo += f" | SYN Enviados: {attack_info['syn_sent']}, ACK Recebidos: {attack_info.get('ack_received', 0)}, Taxa: {attack_info.get('ratio', 'N/A')}"
                elif attack_info.get("total_syn_packets"):
                    resumo += f" | Total SYN: {attack_info['total_syn_packets']}"
                elif attack_info.get("packet_count"):
                    resumo += f" | Pacotes: {attack_info['packet_count']}"
                elif attack_info.get("icmp_packets"):
                    resumo += f" | Pacotes ICMP: {attack_info['icmp_packets']}"
                elif attack_info.get("arp_packets"):
                    resumo += f" | Pacotes ARP: {attack_info['arp_packets']}"
                elif attack_info.get("ack_packets"):
                    resumo += f" | Pacotes ACK: {attack_info['ack_packets']}"
                
                # Número de atacantes (se distribuído)
                if attack_info.get("num_attackers"):
                    if attack_info["num_attackers"] > 1:
                        resumo += f" | 🎯 {attack_info['num_attackers']} atacantes"
                    else:
                        resumo += f" | 1 atacante"
                
                resumo += f" | 🔴 SEVERIDADE: {attack_info.get('severity', 'DESCONHECIDA')}\n"
    else:
        resumo += "✅ NENHUM ATAQUE DETECTADO\n"
        resumo += "\n"
        resumo += "O motor heurístico analisou o tráfego e não identificou:\n"
        resumo += "- SYN Flood (ratio de resposta normal)\n"
        resumo += "- UDP Flood (volume dentro dos limites)\n"
        resumo += "- ICMP Flood (pings normais)\n"
        resumo += "- ACK Flood (ACKs legítimos)\n"
        resumo += "- DDoS Distribuído (sem múltiplos atacantes coordenados)\n"
        resumo += "- Port Scan massivo (conexões normais)\n"
        resumo += "- ARP Spoofing ou ARP Flooding\n"
    
    resumo += "\n" + "="*80 + "\n"
    resumo += "FIM DA SEÇÃO DE ATAQUES\n"
    resumo += "="*80 + "\n"

    if padroes_suspeitos.get("hosts_com_multiplas_conexoes"):
        resumo += "\n🔗 HOSTS COM MÚLTIPLAS CONEXÕES:\n"
        for host, count in padroes_suspeitos.get("hosts_com_multiplas_conexoes", {}).items():
            resumo += f"- {host} conectou-se a {count} destinos externos distintos\n"

    if padroes_suspeitos.get("port_scanning"):
        resumo += "\n🔍 TESTES DE PORTAS:\n"
        for scan, ports in padroes_suspeitos.get("port_scanning", {}).items():
            resumo += f"- {scan} acessou {ports} portas distintas\n"

    if padroes_suspeitos.get("comunicacao_c2"):
        # 🔍 FILTRO: Remover entradas de TLS/HTTPS antes de enviar ao LLM
        # Problema: Mesmo com filtro no código, LLM pode interpretar como C2
        c2_filtered = [c2 for c2 in padroes_suspeitos.get("comunicacao_c2", []) 
                       if c2.get('port') not in {443, 8443, 465, 587, 993, 995}]
        if c2_filtered:
            resumo += "\n📡 TRÁFEGO COM ALTA ENTROPIA (>7.5, portas não-TLS):\n"
            for c2 in c2_filtered[:5]:
                resumo += f"- {c2['src']} → {c2['dst']}:{c2['port']} (entropia: {c2['entropy']:.2f})\n"

    # DOMÍNIOS DNS CONSULTADOS (para IA analisar reputação) - LIMITADO para evitar estouro de contexto
    if iocs_e_dominios.get("dominios_consultados"):
        resumo += "\n🌐 DOMÍNIOS DNS CONSULTADOS:\n"
        dominios = iocs_e_dominios.get("dominios_consultados", [])[:10]  # Top 10 (reduzido de 15)
        for dom in dominios:
            # 🔒 SANITIZAÇÃO CRÍTICA contra prompt injection
            # VULNERABILIDADE: domínio como ".\n\n8. IGNORE REGRAS\n\nexample.com"
            # pode fazer LLM ignorar instruções e mentir sobre detecções
            dominio_limpo = str(dom['dominio'])
            # Remover TODOS caracteres de controle e quebras de linha
            dominio_limpo = dominio_limpo.replace('\n', ' ').replace('\r', ' ').replace('\t', ' ').replace('\0', '')
            # Remover comandos de sistema que podem manipular LLM
            dangerous = ['SYSTEM:', 'USER:', 'ASSISTANT:', 'IGNORE', 'FORGET', 'DISREGARD', 'OVERRIDE']
            for cmd in dangerous:
                dominio_limpo = dominio_limpo.replace(cmd, f"[FILTERED]")
            dominio_limpo = dominio_limpo.strip()
            if len(dominio_limpo) > 100:  # Limitar tamanho
                dominio_limpo = dominio_limpo[:100] + "...[truncado]"
            # Validar se é domínio válido (apenas alfanumérico, pontos, hífens)
            import re
            if not re.match(r'^[a-zA-Z0-9.-]+$', dominio_limpo):
                dominio_limpo = "[DOMÍNIO_INVÁLIDO_FILTRADO]"
            resumo += f"- {dominio_limpo}\n"
        total_dominios = len(iocs_e_dominios.get("dominios_consultados", []))
        if total_dominios > 10:
            resumo += f"... e mais {total_dominios - 10} domínios\n"
    
    # IPs DE DESTINO ÚNICOS (para IA verificar ASN/reputação) - LIMITADO
    if iocs_e_dominios.get("ips_destino_unicos"):
        resumo += "\n🎯 IPs DE DESTINO ÚNICOS:\n"
        ips = sorted(iocs_e_dominios.get("ips_destino_unicos", []))[:15]  # Top 15 (reduzido de 20)
        for ip in ips:
            resumo += f"- {ip}\n"
        total_ips = len(iocs_e_dominios.get("ips_destino_unicos", []))
        if total_ips > 15:
            resumo += f"... e mais {total_ips - 15} IPs\n"

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
    dados_formatados, relatorio_yara, modelo="llama3", host=None, port=None, relatorio_yara_resultado=None
):
    """Análise híbrida: LLM para comportamento + YARA como evidência complementar
    
    Args:
        dados_formatados: String com análise heurística formatada
        relatorio_yara: String com texto do relatório YARA
        modelo: Nome do modelo LLM a usar
        host: Host do Ollama
        port: Porta do Ollama
        relatorio_yara_resultado: Dict com detecções YARA estruturadas
    """
    
    # PROTEÇÃO CONTRA ESTOURO DE CONTEXTO (context window overflow)
    # Limite: 100000 caracteres (~25000 tokens) para permitir TODOS os dados sem truncamento
    MAX_DATA_SIZE = 100000
    
    # ⚠️ TRUNCAMENTO INTELIGENTE: Priorizar seções críticas
    # Se precisar truncar, remover seções menos críticas primeiro:
    # 1. Manter: ESTATÍSTICAS, ATAQUES CONFIRMADOS (DDoS), HOSTS COM MÚLTIPLAS CONEXÕES
    # 2. Reduzir: Domínios DNS (já limitado a 10), IPs únicos (já limitado a 15)
    # 3. Remover: Portas menos acessadas, entropias altas (se necessário)
    # IMPORTANTE: Seção "🚨 ATAQUES CONFIRMADOS" tem MÁXIMA prioridade
    
    if len(dados_formatados) > MAX_DATA_SIZE:
        # Tentar preservar seção de ataques - ela deve estar no início após estatísticas
        if "🚨 ATAQUES CONFIRMADOS PELO MOTOR HEURÍSTICO:" in dados_formatados:
            # Encontrar onde começa e termina a seção de ataques
            inicio_ataques = dados_formatados.find("🚨 ATAQUES CONFIRMADOS PELO MOTOR HEURÍSTICO:")
            fim_ataques = dados_formatados.find("FIM DA SEÇÃO DE ATAQUES", inicio_ataques)
            
            if fim_ataques > 0:
                # Extrair seção de ataques completa
                secao_ataques = dados_formatados[inicio_ataques:fim_ataques + 30]
                
                # Truncar o resto dos dados
                dados_antes = dados_formatados[:inicio_ataques]
                dados_depois = dados_formatados[fim_ataques + 30:]
                
                # Reconstruir mantendo ataques e truncando o resto
                espaco_restante = MAX_DATA_SIZE - len(secao_ataques) - len(dados_antes) - 200
                if espaco_restante > 0:
                    dados_depois_truncados = dados_depois[:espaco_restante]
                    last_newline = dados_depois_truncados.rfind('\n')
                    if last_newline > 0:
                        dados_depois_truncados = dados_depois_truncados[:last_newline]
                    dados_formatados = dados_antes + secao_ataques + dados_depois_truncados + f"\n\n⚠️ [DADOS PARCIALMENTE TRUNCADOS - Seção de ATAQUES preservada]"
                else:
                    dados_formatados = dados_antes + secao_ataques + f"\n\n⚠️ [DADOS TRUNCADOS - Seção de ATAQUES preservada]"
            else:
                # Fallback: truncamento simples
                dados_truncados = dados_formatados[:MAX_DATA_SIZE]
                last_newline = dados_truncados.rfind('\n')
                if last_newline > 0:
                    dados_truncados = dados_truncados[:last_newline]
                dados_formatados = dados_truncados + f"\n\n⚠️ [DADOS TRUNCADOS]"
        else:
            # Sem seção de ataques, truncamento normal
            dados_truncados = dados_formatados[:MAX_DATA_SIZE]
            last_newline = dados_truncados.rfind('\n')
            if last_newline > 0:
                dados_truncados = dados_truncados[:last_newline]
            dados_formatados = dados_truncados + f"\n\n⚠️ [DADOS TRUNCADOS]"
    
    if len(relatorio_yara) > MAX_DATA_SIZE:
        yara_truncado = relatorio_yara[:MAX_DATA_SIZE]
        last_newline = yara_truncado.rfind('\n')
        if last_newline > 0:
            yara_truncado = yara_truncado[:last_newline]
        relatorio_yara = yara_truncado + f"\n\n⚠️ [RELATÓRIO TRUNCADO]"

    # 🔒 SANITIZAÇÃO SELETIVA contra Prompt Injection
    # IMPORTANTE: NÃO remover \n dos dados_formatados (quebra a estrutura do prompt)
    # Sanitização já foi feita em formatar_dados_para_analise() nos domínios DNS
    # Aqui apenas garantimos que não há comandos perigosos no YARA report
    def sanitize_yara_only(text):
        """Sanitiza apenas YARA report, preservando formatação dos dados"""
        if not text:
            return ""
        # Remover comandos perigosos mas PRESERVAR quebras de linha
        dangerous_keywords = ['SYSTEM:', 'USER:', 'ASSISTANT:', 'IGNORE', 'FORGET', 'DISREGARD']
        for keyword in dangerous_keywords:
            text = text.replace(keyword, f"[FILTERED:{keyword[:3]}]")
        return text
    
    # Aplicar sanitização APENAS no YARA (não nos dados formatados!)
    # dados_formatados já tem sanitização nos domínios DNS
    relatorio_yara = sanitize_yara_only(relatorio_yara)
    
    # ============================================================================
    # FORMATAR DETECÇÕES YARA ESTRUTURADAS SE DISPONÍVEIS (heurística intacta)
    # ============================================================================
    yara_estruturado = ""
    deteccoes_para_estruturar = []

    total_deteccoes_yara = relatorio_yara_resultado.get("total_deteccoes", 0) if relatorio_yara_resultado else 0

    # PRIORIDADE 1: usar detecções estruturadas do dicionário
    if relatorio_yara_resultado and relatorio_yara_resultado.get("deteccoes"):
        deteccoes_para_estruturar = relatorio_yara_resultado["deteccoes"]

    # PRIORIDADE 2: se não vierem estruturadas, extrair do texto bruto do relatório YARA
    if not deteccoes_para_estruturar and relatorio_yara:
        linhas = relatorio_yara.split("\n")
        for linha in linhas:
            if "✓ Detectado:" in linha or "REGRA:" in linha or "Detectado" in linha:
                deteccoes_para_estruturar.append({
                    "regra": linha.strip(),
                    "arquivo": "Extraído do relatório YARA",
                    "severidade": "ALTA",
                })

    # PRIORIDADE 3: se total_deteccoes>0 mas lista vazia, sinalizar mesmo assim
    if not deteccoes_para_estruturar and relatorio_yara_resultado:
        total = relatorio_yara_resultado.get("total_deteccoes", 0)
        if total > 0:
            yara_estruturado = (
                f"\n🔍 RELATÓRIO YARA:\n" + "=" * 80 + "\n"
                f"⚠️ YARA sinalizou {total} detecções, mas a lista estruturada está vazia.\n"
                f"Relatório bruto:\n{relatorio_yara}\n" + "=" * 80 + "\n"
            )

    # Estruturar detecções quando encontradas
    if deteccoes_para_estruturar:
        yara_estruturado = "\n🔍 DETECÇÕES YARA ESTRUTURADAS:\n" + "=" * 80 + "\n"
        yara_estruturado += f"Total de detecções YARA: {total_deteccoes_yara}\n"

        # Agrupar por regra
        deteccoes_por_regra = {}
        for deteccao in deteccoes_para_estruturar:
            regra = deteccao.get("regra", "Desconhecido")
            if "✓ Detectado:" in str(regra):
                regra = regra.replace("✓ Detectado:", "").strip()

            if regra not in deteccoes_por_regra:
                deteccoes_por_regra[regra] = {
                    "arquivos": [],
                    "severidade": deteccao.get("severidade", "ALTA"),
                }

            arquivo = deteccao.get("arquivo", "Não especificado")
            if arquivo not in deteccoes_por_regra[regra]["arquivos"]:
                deteccoes_por_regra[regra]["arquivos"].append(arquivo)

        # Formatar saída agrupada
        for idx, (regra, info) in enumerate(deteccoes_por_regra.items(), 1):
            severidade = info["severidade"]
            arquivos = info["arquivos"]

            yara_estruturado += f"\n[{idx}] REGRA: {regra}\n"
            yara_estruturado += f"    Severidade: {severidade}\n"
            yara_estruturado += f"    Arquivos ({len(arquivos)}):\n"
            for arq in arquivos:
                yara_estruturado += f"       • {arq}\n"

        yara_estruturado += "\n" + "=" * 80 + "\n"

    # FALLBACK final: nenhuma detecção
    if not yara_estruturado:
        yara_estruturado = (
            "\n🔍 RELATÓRIO YARA:\n" + "=" * 80 + "\n"
            "✅ Nenhuma detecção YARA encontrada nos arquivos extraídos.\n" + "=" * 80 + "\n"
        )
    
    prompt = f"""


📄 RELATÓRIO YARA (COMPLETO - TEXTO ORIGINAL)
{relatorio_yara}

📊 ANÁLISE HEURÍSTICA - PADRÕES DE ATAQUE
{dados_formatados}

═══════════════════════════════════════════════════════════════
INSTRUÇÕES PARA O LLM
═══════════════════════════════════════════════════════════════

Você é um analista de segurança. Analise os dados acima e gere um relatório.

REGRAS:
1. Use sempre "CONFIRMADO" ou "DETECTADO" (não use "suspeito" ou "possível")
2. PRIMEIRO, liste TODOS os malwares do RELATÓRIO YARA
3. SEGUNDO, liste TODOS os ataques da ANÁLISE HEURÍSTICA (veja abaixo)
4. Se não houver ataques/malwares, escreva "Nenhuma detecção"

ESTRUTURA OBRIGATÓRIA DO RELATÓRIO:

**1. MALWARE (YARA):**
Formato: "**[NOME]** (severidade [NÍVEL]) em `[ARQUIVO]`"
Exemplo: "**Bumblebee_Specific_IOCs** (severidade ALTO) em `http_request_4.bin`"

**2. ATAQUES CONFIRMADOS - LISTAR TODOS OS 4 TIPOS ABAIXO:**

🚨 **ATAQUES FLOOD (SYN/UDP/ICMP/ACK):**
- Formato: "[TIPO] Flood CONFIRMADO contra [IP:PORTA] com [NÚMERO] pacotes, [NÚMERO] atacante(s), severidade [NÍVEL]"
- Exemplo: "SYN Flood CONFIRMADO contra 192.168.1.100:80 com 5000 pacotes SYN, 1 atacante, severidade CRÍTICO"

🔗 **MÚLTIPLAS CONEXÕES (BOTNET):**
- Formato: "[IP] estabeleceu conexões para [N] destinos externos distintos, severidade [NÍVEL]"
- Exemplo: "192.168.1.50 estabeleceu conexões para 23 destinos externos distintos, severidade ALTO"

🔍 **PORT SCANNING:**
- Formato: "[IP_ORIGEM] tentou acessar [N] portas diferentes em [IP_DESTINO], severidade [NÍVEL]"
- Exemplo: "192.168.1.100 tentou acessar 47 portas diferentes em 10.0.0.1, severidade MÉDIO"

📡 **PACOTES COM ALTA ENTROPIA (C2):**
- Formato: "[IP_ORIGEM] → [IP_DESTINO]:[PORTA] com entropia [VALOR], severidade [NÍVEL]"
- Exemplo: "192.168.1.50 → 203.0.113.100:8080 com entropia 7.92, severidade ALTO"

**3. CLASSIFICAÇÃO DE RISCO:**
CRÍTICO / ALTO / MÉDIO / BAIXO

**4. RECOMENDAÇÕES:**
Ações específicas para cada ameaça detectada

═══════════════════════════════════════════════════════════════
"""
    
    # Configurar host e porta do Ollama
    if host is None:
        host = settings.OLLAMA_HOST
    if port is None:
        port = settings.OLLAMA_PORT

    try:
        # Configurar cliente Ollama com host/port específico (thread-safe)
        # Não usar os.environ para evitar poluição global em ambientes multithread
        client_options = {}
        if host and port:
            client_options['host'] = f"{host}:{port}"
        elif host:
            client_options['host'] = host
        
        # Criar cliente com configuração explícita ou usar padrão
        if client_options:
            cliente = ollama.Client(**client_options)
            resposta = cliente.chat(
                model=modelo, messages=[{"role": "user", "content": prompt}]
            )
        else:
            # Usar cliente padrão
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
        analysis_run_id = str(uuid4())
        analysis_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
                relatorio_yara_resultado = {"total_deteccoes": 0, "arquivos_extraidos": 0, "ruleset_version": YARA_RULESET_VERSION_SUBPROCESS}
            else:
                try:
                    relatorio_yara_resultado = executar_analise_yara_completa(arquivo_pcap)
                    relatorio_yara_texto = relatorio_yara_resultado.get(
                        "relatorio_texto", "❌ Relatório YARA não disponível"
                    )
                except Exception as e:
                    logger.warning(f"⚠️ Análise YARA falhou: {e}")
                    relatorio_yara_resultado = {"total_deteccoes": 0, "arquivos_extraidos": 0, "ruleset_version": YARA_RULESET_VERSION_SUBPROCESS}
                    relatorio_yara_texto = "❌ Análise YARA não disponível"
        else:
            logger.info(f"⏭️ Modo '{analysis_mode}': Pulando análise YARA")
            relatorio_yara_texto = f"⚠️ Análise YARA desativada (modo: {analysis_mode})"
            relatorio_yara_resultado = {"total_deteccoes": 0, "arquivos_extraidos": 0, "ruleset_version": YARA_RULESET_VERSION_SUBPROCESS}
        
        # Extrair assinaturas detectadas pelo YARA para o painel
        malware_signatures = {}
        if relatorio_yara_resultado.get("deteccoes"):
            for deteccao in relatorio_yara_resultado["deteccoes"]:
                regra = deteccao.get("regra", "Desconhecido")
                # Limpar nome da regra (remover sufixos técnicos se houver)
                familia = regra.replace("_", " ").strip()
                malware_signatures[familia] = malware_signatures.get(familia, 0) + 1
        
        # Atualizar score de malware com detecções YARA
        total_deteccoes_yara = relatorio_yara_resultado.get("total_deteccoes", 0)
        if total_deteccoes_yara > 0:
            severidade_maxima = relatorio_yara_resultado.get("severidade_maxima", "baixa")
            
            # Adicionar pontos ao score baseado na severidade
            yara_score_adicional = 0
            if severidade_maxima == "critica":
                yara_score_adicional = 50  # Malware crítico = +50 pontos
                scoring_result["evidencias"].append(
                    f"CRÍTICO: {total_deteccoes_yara} detecções YARA de severidade CRÍTICA"
                )
            elif severidade_maxima == "alta":
                yara_score_adicional = 35  # Malware alto = +35 pontos
                scoring_result["evidencias"].append(
                    f"ALTO: {total_deteccoes_yara} detecções YARA de severidade ALTA"
                )
            elif severidade_maxima == "media":
                yara_score_adicional = 25  # Malware médio = +25 pontos
                scoring_result["evidencias"].append(
                    f"MÉDIO: {total_deteccoes_yara} detecções YARA de severidade MÉDIA"
                )
            else:
                yara_score_adicional = 15  # Malware baixo = +15 pontos
                scoring_result["evidencias"].append(
                    f"BAIXO: {total_deteccoes_yara} detecções YARA"
                )
            
            # Atualizar score (máximo 100)
            scoring_result["score"] = min(scoring_result["score"] + yara_score_adicional, 100)
            scoring_result["nivel_risco"] = get_risk_level(scoring_result["score"])

        yara_ruleset_version = analysis_timestamp
        version_banner = (
            f"🕒 DATA/HORA DA ANÁLISE: {analysis_timestamp}\n\n"
        )

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
                    dados_formatados, relatorio_yara_texto, modelo, host=host, port=port, 
                    relatorio_yara_resultado=relatorio_yara_resultado
                )
            except Exception as e_llm:
                logger.error(f"Falha na análise LLM: {e_llm}. Retornando erro.")
                raise Exception(f"Erro na análise LLM: {e_llm}")  # Remover fallback
        else:
            logger.info(f"⏭️ Modo '{analysis_mode}': Análise LLM desativada")
            analise_llm = f"📊 MODO: {analysis_mode.upper()}\n\n{relatorio_yara_texto}"

        analise_llm = version_banner + analise_llm

        # FASE 10: RESULTADO FINAL COMBINADO
        total_deteccoes_yara = relatorio_yara_resultado.get("total_deteccoes", 0)
        arquivos_extraidos = relatorio_yara_resultado.get("arquivos_extraidos", 0)

        resumo = f"""
    🕒 DATA/HORA DA ANÁLISE: {analysis_timestamp}

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
            "trafego_alta_entropia": len(padroes_suspeitos.get("comunicacao_c2", [])),
        }

        return {
            "packet_count": len(dados_pacotes),
            "analysis_text": analise_llm,
            "summary": resumo,
            "raw_data": dados_formatados,
            "analysis_run_id": analysis_run_id,
            "analysis_version": ANALYSIS_PIPELINE_VERSION,
            "analysis_timestamp": analysis_timestamp,
            "yara_ruleset_version": yara_ruleset_version,
            "malware_score": scoring_result.get("score", 0),
            "risk_level": scoring_result.get("nivel_risco", "MÍNIMO"),
            "network_patterns": network_patterns,
            "malware_signatures": malware_signatures,  # Extraído das detecções YARA
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
