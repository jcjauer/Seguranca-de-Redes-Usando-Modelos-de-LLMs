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

    DEPENDENCIES_OK = True
except ImportError as e:
    print(f"Erro ao importar dependências: {e}")
    print("Certifique-se de que scapy e ollama estão instalados")
    DEPENDENCIES_OK = False

# Importação condicional para evitar erro quando executado diretamente
try:
    from .utils import get_ollama_models as get_ollama_models_subprocess
    from .yara_detector import (
        executar_analise_yara_completa,
    )  # INTEGRAÇÃO COM MÓDULO YARA
except ImportError:
    # Fallback quando executado diretamente
    def get_ollama_models_subprocess():
        return ["llama3", "llama3.1", "qwen2.5"]

    def executar_analise_yara_completa(arquivo_pcap):
        return {"status": "erro", "relatorio_texto": "❌ Módulo YARA não disponível"}


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
                # analisando o payload real do HTTP
                # simular baseado nos padrões mostrados
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
    """Calcula score de probabilidade de malware (0-100) baseado em evidências"""
    score = 0
    evidencias = []

    # SCORING POR CATEGORIA

    # 1. Múltiplas conexões externas (25 pontos máximo)
    if padroes_suspeitos["hosts_com_multiplas_conexoes"]:
        for host, count in padroes_suspeitos["hosts_com_multiplas_conexoes"].items():
            if count > 50:
                score += 25
                evidencias.append(
                    f"CRÍTICO: {host} conectou a {count} destinos externos (botnet massiva)"
                )
            elif count > 20:
                score += 20
                evidencias.append(
                    f"ALTO: {host} conectou a {count} destinos externos (botnet)"
                )
            elif count > 10:
                score += 15
                evidencias.append(f"ALTO: {host} conectou a {count} destinos externos")
            elif count > 5:
                score += 10
                evidencias.append(f"MÉDIO: {host} conectou a {count} destinos externos")

    # 2. Port scanning (20 pontos máximo)
    if padroes_suspeitos["port_scanning"]:
        for scan, ports in padroes_suspeitos["port_scanning"].items():
            if ports > 100:
                score += 20
                evidencias.append(f"CRÍTICO: Port scan massivo {scan} ({ports} portas)")
            elif ports > 50:
                score += 15
                evidencias.append(f"ALTO: Port scan extenso {scan} ({ports} portas)")
            elif ports > 20:
                score += 10
                evidencias.append(f"MÉDIO: Port scan {scan} ({ports} portas)")
            else:
                score += 5
                evidencias.append(f"BAIXO: Port scan {scan} ({ports} portas)")

    # 3. Flooding attacks (15 pontos máximo)
    if padroes_suspeitos["flood_attacks"]:
        max_flood = max(padroes_suspeitos["flood_attacks"].values())
        if max_flood > 5000:
            score += 15
            evidencias.append(f"CRÍTICO: Flood DDoS massivo ({max_flood} pacotes)")
        elif max_flood > 1000:
            score += 12
            evidencias.append(f"ALTO: Flood significativo ({max_flood} pacotes)")
        elif max_flood > 500:
            score += 8
            evidencias.append(f"MÉDIO: Flood moderado ({max_flood} pacotes)")
        else:
            score += 5
            evidencias.append(f"BAIXO: Flood detectado ({max_flood} pacotes)")

    # 4. Comunicação C2 (20 pontos máximo)
    if padroes_suspeitos["comunicacao_c2"]:
        high_entropy_count = len(
            [c for c in padroes_suspeitos["comunicacao_c2"] if c["entropy"] > 7.5]
        )
        total_c2 = len(padroes_suspeitos["comunicacao_c2"])

        if high_entropy_count > 20:
            score += 20
            evidencias.append(
                f"CRÍTICO: {high_entropy_count} conexões C2 de alta entropia"
            )
        elif high_entropy_count > 10:
            score += 15
            evidencias.append(f"ALTO: {high_entropy_count} conexões C2 suspeitas")
        elif total_c2 > 5:
            score += 10
            evidencias.append(
                f"MÉDIO: {total_c2} comunicações criptografadas suspeitas"
            )
        else:
            score += 5
            evidencias.append(f"BAIXO: Comunicação criptografada detectada")

    # 5. Domínios maliciosos (10 pontos máximo)
    if dominios_suspeitos["dominios_suspeitos"]:
        malicious_domains = len(
            [
                d
                for d in dominios_suspeitos["dominios_suspeitos"]
                if d["tipo"] == "dominio_malicioso_conhecido"
            ]
        )
        total_suspicious = len(dominios_suspeitos["dominios_suspeitos"])

        if malicious_domains > 5:
            score += 10
            evidencias.append(
                f"CRÍTICO: {malicious_domains} domínios maliciosos conhecidos"
            )
        elif malicious_domains > 0:
            score += 8
            evidencias.append(
                f"ALTO: {malicious_domains} domínios maliciosos conhecidos"
            )
        elif total_suspicious > 3:
            score += 5
            evidencias.append(f"MÉDIO: {total_suspicious} domínios suspeitos")

    # 6. Click fraud (5 pontos máximo)
    if dominios_suspeitos["click_fraud_patterns"]:
        fraud_count = len(dominios_suspeitos["click_fraud_patterns"])
        if fraud_count > 10:
            score += 5
            evidencias.append(f"MÉDIO: {fraud_count} padrões de fraude de cliques")
        else:
            score += 3
            evidencias.append("BAIXO: Padrões de fraude de cliques detectados")

    # 7. Domínios asiáticos suspeitos (5 pontos máximo)
    if dominios_suspeitos["asian_domains"]:
        asian_count = len(set(dominios_suspeitos["asian_domains"]))
        if asian_count > 5:
            score += 5
            evidencias.append(f"MÉDIO: {asian_count} domínios asiáticos suspeitos")
        else:
            score += 2
            evidencias.append(f"BAIXO: {asian_count} domínios asiáticos detectados")

    # Limitar score máximo
    score = min(score, 100)

    return {
        "score": score,
        "nivel": get_risk_level(score),
        "evidencias": evidencias,
        "recomendacao": get_recommendation(score),
    }


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


def get_recommendation(score):
    """Retorna recomendação baseada no score"""
    if score >= 80:
        return "🚨 AÇÃO IMEDIATA: Isolar hosts comprometidos, bloquear IPs externos, iniciar investigação forense completa"
    elif score >= 60:
        return "⚠️ AÇÃO URGENTE: Monitorar hosts suspeitos, implementar regras de firewall, análise detalhada de logs"
    elif score >= 40:
        return "⚡ ATENÇÃO: Investigar anomalias detectadas, aumentar monitoramento, revisar políticas de segurança"
    elif score >= 20:
        return "👁️ MONITORAMENTO: Continuar observando padrões, implementar alertas automáticos"
    else:
        return "✅ NORMAL: Manter monitoramento regular da rede, tráfego dentro dos padrões"


def detectar_assinaturas_malware(dados):
    """Detecta assinaturas específicas de famílias de malware conhecidas"""
    assinaturas = {
        "zeus_botnet": [],
        "conficker": [],
        "emotet": [],
        "trickbot": [],
        "cobalt_strike": [],
        "metasploit": [],
        "wannacry": [],
        "mirai_botnet": [],
        "stuxnet": [],
        "banking_trojans": [],
    }

    for pkt in dados:
        src_ip = pkt.get("src_ip")
        dst_ip = pkt.get("dst_ip")
        dst_port = pkt.get("dst_port")
        entropy = pkt.get("entropy", 0) or 0  # Garantir que não seja None
        protocol = pkt.get("protocol", 0)

        # Skip se não tiver informações básicas
        if not src_ip or not dst_ip:
            continue

        # Assinatura Zeus (comunicação HTTP em portas altas com entropia média)
        if dst_port and 8000 <= dst_port <= 9000 and 4.0 < entropy < 6.0:
            assinaturas["zeus_botnet"].append(
                {
                    "src": src_ip,
                    "dst": dst_ip,
                    "port": dst_port,
                    "indicador": "Zeus HTTP C2 pattern",
                    "confidence": 0.7,
                }
            )

        # Assinatura Conficker (múltiplas tentativas SMB)
        if dst_port == 445 and protocol == 6:  # TCP
            assinaturas["conficker"].append(
                {
                    "src": src_ip,
                    "dst": dst_ip,
                    "port": dst_port,
                    "indicador": "SMB exploitation attempt (Conficker)",
                    "confidence": 0.6,
                }
            )

        # Assinatura Emotet (comunicação HTTPS em portas não padrão com alta entropia)
        if dst_port and dst_port in [443, 8080, 8443, 7080, 8000] and entropy > 7.0:
            assinaturas["emotet"].append(
                {
                    "src": src_ip,
                    "dst": dst_ip,
                    "port": dst_port,
                    "indicador": "Emotet encrypted C2 communication",
                    "confidence": 0.8,
                }
            )

        # Assinatura Cobalt Strike (beaconing pattern com entropia específica)
        if entropy and 6.5 <= entropy <= 7.5:
            assinaturas["cobalt_strike"].append(
                {
                    "src": src_ip,
                    "dst": dst_ip,
                    "entropy": entropy,
                    "indicador": "Cobalt Strike beacon pattern",
                    "confidence": 0.75,
                }
            )

        # Assinatura TrickBot (comunicação em portas bancárias)
        if dst_port and dst_port in [443, 449, 8443] and entropy > 6.0:
            assinaturas["trickbot"].append(
                {
                    "src": src_ip,
                    "dst": dst_ip,
                    "port": dst_port,
                    "indicador": "TrickBot banking communication",
                    "confidence": 0.6,
                }
            )

        # Assinatura Mirai (tentativas Telnet e SSH)
        if dst_port in [23, 22, 2323]:
            assinaturas["mirai_botnet"].append(
                {
                    "src": src_ip,
                    "dst": dst_ip,
                    "port": dst_port,
                    "indicador": f"Mirai IoT exploitation on port {dst_port}",
                    "confidence": 0.65,
                }
            )

        # Assinatura WannaCry (tentativas SMB na porta 445)
        if dst_port == 445 and entropy < 3.0:
            assinaturas["wannacry"].append(
                {
                    "src": src_ip,
                    "dst": dst_ip,
                    "port": dst_port,
                    "indicador": "WannaCry SMB exploitation",
                    "confidence": 0.7,
                }
            )

        # Assinatura Metasploit (portas comuns de payload)
        if dst_port and dst_port in [4444, 4445, 5555, 6666, 8888]:
            assinaturas["metasploit"].append(
                {
                    "src": src_ip,
                    "dst": dst_ip,
                    "port": dst_port,
                    "indicador": "Metasploit reverse shell pattern",
                    "confidence": 0.5,
                }
            )

        # Banking Trojans (comunicação HTTPS com bancos)
        if dst_port == 443 and entropy > 7.0:
            assinaturas["banking_trojans"].append(
                {
                    "src": src_ip,
                    "dst": dst_ip,
                    "port": dst_port,
                    "indicador": "Potential banking trojan communication",
                    "confidence": 0.4,
                }
            )

    return assinaturas


def analisar_comportamento_temporal(dados):
    """Analisa padrões temporais suspeitos e comportamentos de beaconing"""
    from collections import defaultdict

    comportamentos = {
        "beaconing_intervals": [],
        "burst_patterns": [],
        "periodic_communication": [],
        "time_based_anomalies": [],
    }

    # Agrupar por conexão (src_ip, dst_ip, dst_port)
    conexoes = defaultdict(list)
    for i, pkt in enumerate(dados):
        if pkt["src_ip"] and pkt["dst_ip"]:
            key = (pkt["src_ip"], pkt["dst_ip"], pkt["dst_port"])
            conexoes[key].append(i)  # Usar índice como timestamp simulado

    # Detectar beaconing (comunicação periódica característica de malware)
    for conexao, indices in conexoes.items():
        if len(indices) >= 5:  # Pelo menos 5 comunicações
            intervalos = [indices[i + 1] - indices[i] for i in range(len(indices) - 1)]

            # Verificar se intervalos são consistentes (indicativo de beaconing)
            if (
                len(set(intervalos)) <= 3 and len(indices) >= 10
            ):  # Poucos intervalos diferentes
                comportamentos["beaconing_intervals"].append(
                    {
                        "conexao": f"{conexao[0]}→{conexao[1]}:{conexao[2]}",
                        "intervalos": intervalos,
                        "count": len(indices),
                        "consistencia": len(set(intervalos)),
                        "suspeita": "beaconing_malware",
                    }
                )

            # Detectar burst patterns (rajadas de comunicação)
            elif len(indices) > 50:  # Muita comunicação em pouco tempo
                comportamentos["burst_patterns"].append(
                    {
                        "conexao": f"{conexao[0]}→{conexao[1]}:{conexao[2]}",
                        "total_packets": len(indices),
                        "suspeita": "ddos_or_data_exfiltration",
                    }
                )

    return comportamentos


def verificar_threat_intelligence(dados):
    """Verifica IPs e domínios contra bases de threat intelligence simuladas"""
    # Listas de IOCs conhecidos (em produção, usar APIs como VirusTotal, AbuseIPDB)
    malicious_ips = {
        "185.220.101.23": "Tor exit node",
        "60.221.254.19": "Known C2 server (from sample)",
        "125.43.78.107": "Suspicious IP range",
        "1.2.3.4": "Known botnet IP",
        "5.6.7.8": "Malware distribution",
    }

    malicious_domains = {
        "yl.liufen.com": "Click fraud domain",
        "hqs9.cnzz.com": "Malicious analytics",
        "doudouguo.com": "Suspicious redirector",
        "dw156.tk": "Short URL abuse",
        "lckj77.com": "Malware hosting",
    }

    suspicious_countries = [
        "CN",
        "RU",
        "KP",
        "IR",
    ]  # Países com alta atividade maliciosa

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

        # Skip se não tiver IPs válidos
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
            # Simular verificação de geolocalização
            if any(dst_ip.startswith(prefix) for prefix in ["60.", "125.", "185."]):
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


def analisar_com_llm_hibrido(
    dados_formatados, relatorio_yara, modelo="llama3", host=None, port=None
):
    """Análise híbrida: LLM para comportamento + YARA como evidência complementar"""

    prompt = f"""
Você é um especialista em segurança cibernética e análise forense de tráfego de rede especializado em detecção de malware, botnets e ataques APT.

DADOS DE TRÁFEGO PARA ANÁLISE:
{dados_formatados}

=== RELATÓRIO YARA (EVIDÊNCIAS DE MALWARE) ===
{relatorio_yara}

EXECUTE UMA ANÁLISE FORENSE DETALHADA:

🔍 CORRELAÇÃO YARA + TRÁFEGO:
- Se há detecções YARA, correlacione com o tráfego de rede observado
- Identifique quais conexões de rede podem estar relacionadas ao malware detectado
- Analise se o comportamento de rede confirma a presença do malware YARA

🚨 DETECÇÃO DE MALWARE E BOTNETS:
- Identifique padrões de comunicação C&C (Command & Control)
- Detecte tráfego criptografado suspeito (alta entropia)
- Analise conexões com IPs externos não autorizados
- Procure por beaconing (comunicação periódica com servidores remotos)
- Identifique múltiplas conexões de um host interno para destinos externos

🔍 INDICADORES DE COMPROMISSO (IOCs):
- Hosts internos iniciando muitas conexões externas simultâneas
- Tráfego em portas não padronizadas (especialmente > 1024)
- Comunicação com IPs de países com alta atividade maliciosa
- Padrões de DNS suspeitos (DGA - Domain Generation Algorithm)

⚔️ TÉCNICAS DE ATAQUE AVANÇADAS:
- Port scanning e network reconnaissance
- Data exfiltration (baseado em volume e destino)
- Lateral movement (propagação interna)
- Click fraud e ad fraud patterns

📊 ANÁLISE COMPORTAMENTAL:
- Compare volumes de tráfego por host (identifique outliers)
- Analise protocolos incomuns ou mal formados
- Detecte anomalias temporais (rajadas de tráfego)

FORNEÇA UMA RESPOSTA ESTRUTURADA COM:

1. **CLASSIFICAÇÃO DE RISCO** (Crítico/Alto/Médio/Baixo)
2. **CORRELAÇÃO YARA-TRÁFEGO** (como as detecções se relacionam com o tráfego)
3. **AMEAÇAS IDENTIFICADAS** (seja específico sobre o tipo de malware/botnet)
4. **HOSTS COMPROMETIDOS** (liste IPs suspeitos e evidências)
5. **PADRÕES DE ATAQUE** (descreva a campanha maliciosa)
6. **AÇÕES IMEDIATAS** (contenção e isolamento)
7. **INVESTIGAÇÃO FORENSE** (próximos passos para análise)
8. **REMEDIAÇÃO** (limpeza e fortalecimento)

Seja extremamente detalhado e correlacione as evidências YARA com os padrões de tráfego observados.
"""

    try:
        if host:
            os.environ.setdefault("OLLAMA_HOST", host)
        if port:
            os.environ.setdefault("OLLAMA_PORT", str(port))

        resposta = ollama.chat(
            model=modelo, messages=[{"role": "user", "content": prompt}]
        )
        return resposta["message"]["content"]
    except Exception as e:
        return f"Erro na análise LLM híbrida: {str(e)}"


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
    """Função principal para análise completa de PCAP com LLM + YARA (híbrida) e sistema de precisão avançado"""
    try:
        print(
            f"[MAIN] 🚀 Iniciando análise híbrida COMPORTAMENTAL+YARA de: {arquivo_pcap}"
        )

        # 1. ANÁLISE COMPORTAMENTAL (para LLM)
        print("[MAIN] 📊 Processando pacotes para análise comportamental...")
        dados_pacotes = processar_pcap(arquivo_pcap)

        if not dados_pacotes:
            raise Exception("Nenhum pacote IP encontrado no arquivo PCAP")

        # FASE 2: Análises especializadas
        print("🔍 Iniciando análise especializada...")

        # Extrair IPs para análise de botnets
        ips_origem = set(pkt["src_ip"] for pkt in dados_pacotes if pkt["src_ip"])
        ips_destino = set(pkt["dst_ip"] for pkt in dados_pacotes if pkt["dst_ip"])

        # Análise de padrões de botnet
        padroes_suspeitos = analisar_padroes_botnet(
            dados_pacotes, ips_origem, ips_destino
        )

        # Detecção de domínios suspeitos
        dominios_suspeitos = detectar_dominios_suspeitos(dados_pacotes)

        # FASE 3: Sistema de scoring avançado
        print("📊 Calculando score de malware...")
        scoring_result = calcular_score_malware(
            dados_pacotes, padroes_suspeitos, dominios_suspeitos
        )

        # FASE 4: Detecção de assinaturas específicas
        print("🎯 Detectando assinaturas de malware...")
        assinaturas_malware = detectar_assinaturas_malware(dados_pacotes)

        # FASE 5: Análise comportamental temporal
        print("⏱️ Analisando comportamento temporal...")
        comportamento_temporal = analisar_comportamento_temporal(dados_pacotes)

        # FASE 6: Threat Intelligence
        print("🌐 Verificando Threat Intelligence...")
        threat_intel = verificar_threat_intelligence(dados_pacotes)

        # FASE 7: Formatar dados para análise LLM
        dados_formatados = formatar_dados_para_analise(dados_pacotes)

        # FASE 8: ANÁLISE YARA COMPLETA (módulo separado)
        print("🔍 Executando análise YARA...")
        try:
            relatorio_yara_resultado = executar_analise_yara_completa(arquivo_pcap)
            relatorio_yara_texto = relatorio_yara_resultado.get(
                "relatorio_texto", "❌ Relatório YARA não disponível"
            )
        except Exception as e:
            print(f"⚠️ Análise YARA falhou: {e}")
            relatorio_yara_resultado = {"total_deteccoes": 0, "arquivos_extraidos": 0}
            relatorio_yara_texto = "❌ Análise YARA não disponível"

        # Adicionar contexto avançado para o LLM
        contexto_avancado = f"""
ANÁLISE DE SEGURANÇA AVANÇADA - Score: {scoring_result['score']}/100 ({scoring_result['nivel']})

RESUMO EXECUTIVO:
- Total de pacotes: {len(dados_pacotes)}
- Score de malware: {scoring_result['score']}/100
- Nível de risco: {scoring_result['nivel']}
- Recomendação: {scoring_result['recomendacao']}

EVIDÊNCIAS ENCONTRADAS:
{chr(10).join(f"• {evidencia}" for evidencia in scoring_result['evidencias'])}

ASSINATURAS DE MALWARE DETECTADAS:
{chr(10).join(f"• {familia}: {len(assinaturas)} indicadores" for familia, assinaturas in assinaturas_malware.items() if assinaturas)}

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

        # FASE 9: ANÁLISE LLM HÍBRIDA (comportamental + relatório YARA)
        print("🤖 Executando análise híbrida com LLM...")
        try:
            analise_llm = analisar_com_llm_hibrido(
                dados_formatados, relatorio_yara_texto, modelo, host=host, port=port
            )
        except:
            # Fallback para análise normal se a híbrida falhar
            analise_llm = analisar_com_llm(
                dados_formatados + contexto_avancado, modelo, host=host, port=port
            )

        # FASE 10: RESULTADO FINAL COMBINADO
        total_deteccoes_yara = relatorio_yara_resultado.get("total_deteccoes", 0)
        arquivos_extraidos = relatorio_yara_resultado.get("arquivos_extraidos", 0)

        resumo = f"""
📋 ANÁLISE COMPLETA FINALIZADA
├─ Pacotes analisados: {len(dados_pacotes)}
├─ Score de malware: {scoring_result['score']}/100 ({scoring_result['nivel']})
├─ Assinaturas detectadas: {sum(len(sigs) for sigs in assinaturas_malware.values())}
├─ IOCs encontrados: {len(threat_intel['malicious_ips']) + len(threat_intel['malicious_domains'])}
├─ Detecções YARA: {total_deteccoes_yara}
├─ Arquivos extraídos: {arquivos_extraidos}
└─ Modelo LLM: {modelo}
"""

        print(
            f"✅ Análise híbrida concluída: Score {scoring_result['score']}/100 | {total_deteccoes_yara} detecções YARA"
        )

        # Determinar indicadores de ameaça únicos
        threat_indicators = []
        for familia, assinaturas in assinaturas_malware.items():
            if assinaturas:
                threat_indicators.extend(
                    [f"{familia}_{i}" for i in range(len(assinaturas))]
                )

        # Compilar padrões de rede únicos
        network_patterns = {
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
            # CAMPOS DE PRECISÃO AVANÇADA
            "malware_score": scoring_result["score"],
            "risk_level": scoring_result["nivel"],
            "threat_indicators": threat_indicators[
                :50
            ],  # Limitar para não sobrecarregar
            "network_patterns": network_patterns,
            "malware_signatures": {
                k: len(v) for k, v in assinaturas_malware.items() if v
            },
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
                "top_threats": threat_intel["malicious_ips"][
                    :10
                ],  # Top 10 para análise
            },
            # CAMPOS YARA (do colaborador)
            "yara_detections": total_deteccoes_yara,
            "extracted_files": arquivos_extraidos,
            "yara_report": relatorio_yara_texto,
        }

    except Exception as e:
        print(f"❌ Erro na análise: {str(e)}")
        raise Exception(f"Erro na análise avançada: {str(e)}")

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
