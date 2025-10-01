#!/usr/bin/env python3
# gerar_pcap_anomalias.py
"""
Gerador de arquivo PCAP com anomalias de segurança para testes
"""

from scapy.all import IP, TCP, UDP, Raw, DNS, DNSQR, wrpcap
import random
import time
import os


def gerar_trafego_normal():
    """Gera alguns pacotes de tráfego normal"""
    pacotes = []

    # Tráfego HTTP normal
    for i in range(5):
        pkt = IP(src=f"192.168.1.{random.randint(10, 50)}", dst="192.168.1.1") / TCP(
            sport=random.randint(1024, 65535), dport=80
        )
        pacotes.append(pkt)

    # Tráfego HTTPS normal
    for i in range(3):
        pkt = IP(src=f"192.168.1.{random.randint(10, 50)}", dst="8.8.8.8") / TCP(
            sport=random.randint(1024, 65535), dport=443
        )
        pacotes.append(pkt)

    return pacotes


def gerar_port_scan():
    """Simula um port scan - ANOMALIA 1"""
    pacotes = []
    atacante_ip = "10.0.0.100"
    alvo_ip = "192.168.1.50"

    # Scan de várias portas do mesmo IP origem para mesmo IP destino
    portas_comuns = [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        135,
        139,
        443,
        445,
        993,
        995,
        1433,
        3389,
        5432,
    ]

    for porta in portas_comuns:
        # SYN scan
        pkt = IP(src=atacante_ip, dst=alvo_ip) / TCP(
            sport=random.randint(1024, 65535), dport=porta, flags="S"
        )
        pacotes.append(pkt)

        # Simulando resposta RST (porta fechada)
        if random.choice([True, False]):
            resp = IP(src=alvo_ip, dst=atacante_ip) / TCP(
                sport=porta, dport=pkt[TCP].sport, flags="RA"
            )
            pacotes.append(resp)

    return pacotes


def gerar_ddos_attempt():
    """Simula tentativa de DDoS - ANOMALIA 2"""
    pacotes = []
    alvo_ip = "192.168.1.100"

    # Múltiplos IPs atacando o mesmo alvo
    for i in range(20):
        atacante_ip = f"10.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

        # SYN flood
        pkt = IP(src=atacante_ip, dst=alvo_ip) / TCP(
            sport=random.randint(1024, 65535), dport=80, flags="S"
        )
        pacotes.append(pkt)

        # UDP flood
        pkt_udp = IP(src=atacante_ip, dst=alvo_ip) / UDP(
            sport=random.randint(1024, 65535), dport=random.randint(1, 1024)
        )
        pacotes.append(pkt_udp)

    return pacotes


def gerar_trafego_suspeito_criptografado():
    """Gera tráfego com alta entropia (possível malware/exfiltração) - ANOMALIA 3"""
    pacotes = []

    # Dados com alta entropia (simulando criptografia/malware)
    dados_suspeitos = os.urandom(1000)  # Dados aleatórios = alta entropia

    # Enviando para IP suspeito em porta não padrão
    for chunk in range(0, len(dados_suspeitos), 100):
        payload = dados_suspeitos[chunk : chunk + 100]
        pkt = (
            IP(src="192.168.1.25", dst="185.220.101.23")
            / TCP(sport=random.randint(1024, 65535), dport=8443)
            / Raw(load=payload)
        )
        pacotes.append(pkt)

    return pacotes


def gerar_brute_force_ssh():
    """Simula ataque de força bruta SSH - ANOMALIA 4"""
    pacotes = []
    atacante_ip = "203.0.113.100"
    alvo_ip = "192.168.1.10"

    # Múltiplas tentativas de conexão SSH em sequência
    for i in range(15):
        pkt = IP(src=atacante_ip, dst=alvo_ip) / TCP(
            sport=random.randint(1024, 65535), dport=22, flags="S"
        )
        pacotes.append(pkt)

        # Resposta SYN-ACK (conexão aceita)
        resp = IP(src=alvo_ip, dst=atacante_ip) / TCP(
            sport=22, dport=pkt[TCP].sport, flags="SA"
        )
        pacotes.append(resp)

        # ACK do atacante
        ack = IP(src=atacante_ip, dst=alvo_ip) / TCP(
            sport=pkt[TCP].sport, dport=22, flags="A"
        )
        pacotes.append(ack)

    return pacotes


def gerar_dns_tunneling():
    """Simula DNS tunneling - ANOMALIA 5"""
    pacotes = []

    # Queries DNS suspeitas com nomes muito longos/codificados
    dominios_suspeitos = [
        "aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxk.malware-c2.com",
        "dGhpc2lzYXRlc3RzdHJpbmdmb3JkbnN0dW5uZWw.evil-domain.net",
        "YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE.suspicious.org",
    ]

    for dominio in dominios_suspeitos:
        # Query DNS
        pkt = (
            IP(src="192.168.1.75", dst="8.8.8.8")
            / UDP(sport=random.randint(1024, 65535), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=dominio))
        )
        pacotes.append(pkt)

    return pacotes


def gerar_arquivo_pcap_com_anomalias(nome_arquivo="anomalias_seguranca.pcap"):
    """Gera arquivo PCAP completo com várias anomalias"""
    print("🔧 Gerando arquivo PCAP com anomalias de segurança...")

    todos_pacotes = []

    # Adicionar tráfego normal (para contexto)
    print("📡 Adicionando tráfego normal...")
    todos_pacotes.extend(gerar_trafego_normal())

    # Adicionar anomalias
    print("🚨 Adicionando ANOMALIA 1: Port Scan...")
    todos_pacotes.extend(gerar_port_scan())

    print("🚨 Adicionando ANOMALIA 2: Tentativa de DDoS...")
    todos_pacotes.extend(gerar_ddos_attempt())

    print("🚨 Adicionando ANOMALIA 3: Tráfego criptografado suspeito...")
    todos_pacotes.extend(gerar_trafego_suspeito_criptografado())

    print("🚨 Adicionando ANOMALIA 4: Brute Force SSH...")
    todos_pacotes.extend(gerar_brute_force_ssh())

    print("🚨 Adicionando ANOMALIA 5: DNS Tunneling...")
    todos_pacotes.extend(gerar_dns_tunneling())

    # Embaralhar pacotes para simular tráfego real
    random.shuffle(todos_pacotes)

    # Salvar no arquivo PCAP
    print(f"💾 Salvando {len(todos_pacotes)} pacotes em '{nome_arquivo}'...")
    wrpcap(nome_arquivo, todos_pacotes)

    print(f"✅ Arquivo '{nome_arquivo}' criado com sucesso!")
    print(f"📊 Total de pacotes: {len(todos_pacotes)}")
    print("\n📋 Anomalias incluídas:")
    print("   1. 🎯 Port Scan (múltiplas portas do mesmo origem)")
    print("   2. 💥 Tentativa de DDoS (múltiplos IPs → mesmo alvo)")
    print("   3. 🔐 Tráfego com alta entropia (possível malware)")
    print("   4. 🔓 Brute Force SSH (múltiplas tentativas)")
    print("   5. 🕳️ DNS Tunneling (queries suspeitas)")

    return nome_arquivo


if __name__ == "__main__":
    import os

    print("🔒 Gerador de PCAP com Anomalias de Segurança")
    print("=" * 50)

    # Gerar arquivo com anomalias
    arquivo_gerado = gerar_arquivo_pcap_com_anomalias()

    # Mostrar informações do arquivo
    if os.path.exists(arquivo_gerado):
        tamanho = os.path.getsize(arquivo_gerado)
        print(f"\n📁 Arquivo criado: {arquivo_gerado}")
        print(f"📏 Tamanho: {tamanho} bytes")
        print(f"📍 Localização: {os.path.abspath(arquivo_gerado)}")
    else:
        print("❌ Erro ao criar arquivo!")
