# pcap_llama_cli.py
import math
from scapy.all import rdpcap, IP, TCP, Raw
import ollama


def calcular_entropia(data):
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
    pacotes = rdpcap(arquivo_pcap)
    resumo = []
    for pkt in pacotes:
        if IP in pkt:
            info = {
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "protocol": pkt[IP].proto,
                "length": len(pkt),
                "entropy": None,
            }
            if TCP in pkt:
                info["tcp_flags"] = str(pkt[TCP].flags)
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
                info["entropy"] = round(calcular_entropia(payload), 4)
            resumo.append(info)
    return resumo


def formatar_tabela(dados):
    tabela = "| Src IP | Dst IP | Proto | Length | TCP Flags | Entropy |\n"
    tabela += "|--------|--------|-------|--------|-----------|---------|\n"
    for pkt in dados:
        tabela += f"| {pkt['src_ip']} | {pkt['dst_ip']} | {pkt['protocol']} | {pkt['length']} | {pkt.get('tcp_flags', '')} | {pkt['entropy']} |\n"
    return tabela


def analisar_com_llama(dados):
    tabela = formatar_tabela(dados)
    prompt = f"""
Você é um analista de rede. Analise os seguintes pacotes e identifique comportamentos suspeitos:

{tabela}
    """
    resposta = ollama.chat(
        model="llama3", messages=[{"role": "user", "content": prompt}]
    )
    print("\n--- Análise do LLaMA 3 ---\n")
    print(resposta["message"]["content"])


if __name__ == "__main__":
    arquivo = "exemplo.pcap"  # coloque o nome do seu arquivo aqui
    pacotes_resumidos = processar_pcap(arquivo)
    analisar_com_llama(pacotes_resumidos)
