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
import threading
from functools import wraps

# Métricas de performance
YARA_METRICS = {
    "total_analyses": 0,
    "total_detections": 0,
    "average_analysis_time": 0,
    "rules_loaded_count": 0,
    "cache_hits": 0,
    "cache_misses": 0,
}


def measure_performance(func):
    """Decorator para medir performance das funções YARA"""

    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)  # Fix: chamar func, não wrapper
        end_time = time.time()

        execution_time = end_time - start_time
        func_name = func.__name__

        # Atualizar métricas globais
        if func_name == "executar_analise_yara_completa":
            YARA_METRICS["total_analyses"] += 1
            if YARA_METRICS["total_analyses"] > 0:
                YARA_METRICS["average_analysis_time"] = (
                    YARA_METRICS["average_analysis_time"]
                    * (YARA_METRICS["total_analyses"] - 1)
                    + execution_time
                ) / YARA_METRICS["total_analyses"]

        print(f"[YARA-PERF] {func_name}: {execution_time:.2f}s")
        return result

    return wrapper


def obter_metricas_yara():
    """Retorna métricas de performance do módulo YARA"""
    return {
        "total_analises": YARA_METRICS["total_analyses"],
        "total_deteccoes": YARA_METRICS["total_detections"],
        "tempo_medio_analise": round(YARA_METRICS["average_analysis_time"], 2),
        "regras_carregadas": YARA_METRICS["rules_loaded_count"],
        "cache_hits": YARA_METRICS["cache_hits"],
        "cache_misses": YARA_METRICS["cache_misses"],
        "status_yara": "ativo" if YARA_ENABLED else "inativo",
    }


# Adicionar path do projeto principal para importar módulos
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(current_dir)))
sys.path.append(parent_dir)

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, Raw, DNS, DNSQR, ARP, Ether

    YARA_DEPENDENCIES_OK = True
except ImportError as e:
    print(f"[YARA] ❌ Erro ao importar scapy: {e}")
    YARA_DEPENDENCIES_OK = False

# Importar yara separadamente para evitar conflitos
yara_module = None
try:
    import yara as yara_module

    YARA_MODULE_OK = True
except ImportError as e:
    print(f"[YARA] ❌ Erro ao importar yara-python: {e}")
    print("[YARA] Certifique-se de que yara-python está instalado")
    YARA_MODULE_OK = False
    yara_module = None

YARA_DEPENDENCIES_OK = YARA_MODULE_OK

# --- CARREGAMENTO INTELIGENTE DAS REGRAS YARA ---
YARA_RULES = None
YARA_ENABLED = False
YARA_CACHE_FILE = None
YARA_CACHE_TIMESTAMP = None


def carregar_regras_yara_com_cache():
    """Carrega regras YARA com cache inteligente"""
    global YARA_RULES, YARA_ENABLED, YARA_CACHE_TIMESTAMP

    pasta_yara = os.path.abspath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "yara")
    )

    try:
        rule_files = []
        timestamp_mais_recente = 0

        # Buscar arquivos YARA (excluindo pasta archive)
        for root, dirs, files in os.walk(pasta_yara):
            # Excluir pasta archive automaticamente
            if "archive" in dirs:
                dirs.remove("archive")

            for file in files:
                if file.endswith(".yar") or file.endswith(".yara"):
                    file_path = os.path.abspath(os.path.join(root, file))
                    rule_files.append(file_path)
                    # Verificar timestamp do arquivo
                    file_timestamp = os.path.getmtime(file_path)
                    if file_timestamp > timestamp_mais_recente:
                        timestamp_mais_recente = file_timestamp

        # Verificar se precisa recarregar
        if (
            YARA_CACHE_TIMESTAMP is None
            or timestamp_mais_recente > YARA_CACHE_TIMESTAMP
            or YARA_RULES is None
        ):

            print(f"[YARA] 🔄 Recarregando {len(rule_files)} regras YARA...")

            rules_dict = {}
            regras_carregadas = 0
            regras_erro = 0

            for file_path in rule_files:
                try:
                    # Nome único para evitar conflitos
                    nome_regra = f"{os.path.basename(os.path.dirname(file_path))}_{os.path.splitext(os.path.basename(file_path))[0]}"
                    rules_dict[nome_regra] = file_path
                    regras_carregadas += 1
                except Exception as e:
                    print(f"[YARA] ⚠️ Erro ao processar {file_path}: {e}")
                    regras_erro += 1

            if rules_dict and yara_module is not None:
                print(f"[YARA] 🔧 Tentando compilar {len(rules_dict)} regras...")

                # WORKAROUND: YARA tem problemas com caminhos longos/acentos no Windows
                # Copiar regras para diretório temporário com nomes simples
                import tempfile
                import shutil

                temp_dir = tempfile.mkdtemp(prefix="yara_")
                temp_rules = {}

                try:
                    for nome, caminho_original in rules_dict.items():
                        nome_simples = nome.replace(".", "_").replace("-", "_")[
                            :50
                        ]  # Limitar tamanho
                        temp_file = os.path.join(temp_dir, f"{nome_simples}.yara")
                        shutil.copy2(caminho_original, temp_file)
                        temp_rules[nome] = temp_file

                    YARA_RULES = yara_module.compile(filepaths=temp_rules)
                    YARA_ENABLED = True
                    YARA_CACHE_TIMESTAMP = timestamp_mais_recente
                    print(
                        f"[YARA] ✅ {regras_carregadas} regras carregadas ({regras_erro} erros)"
                    )
                    if regras_erro > 0:
                        print(
                            f"[YARA] ⚠️ {regras_erro} regras com problemas foram ignoradas"
                        )

                except Exception as e:
                    print(f"[YARA] ❌ Erro na compilacao: {e}")
                    YARA_ENABLED = False
                finally:
                    # Limpar diretório temporário
                    try:
                        shutil.rmtree(temp_dir)
                    except:
                        pass
            else:
                if yara_module is None:
                    print("[YARA] ❌ Módulo YARA não disponível")
                else:
                    print("[YARA] ❌ Nenhuma regra YARA válida encontrada")
                YARA_ENABLED = False
        else:
            print(
                f"[YARA] ♻️ Usando cache de regras (timestamp: {timestamp_mais_recente})"
            )

    except Exception as e:
        print(f"[YARA] ❌ Erro ao carregar regras: {e}")
        YARA_ENABLED = False


# Inicializar automaticamente
try:
    carregar_regras_yara_com_cache()

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
                stream_key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
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
                with open(arquivo_stream, "wb") as f:
                    f.write(payload_total)

                streams_extraidos.append(
                    {
                        "stream_id": stream_id,
                        "arquivo": arquivo_stream,
                        "tamanho": len(payload_total),
                        "pacotes": len(pacotes_stream),
                        "src": f"{stream_key[0]}:{stream_key[1]}",
                        "dst": f"{stream_key[2]}:{stream_key[3]}",
                        "tipo": "TCP Stream",
                    }
                )

                print(
                    f"[YARA-TCP]   📄 Stream {stream_id}: {len(payload_total)} bytes extraídos"
                )
                stream_id += 1

        # Ordenar por tamanho e pegar os 10 maiores
        streams_extraidos.sort(key=lambda x: x["tamanho"], reverse=True)
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
                if any(
                    method in payload[:100]
                    for method in [b"GET ", b"POST ", b"PUT ", b"DELETE "]
                ):
                    if len(payload) > 50:
                        arquivo_http = os.path.join(
                            pasta_base, f"http_request_{request_count}.bin"
                        )
                        with open(arquivo_http, "wb") as f:
                            f.write(payload)

                        arquivos_extraidos.append(
                            {
                                "arquivo": arquivo_http,
                                "tamanho": len(payload),
                                "tipo": "HTTP Request",
                                "porta": pkt[TCP].dport,
                            }
                        )

                        request_count += 1
                        if request_count >= 20:  # Limitar requests
                            break

                # Detectar HTTP responses
                elif payload.startswith(b"HTTP/1."):
                    if len(payload) > 50:
                        arquivo_http = os.path.join(
                            pasta_base, f"http_response_{response_count}.bin"
                        )
                        with open(arquivo_http, "wb") as f:
                            f.write(payload)

                        arquivos_extraidos.append(
                            {
                                "arquivo": arquivo_http,
                                "tamanho": len(payload),
                                "tipo": "HTTP Response",
                                "porta": pkt[TCP].sport,
                            }
                        )

                        response_count += 1
                        if response_count >= 20:  # Limitar responses
                            break

        print(
            f"[YARA-HTTP] 📊 Total de {len(arquivos_extraidos)} HTTP payloads extraídos"
        )
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

                    if porta_dst > 1024 and porta_dst not in [
                        8080,
                        8443,
                        3389,
                    ]:  # Porta não padrão
                        suspeito = True
                        razoes.append(f"Porta suspeita ({porta_dst})")

                    if len(payload) > 50000:  # Payload muito grande
                        suspeito = True
                        razoes.append(f"Payload grande ({len(payload)} bytes)")

                    if suspeito:
                        arquivo_susp = os.path.join(
                            pasta_base, f"suspicious_{contador}.bin"
                        )
                        with open(arquivo_susp, "wb") as f:
                            f.write(payload)

                        arquivos_extraidos.append(
                            {
                                "arquivo": arquivo_susp,
                                "tamanho": len(payload),
                                "entropia": entropia,
                                "porta": porta_dst,
                                "razoes": razoes,
                                "tipo": "Payload Suspeito",
                            }
                        )

                        contador += 1
                        if contador >= 15:  # Limitar
                            break

        print(
            f"[YARA-SUSP] 📊 Total de {len(arquivos_extraidos)} payloads suspeitos extraídos"
        )
        return arquivos_extraidos

    except Exception as e:
        print(f"[YARA-SUSP] ❌ Erro ao extrair suspeitos: {e}")
        return []


# Sistema de filtros inteligentes
YARA_WHITELIST = {
    # Arquivos legítimos conhecidos (hash SHA256 ou nomes)
    "arquivos_legitimos": {
        "jquery.min.js": "JavaScript legítimo",
        "bootstrap.min.css": "CSS Framework legítimo",
        "favicon.ico": "Ícone padrão do site",
    },
    # Regras que são muito genéricas e causam falsos positivos
    "regras_ignoradas": {
        "Generic_HTTP_Traffic": "Muito genérico para HTTP normal",
        "Common_Binary_Pattern": "Padrão binário comum demais",
    },
}

YARA_BLACKLIST = {
    # Regras críticas que sempre devem ser reportadas
    "regras_criticas": {
        "Bumblebee_Network_IOC",
        "Ransomware_Payment_Demand",
        "Backdoor_C2_Communication",
    }
}


def filtrar_deteccoes_inteligente(deteccoes):
    """Aplica filtros inteligentes para reduzir falsos positivos"""
    deteccoes_filtradas = []
    falsos_positivos = 0

    for deteccao in deteccoes:
        nome_arquivo = deteccao["arquivo"]
        regra = deteccao["regra"]

        # Verificar whitelist de arquivos
        if nome_arquivo in YARA_WHITELIST["arquivos_legitimos"]:
            print(f"[YARA-FILTER] ℹ️ Ignorando arquivo legítimo: {nome_arquivo}")
            falsos_positivos += 1
            continue

        # Verificar whitelist de regras genéricas
        if regra in YARA_WHITELIST["regras_ignoradas"]:
            print(f"[YARA-FILTER] ℹ️ Ignorando regra genérica: {regra}")
            falsos_positivos += 1
            continue

        # Regras críticas sempre passam
        if regra in YARA_BLACKLIST["regras_criticas"]:
            deteccao["critica"] = True
            print(f"[YARA-FILTER] 🚨 Regra crítica detectada: {regra}")

        deteccoes_filtradas.append(deteccao)

    if falsos_positivos > 0:
        print(
            f"[YARA-FILTER] 🧹 {falsos_positivos} possíveis falsos positivos filtrados"
        )

    return deteccoes_filtradas


@measure_performance
def analisar_arquivos_com_yara_melhorado(arquivos_extraidos):
    """Analisa arquivos com YARA + filtros inteligentes"""
    global YARA_RULES, YARA_ENABLED

    if not YARA_ENABLED or not YARA_RULES:
        print("[YARA] ❌ Regras YARA não disponíveis")
        return []

    print(f"[YARA] 🔍 Analisando {len(arquivos_extraidos)} arquivo(s) extraído(s)")
    deteccoes_brutas = []
    arquivos_analisados = 0
    arquivos_com_erro = 0

    for arquivo_info in arquivos_extraidos:
        arquivo_path = arquivo_info["arquivo"]

        try:
            matches = YARA_RULES.match(arquivo_path, timeout=10)  # Timeout maior
            arquivos_analisados += 1

            if matches:
                for match in matches:
                    deteccoes_brutas.append(
                        {
                            "arquivo": os.path.basename(arquivo_path),
                            "arquivo_completo": arquivo_path,
                            "regra": match.rule,
                            "meta": dict(match.meta),
                            "tags": match.tags,
                            "strings": [str(string) for string in match.strings],
                            "tamanho_arquivo": arquivo_info.get("tamanho", 0),
                            "tipo_fonte": arquivo_info.get("tipo", "desconhecido"),
                            "critica": False,
                        }
                    )

                    print(
                        f"[YARA] 🚨 DETECÇÃO: {match.rule} em {os.path.basename(arquivo_path)}"
                    )

        except Exception as e:
            print(f"[YARA] ⚠️ Erro ao analisar {arquivo_path}: {e}")
            arquivos_com_erro += 1
            continue

    # Aplicar filtros inteligentes
    deteccoes_filtradas = filtrar_deteccoes_inteligente(deteccoes_brutas)

    # Atualizar métricas
    YARA_METRICS["total_detections"] += len(deteccoes_filtradas)

    print(f"[YARA] 📊 Análise concluída:")
    print(f"[YARA]   • Arquivos analisados: {arquivos_analisados}")
    print(f"[YARA]   • Arquivos com erro: {arquivos_com_erro}")
    print(f"[YARA]   • Detecções brutas: {len(deteccoes_brutas)}")
    print(f"[YARA]   • Detecções filtradas: {len(deteccoes_filtradas)}")

    return deteccoes_filtradas


def classificar_severidade_deteccao(deteccao):
    """Classifica severidade da detecção baseada em regra e contexto"""
    regra = deteccao.get("regra", "").lower()
    tags = [tag.lower() for tag in deteccao.get("tags", [])]

    # Classificação por palavras-chave da regra
    if any(
        palavra in regra for palavra in ["ransomware", "trojan", "backdoor", "rootkit"]
    ):
        return "CRÍTICA"
    elif any(palavra in regra for palavra in ["exploit", "downloader", "infostealer"]):
        return "ALTA"
    elif any(palavra in regra for palavra in ["pua", "adware", "suspicious"]):
        return "MÉDIA"
    elif any(palavra in regra for palavra in ["generic", "heuristic"]):
        return "BAIXA"

    # Classificação por tags
    if any(tag in tags for tag in ["malware", "trojan", "ransomware"]):
        return "CRÍTICA"
    elif any(tag in tags for tag in ["exploit", "suspicious"]):
        return "ALTA"

    return "MÉDIA"


def gerar_relatorio_yara_melhorado(deteccoes_yara):
    """Gera relatório YARA avançado com classificação de severidade"""

    if not deteccoes_yara:
        return {
            "status": "limpo",
            "total_deteccoes": 0,
            "relatorio_texto": "✅ Nenhuma detecção YARA encontrada nos arquivos extraídos.",
            "deteccoes": [],
            "severidade_maxima": "NENHUMA",
        }

    # Classificar detecções por severidade
    deteccoes_classificadas = []
    severidades = {"CRÍTICA": 0, "ALTA": 0, "MÉDIA": 0, "BAIXA": 0}

    for det in deteccoes_yara:
        severidade = classificar_severidade_deteccao(det)
        det["severidade"] = severidade
        severidades[severidade] += 1
        deteccoes_classificadas.append(det)

    # Ordenar por severidade
    ordem_severidade = {"CRÍTICA": 4, "ALTA": 3, "MÉDIA": 2, "BAIXA": 1}
    deteccoes_classificadas.sort(
        key=lambda x: ordem_severidade.get(x["severidade"], 0), reverse=True
    )

    # Determinar severidade máxima
    severidade_maxima = "BAIXA"
    for sev in ["CRÍTICA", "ALTA", "MÉDIA"]:
        if severidades[sev] > 0:
            severidade_maxima = sev
            break

    # Criar relatório estruturado
    emoji_severidade = {"CRÍTICA": "🚨", "ALTA": "⚠️", "MÉDIA": "⚡", "BAIXA": "💡"}

    relatorio_texto = (
        f"🚨 RELATÓRIO YARA AVANÇADO - {len(deteccoes_yara)} DETECÇÕES:\n\n"
    )

    # Resumo por severidade
    relatorio_texto += "📊 SEVERIDADE DAS AMEAÇAS:\n"
    for sev, count in severidades.items():
        if count > 0:
            emoji = emoji_severidade.get(sev, "❓")
            relatorio_texto += f"   {emoji} {sev}: {count} detecção(ões)\n"
    relatorio_texto += "\n"

    # Agrupar por regra
    deteccoes_por_regra = defaultdict(list)
    for det in deteccoes_classificadas:
        deteccoes_por_regra[det["regra"]].append(det)

    # Relatório detalhado por severidade
    contador = 1
    for severidade in ["CRÍTICA", "ALTA", "MÉDIA", "BAIXA"]:
        deteccoes_sev = [
            d for d in deteccoes_classificadas if d["severidade"] == severidade
        ]
        if not deteccoes_sev:
            continue

        emoji = emoji_severidade[severidade]
        relatorio_texto += f"🎯 AMEAÇAS DE SEVERIDADE {severidade} {emoji}:\n"

        regras_sev = {}
        for det in deteccoes_sev:
            regra = det["regra"]
            if regra not in regras_sev:
                regras_sev[regra] = []
            regras_sev[regra].append(det)

        for regra, deteccoes_regra in regras_sev.items():
            relatorio_texto += (
                f"   {contador}. {regra} ({len(deteccoes_regra)} arquivo(s))\n"
            )

            # Mostrar até 3 arquivos
            for i, det in enumerate(deteccoes_regra[:3], 1):
                tamanho_kb = det["tamanho_arquivo"] // 1024
                relatorio_texto += f"      {i}) {det['arquivo']} ({tamanho_kb}KB, {det['tipo_fonte']})\n"
                if det.get("strings"):
                    relatorio_texto += f"         Padrões: {len(det['strings'])} string(s) detectada(s)\n"

            if len(deteccoes_regra) > 3:
                relatorio_texto += (
                    f"      ... e mais {len(deteccoes_regra) - 3} arquivo(s)\n"
                )
            contador += 1
        relatorio_texto += "\n"

    # Estatísticas adicionais
    tipos_fonte = defaultdict(int)
    for det in deteccoes_classificadas:
        tipos_fonte[det["tipo_fonte"]] += 1

    relatorio_texto += "📈 ORIGEM DAS DETECÇÕES:\n"
    for tipo, count in tipos_fonte.items():
        relatorio_texto += f"   • {tipo}: {count} detecção(ões)\n"

    return {
        "status": "infectado",
        "severidade_maxima": severidade_maxima,
        "total_deteccoes": len(deteccoes_yara),
        "regras_ativadas": len(deteccoes_por_regra),
        "severidades": severidades,
        "relatorio_texto": relatorio_texto,
        "deteccoes": deteccoes_classificadas[:15],  # Top 15 mais críticas
    }

    # Criar relatório estruturado
    relatorio_texto = (
        f"🚨 RELATÓRIO YARA - {len(deteccoes_yara)} DETECÇÕES DE MALWARE:\n\n"
    )

    # Agrupar por regra
    deteccoes_por_regra = defaultdict(list)
    for det in deteccoes_yara:
        deteccoes_por_regra[det["regra"]].append(det)

    # Relatório detalhado
    for i, (regra, deteccoes_regra) in enumerate(deteccoes_por_regra.items(), 1):
        relatorio_texto += f"{i}. REGRA: {regra}\n"
        relatorio_texto += f"   ARQUIVOS INFECTADOS: {len(deteccoes_regra)}\n"

        # Mostrar até 3 arquivos por regra
        for j, det in enumerate(deteccoes_regra[:3], 1):
            relatorio_texto += f"   {j}) {det['arquivo']} ({det['tamanho_arquivo']} bytes, {det['tipo_fonte']})\n"
            if det.get("tags"):
                relatorio_texto += f"      Tags: {', '.join(det['tags'])}\n"
            if det.get("strings"):
                relatorio_texto += f"      Strings detectadas: {len(det['strings'])}\n"

        if len(deteccoes_regra) > 3:
            relatorio_texto += f"   ... e mais {len(deteccoes_regra) - 3} arquivo(s)\n"
        relatorio_texto += "\n"

    # Estatísticas
    tipos_fonte = defaultdict(int)
    for det in deteccoes_yara:
        tipos_fonte[det["tipo_fonte"]] += 1

    relatorio_texto += "📊 ESTATÍSTICAS DAS DETECÇÕES:\n"
    for tipo, count in tipos_fonte.items():
        relatorio_texto += f"   - {tipo}: {count} detecção(ões)\n"

    return {
        "status": "infectado",
        "total_deteccoes": len(deteccoes_yara),
        "regras_ativadas": len(deteccoes_por_regra),
        "relatorio_texto": relatorio_texto,
        "deteccoes": deteccoes_yara[:10],  # Top 10 para detalhes
    }


@measure_performance
def executar_analise_yara_completa(arquivo_pcap):
    """Executa análise YARA completa - FUNÇÃO PRINCIPAL DO MÓDULO YARA"""

    if not YARA_DEPENDENCIES_OK:
        return {
            "status": "erro",
            "erro": "Dependências YARA não disponíveis",
            "relatorio_texto": "❌ Análise YARA não pôde ser executada - dependências não instaladas",
        }

    print(f"[YARA] 🚀 Iniciando análise YARA completa de: {arquivo_pcap}")

    try:
        # Criar pasta temporária do sistema para extrações
        with tempfile.TemporaryDirectory(prefix="yara_extraction_") as pasta_temp:
            print(f"[YARA] 📁 Usando pasta temporária: {pasta_temp}")

            # 1. Extrair TCP streams
            streams_tcp = extrair_tcp_streams_com_scapy(
                arquivo_pcap, f"{pasta_temp}/tcp"
            )

            # 2. Extrair HTTP payloads
            payloads_http = extrair_http_payloads_com_scapy(
                arquivo_pcap, f"{pasta_temp}/http"
            )

            # 3. Extrair payloads suspeitos
            payloads_suspeitos = extrair_payloads_suspeitos_com_scapy(
                arquivo_pcap, f"{pasta_temp}/suspicious"
            )

            # 4. Combinar todos os arquivos
            todos_arquivos = streams_tcp + payloads_http + payloads_suspeitos

            if not todos_arquivos:
                return {
                    "status": "sem_arquivos",
                    "total_deteccoes": 0,
                    "relatorio_texto": "⚠️ Nenhum arquivo foi extraído do PCAP para análise YARA",
                }

            # 5. Analisar com YARA (versão melhorada)
            deteccoes = analisar_arquivos_com_yara_melhorado(todos_arquivos)

            # 6. Gerar relatório final
            relatorio = gerar_relatorio_yara_melhorado(deteccoes)
            relatorio["arquivos_extraidos"] = len(todos_arquivos)
            relatorio["pasta_extracao"] = "temporaria_removida_automaticamente"

            print(f"[YARA] ✅ Análise completa finalizada: {len(deteccoes)} detecções")
            print("[YARA] 🗑️ Pasta temporária será removida automaticamente")

            return relatorio
        # Pasta temporária é removida automaticamente aqui

    except Exception as e:
        print(f"[YARA] ❌ Erro na análise completa: {e}")
        return {
            "status": "erro",
            "erro": str(e),
            "relatorio_texto": f"❌ Erro durante análise YARA: {str(e)}",
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
        print(resultado["relatorio_texto"])
