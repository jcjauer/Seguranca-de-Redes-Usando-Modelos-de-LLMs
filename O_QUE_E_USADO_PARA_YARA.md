# O que é Usado para Gerar o Relatório YARA do Projeto

## 📋 Resumo Executivo

Seu projeto usa **4 componentes principais** para gerar o relatório YARA:

1. **`yara_detector.py`** - Motor YARA (análise de malware)
2. **Regras YARA** - Assinaturas de malware (pasta `yara/`)
3. **Scapy** - Extração de payloads do PCAP
4. **`pcap_analyzer.py`** - Integração com LLM

---

## 🔧 Componentes Detalhados

### 1. **`yara_detector.py`** - Motor YARA Completo

Local: `pcap_web/analyzer/yara_detector.py` (832 linhas)

#### Função Principal: `executar_analise_yara_completa(arquivo_pcap)`

```python
def executar_analise_yara_completa(arquivo_pcap):
    """Executa análise YARA completa - FUNÇÃO PRINCIPAL DO MÓDULO YARA"""
    
    # Cria pasta temporária para extrações
    with tempfile.TemporaryDirectory() as pasta_temp:
        
        # 1. Extrai TCP streams
        streams_tcp = extrair_tcp_streams_com_scapy(arquivo_pcap)
        
        # 2. Extrai HTTP payloads
        payloads_http = extrair_http_payloads_com_scapy(arquivo_pcap)
        
        # 3. Extrai payloads suspeitos
        payloads_suspeitos = extrair_payloads_suspeitos_com_scapy(arquivo_pcap)
        
        # 4. Combina todos os arquivos
        todos_arquivos = streams_tcp + payloads_http + payloads_suspeitos
        
        # 5. Analisa com YARA
        deteccoes = analisar_arquivos_com_yara_melhorado(todos_arquivos)
        
        # 6. Gera relatório final
        relatorio = gerar_relatorio_yara_melhorado(deteccoes)
        
        return relatorio
```

**Retorno:**
```python
{
    "status": "infectado" ou "limpo" ou "erro",
    "total_deteccoes": 10,  # Quantidade de malwares detectados
    "severidade_maxima": "ALTO",  # CRÍTICA, ALTA, MÉDIA, BAIXA
    "relatorio_texto": "[TEXTO FORMATADO]",  # Para o LLM ler
    "deteccoes": [  # Lista de detecções estruturadas
        {
            "regra": "Neutrino_Exploit_Kit_Landing_Page",
            "arquivo": "tcp_stream_1.bin",
            "severidade": "ALTO",
            "tags": ["trojan", "exploit"],
            "strings": [...]
        },
        # ... mais detecções
    ]
}
```

---

### 2. **Funções de Extração de Payloads**

Todas usam **Scapy** para ler o PCAP e extrair dados:

#### A) `extrair_tcp_streams_com_scapy(arquivo_pcap)`

```python
def extrair_tcp_streams_com_scapy(arquivo_pcap):
    """Extrai TCP streams usando Scapy"""
    
    pacotes = rdpcap(arquivo_pcap)
    streams_tcp = defaultdict(list)
    
    # Agrupar pacotes por 4-tuple (src_ip, src_port, dst_ip, dst_port)
    for pkt in pacotes:
        if TCP in pkt and IP in pkt:
            stream_key = (pkt[IP].src, pkt[TCP].sport, 
                         pkt[IP].dst, pkt[TCP].dport)
            streams_tcp[stream_key].append(pkt)
    
    # Extrair payloads TCP > 100 bytes
    for stream_key, pacotes_stream in streams_tcp.items():
        payload_total = b""
        for pkt in pacotes_stream:
            if Raw in pkt:
                payload_total += bytes(pkt[Raw].load)
        
        # Salvar em arquivo binário
        arquivo_stream = f"tcp_stream_{stream_id}.bin"
        with open(arquivo_stream, "wb") as f:
            f.write(payload_total)
```

**O que extrai:**
- Payloads de qualquer protocolo sobre TCP
- Mínimo 100 bytes de payload
- Máximo 10 maiores streams (ordenado por tamanho)

---

#### B) `extrair_http_payloads_com_scapy(arquivo_pcap)`

```python
def extrair_http_payloads_com_scapy(arquivo_pcap):
    """Extrai HTTP requests e responses"""
    
    pacotes = rdpcap(arquivo_pcap)
    
    for pkt in pacotes:
        if Raw in pkt and TCP in pkt:
            payload = bytes(pkt[Raw].load)
            
            # Detectar HTTP GET/POST/PUT/DELETE
            if payload[:100].startswith(b"GET " or b"POST " ...):
                arquivo_http = f"http_request_{request_count}.bin"
                # Salvar arquivo
            
            # Detectar HTTP responses
            elif payload.startswith(b"HTTP/1."):
                arquivo_http = f"http_response_{response_count}.bin"
                # Salvar arquivo
```

**O que extrai:**
- HTTP requests (GET, POST, PUT, DELETE)
- HTTP responses (HTTP/1.0, HTTP/1.1, etc)
- Máximo 20 requests e 20 responses

---

#### C) `extrair_payloads_suspeitos_com_scapy(arquivo_pcap)`

Extrai payloads com **alta entropia** ou em **portas não-padrão**.

---

### 3. **Análise com YARA**

#### `analisar_arquivos_com_yara_melhorado(arquivos_extraidos)`

```python
def analisar_arquivos_com_yara_melhorado(arquivos_extraidos):
    """Analisa cada arquivo extraído com as regras YARA"""
    
    deteccoes_brutas = []
    
    for arquivo_info in arquivos_extraidos:
        arquivo_path = arquivo_info["arquivo"]
        
        # Executar YARA (timeout 10 segundos)
        matches = YARA_RULES.match(arquivo_path, timeout=10)
        
        if matches:
            for match in matches:
                deteccoes_brutas.append({
                    "arquivo": os.path.basename(arquivo_path),
                    "regra": match.rule,
                    "meta": dict(match.meta),
                    "tags": match.tags,
                    "strings": match.strings,
                    "tamanho_arquivo": arquivo_info["tamanho"],
                    "tipo_fonte": arquivo_info["tipo"]  # TCP Stream, HTTP, etc
                })
                
                print(f"🚨 DETECÇÃO: {match.rule} em {arquivo_path}")
    
    # Filtrar detecções duplicadas/falsas
    deteccoes_filtradas = filtrar_deteccoes_inteligente(deteccoes_brutas)
    
    return deteccoes_filtradas
```

---

### 4. **Geração do Relatório**

#### `gerar_relatorio_yara_melhorado(deteccoes_yara)`

```python
def gerar_relatorio_yara_melhorado(deteccoes_yara):
    """Gera relatório formatado com severidade"""
    
    # 1. Classificar severidade de cada detecção
    for det in deteccoes_yara:
        severidade = classificar_severidade_deteccao(det)
        det["severidade"] = severidade
    
    # 2. Ordenar por severidade (CRÍTICA > ALTA > MÉDIA > BAIXA)
    deteccoes_yara.sort(key=lambda x: ordem_severidade[x["severidade"]], reverse=True)
    
    # 3. Agrupar por regra
    deteccoes_por_regra = defaultdict(list)
    for det in deteccoes_yara:
        deteccoes_por_regra[det["regra"]].append(det)
    
    # 4. Gerar texto formatado
    relatorio_texto = "🚨 RELATÓRIO YARA - {len} DETECÇÕES:\n"
    relatorio_texto += "📊 SEVERIDADE DAS AMEAÇAS:\n"
    relatorio_texto += "   🚨 CRÍTICA: X detecção(ões)\n"
    relatorio_texto += "   ⚠️ ALTA: X detecção(ões)\n"
    # ...
    
    relatorio_texto += "🎯 AMEAÇAS DE SEVERIDADE CRÍTICA 🚨:\n"
    for regra, deteccoes_regra in deteccoes_por_regra.items():
        relatorio_texto += f"   1. {regra} ({len} arquivo(s))\n"
        # Mostrar até 3 arquivos
        for det in deteccoes_regra[:3]:
            relatorio_texto += f"      {det['arquivo']} ({det['tamanho']}KB)\n"
    
    return {
        "status": "infectado",
        "total_deteccoes": len(deteccoes_yara),
        "severidade_maxima": "ALTA",
        "relatorio_texto": relatorio_texto,
        "deteccoes": deteccoes_yara[:15]  # Top 15
    }
```

**Classificação de Severidade:**

```python
def classificar_severidade_deteccao(deteccao):
    """Classifica severidade baseada em regra e tags"""
    regra = deteccao.get("regra").lower()
    tags = deteccao.get("tags", [])
    
    # CRÍTICA: ransomware, trojan, backdoor, rootkit
    if any(p in regra for p in ["ransomware", "trojan", "backdoor", "rootkit"]):
        return "CRÍTICA"
    
    # ALTA: exploit, downloader, infostealer
    elif any(p in regra for p in ["exploit", "downloader", "infostealer"]):
        return "ALTA"
    
    # MÉDIA: pua, adware, suspicious
    elif any(p in regra for p in ["pua", "adware", "suspicious"]):
        return "MÉDIA"
    
    # BAIXA: generic, heuristic
    else:
        return "BAIXA"
```

---

### 5. **Carregamento de Regras YARA**

#### `carregar_regras_yara_com_cache()`

```python
def carregar_regras_yara_com_cache():
    """Carrega regras YARA com cache inteligente"""
    
    pasta_yara = "pcap_web/yara_rules"
    
    # Buscar todos os arquivos .yar e .yara
    for root, dirs, files in os.walk(pasta_yara):
        if "archive" in dirs:
            dirs.remove("archive")  # Excluir pasta archive
        
        for file in files:
            if file.endswith(".yar") or file.endswith(".yara"):
                file_path = os.path.join(root, file)
                nome_regra = f"{subpasta}_{arquivo}"
                rules_dict[nome_regra] = file_path
    
    # Compilar regras YARA
    YARA_RULES = yara.filerules(rules_dict)
    
    return YARA_RULES
```

**Regras Incluídas:**
```
yara/
├── backdoor/
├── certificate/
├── downloader/
├── exploit/
├── infostealer/
├── pua/
├── ransomware/
├── rootkit/
├── trojan/
└── virus/
```

---

### 6. **Integração com `pcap_analyzer.py`**

No arquivo `pcap_analyzer.py`, o relatório YARA é usado assim:

```python
# 1. Executar análise YARA
relatorio_yara_resultado = executar_analise_yara_completa(arquivo_pcap)

# 2. Extrair texto e dicionário
relatorio_yara_texto = relatorio_yara_resultado.get("relatorio_texto")

# 3. Enviar para LLM (junto com heurística)
analise_llm = analisar_com_llm_hibrido(
    dados_formatados,           # Heurística (DDoS, Port Scan, etc)
    relatorio_yara_texto,       # Texto do YARA
    modelo="llama3",
    relatorio_yara_resultado=relatorio_yara_resultado  # Dict com detecções
)
```

---

## 📊 Fluxo Completo

```
ARQUIVO PCAP
    ↓
[yara_detector.py] executar_analise_yara_completa()
    ├─→ extrair_tcp_streams_com_scapy()       [Scapy]
    ├─→ extrair_http_payloads_com_scapy()    [Scapy]
    ├─→ extrair_payloads_suspeitos_com_scapy() [Scapy]
    └─→ analisar_arquivos_com_yara_melhorado()
            └─→ YARA_RULES.match() [Motor YARA]
                └─→ gerar_relatorio_yara_melhorado()
                    └─→ classificar_severidade_deteccao()
                        ↓
                DICIONÁRIO COM DETECÇÕES
                    ↓
[pcap_analyzer.py] analisar_com_llm_hibrido()
    ├─→ Combina YARA + Heurística
    └─→ Envia para LLM (Ollama/llama3)
            ↓
        ANÁLISE FINAL (JSON/relatório)
```

---

## 🔍 Exemplo Real

### Input: `anomalias_seguranca.pcap`

```
1. Scapy extrai:
   - tcp_stream_1.bin (32KB)
   - tcp_stream_2.bin (8KB)
   - http_file_2.bin (4KB)
   - http_file_3.bin (2KB)
   ... (total ~8 arquivos)

2. YARA analisa cada arquivo:
   ✓ Detectado: Neutrino_Exploit_Kit_Landing_Page (severidade ALTO)
   ✓ Detectado: Bumblebee_Core (severidade MÉDIO)
   ✓ Detectado: Bumblebee_Encrypted (severidade MÉDIO)
   ... (total 10 detecções)

3. Relatório gerado:
   {
       "status": "infectado",
       "total_deteccoes": 10,
       "severidade_maxima": "ALTO",
       "relatorio_texto": "🚨 RELATÓRIO YARA - 10 DETECÇÕES...",
       "deteccoes": [...]
   }

4. LLM recebe:
   "De acordo com o RELATÓRIO YARA:
    - Neutrino_Exploit_Kit_Landing_Page (ALTO)
    - Bumblebee_Core (MÉDIO)
    ... (10 malwares encontrados)"
```

---

## ⚙️ Dependências

| Dependência | Função | Local |
|-------------|--------|-------|
| **yara-python** | Compilação e execução de regras YARA | `yara_detector.py` |
| **scapy** | Leitura e extração de PCAP | `yara_detector.py` |
| **Python 3.9+** | Linguagem de programação | Geral |
| **Ollama (llama3)** | LLM para análise | `pcap_analyzer.py` |

---

## 📈 Performance

Medidas através do decorator `@measure_performance`:

- **Tempo médio de análise**: Dependente do tamanho do PCAP
- **Regras YARA carregadas**: ~1250 regras
- **Cache inteligente**: Reutiliza compilação se regras não mudarem
- **Timeout YARA**: 10 segundos por arquivo
- **Limite de detecções retornadas**: Top 15 mais críticas

---

## 🎯 Resumo

**O projeto usa:**

1. ✅ **Scapy** para extrair payloads (TCP, HTTP, suspeitos)
2. ✅ **yara-python** para analisar cada payload contra ~1250 regras
3. ✅ **yara_detector.py** para orquestrar extração + análise + relatório
4. ✅ **Classificação de severidade** automática (CRÍTICA/ALTA/MÉDIA/BAIXA)
5. ✅ **Integração com LLM** para análise contextual final

Tudo coordenado para fornecer ao LLM uma lista estruturada de malwares detectados com contexto de severidade.

