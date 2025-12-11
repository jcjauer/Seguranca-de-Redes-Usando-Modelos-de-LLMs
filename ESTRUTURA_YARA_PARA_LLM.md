# Estrutura Completa do RELATÓRIO YARA que o LLM Recebe

## **Visão Geral**

O LLM recebe o YARA em **2 formatos diferentes** no mesmo prompt:

1. **`relatorio_yara_texto`** - String com o texto formatado do relatório
2. **`yara_estruturado`** - Seção com detecções organizadas por regra/arquivo/severidade

Ambos vêm da função `executar_analise_yara_completa(arquivo_pcap)` que retorna um dicionário.

---

## **FORMATO 1: Texto do Relatório YARA (`relatorio_yara_texto`)**

Este é o texto **bruto** que aparece na seção YARA do prompt:

```
═══════════════════════════════════════════════════════════════
📋 RELATÓRIO YARA - ANÁLISE DE MALWARE
═══════════════════════════════════════════════════════════════

RESUMO EXECUTIVO:
- Total de regras YARA carregadas: 1250
- Total de arquivos analisados: 8
- Total de detecções: 10
- Severidade máxima: ALTO

DETECÇÕES ENCONTRADAS:

✓ Detectado: Neutrino_Exploit_Kit_Landing_Page (severidade ALTO): Arquivo `tcp_stream_1.bin`
✓ Detectado: Neutrino_EK_Encrypted_Payload (severidade MÉDIO): Arquivo extraído
✓ Detectado: Bumblebee_Core (severidade MÉDIO): Arquivo extraído
✓ Detectado: Bumblebee_Encrypted (severidade MÉDIO): Arquivo extraído
✓ Detectado: Bumblebee_Script (severidade MÉDIO): Arquivo extraído
✓ Detectado: Bumblebee_Sniffer (severidade MÉDIO): Arquivo extraído
✓ Detectado: Bumblebee_Uploader (severidade MÉDIO): Arquivo extraído
✓ Detectado: Bumblebee_Downloader (severidade MÉDIO): Arquivo extraído
✓ Detectado: Bumblebee_Scanner (severidade MÉDIO): Arquivo extraído

ESTATÍSTICAS POR SEVERIDADE:
- CRÍTICA: 0
- ALTA: 1
- MÉDIA: 8
- BAIXA: 0

ARQUIVOS ANALISADOS: 8
- tcp_stream_1.bin
- http_file_2.bin
- http_file_3.bin
- http_file_4.bin
- http_file_5.bin
- http_file_7.bin
- http_file_8.bin
- http_file_9.bin

═══════════════════════════════════════════════════════════════
```

### **Estrutura Esperada do `relatorio_yara_texto`:**

```python
{
    "total_deteccoes": 10,
    "severidade_maxima": "ALTO",
    "arquivos_extraidos": 8,
    "relatorio_texto": "[TEXTO ACIMA]",  # ← Isso é enviado para o LLM
    "deteccoes": [
        {
            "regra": "Neutrino_Exploit_Kit_Landing_Page",
            "arquivo": "tcp_stream_1.bin",
            "severidade": "ALTO",
            "descricao": "Página de pouso do Neutrino EK"
        },
        {
            "regra": "Neutrino_EK_Encrypted_Payload",
            "arquivo": "Extraído",
            "severidade": "MÉDIO",
            "descricao": "Payload criptografado do Neutrino EK"
        },
        # ... mais detecções
    ]
}
```

---

## **FORMATO 2: Detecções Estruturadas (`yara_estruturado`)**

Esta é a **versão processada e estruturada** que aparece logo após o `relatorio_yara_texto`:

```
🔍 DETECÇÕES YARA ESTRUTURADAS:
════════════════════════════════════════════════════════════════

[1] REGRA: Neutrino_Exploit_Kit_Landing_Page
    Arquivo: tcp_stream_1.bin
    Severidade: ALTO
    Descrição: Página de pouso do Neutrino EK

[2] REGRA: Neutrino_EK_Encrypted_Payload
    Arquivo: Extraído
    Severidade: MÉDIO
    Descrição: Payload criptografado do Neutrino EK

[3] REGRA: Bumblebee_Core
    Arquivo: Extraído
    Severidade: MÉDIO
    Descrição: Núcleo do malware Bumblebee

[4] REGRA: Bumblebee_Encrypted
    Arquivo: Extraído
    Severidade: MÉDIO
    Descrição: Componente criptografado do Bumblebee

[5] REGRA: Bumblebee_Script
    Arquivo: Extraído
    Severidade: MÉDIO
    Descrição: Script de execução do Bumblebee

[6] REGRA: Bumblebee_Sniffer
    Arquivo: Extraído
    Severidade: MÉDIO
    Descrição: Componente sniffer do Bumblebee

[7] REGRA: Bumblebee_Uploader
    Arquivo: Extraído
    Severidade: MÉDIO
    Descrição: Componente uploader do Bumblebee

[8] REGRA: Bumblebee_Downloader
    Arquivo: Extraído
    Severidade: MÉDIO
    Descrição: Componente downloader do Bumblebee

[9] REGRA: Bumblebee_Scanner
    Arquivo: Extraído
    Severidade: MÉDIO
    Descrição: Componente scanner do Bumblebee

════════════════════════════════════════════════════════════════
```

---

## **FLUXO COMPLETO DO PROMPT ENVIADO AO LLM**

### **Ordem de Aparição no Prompt:**

```python
prompt = f"""
═══════════════════════════════════════════════════════════════
📋 RELATÓRIO YARA - ANÁLISE DE MALWARE
═══════════════════════════════════════════════════════════════

{relatorio_yara}  ← FORMATO 1: Texto bruto

{yara_estruturado}  ← FORMATO 2: Detecções estruturadas

═══════════════════════════════════════════════════════════════
📊 ANÁLISE HEURÍSTICA - PADRÕES DE ATAQUE
═══════════════════════════════════════════════════════════════

{dados_formatados}  ← Heurística (DDoS, Port Scan, C2, etc)

═══════════════════════════════════════════════════════════════
📝 INSTRUÇÕES
═══════════════════════════════════════════════════════════════

[INSTRUÇÕES PARA O LLM]
"""
```

---

## **PROCESSAMENTO NO CÓDIGO**

### **Passo 1: Executar YARA**
```python
relatorio_yara_resultado = executar_analise_yara_completa(arquivo_pcap)
# Retorna:
# {
#     "total_deteccoes": 10,
#     "severidade_maxima": "ALTO",
#     "arquivos_extraidos": 8,
#     "relatorio_texto": "[TEXTO ACIMA]",
#     "deteccoes": [...]
# }

relatorio_yara_texto = relatorio_yara_resultado.get("relatorio_texto", "...")
```

### **Passo 2: Formatar Detecções Estruturadas**
```python
if relatorio_yara_resultado and relatorio_yara_resultado.get("deteccoes"):
    deteccoes_para_estruturar = relatorio_yara_resultado["deteccoes"]
elif relatorio_yara and "✓ Detectado:" in relatorio_yara:
    # Parsear o texto se "deteccoes" não estiver disponível
    deteccoes_para_estruturar = []
    for linha in relatorio_yara.split("\n"):
        if "✓ Detectado:" in linha:
            deteccoes_para_estruturar.append({
                "regra": linha.replace("✓ Detectado:", "").strip(),
                "arquivo": "Extraído do texto",
                "severidade": "DESCONHECIDA"
            })

# Construir yara_estruturado
yara_estruturado = ""
if deteccoes_para_estruturar:
    yara_estruturado = "🔍 DETECÇÕES YARA ESTRUTURADAS:\n"
    for idx, deteccao in enumerate(deteccoes_para_estruturar, 1):
        yara_estruturado += f"[{idx}] REGRA: {deteccao['regra']}\n"
        yara_estruturado += f"    Arquivo: {deteccao['arquivo']}\n"
        yara_estruturado += f"    Severidade: {deteccao['severidade']}\n"
```

### **Passo 3: Enviar para LLM**
```python
analise_llm = analisar_com_llm_hibrido(
    dados_formatados,           # Heurística
    relatorio_yara_texto,       # YARA texto bruto
    modelo,
    relatorio_yara_resultado=relatorio_yara_resultado  # ← Dicionário com detecções
)
```

---

## **EXEMPLO REAL: Como o LLM Vê**

Quando o LLM recebe o prompt, ele vê:

```
═══════════════════════════════════════════════════════════════
📋 RELATÓRIO YARA - ANÁLISE DE MALWARE
═══════════════════════════════════════════════════════════════

RESUMO EXECUTIVO:
- Total de regras YARA carregadas: 1250
- Total de arquivos analisados: 8
- Total de detecções: 10
- Severidade máxima: ALTO

DETECÇÕES ENCONTRADAS:

✓ Detectado: Neutrino_Exploit_Kit_Landing_Page (severidade ALTO): Arquivo `tcp_stream_1.bin`
✓ Detectado: Neutrino_EK_Encrypted_Payload (severidade MÉDIO): Arquivo extraído
✓ Detectado: Bumblebee_Core (severidade MÉDIO): Arquivo extraído
✓ Detectado: Bumblebee_Encrypted (severidade MÉDIO): Arquivo extraído
✓ Detectado: Bumblebee_Script (severidade MÉDIO): Arquivo extraído
✓ Detectado: Bumblebee_Sniffer (severidade MÉDIO): Arquivo extraído
✓ Detectado: Bumblebee_Uploader (severidade MÉDIO): Arquivo extraído
✓ Detectado: Bumblebee_Downloader (severidade MÉDIO): Arquivo extraído
✓ Detectado: Bumblebee_Scanner (severidade MÉDIO): Arquivo extraído

🔍 DETECÇÕES YARA ESTRUTURADAS:
════════════════════════════════════════════════════════════════

[1] REGRA: Neutrino_Exploit_Kit_Landing_Page
    Arquivo: tcp_stream_1.bin
    Severidade: ALTO

[2] REGRA: Neutrino_EK_Encrypted_Payload
    Arquivo: Extraído
    Severidade: MÉDIO

[3] REGRA: Bumblebee_Core
    Arquivo: Extraído
    Severidade: MÉDIO

... (6 mais)

════════════════════════════════════════════════════════════════

═══════════════════════════════════════════════════════════════
📊 ANÁLISE HEURÍSTICA - PADRÕES DE ATAQUE
═══════════════════════════════════════════════════════════════

[DADOS HEURÍSTICOS...]

═══════════════════════════════════════════════════════════════
📝 INSTRUÇÕES
═══════════════════════════════════════════════════════════════

Você é um analista de segurança...
```

---

## **O Que o LLM Deve Extrair**

Com essa estrutura, o LLM consegue:

✅ **Listar cada malware YARA detectado** com arquivo e severidade  
✅ **Combinar YARA com heurística** para análise completa  
✅ **Reportar todos os malwares** na seção "1. MALWARE DETECTADO (YARA)"  
✅ **Associar severidade** de cada detecção  
✅ **Gerar recomendações** baseadas em malwares específicos  

---

## **Possíveis Problemas e Soluções**

| Problema | Causa | Solução |
|----------|-------|---------|
| LLM diz "malware1, malware2" | Dicionário vazio sem "deteccoes" | Código parseia `relatorio_yara_texto` automaticamente |
| Detecções aparecem duplicadas | Ambos formatos enviados | Normal - LLM usa o estruturado como prioridade |
| YARA não aparece | `relatorio_yara_texto` vazio | Verificar se `executar_analise_yara_completa()` retorna dados |
| Severidades genéricas | Arquivo não tem severidade real | Código tenta extrair do texto ou usa "DESCONHECIDA" |

---

## **Resumo**

O LLM recebe **AMBOS os formatos** do YARA:

1. **Texto bruto** - Para análise contextual geral
2. **Estruturado** - Para parsing direto e reportagem clara

Ambos são **complementares** e ajudam o LLM a:
- Entender o contexto dos malwares
- Extrair informações estruturadas
- Gerar relatórios detalhados e consistentes

