# Estrutura do Relatório que o LLM Recebe

## **Parte 1: RESUMO GERAL (da função `formatar_dados_para_analise()`)**

```
RESUMO DA ANÁLISE DE REDE:

ESTATÍSTICAS GERAIS:
- Total de pacotes: [NÚMERO]
- IPv4: [X] | IPv6: [Y] | ARP: [Z] | Raw: [W]
- IPs de origem únicos: [NÚMERO]
- IPs de destino únicos: [NÚMERO]

PROTOCOLOS DETECTADOS:
- TCP: [X] pacotes
- UDP: [Y] pacotes
- ICMP: [Z] pacotes
...

PORTAS MAIS ACESSADAS:
- Porta [X] (SERVIÇO): [Y] pacotes
- Porta [X] (SERVIÇO): [Y] pacotes
...

PACOTES COM ALTA ENTROPIA (>6.0): [NÚMERO]
- [IP_ORIGEM] → [IP_DESTINO]:[PORTA] (entropia: [VALOR])
...
```

---

## **Parte 2: SEÇÃO CRÍTICA - ATAQUES HEURÍSTICOS**

```
════════════════════════════════════════════════════════════════════
🚨 ATAQUES CONFIRMADOS PELO MOTOR HEURÍSTICO:
════════════════════════════════════════════════════════════════════

✅ [N] ATAQUE(S) DETECTADO(S):

>>> SYN FLOOD: [N] detecção(ões)
   [1] Origem: [IP_ATACANTE] | Alvo: [IP_ALVO]:PORT | SYN Enviados: [N], ACK Recebidos: [N], Taxa: [RATIO] | 🎯 [N] atacantes | 🔴 SEVERIDADE: [CRÍTICO/ALTO/MÉDIO]
   [2] ... (se houver mais)

>>> UDP FLOOD: [N] detecção(ões)
   [1] Alvo: [IP_ALVO] | Pacotes: [N] | 🎯 [N] atacantes | 🔴 SEVERIDADE: [CRÍTICO/ALTO/MÉDIO]
   [2] ... (se houver mais)

>>> ICMP FLOOD: [N] detecção(ões)
   [1] Alvo: [IP_ALVO] | Pacotes ICMP: [N] | 🔴 SEVERIDADE: [CRÍTICO/ALTO/MÉDIO]
   [2] ... (se houver mais)

>>> ACK FLOOD: [N] detecção(ões)
   [1] Alvo: [IP_ALVO]:PORT | Pacotes ACK: [N] | 🔴 SEVERIDADE: ALTO
   [2] ... (se houver mais)

>>> ARP FLOODING: [N] detecção(ões)
   [1] Origem: [IP_ATACANTE] | Pacotes ARP: [N] | 1 atacante | 🔴 SEVERIDADE: MÉDIO
   [2] ... (se houver mais)

>>> ARP SPOOFING (CONFLITO DE MAC): [N] detecção(ões)
   [1] IP: [IP_ALVO] | Endereços MAC: [MAC1, MAC2, MAC3] | 🔴 SEVERIDADE: CRÍTICO

>>> FRAGMENTAÇÃO IP: [N] detecção(ões)
   [1] Alvo: [IP_ALVO] | Pacotes Fragmentados: [N] | 🔴 SEVERIDADE: MÉDIO

════════════════════════════════════════════════════════════════════
FIM DA SEÇÃO DE ATAQUES
════════════════════════════════════════════════════════════════════
```

### **Se NÃO houver ataques:**
```
✅ NENHUM ATAQUE DETECTADO

O motor heurístico analisou o tráfego e não identificou:
- SYN Flood (ratio de resposta normal)
- UDP Flood (volume dentro dos limites)
- ICMP Flood (pings normais)
- ACK Flood (ACKs legítimos)
- DDoS Distribuído (sem múltiplos atacantes coordenados)
- Port Scan massivo (conexões normais)
- ARP Spoofing ou ARP Flooding
```

---

## **Parte 3: OUTROS PADRÕES DETECTADOS (se aplicável)**

```
🔗 HOSTS COM MÚLTIPLAS CONEXÕES:
- [IP_HOST] conectou-se a [N] destinos externos distintos

🔍 TESTES DE PORTAS:
- [IP_ORIGEM] → [IP_DESTINO] acessou [N] portas distintas

📡 TRÁFEGO COM ALTA ENTROPIA (>7.5, portas não-TLS):
- [IP_ORIGEM] → [IP_DESTINO]:[PORTA] (entropia: [VALOR])

⚠️ ANOMALIAS DE TRÁFEGO:
- [TIPO_ANOMALIA]: [DETALHES]

🔌 CONEXÕES SUSPEITAS:
- [IP_ORIGEM] → [IP_DESTINO]:[PORTA]: [N] pacotes (porta não-padrão)

📤 POSSÍVEL VAZAMENTO DE DADOS:
- [IP_ORIGEM]: [MB] MB enviados externamente

🌐 DOMÍNIOS DNS CONSULTADOS:
- exemplo.com
- outro-dominio.net
- ... (limitado a 10 + contagem de restantes)

🎯 IPs DE DESTINO ÚNICOS:
- 203.0.113.1
- 198.51.100.5
- ... (limitado a 15 + contagem de restantes)
```

---

## **Parte 4: RELATÓRIO YARA (recebido separadamente)**

O LLM também recebe:

```
═══════════════════════════════════════════════════════════════
📋 RELATÓRIO YARA - ANÁLISE DE MALWARE
═══════════════════════════════════════════════════════════════

[DETECÇÕES DE MALWARE ENCONTRADAS OU "NENHUMA DETECÇÃO"]
```

---

## **Parte 5: INSTRUÇÕES DO LLM**

```
═══════════════════════════════════════════════════════════════
📝 INSTRUÇÕES
═══════════════════════════════════════════════════════════════

Você é um analista de segurança. Acima você recebeu:
1. RELATÓRIO YARA (detecções de malware por assinaturas)
2. ANÁLISE HEURÍSTICA (ataques DDoS, port scan, múltiplas conexões, ARP flooding, etc)

VOCABULÁRIO OBRIGATÓRIO:
- Use "CONFIRMADO" ou "DETECTADO" (NÃO "suspeito", "possível", "indica")
- Use "ATAQUE" (NÃO "atividade suspeita")

⚠️ INSTRUÇÃO CRÍTICA - LEIA COM ATENÇÃO:

Na seção "🚨 ATAQUES CONFIRMADOS PELO MOTOR HEURÍSTICO" acima:
- Se houver "✅ X ATAQUE(S) DETECTADO(S):" = há X ataques que VOCÊ DEVE LISTAR
- Cada ataque está marcado com ">>>" e contém: [tipo] | Origem | Alvo | Métricas | Severidade
- TODOS os ataques listados devem aparecer no seu relatório final

REGRAS OBRIGATÓRIAS:

1. INICIE mencionando AMBOS os relatórios:
   - "De acordo com o RELATÓRIO YARA: [malwares encontrados ou 'nenhuma detecção']"
   - "De acordo com a ANÁLISE HEURÍSTICA: [LISTE TODOS os tipos de ataque ou 'nenhum']"

2. SE HOUVER ATAQUES HEURÍSTICOS:
   - LISTA CADA tipo de ataque separadamente
   - Para cada ataque, inclua: tipo + alvo + números exatos + severidade

3. SE NÃO HOUVER ATAQUES:
   - "Nenhuma detecção YARA"
   - "Nenhum ataque confirmado pelo motor heurístico"

ESTRUTURA OBRIGATÓRIA:

**1. MALWARE DETECTADO (YARA):**
- [Liste cada malware DETECTADO com arquivo e severidade]

**2. ATAQUES CONFIRMADOS (HEURÍSTICA):**
- [LISTA TODOS - tipo de ataque + alvo + números + severidade]

**3. CLASSIFICAÇÃO DE RISCO:**
- CRÍTICO / ALTO / MÉDIO / BAIXO

**4. IMPACTO:**
- [Consequências de CADA malware e CADA ataque DETECTADO]

**5. RECOMENDAÇÕES:**
- [Ações específicas para CADA ameaça DETECTADA]
```

---

## **FLUXO COMPLETO**

O LLM recebe **TUDO** junto em um único prompt:

1. **RELATÓRIO YARA** (malware)
2. **DADOS FORMATADOS** (heurística completa)
3. **INSTRUÇÕES** (como analisar)

Tudo passa por **truncamento inteligente** (máx 10.000 caracteres) que:
- ✅ **Preserva sempre** a seção "🚨 ATAQUES CONFIRMADOS"
- ❌ **Trunca primeiro** IPs e domínios se necessário
- ✅ **Preserva** todas as métricas de ataque

---

## **O QUE O LLM ANALISA**

Com essas informações, o LLM pode:

✅ Identificar **todos os 7 tipos de DDoS**  
✅ Reportar **port scanning**  
✅ Detectar **comunicação C2** (alta entropia)  
✅ Apontar **hosts comprometidos** (múltiplas conexões)  
✅ Avisar sobre **vazamento de dados**  
✅ Alertar sobre **anomalias de tráfego**  
✅ Reportar **conexões suspeitas**  
✅ Combinar com **detecções YARA** para análise completa

