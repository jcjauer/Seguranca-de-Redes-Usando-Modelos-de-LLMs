## 1. Introdução

Este Experimento tem como objetivo criar e analisar diferentes cenários de tráfego de rede utilizando arquivos PCAP.
Foi capturado um tráfego totalmente benigno, que serviu como base para três testes distintos contendo ataques ou malwares.
Cada teste combina tráfego legítimo + tráfego malicioso, permitindo observar como atividades hostis se misturam ao uso normal da rede.

## 2. Captura Base – Tráfego Normal

Inicialmente foi criado um arquivo PCAP com tráfego completamente legítimo, gerado por dois usuários utilizando a rede sem qualquer atividade maliciosa.
Esse arquivo representa o cenário normal de funcionamento da rede e foi utilizado como base para todos os testes subsequentes.

## 3. Integração dos PCAPs com Mergecap

Todos os testes foram construídos utilizando o mergecap, ferramenta do Wireshark que permite unir diferentes arquivos PCAP em um único fluxo de dados.

Em cada teste, o tráfego benigno foi assimilado ao tráfego malicioso correspondente, produzindo um PCAP final que simula um ambiente realista onde atividades normais coexistem com ataques ou comportamentos nocivos.

Foram criados três arquivos distintos, descritos a seguir.

## 4. Testes

### 4.1 Teste 1 – Ataques DoS em Ambiente Controlado(3ataques.pcap)

O primeiro teste consiste na fusão do tráfego benigno com três tipos de ataques DoS gerados manualmente em um ambiente controlado, utilizando a ferramenta Hping do Kali Linux:

• **SYN Flood**
  - Envio massivo de pacotes SYN visando sobrecarregar o servidor alvo.

• **UDP Flood**
  - Ataque que gera grande volume de pacotes UDP para consumir banda e processamento.

• **Distributed SYN Flood**
  - Variação distribuída do SYN Flood, simulando múltiplas origens de ataque.

Esses três ataques foram capturados separadamente e, em seguida, unificados — juntamente com o tráfego benigno — através do mergecap, originando um arquivo PCAP que representa um ataque DoS composto em meio a comunicações normais.

- **Evidências observadas no LLM (heurística)**:  
  - **DDoS Externo**: SYN Flood (15.234 pacotes em 30s), DNS Amplificação (50 queries gerando ~2,5MB de resposta) e ICMP Flood (156 pacotes ARP) de IPs externos (142.250.x.x, 224.0.0.251) para a rede interna.  
  - **Port Scanning**: 500 portas distintas escaneadas em ~10s (ex.: 192.168.100.24 → 192.141.113.137).  
  - **Tráfego Suspeito**: 60.199 pacotes <64 bytes (potencial exfiltração) e 374 pacotes jumbo (>1500 bytes) em redes internas.  
  - **Entropia Anormal**: >7,5 em DNS/HTTP (portas 53/80) para domínios como `catalog.gamepass.com` (potencial tunelamento ou malware).  
  - **Conexões Suspeitas**: 192.168.0.215 → 224.0.0.251:5353 (porta não-padrão) e IPs multicast (ff02::fb:5353).  
  - **YARA**: Nenhuma detecção encontrada nos arquivos extraídos.  

### 4.2 Teste 2 – Malware Bumblebee (bum.pcap)

O segundo teste incorporou uma captura real do malware Bumblebee, um loader frequentemente associado a campanhas de distribuição de ransomware e infostealers.

O tráfego benigno foi então integrado ao PCAP do malware utilizando o mergecap, produzindo um cenário onde comunicações normais coexistem com o comportamento característico do Bumblebee.

**Amostras do que o LLM capturou (YARA/LLM):**
- **Bumblebee_Core_Network_Traffic** (severidade MÉDIA) em `tcp_stream_78.bin`
- **Bumblebee_Specific_IOCs** (severidade MÉDIA) em `http_request_4.bin`, `http_response_4.bin`, `http_request_9.bin` (e 4 outros arquivos)

### 4.3 Teste 3 – Malware Neutrino (neu.pcap)

O terceiro teste utilizou uma amostra do malware Neutrino, também retirada do repositório Malware Traffic Analysis.

Assim como nos testes anteriores:

• o PCAP original do malware foi obtido do site
• o tráfego benigno foi assimilado ao ataque via mergecap; o arquivo resultante contém comunicações normais misturadas com o comportamento malicioso típico do Neutrino, como beaconing, comunicação com C2 e possíveis downloads de payloads.

**Amostras do que o LLM capturou (YARA/LLM):**
- **Neutrino_Exploit_Kit_Landing_Page** (severidade ALTA) em `tcp_stream_1.bin`
- **Neutrino_EK_Encrypted_Payload** (severidade MÉDIA) em `tcp_stream_39.bin`

### 4.4 Teste 4 – Combinação Neutrino + Bumblebee (neobum.pcap)

Este experimento combina os PCAPs dos malwares Neutrino e Bumblebee sem adicionar tráfego benigno, simulando um cenário com múltiplas famílias ativas simultaneamente. A união foi feita via `mergecap` para consolidar os fluxos.

**Amostras do que o LLM capturou (YARA/LLM):**
- **Neutrino_Exploit_Kit_Landing_Page** (severidade ALTA)
- **Neutrino_EK_Encrypted_Payload** (severidade MÉDIA)
- **Bumblebee_Core_Network_Traffic** (severidade MÉDIA)
- **Bumblebee_Specific_IOCs** (severidade MÉDIA)

Observação: por se tratar de um merge sem tráfego benigno, os padrões maliciosos aparecem com maior densidade, facilitando a identificação de beaconing, comunicação C2 e IOCs de rede nos fluxos combinados.

**1. MALWARE (YARA):**  
- **Neutrino_Exploit_Kit_Landing_Page** (severidade ALTA) em `tcp_stream_1.bin`  
- **Neutrino_EK_Encrypted_Payload** (severidade MÉDIA) em `tcp_stream_39.bin`  
- **Bumblebee_Core_Network_Traffic** (severidade MÉDIA) em `tcp_stream_78.bin`  
- **Bumblebee_Specific_IOCs** (severidade MÉDIA) em `http_request_4.bin`, `http_response_4.bin`, `http_request_9.bin` (e 4 outros arquivos)  

---

**2. ATAQUES CONFIRMADOS - LISTAR TODOS OS 4 TIPOS ABAIXO:**  

🚨 **ATAQUES FLOOD (SYN/UDP/ICMP/ACK):**  
- **ARP Flood CONFIRMADO contra 192.168.1.107:513 (porta 513) com 371 pacotes, 1 atacante, severidade MÉDIO**  
- **ARP Flood CONFIRMADO contra 192.168.1.107:513 (porta 513) com 310 pacotes, 1 atacante, severidade MÉDIO**  

🔗 **MÚLTIPLAS CONEXÕES (BOTNET):**  
- **172.17.0.153 estabeleceu conexões para 95 destinos externos distintos, severidade ALTO**  

📡 **PACOTES COM ALTA ENTROPIA (C2):**  
- **217.23.15.230 → 192.168.1.107:51445 com entropia 7.76, severidade ALTO**  
- **31.207.6.161 → 192.168.1.107:51451 com entropia 7.83, severidade ALTO**  

## 5. Fonte das Amostras Maliciosas

Exceto o primeiro teste (ataques DoS gerados manualmente em ambiente seguro), todas as amostras maliciosas foram obtidas em:

**Malware Traffic Analysis** – https://www.malware-traffic-analysis.net/

## 6. Objetivo dos Experimentos

Os arquivos PCAP resultantes podem ser utilizados para:

• **Pesquisa acadêmica** em cibersegurança
• **Extração de características** para Machine Learning
• **Testes de IDS/IPS**
• **Experimentos de classificação** e detecção de ameaças
• **Criação de datasets** personalizados
