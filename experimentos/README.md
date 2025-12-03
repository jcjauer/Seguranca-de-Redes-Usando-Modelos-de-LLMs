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

### 4.1 Teste 1 – Ataques DoS em Ambiente Controlado

O primeiro teste consiste na fusão do tráfego benigno com três tipos de ataques DoS gerados manualmente em um ambiente controlado, utilizando ferramentas do Kali Linux:

• **SYN Flood**
  - Envio massivo de pacotes SYN visando sobrecarregar o servidor alvo.

• **UDP Flood**
  - Ataque que gera grande volume de pacotes UDP para consumir banda e processamento.

• **Distributed SYN Flood**
  - Variação distribuída do SYN Flood, simulando múltiplas origens de ataque.

Esses três ataques foram capturados separadamente e, em seguida, unificados — juntamente com o tráfego benigno — através do mergecap, originando um arquivo PCAP que representa um ataque DoS composto em meio a comunicações normais.

### 4.2 Teste 2 – Malware Bumblebee

O segundo teste incorporou uma captura real do malware Bumblebee, um loader frequentemente associado a campanhas de distribuição de ransomware e infostealers.

O tráfego benigno foi então integrado ao PCAP do malware utilizando o mergecap, produzindo um cenário onde comunicações normais coexistem com o comportamento característico do Bumblebee.

### 4.3 Teste 3 – Malware Neutrino

O terceiro teste utilizou uma amostra do malware Neutrino, também retirada do repositório Malware Traffic Analysis.

Assim como nos testes anteriores:

• o PCAP original do malware foi obtido do site
• o tráfego benigno foi assimilado ao ataque via mergecapO arquivo resultante contém comunicações normais misturadas com o comportamento malicioso típico do Neutrino, como beaconing, comunicação com C2 e possíveis downloads de payloads.

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