# Segurança-de-Redes-Usando-Modelos-de-LLMs
Segurança de Redes usando modelos de LLMs

## 📊 Analisador de PCAP com IA

Este projeto permite analisar arquivos PCAP (capturas de pacotes de rede) utilizando o Scapy para processar os pacotes e modelos LLM via Ollama para interpretar e identificar possíveis anomalias de segurança.

## Sumário

- [Estrutura do projeto](#️-estrutura-do-projeto)
- [Funcionalidades](#-funcionalidades)
- [Tecnologias Utilizadas](#-tecnologias-utilizadas)
- [Pré-requisitos](#️-pré-requisitos)
- [Instalação](#-instalação)
- [Execução](#️-execução)
- [Experimentos](#-experimentos)
- [Relatório Formatado para LLM](#-relatório-formatado-para-llm)
- [Troubleshooting](#-troubleshooting)
- [Referências](#-referências)

## 🏗️ Estrutura do projeto

```
Segurança-de-Redes-Usando-Modelos-de-LLMs/
├── gerar_pcap_anomalias.py    # Gerador de arquivos de teste
├── requirements.txt           # Dependências Python
├── README.md                  # Este arquivo
├── exemplo.pcap               # Arquivo PCAP de exemplo
└── pcap_web/                  # Aplicação web (Django)
```

## 🚀 Funcionalidades

- ✅ **Leitura de arquivos .pcap/.pcapng**
- ✅ **Extração de informações** como IP origem/destino, protocolo, tamanho e entropia
- ✅ **Escolha de modelos LLM** (llama3, mistral, gemma, etc.)
- ✅ **Interface gráfica intuitiva** com Tkinter
- ✅ **Gerador de PCAP com anomalias** para testes
- ✅ **Análise assistida por IA** com detecção de:
  - 🎯 Port scanning
  - 💥 Ataques DDoS
  - 🔐 Tráfego criptografado suspeito
  - 🔓 Ataques de força bruta
  - 🕳️ DNS tunneling
  - 📡 Padrões anômalos de comunicação

## 🔧 Tecnologias Utilizadas

- **Python 3.10+** – Linguagem principal
- **Scapy** – Manipulação e análise de pacotes de rede
- **Ollama** – Host de modelos LLM locais
- **Django** – Interface web para upload/análise de PCAPs
- **Tkinter** – Interface gráfica nativa (uso opcional)
- **LLaMA 3 / Mistral / Gemma** – Modelos de IA para análise

## 🛠️ Pré-requisitos

Antes de rodar, você precisa ter instalado:

- **Python 3.10+**
- **Ollama** (com modelos LLM baixados)
- **Git** (para clonar o repositório)

## 📦 Instalação

### 1. Clone o repositório:
```bash
git clone https://github.com/jcjauer/Seguranca-de-Redes-Usando-Modelos-de-LLMs.git
cd Seguranca-de-Redes-Usando-Modelos-de-LLMs
```

### 2. Crie e ative o ambiente virtual
Exemplos para criar e ativar o ambiente virtual (escolha o comando conforme seu sistema/shell):

PowerShell (Windows):
```powershell
python -m venv venv
venv\Scripts\activate
```

Bash (Linux / macOS):
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Instale as dependências
```bash
python.exe -m pip install --upgrade pip
pip install scapy ollama django pillow requests
```

### 4. Configure o Ollama:
```bash
# Instalar Ollama: https://ollama.ai
# Baixar modelos (escolha um ou mais):
ollama pull llama3
ollama pull mistral
ollama pull gemma
```

## ▶️ Execução

### Web (Django)

1) Migrar o banco de dados

Se o app `analyzer` ainda não tiver migrações, gere-as (execute a partir da raiz do projeto):
```powershell
python pcap_web/manage.py makemigrations analyzer
```
Em seguida, aplique todas as migrações:
```powershell
python pcap_web/manage.py migrate
```

2) Arquivos estáticos

Crie a pasta para arquivos estáticos caso não exista:
```powershell
mkdir pcap_web\static
```

3) Iniciar servidor de desenvolvimento

Inicie o servidor (a partir da raiz do projeto):
```powershell
python pcap_web/manage.py runserver
```

Abra: http://127.0.0.1:8000

### CLI

Gerar um PCAP com anomalias (port scan, DDoS simulado, alta entropia):
```powershell
python gerar_pcap_anomalias.py
```
O arquivo `anomalias_seguranca.pcap` é salvo na raiz do projeto.

## 🧪 Experimentos

Este projeto inclui uma série de experimentos práticos que demonstram a eficácia do sistema na detecção de ameaças reais. Foram criados quatro cenários distintos combinando tráfego benigno com diferentes tipos de ataques e malwares:

- **Teste 1**: Ataques DoS (SYN Flood, UDP Flood, Distributed SYN Flood) gerados em ambiente controlado
- **Teste 2**: Malware Bumblebee (loader de ransomware/infostealer) com tráfego benigno
- **Teste 3**: Malware Neutrino (exploit kit) integrado a comunicações normais
- **Teste 4**: Combinação Neutrino + Bumblebee sem tráfego benigno (cenário de múltiplas ameaças)

Cada teste foi construído utilizando `mergecap` para simular ambientes realistas onde atividades maliciosas coexistem com tráfego legítimo. Os experimentos incluem detecções via YARA (regras de assinatura) e heurísticas (DDoS, port scanning, alta entropia, botnet), além de amostras reais capturadas pelos modelos LLM.

**📄 Documentação completa dos experimentos:**  
[experimentos/README.md](https://github.com/jcjauer/Seguranca-de-Redes-Usando-Modelos-de-LLMs/blob/main/experimentos/README.md)

## 📋 Relatório Formatado para LLM

O sistema gera um relatório estruturado que combina múltiplas fontes de análise de segurança antes de enviá-lo aos modelos de linguagem. Este relatório consolidado inclui:

- **Estatísticas gerais do PCAP**: Total de pacotes, protocolos identificados, IPs envolvidos, distribuição temporal
- **Relatório YARA**: Detecções de malware via assinaturas (classificadas por severidade: ALTA, MÉDIA, BAIXA)
- **Análise Heurística**: Identificação de padrões suspeitos como:
  - Ataques de flood (SYN/UDP/ICMP/ACK)
  - Port scanning e reconhecimento
  - Comunicação com botnets (múltiplos destinos)
  - Payloads com alta entropia (possível C2 ou criptografia)
- **Extração de Payloads**: Conteúdo relevante de requisições HTTP, streams TCP/UDP para análise contextual

O relatório é formatado de maneira a otimizar a compreensão dos modelos LLM, permitindo que identifiquem correlações entre diferentes tipos de evidências e gerem análises mais precisas sobre a natureza e severidade das ameaças detectadas.

**📄 Estrutura detalhada do relatório:**  
[RELATORIO_FORMATADO_PARA_LLM.md](https://github.com/jcjauer/Seguranca-de-Redes-Usando-Modelos-de-LLMs/blob/main/RELATORIO_FORMATADO_PARA_LLM.md)

## 🚨 Troubleshooting

### Erro "Ollama não encontrado"
```bash
# Verificar se Ollama está rodando
ollama list

# Se não estiver, instalar:
# Windows/Mac: Baixar de https://ollama.ai
# Linux: curl -fsSL https://ollama.ai/install.sh | sh
```

### Erro "Modelo não encontrado"
```bash
# Baixar modelo necessário
ollama pull llama3
```

### Erro de dependências Python
```bash
# Reinstalar dependências
pip install --force-reinstall -r requirements.txt
```

## 📚 Referências

- [Scapy Documentation](https://scapy.readthedocs.io/)
- [Ollama Models](https://ollama.ai/library)
- [Network Security Analysis](https://www.sans.org/white-papers/)
