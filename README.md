# Segurança-de-Redes-Usando-Modelos-de-LLMs
Segurança de Redes usando modelos de LLMs

## 📊 Analisador de PCAP com IA

Este projeto permite analisar arquivos PCAP (capturas de pacotes de rede) utilizando o Scapy para processar os pacotes e modelos LLM via Ollama para interpretar e identificar possíveis anomalias de segurança.

## Sumário

- [Estrutura do projeto](#-estrutura-do-projeto)
- [Quick Start](#-quick-start)
- [Pré-requisitos](#-pré-requisitos)
- [Instalação](#-instalação)
- [Execução e exemplos](#-execução-e-exemplos)
- [Tecnologias](#-tecnologias-utilizadas)
- [Modelos LLM suportados](#-modelos-llm-suportados)
- [Tipos de Anomalias Detectadas](#-tipos-de-anomalias-detectadas)
- [Troubleshooting](#-troubleshooting)
- [Referências](#-referências)

## 🏗️ Estrutura do projeto

```
Segurança-de-Redes-Usando-Modelos-de-LLMs/
├── gerar_pcap_anomalias.py    # Gerador de arquivos de teste
├── requirements.txt           # Dependências Python
├── README.md                  # Este arquivo
├── exemplo.pcap               # Arquivo PCAP de exemplo
└── pcap_web/                   # Aplicação Django (se aplicável)
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

- **Python 3.10+** - Linguagem principal
- **Scapy** - Manipulação e análise de pacotes de rede
- **Ollama** - Interface para modelos LLM locais
- **Tkinter** - Interface gráfica nativa do Python
- **LLaMA 3/Mistral/Gemma** - Modelos de IA para análise

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
.\venv\Scripts\Activate.ps1
```

Command Prompt (cmd) - Windows:
```cmd
python -m venv venv
venv\Scripts\activate.bat
```

Bash (Linux / macOS):
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Instale as dependências
```bash
python.exe -m pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Configure o Ollama:
```bash
# Instalar Ollama: https://ollama.ai
# Baixar modelos (escolha um ou mais):
ollama pull llama3
ollama pull mistral
ollama pull gemma
```

### 5. Preparação e execução da interface web (Django)

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

Acesse a interface em: http://127.0.0.1:8000

### Gerar PCAP com anomalias para teste

Se desejar gerar um arquivo de teste com anomalias (port scan, DDoS simulado, tráfego de alta entropia etc.), execute:
```bash
python gerar_pcap_anomalias.py
```

Observação: por padrão o gerador salva o arquivo `anomalias_seguranca.pcap` na raiz do projeto e imprime o caminho absoluto ao final da execução.

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
