# Seguranca-de-Redes-Usando-Modelos-de-LLMs
Segurança de Redes Usando Modelos de LLMs

## 📊 Analisador de PCAP com IA

Este projeto permite analisar arquivos PCAP (capturas de pacotes de rede) utilizando o Scapy para processar os pacotes e modelos LLM via Ollama para interpretar e identificar possíveis anomalias de segurança.

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

### 2. Crie e ative o ambiente virtual:
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate
```

### 3. Instale as dependências:
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

### 5. Preparação e Execução do Projeto Django

**1. Migrações do banco de dados**
    - Certifique-se de que o app `analyzer` possui um arquivo de migração inicial. Se não existir, crie com:
       ```powershell
       python pcap_web/manage.py makemigrations analyzer
       ```
    - Em seguida, aplique todas as migrações:
       ```powershell
       python pcap_web/manage.py migrate
       ```

**2. Criação da pasta de arquivos estáticos**
    - Crie a pasta `static` dentro de `pcap_web` (caso não exista):
       ```powershell
       mkdir pcap_web\static
       ```

**3. Execução do servidor web Django**
    - Para iniciar a interface web:
       ```powershell
       python pcap_web/manage.py runserver
       ```

## 🎮 Como Usar

### Opção 1: Interface Gráfica (Recomendado)
```bash
python pcap_analyzer_gui.py
```

**Funcionalidades da GUI:**
- 📁 Seleção fácil de arquivos PCAP
- 🤖 Escolha de modelos LLM disponíveis
- 📊 Visualização detalhada dos resultados
- 🔄 Análise em tempo real com barra de progresso

### Opção 2: Linha de Comando
```bash
python pcap_llama_cli.py
```

### Opção 3: Gerar PCAP com Anomalias para Teste
```bash
python gerar_pcap_anomalias.py
```

Este script criará um arquivo `anomalias_seguranca.pcap` contendo:
- Tráfego normal (baseline)
- Port scan simulado
- Tentativa de DDoS
- Tráfego com alta entropia
- Brute force SSH
- DNS tunneling

## 💡 Exemplo de Uso Completo

```bash
# 1. Gerar arquivo de teste com anomalias
python gerar_pcap_anomalias.py

# 2. Abrir interface gráfica
python pcap_analyzer_gui.py

# 3. Na GUI:
#    - Selecionar o arquivo "anomalias_seguranca.pcap"
#    - Escolher modelo (ex: llama3)
#    - Clicar em "Analisar PCAP"
```

## 📋 Exemplo de Saída

```
=== RELATÓRIO DE ANÁLISE DE SEGURANÇA ===
Arquivo: anomalias_seguranca.pcap
Modelo IA: llama3
Total de pacotes: 127
Data/Hora: 01/09/2025 15:30:25

=== ANÁLISE DE SEGURANÇA COM IA ===

🚨 ANOMALIAS DETECTADAS:

1. **PORT SCAN IDENTIFICADO** (Alto Risco)
   - Origem: 10.0.0.100
   - Alvo: 192.168.1.50
   - Múltiplas tentativas em portas sequenciais
   - Recomendação: Bloquear IP origem

2. **POSSÍVEL ATAQUE DDOS** (Alto Risco)  
   - Múltiplos IPs atacando 192.168.1.100
   - Volume anômalo de requisições
   - Recomendação: Implementar rate limiting

3. **TRÁFEGO CRIPTOGRAFADO SUSPEITO** (Médio Risco)
   - Alta entropia detectada (>7.5)
   - Destino: 185.220.101.23:8443
   - Possível exfiltração de dados
```

## 🏗️ Estrutura do Projeto

```
📦 Seguranca-de-Redes-Usando-Modelos-de-LLMs/
├── 📄 pcap_llama_cli.py        # Analisador via linha de comando
├── 🖼️ pcap_analyzer_gui.py     # Interface gráfica
├── 🔧 gerar_pcap_anomalias.py  # Gerador de arquivos de teste
├── 📋 requirements.txt         # Dependências Python
├── 📖 README.md               # Este arquivo
├── 📊 exemplo.pcap            # Arquivo PCAP original
└── 🗂️ venv/                   # Ambiente virtual
```

## 🔧 Tecnologias Utilizadas

- **Python 3.10+** - Linguagem principal
- **Scapy** - Manipulação e análise de pacotes de rede
- **Ollama** - Interface para modelos LLM locais
- **Tkinter** - Interface gráfica nativa do Python
- **LLaMA 3/Mistral/Gemma** - Modelos de IA para análise

## 🎯 Modelos LLM Suportados

- **llama3** - Modelo principal recomendado
- **mistral** - Alternativa rápida e eficiente  
- **gemma** - Modelo do Google
- **codellama** - Especializado em código
- Qualquer modelo disponível no Ollama

## 🛡️ Tipos de Anomalias Detectadas

| Tipo | Descrição | Indicadores |
|------|-----------|-------------|
| 🎯 **Port Scan** | Varredura de portas | Múltiplas portas, mesmo origem |
| 💥 **DDoS** | Ataque distribuído | Múltiplos IPs → mesmo alvo |
| 🔐 **Malware** | Tráfego criptografado suspeito | Alta entropia (>6.0) |
| 🔓 **Brute Force** | Tentativas de login | Conexões repetidas SSH/RDP |
| 🕳️ **DNS Tunneling** | Exfiltração via DNS | Queries longas/codificadas |
| 📡 **Comunicação C&C** | Comando e controle | Padrões regulares suspeitos |

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

---
**Desenvolvido para fins educacionais em Segurança de Redes** 🎓