# Seguranca-de-Redes-Usando-Modelos-de-LLMs
Segurança de Redes Usando Modelos de LLMs

Analisador de PCAP com LLaMA

Este projeto permite analisar arquivos PCAP (capturas de pacotes de rede) utilizando o Scapy para processar os pacotes e o modelo LLaMA 3 via Ollama para interpretar e identificar possíveis padrões suspeitos.

Funcionalidades

-Leitura de arquivos .pcap
-Extração de informações como IP de origem/destino, protocolo, tamanho e entropia
-Análise assistida por IA usando o LLaMA 3
-Indicação de pacotes potencialmente suspeitos

Pré-requisitos
Antes de rodar, você precisa ter instalado:

-Python 3.10+
-Ollama (com o modelo llama3 baixado)
-venv para ambiente virtual (opcional)
-Dependências do projeto: scapy e ollama

Instalação

Clone o repositório:

git clone https://github.com/SEU-USUARIO/SEU-REPOSITORIO.git
cd SEU-REPOSITORIO


Crie e ative o ambiente virtual:

python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows


Instale as dependências:

pip install scapy ollama


Baixe o modelo llama3 no Ollama:

ollama pull llama3

Uso

Coloque o arquivo exemplo.pcap (ou outro .pcap) na mesma pasta do script.

Execute o analisador:

python pcap_llama_cli.py

O LLaMA irá processar as informações e fornecer uma análise textual sobre os pacotes.

Exemplo de Saída
WARNING: PcapReader: unknown LL type [138]/[0x8a]. Using Raw packets

--- Análise do LLaMA 3 ---

Pacote com alta entropia detectado, possível tráfego criptografado ou malicioso.
Pacote com destino à porta 3389 (RDP) — possível tentativa de acesso remoto.

Tecnologias Utilizadas

Python

Scapy — Leitura e processamento de pacotes de rede

Ollama — Interface para modelos de IA locais

LLaMA 3 — Modelo de linguagem para análise