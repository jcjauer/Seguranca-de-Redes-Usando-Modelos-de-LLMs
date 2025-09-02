# 🌐 Feature: Interface Web Django - Branch `feature/tela`

## 🎯 **NOVIDADE**: Interface Web Completa para Análise de PCAP!

Esta branch contém uma **aplicação web Django completa** que substitui a interface CLI por uma **interface web moderna e responsiva** para análise de segurança de redes usando LLMs.

## 🚀 **Como Rodar Rapidamente:**

### 1. **Clone e Configure:**
```bash
git clone https://github.com/jcjauer/Seguranca-de-Redes-Usando-Modelos-de-LLMs.git
cd Seguranca-de-Redes-Usando-Modelos-de-LLMs
git checkout feature/tela
```

### 2. **Instale Dependências:**
```bash
# Criar ambiente virtual
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/Mac

# Instalar dependências mínimas
pip install -r requirements.txt
```

### 3. **Execute o Servidor:**
```bash
cd pcap_web
python manage.py migrate  # Primeira vez apenas
python manage.py runserver
```

### 4. **Acesse:** `http://127.0.0.1:8000`

## ✨ **Principais Funcionalidades:**

### 🎨 **Interface Web Moderna:**
- ✅ **Bootstrap 5** - Design responsivo e profissional  
- ✅ **Drag & Drop** - Upload intuitivo de arquivos PCAP
- ✅ **Navegação fluida** - SPA-like experience
- ✅ **Mobile-friendly** - Funciona em smartphones/tablets

### 🔍 **Análise Avançada:**
- ✅ **Multi-protocolo** - IPv4, IPv6, ARP, Raw Data
- ✅ **Link Layer robusto** - Suporta tipos desconhecidos
- ✅ **Interpretação inteligente** - Converte dados Raw em IP
- ✅ **Análise LLM** - Detecção de anomalias via Ollama

### 🛠️ **Recursos Técnicos:**
- ✅ **Threading** - Análise em background sem travar UI
- ✅ **API RESTful** - Endpoints para integração
- ✅ **Admin Django** - Painel administrativo
- ✅ **Testes robustos** - 14 testes, 100% passando
- ✅ **Comandos customizados** - Limpeza automática

## 📊 **O que Mudou:**

| **Antes (CLI)** | **Agora (Web)** |
|----------------|-----------------|
| ❌ Interface texto | ✅ Interface web moderna |
| ❌ Apenas IPv4 | ✅ IPv4, IPv6, ARP, Raw |
| ❌ Erros com PCAP do Wireshark | ✅ Suporte completo |
| ❌ 20+ dependências | ✅ 3 dependências essenciais |
| ❌ Sem testes | ✅ 14 testes abrangentes |
| ❌ Sem validação | ✅ Validação completa de arquivos |

## 🧪 **Para Testar:**

### Arquivos PCAP Incluídos:
- `exemplo.pcap` - Arquivo com Link Layer tipo 138 (funciona agora!)
- `anomalias_seguranca.pcap` - PCAP gerado com anomalias

### Funcionalidades para Testar:
1. **Upload de arquivos** - Drag & drop ou clique
2. **Validação** - Tente arquivos inválidos
3. **Análise em tempo real** - Veja o progresso
4. **Visualização de resultados** - Dados estruturados
5. **Lista de análises** - Histórico completo
6. **API endpoints** - `/api/analysis/<id>/status/`

## 🔧 **Comandos Úteis:**

```bash
# Executar testes
python manage.py test analyzer.tests -v 2

# Criar superusuário (admin)
python manage.py createsuperuser

# Acessar admin Django
# http://127.0.0.1:8000/admin/

# Ver logs de desenvolvimento
python manage.py runserver --verbosity 2
```

## 📁 **Estrutura da Feature:**

```
pcap_web/                    # Aplicação Django principal
├── analyzer/                # App de análise de PCAP
│   ├── templates/           # Templates HTML responsivos
│   ├── management/          # Comandos customizados
│   ├── migrations/          # Migrações do banco
│   ├── pcap_analyzer.py     # Core da análise (melhorado)
│   ├── models.py            # Modelo de dados
│   ├── views.py             # Lógica de negócio
│   ├── forms.py             # Validação de formulários
│   └── tests.py             # Testes abrangentes
├── media/                   # Uploads de arquivos
├── static/                  # CSS, JS, imagens
└── manage.py                # CLI Django
```

## 🎭 **Screenshots/Demonstração:**

Depois de rodar o servidor, você verá:
- 🏠 **Home** - Introdução e links rápidos
- 📤 **Upload** - Interface drag-and-drop moderna  
- 📊 **Análise** - Resultados estruturados com LLM
- 📋 **Lista** - Histórico de todas as análises
- ⚙️ **Admin** - Painel administrativo Django

## 🤝 **Para Contribuir:**

Esta é uma feature branch ativa! Para colaborar:
1. Faça checkout da branch: `git checkout feature/tela`
2. Crie uma sub-branch: `git checkout -b feature/tela-sua-melhoria`
3. Implemente melhorias
4. Teste: `python manage.py test`
5. Commit e push
6. Abra um PR para `feature/tela`

## 🔮 **Próximos Passos:**

- [ ] Integração com múltiplos modelos LLM
- [ ] Dashboard de estatísticas
- [ ] Exportação de relatórios PDF
- [ ] Análise comparativa de PCAPs
- [ ] Alertas em tempo real
- [ ] API de integração externa

---

**Esta feature representa uma evolução completa do projeto** - de uma ferramenta CLI simples para uma **aplicação web profissional** pronta para uso em ambiente corporativo! 🚀

*Desenvolvido com Django 5.1, Bootstrap 5, e muito ❤️*
