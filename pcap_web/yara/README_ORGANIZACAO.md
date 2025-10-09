# 📂 ORGANIZAÇÃO DAS REGRAS YARA - BUMBLEBEE DETECTION SYSTEM

## 🎯 Estrutura Organizada:

### 📁 `pcap_web/yara/bumblebee/` - Regras Específicas do Bumblebee
- **bumblebee_detection_final.yara** - Regras finais otimizadas (MÁXIMA PRIORIDADE)
- **bumblebee_network_specific.yara** - IOCs específicos de rede
- **bumblebee_enhanced.yara** - Regras avançadas com múltiplos padrões
- **bumblebee_iocs_especificos.yara** - IOCs básicos e assinaturas iniciais

### 📁 Outras Categorias Disponíveis:
- `pcap_web/yara/trojan/` - Trojans genéricos
- `pcap_web/yara/infostealer/` - Stealers de informação  
- `pcap_web/yara/backdoor/` - Backdoors
- `pcap_web/yara/exploit/` - Exploit Kits
- `pcap_web/yara/ransomware/` - Ransomware
- `pcap_web/yara/rootkit/` - Rootkits

## 🔧 Sistema de Priorização:
1. **🎯 MÁXIMA PRIORIDADE**: Regras finais otimizadas
2. **🚀 ALTA**: Regras específicas de rede  
3. **✅ NORMAL**: IOCs básicos e regras genéricas

## 📝 Carregamento Automático:
O sistema `bumblebee_focused_detector.py` agora carrega automaticamente:
- Todas as regras da pasta `bumblebee/` (prioridade)
- Regras complementares de `trojan/`, `infostealer/`, `backdoor/`, `exploit/`

## 🎯 Vantagens da Organização:
- ✅ Fácil manutenção e atualização
- ✅ Separação por categorias de malware
- ✅ Sistema de prioridades claro
- ✅ Carregamento otimizado e automático
- ✅ Escalabilidade para novos tipos de malware