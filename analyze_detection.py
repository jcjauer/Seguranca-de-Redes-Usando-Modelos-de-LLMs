#!/usr/bin/env python3

import sys

def analyze_file(filepath):
    print(f"🔍 ANALISANDO: {filepath}")
    print("=" * 50)
    
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        print(f"📊 Tamanho: {len(data)} bytes")
        
        # Converter para texto
        try:
            text = data.decode('utf-8', errors='ignore')
        except:
            text = data.decode('latin-1', errors='ignore')
        
        print("\n📝 PRIMEIROS 500 CARACTERES:")
        print("-" * 30)
        # Substituir caracteres não printáveis por pontos
        printable = ''.join(c if ord(c) >= 32 and ord(c) <= 126 else '.' for c in text[:500])
        print(printable)
        
        print("\n🔍 PROCURANDO INDICADORES:")
        print("-" * 30)
        
        # Procurar por indicadores específicos
        indicators = {
            'neutrino': 'NEUTRINO EK',
            'bumblebee': 'BUMBLEBEE',
            'campaign': 'CAMPAIGN',
            'bot_id': 'BOT_ID', 
            'task': 'TASK',
            'gate': 'GATE',
            'load': 'LOAD',
            'exe': 'EXECUTABLE'
        }
        
        found = []
        for indicator, name in indicators.items():
            if indicator.lower() in text.lower():
                found.append(name)
                print(f"✅ {name} encontrado!")
        
        if not found:
            print("⚠️ Nenhum indicador específico encontrado")
        
        print("\n🧮 ANÁLISE DE ENTROPIA:")
        print("-" * 30)
        # Calcular entropia Shannon básica
        import math
        from collections import Counter
        
        if len(data) > 0:
            counter = Counter(data)
            entropy = 0
            for count in counter.values():
                p = count / len(data)
                if p > 0:
                    entropy -= p * math.log2(p)
            print(f"📈 Entropia Shannon: {entropy:.2f}")
            
            if entropy > 7.5:
                print("🔥 ALTA ENTROPIA - Dados possivelmente criptografados/comprimidos")
            elif entropy > 6.0:
                print("⚠️ MÉDIA ENTROPIA - Dados possivelmente codificados")
            else:
                print("📝 BAIXA ENTROPIA - Dados principalmente texto/estruturados")
        
        print("\n🎯 ANÁLISE DE BASE64:")
        print("-" * 30)
        import re
        base64_matches = re.findall(r'[A-Za-z0-9+/]{50,}={0,2}', text)
        if base64_matches:
            print(f"✅ {len(base64_matches)} sequências Base64 longas encontradas")
            print(f"📊 Maior sequência: {len(max(base64_matches, key=len))} caracteres")
        else:
            print("❌ Nenhuma sequência Base64 longa encontrada")
            
        return found
        
    except Exception as e:
        print(f"❌ Erro ao analisar arquivo: {e}")
        return []

if __name__ == "__main__":
    # Analisar arquivos do PCAP real do Bumblebee
    files_to_check = [
        "bumblebee_focused/tcp_large/large_stream_1_1460.bin",  # 50KB - mais promissor
        "bumblebee_focused/tcp_large/large_stream_6_1460.bin",  # 12KB
        "bumblebee_focused/tcp_large/large_stream_12_1460.bin", # 9KB
        "bumblebee_focused/tcp_large/large_stream_0_1460.bin"   # 5KB
    ]
    
    print("🎯 ANÁLISE DO PCAP REAL DO BUMBLEBEE 2022")
    print("=" * 60)
    
    for filepath in files_to_check:
        try:
            found = analyze_file(filepath)
            print(f"\n{'='*60}\n")
        except Exception as e:
            print(f"❌ Erro ao analisar {filepath}: {e}")
            print(f"\n{'='*60}\n")