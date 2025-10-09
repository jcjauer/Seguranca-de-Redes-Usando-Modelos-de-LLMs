#!/usr/bin/env python3
"""
Deep Bumblebee Analysis - Análise de Entropy e Padrões Ocultos
"""

import os
import struct
import math
from collections import Counter
from pathlib import Path

def calcular_entropy(data):
    """Calcula entropia dos dados (mede o quão aleatórios são)"""
    if len(data) == 0:
        return 0
    
    counter = Counter(data)
    total = len(data)
    entropy = 0
    
    for count in counter.values():
        prob = count / total
        if prob > 0:
            entropy -= prob * math.log2(prob)
    
    return entropy

def encontrar_strings_ocultas(data, min_length=4):
    """Encontra strings ASCII ocultas nos dados"""
    strings = []
    current_string = ""
    
    for byte in data:
        if 32 <= byte <= 126:  # ASCII printável
            current_string += chr(byte)
        else:
            if len(current_string) >= min_length:
                strings.append(current_string)
            current_string = ""
    
    if len(current_string) >= min_length:
        strings.append(current_string)
    
    return strings

def analisar_padroes_xor(data, max_key_len=16):
    """Tenta detectar XOR simples com chaves pequenas"""
    resultados = []
    
    for key_len in range(1, max_key_len + 1):
        for key_byte in range(1, 256):  # Evita chave 0
            if key_len == 1:
                key = [key_byte]
            else:
                key = [key_byte] * key_len
            
            # Decodifica uma pequena amostra
            sample_size = min(100, len(data))
            decoded = []
            
            for i in range(sample_size):
                decoded_byte = data[i] ^ key[i % key_len]
                decoded.append(decoded_byte)
            
            # Verifica se produziu ASCII legível
            ascii_count = sum(1 for b in decoded if 32 <= b <= 126)
            if ascii_count > sample_size * 0.7:  # 70% ASCII
                decoded_string = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in decoded)
                if any(word in decoded_string.lower() for word in ['bumblebee', 'loader', 'campaign', 'bot']):
                    resultados.append({
                        'key': key,
                        'sample': decoded_string,
                        'ascii_ratio': ascii_count / sample_size
                    })
    
    return resultados

def buscar_pe_headers(data):
    """Busca por headers PE (executáveis Windows) nos dados"""
    pe_headers = []
    
    # Buscar por "MZ" (início de PE)
    i = 0
    while i < len(data) - 64:
        if data[i:i+2] == b'MZ':
            # Verificar se é um PE válido
            try:
                if i + 60 < len(data):
                    pe_offset = struct.unpack('<I', data[i+60:i+64])[0]
                    if i + pe_offset + 4 < len(data):
                        if data[i+pe_offset:i+pe_offset+2] == b'PE':
                            pe_headers.append({
                                'offset': i,
                                'pe_offset': pe_offset,
                                'size_estimate': min(1000, len(data) - i)
                            })
            except:
                pass
        i += 1
    
    return pe_headers

def analisar_arquivo_profundo(arquivo_path):
    """Análise profunda de um arquivo"""
    print(f"\n🔍 ANÁLISE PROFUNDA: {os.path.basename(arquivo_path)}")
    print("=" * 60)
    
    try:
        with open(arquivo_path, 'rb') as f:
            data = f.read()
        
        if len(data) == 0:
            print("   ⚠️ Arquivo vazio")
            return
        
        # 1. Análise de entropia
        entropy = calcular_entropy(data)
        print(f"   📊 Entropia: {entropy:.2f}/8.0")
        
        if entropy > 7.5:
            print("   🚨 ALTA ENTROPIA - Possível dados criptografados/comprimidos!")
        elif entropy < 3.0:
            print("   📝 Baixa entropia - Dados repetitivos ou texto")
        else:
            print("   ⚖️ Entropia normal")
        
        # 2. Buscar strings ocultas
        strings = encontrar_strings_ocultas(data, min_length=6)
        strings_suspeitas = [s for s in strings if any(word in s.lower() 
                           for word in ['bumblebee', 'bbee', 'loader', 'campaign', 'bot', 'gate', 'php', 'exe', 'dll'])]
        
        if strings_suspeitas:
            print(f"   🎯 STRINGS SUSPEITAS ENCONTRADAS ({len(strings_suspeitas)}):")
            for s in strings_suspeitas[:10]:  # Mostrar primeiras 10
                print(f"      🔤 '{s}'")
        
        # 3. Análise XOR
        print("   🔐 Testando decodificação XOR...")
        xor_results = analisar_padroes_xor(data[:1000])  # Testar apenas os primeiros 1000 bytes
        
        if xor_results:
            print(f"   🚨 POSSÍVEL XOR ENCONTRADO ({len(xor_results)} candidatos):")
            for result in xor_results[:3]:  # Mostrar primeiros 3
                print(f"      🔑 Chave: {result['key']}")
                print(f"      📝 Amostra: {result['sample'][:50]}...")
        
        # 4. Buscar PE headers
        pe_headers = buscar_pe_headers(data)
        if pe_headers:
            print(f"   💾 PE EXECUTÁVEIS ENCONTRADOS ({len(pe_headers)}):")
            for pe in pe_headers[:3]:
                print(f"      📍 Offset: {pe['offset']}, Tamanho: ~{pe['size_estimate']} bytes")
        
        # 5. Análise de protocolos
        if data.startswith(b'SMB') or b'SMB' in data[:100]:
            print("   🌐 Protocolo SMB detectado")
        
        if data.startswith(b'HTTP') or b'HTTP' in data[:100]:
            print("   🌐 Protocolo HTTP detectado")
        
        if b'\x30\x84' in data[:10]:  # LDAP ASN.1
            print("   🌐 Protocolo LDAP detectado")
        
        # 6. Procurar por Base64
        base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        text_data = data.decode('utf-8', errors='ignore')
        
        potential_b64 = []
        for line in text_data.split('\n'):
            line = line.strip()
            if len(line) > 20 and all(c in base64_chars for c in line) and line.endswith('='):
                potential_b64.append(line)
        
        if potential_b64:
            print(f"   🔤 POSSÍVEL BASE64 ENCONTRADO ({len(potential_b64)} strings):")
            for b64 in potential_b64[:3]:
                try:
                    import base64
                    decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
                    if any(word in decoded.lower() for word in ['bumblebee', 'loader', 'exe']):
                        print(f"      🎯 SUSPEITO: {decoded[:50]}...")
                except:
                    pass
        
    except Exception as e:
        print(f"   ❌ Erro na análise: {e}")

def main():
    print("🕵️ DEEP BUMBLEBEE ANALYSIS")
    print("=" * 50)
    
    # Analisar todos os TCP streams grandes
    tcp_dir = Path("bumblebee_focused/tcp_large")
    
    if not tcp_dir.exists():
        print("❌ Diretório de TCP streams não encontrado!")
        return
    
    arquivos = list(tcp_dir.glob("*.bin"))
    arquivos.sort(key=lambda x: x.stat().st_size, reverse=True)  # Maiores primeiro
    
    print(f"📁 Analisando {len(arquivos)} arquivos TCP...")
    
    for arquivo in arquivos:
        if arquivo.stat().st_size > 100:  # Só arquivos com mais de 100 bytes
            analisar_arquivo_profundo(arquivo)
    
    print(f"\n🎯 Análise profunda concluída!")
    print("Procure por:")
    print("   - Alta entropia (dados criptografados)")
    print("   - Strings suspeitas")
    print("   - Decodificações XOR")
    print("   - Headers PE (executáveis)")

if __name__ == "__main__":
    main()