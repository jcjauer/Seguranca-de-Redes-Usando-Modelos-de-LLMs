#!/usr/bin/env python3
"""
Teste de carregamento das regras YARA
"""
import os
import sys
import glob

# Adiciona o path do projeto
sys.path.append('pcap_web')

def verificar_yara():
    """Verifica se o YARA está funcionando corretamente"""
    
    print("🔍 Verificando configuração YARA...")
    
    try:
        import yara
        print("✅ Módulo YARA importado com sucesso")
    except ImportError as e:
        print(f"❌ Erro ao importar YARA: {e}")
        return False
    
    # Verifica o caminho das regras
    current_dir = os.path.dirname(os.path.abspath(__file__))
    yara_dir = os.path.join(current_dir, 'pcap_web', 'yara')
    
    print(f"📁 Procurando regras em: {yara_dir}")
    
    if not os.path.exists(yara_dir):
        print(f"❌ Pasta YARA não encontrada: {yara_dir}")
        return False
    
    # Lista arquivos .yara
    rule_files = glob.glob(os.path.join(yara_dir, '**', '*.yara'), recursive=True)
    print(f"📋 Encontradas {len(rule_files)} regras YARA")
    
    if not rule_files:
        print("❌ Nenhuma regra .yara encontrada")
        return False
    
    # Mostra algumas regras
    print("\n📄 Primeiras 10 regras encontradas:")
    for i, rule_file in enumerate(rule_files[:10]):
        rel_path = os.path.relpath(rule_file, yara_dir)
        size = os.path.getsize(rule_file)
        print(f"  {i+1}. {rel_path} ({size} bytes)")
    
    # Tenta compilar algumas regras
    print("\n🔨 Testando compilação de regras...")
    
    try:
        # Testa com apenas uma regra primeiro
        first_rule = rule_files[0]
        print(f"🧪 Compilando regra de teste: {os.path.basename(first_rule)}")
        
        with open(first_rule, 'r', encoding='utf-8', errors='ignore') as f:
            rule_content = f.read()
            print("📝 Primeiras linhas da regra:")
            lines = rule_content.split('\n')[:5]
            for line in lines:
                if line.strip():
                    print(f"     {line}")
        
        yara.compile(filepath=first_rule)
        print("✅ Compilação de regra única: SUCESSO")
        
        # Testa com um dicionário pequeno de regras
        print("\n🧪 Compilando primeiras 5 regras...")
        rules_dict = {f"rule_{i}": rule_files[i] for i in range(min(5, len(rule_files)))}
        
        yara.compile(filepaths=rules_dict)
        print("✅ Compilação de múltiplas regras: SUCESSO")
        
        return True
        
    except Exception as e:
        print(f"❌ Erro na compilação: {e}")
        return False

def testar_regra_simples():
    """Testa uma regra YARA simples criada manualmente"""
    
    print("\n🧪 Testando regra YARA simples...")
    
    try:
        import yara
        
        # Cria uma regra simples para testar
        rule_text = '''
        rule TestRule
        {
            strings:
                $mz = { 4D 5A }
                $dos = "This program cannot be run in DOS mode"
                $cmd = "cmd.exe"
            condition:
                $mz or $dos or $cmd
        }
        '''
        
        compiled_rule = yara.compile(source=rule_text)
        print("✅ Regra de teste compilada com sucesso")
        
        # Cria arquivo de teste
        test_content = b"MZThis program cannot be run in DOS modecmd.exe"
        
        matches = compiled_rule.match(data=test_content)
        
        if matches:
            print(f"🎯 Regra de teste detectou: {matches[0].rule}")
            return True
        else:
            print("⚠️ Regra de teste não detectou o conteúdo")
            return False
            
    except Exception as e:
        print(f"❌ Erro no teste de regra simples: {e}")
        return False

if __name__ == "__main__":
    print("🔍 DIAGNÓSTICO YARA")
    print("=" * 40)
    
    yara_ok = verificar_yara()
    test_ok = testar_regra_simples()
    
    print("\n" + "=" * 40)
    print("📊 RESUMO")
    print("=" * 40)
    print(f"YARA configurado: {'✅' if yara_ok else '❌'}")
    print(f"Teste simples: {'✅' if test_ok else '❌'}")
    
    if yara_ok and test_ok:
        print("🎉 YARA está funcionando corretamente!")
    else:
        print("⚠️ Há problemas com a configuração YARA")