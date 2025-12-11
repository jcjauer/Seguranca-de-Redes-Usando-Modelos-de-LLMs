from analyzer.models import PCAPAnalysis

# Verificar últimas análises
analyses = PCAPAnalysis.objects.all().order_by('-id')[:5]

print("\n=== ÚLTIMAS 5 ANÁLISES ===\n")
for a in analyses:
    print(f"ID: {a.id}")
    print(f"  Status: {a.status}")
    print(f"  Arquivo: {a.original_filename}")
    print(f"  Modo: {a.analysis_mode}")
    print(f"  Modelo: {a.llm_model}")
    print(f"  Criado: {a.created_at}")
    if a.error_message:
        print(f"  ERRO: {a.error_message[:200]}")
    print()

# Resetar análises presas
stuck = PCAPAnalysis.objects.filter(status__in=['pending', 'processing'])
if stuck.exists():
    print(f"\n⚠️ Encontradas {stuck.count()} análises presas:")
    for s in stuck:
        print(f"  - ID {s.id}: {s.original_filename} ({s.status})")
    
    reset = input("\nResetar para 'error'? (s/n): ")
    if reset.lower() == 's':
        stuck.update(status='error', error_message='Análise interrompida - resetada manualmente')
        print("✅ Análises resetadas")
