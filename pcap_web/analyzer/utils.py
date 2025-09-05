import subprocess

def get_ollama_models():
    """Obtém lista de modelos disponíveis no Ollama"""
    try:
        result = subprocess.run(
            ['ollama', 'list'],
            capture_output=True,
            text=True,
            check=True
        )
        models = []
        for line in result.stdout.strip().split('\n')[1:]:
            if line.strip():
                name = line.split()[0]
                models.append((name, name))
        return models
    except Exception:
        return []
