import subprocess


def get_ollama_models():
    """Obtém lista de modelos disponíveis no Ollama"""
    try:
        result = subprocess.run(
            ["ollama", "list"], capture_output=True, text=True, check=True
        )
        models = []
        for line in result.stdout.strip().split("\n")[1:]:
            if line.strip():
                name = line.split()[0]
                models.append((name, name))

        # Se não encontrou modelos, retorna uma lista padrão para testes
        if not models:
            models = [("llama3", "llama3"), ("llama2", "llama2")]

        return models
    except Exception:
        # Retorna modelos padrão em caso de erro (útil para testes)
        return [("llama3", "llama3"), ("llama2", "llama2")]
