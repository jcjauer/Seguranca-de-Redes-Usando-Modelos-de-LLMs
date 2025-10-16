graph TD
    subgraph 1. Entrada de Dados
        A[PCAP File]
    end

    subgraph 2. Fase I: Análise Heurística e Feature Engineering
        direction LR
        A --> B{Processamento de Pacotes (Scapy)}
        B --> C[Análise Estatística: Entropia de Shannon]
        B --> D[Análise de Padrões: Port Scan, Flooding, DNS]
        E[Módulo de Assinaturas YARA]

        C --> F(Agregação de Evidências)
        D --> F
        E --> F
        F --> G[Score de Risco Ponderado (0-100)]
        G --> H{Resumo Textual Estruturado}
    end

    subgraph 3. Fase II: Raciocínio e Correlação (LLM)
        H --> I{Prompt Engineering}
        J[Score de Risco + Relatório YARA] --> I
        I --> K((LLM (Ollama/Llama3)))

        K --> L[Correlação de Evidências e Classificação de Ameaças]
    end

    subgraph 4. Saída Forense
        L --> M{Relatório Forense Estruturado}
        M --> N[Ações Imediatas, Hosts Comprometidos]
    end

    % Estilos para distinção visual
    style A fill:#DCEFFC,stroke:#337ab7,stroke-width:2
    style E fill:#FFF2E6,stroke:#FF9933,stroke-width:2
    style G fill:#FFD6D6,stroke:#FF0000,stroke-width:3
    style K fill:#E6CCFF,stroke:#9900CC,stroke-width:3
    style N fill:#CCFFCC,stroke:#009933,stroke-width:2
