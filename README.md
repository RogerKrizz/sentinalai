# SentinelAI
Autonomous Cyber Incident Response Agent for Banking.
Fully local, offline AI pipeline — no cloud dependencies.

## Stack
Python 3.11 | Elasticsearch | PyOD | River | LangGraph | Ollama | Mistral 7B

## Layers
- Layer 1: Log Ingestion + Normalization
- Layer 2: Anomaly Detection (PyOD + River)
- Layer 3: Alert Correlation (LangGraph)
- Layer 4: Classification (CyberSecBERT)
- Layer 5: LLM Agent (Ollama + Mistral 7B)
- Layer 6: Playbook Generation
