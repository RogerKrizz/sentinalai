# SentinelAI
Autonomous Cyber Incident Response Agent for Banking.
Fully local, offline AI pipeline — zero cloud dependencies.

## Stack
Python 3.11 | Elasticsearch | PyOD | River | LangGraph | Ollama | Mistral 7B

## Layers
- Layer 1: Log Ingestion + Normalization (Elasticsearch)
- Layer 2: Anomaly Detection (PyOD + River)
- Layer 3: Alert Correlation (LangGraph)
- Layer 4: Classification (CyberSecBERT)
- Layer 5: LLM Agent (Ollama + Mistral 7B)
- Layer 6: Playbook Generation

## Datasets (download separately — not included in repo)
- CICIDS2017 → data/raw/cicids2017/
- RBA Dataset → data/raw/rba_dataset/
- Loghub SSH → data/raw/loghub_ssh/
- PaySim → data/raw/paysim/
