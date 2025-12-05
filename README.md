# RiskMapper (Flet) — CVSS v3.1 + Attack Surface Mapping

## Features
- CVSS v3.1 Base Score calculator (manual metric selection)
- Severity classification (None/Low/Medium/High/Critical)
- Import findings from CSV/JSON: asset,title,AV,AC,PR,UI,S,C,I,A
- Attack surface inventory (assets with tags + services)
- Risk view per asset (max/avg + counts by severity)

## Run
```bash
cd riskmapper_flet
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -r requirements.txt
python main.py
