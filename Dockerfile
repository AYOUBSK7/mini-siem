# Image Python du Mini-SIEM : utilisée par les services api, dashboard et pipeline
# (même code, seule la commande lancée change).
FROM python:3.12-slim

WORKDIR /code

# On installe les dépendances AVANT de copier le code : tant que requirements.txt
# ne change pas, Docker réutilise cette étape (reconstruction beaucoup plus rapide).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/
COPY sql/ sql/
COPY dashboard/ dashboard/
COPY .streamlit/ .streamlit/
COPY tests/ tests/
COPY pytest.ini .
