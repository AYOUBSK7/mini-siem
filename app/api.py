"""API du Mini-SIEM (FastAPI) : expose les alertes et des statistiques.

Lancer :
    uvicorn api:app --app-dir app --host 127.0.0.1 --port 8000
Puis ouvrir http://127.0.0.1:8000/docs (documentation interactive générée automatiquement).

Sécurité : l'API est en lecture seule et toutes les requêtes SQL utilisent des
PARAMÈTRES (:regle, :ip...) : une valeur envoyée par l'utilisateur n'est jamais
collée dans le texte SQL, donc pas d'injection SQL possible.
"""
from datetime import datetime
from typing import Literal

from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.exc import OperationalError, ProgrammingError

from etl import creer_moteur

app = FastAPI(
    title="Mini-SIEM API",
    description="Alertes de sécurité détectées dans les journaux nginx du laboratoire.",
    version="1.0",
)
moteur = creer_moteur()

# Valeurs autorisées : FastAPI refuse tout le reste (erreur 422)
Regle = Literal["R1_brute_force", "R2_injection_sql", "R3_xss", "R4_scan", "R5_traversal"]
Gravite = Literal["faible", "moyenne", "haute"]


class Alerte(BaseModel):
    """Format d'une alerte renvoyée par l'API (affiché dans /docs)."""
    id_alerte: int
    regle: str
    categorie_owasp: str
    ip: str
    horodatage: datetime
    gravite: str
    preuve: str


def lire(sql, parametres=None):
    """Exécute une requête SELECT et renvoie une liste de dictionnaires."""
    with moteur.connect() as conn:
        resultat = conn.execute(text(sql), parametres or {})
        return [dict(ligne._mapping) for ligne in resultat]


@app.exception_handler(OperationalError)
def base_indisponible(request: Request, erreur: OperationalError):
    """Si PostgreSQL est arrêté : message clair (503) au lieu d'une erreur 500."""
    return JSONResponse(status_code=503,
                        content={"erreur": "Base de données indisponible. Le labo est-il lancé ?"})


@app.exception_handler(ProgrammingError)
def tables_absentes(request: Request, erreur: ProgrammingError):
    """Premier lancement : les tables n'existent pas tant que l'ETL n'a pas tourné."""
    return JSONResponse(status_code=503,
                        content={"erreur": "Tables absentes : lancer le pipeline "
                                           "(docker compose run --rm pipeline)."})


@app.get("/")
def accueil():
    return {"projet": "Mini-SIEM", "routes": ["/alertes", "/stats", "/docs"]}


@app.get("/alertes", response_model=list[Alerte])
def liste_alertes(
    regle: Regle | None = None,
    gravite: Gravite | None = None,
    ip: str | None = None,
    limite: int = Query(50, ge=1, le=500, description="Nombre maximum d'alertes"),
):
    """Dernières alertes, les plus récentes d'abord, avec filtres optionnels."""
    # On construit le WHERE avec des morceaux de SQL FIXES ; les valeurs
    # de l'utilisateur passent uniquement par le dictionnaire `parametres`.
    conditions = []
    parametres = {"limite": limite}
    if regle:
        conditions.append("a.regle = :regle")
        parametres["regle"] = regle
    if gravite:
        conditions.append("a.gravite = :gravite")
        parametres["gravite"] = gravite
    if ip:
        conditions.append("i.adresse_ip = :ip")
        parametres["ip"] = ip
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    return lire(f"""
        SELECT a.id_alerte, a.regle, a.categorie_owasp, i.adresse_ip AS ip,
               a.horodatage, a.gravite, a.preuve
        FROM dw.alerte a
        JOIN dw.dim_ip i ON i.id_ip = a.id_ip
        {where}
        ORDER BY a.horodatage DESC, a.id_alerte DESC
        LIMIT :limite
    """, parametres)


@app.get("/stats")
def statistiques():
    """Chiffres clés pour le dashboard (lit uniquement le schéma dw)."""
    totaux = lire("""
        SELECT (SELECT COUNT(*) FROM dw.fait_requete) AS nb_requetes,
               (SELECT COUNT(*) FROM dw.dim_ip WHERE nb_requetes > 0) AS nb_ip,
               (SELECT COUNT(*) FROM dw.alerte) AS nb_alertes
    """)[0]

    return {
        **totaux,
        "alertes_par_regle": lire("""
            SELECT regle, categorie_owasp, COUNT(*) AS nb
            FROM dw.alerte GROUP BY regle, categorie_owasp ORDER BY regle
        """),
        "alertes_par_gravite": lire("""
            SELECT gravite, COUNT(*) AS nb FROM dw.alerte GROUP BY gravite ORDER BY nb DESC
        """),
        # Par heure ET par règle : le dashboard peut empiler les règles dans chaque barre
        "alertes_par_heure": lire("""
            SELECT DATE_TRUNC('hour', horodatage) AS heure, regle, COUNT(*) AS nb
            FROM dw.alerte GROUP BY 1, 2 ORDER BY 1, 2
        """),
        # Top 10 des IP qui ont déclenché le plus d'alertes
        "top_ip": lire("""
            SELECT i.adresse_ip AS ip, COUNT(*) AS nb_alertes, i.nb_requetes,
                   STRING_AGG(DISTINCT a.regle, ', ') AS regles
            FROM dw.alerte a JOIN dw.dim_ip i ON i.id_ip = a.id_ip
            GROUP BY i.adresse_ip, i.nb_requetes
            ORDER BY nb_alertes DESC
            LIMIT 10
        """),
    }
