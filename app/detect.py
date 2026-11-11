"""Détection d'attaques : applique les règles R1 à R5 sur staging.access_log
et enregistre les alertes dans dw.alerte.

Chaque règle est une fonction qui reçoit un DataFrame (une ligne = une requête)
et renvoie une liste d'alertes. Elles ne touchent pas à la base : on peut donc
les tester avec pytest sur quelques lignes d'exemple (tests/test_rules.py).

Utilisation (après etl.py) :
    python app/detect.py
"""
import re
from urllib.parse import unquote

import pandas as pd
from sqlalchemy import text

# Seuils (valeurs de départ du cahier des charges, à ajuster si trop de fausses alertes)
SEUIL_BRUTE_FORCE = 10   # R1 : plus de 10 réponses 401 sur le login, même IP, même minute
SEUIL_SCAN = 30          # R4 : plus de 30 réponses 404, même IP, même minute
ROUTE_LOGIN = "/rest/user/login"

# Motifs recherchés dans l'URL (re.IGNORECASE : UNION = union = UnIoN)
MOTIFS_SQLI_FORTS = re.compile(
    r"\bunion\b.*\bselect\b"          # UNION SELECT : lire une autre table
    r"|\bor\b\s+'?\d+'?\s*=\s*'?\d+"  # OR 1=1, OR '1'='1 : condition toujours vraie
    r"|'\s*or\s*'"                    # ' OR '
    r"|--"                            # commentaire SQL : ignore la fin de la requête
    r"|;\s*(drop|delete|insert|update)\b"
    r"|\bsleep\s*\(",
    re.IGNORECASE,
)
MOTIFS_XSS = re.compile(
    r"<\s*script|<\s*iframe|javascript\s*:|\bon[a-z]+\s*=",  # onerror=, onload=...
    re.IGNORECASE,
)
MOTIF_TRAVERSAL = re.compile(r"\.\./|\.\.\\")   # ../ ou ..\


def url_complete(ligne):
    """Chemin + paramètres, décodés une 2e fois pour attraper le double encodage.

    L'ETL a déjà décodé une fois (%27 -> '). Un attaquant peut encoder deux fois
    (%2527 -> %27 -> ') pour tromper un filtre : on décode donc encore une fois.
    """
    texte = ligne["chemin"]
    # pd.notna : une case vide vaut None OU NaN selon pandas, et "if NaN" est vrai !
    if pd.notna(ligne["parametres"]):
        texte += "?" + ligne["parametres"]
    return unquote(texte)


def creer_alerte(regle, categorie, ip, horodatage, gravite, preuve):
    return {"regle": regle, "categorie_owasp": categorie, "ip": ip,
            "horodatage": horodatage, "gravite": gravite, "preuve": preuve[:500]}


def compter_par_ip_et_minute(df):
    """Nombre de lignes par (IP, minute), avec la première et la dernière heure."""
    df = df.assign(minute=df["horodatage"].dt.floor("min"))  # 16:49:37 -> 16:49:00
    return (df.groupby(["ip", "minute"])["horodatage"]
              .agg(nb="count", debut="min", fin="max")
              .reset_index())


# ---------------------------------------------------------------------------
#  Règles « par comptage » : beaucoup d'erreurs pour une même IP en 1 minute
# ---------------------------------------------------------------------------
def regle_r1_brute_force(df):
    echecs = df[(df["chemin"] == ROUTE_LOGIN) & (df["statut"] == 401)]
    alertes = []
    for _, groupe in compter_par_ip_et_minute(echecs).iterrows():
        if groupe["nb"] > SEUIL_BRUTE_FORCE:
            preuve = (f"{groupe['nb']} connexions échouées (401) sur {ROUTE_LOGIN} "
                      f"entre {groupe['debut']:%H:%M:%S} et {groupe['fin']:%H:%M:%S}")
            alertes.append(creer_alerte("R1_brute_force", "A07 Authentification",
                                        groupe["ip"], groupe["debut"], "haute", preuve))
    return alertes


def regle_r4_scan(df):
    pages_absentes = df[df["statut"] == 404]
    alertes = []
    for _, groupe in compter_par_ip_et_minute(pages_absentes).iterrows():
        if groupe["nb"] > SEUIL_SCAN:
            preuve = (f"{groupe['nb']} pages inexistantes (404) "
                      f"entre {groupe['debut']:%H:%M:%S} et {groupe['fin']:%H:%M:%S}")
            alertes.append(creer_alerte("R4_scan", "Reconnaissance",
                                        groupe["ip"], groupe["debut"], "moyenne", preuve))
    return alertes


# ---------------------------------------------------------------------------
#  Règles « par motif » : une requête suspecte = une alerte
# ---------------------------------------------------------------------------
def regle_r2_injection_sql(df):
    alertes = []
    for _, ligne in df.iterrows():
        url = url_complete(ligne)
        if MOTIFS_SQLI_FORTS.search(url):
            gravite = "haute"
        elif "'" in url:
            # Une apostrophe seule est suspecte, mais un humain peut chercher
            # « l'orange » : gravité faible (faux positif probable).
            gravite = "faible"
        else:
            continue
        alertes.append(creer_alerte("R2_injection_sql", "A03 Injection",
                                    ligne["ip"], ligne["horodatage"], gravite, url))
    return alertes


def regle_r3_xss(df):
    alertes = []
    for _, ligne in df.iterrows():
        url = url_complete(ligne)
        if MOTIFS_XSS.search(url):
            alertes.append(creer_alerte("R3_xss", "A03 Injection",
                                        ligne["ip"], ligne["horodatage"], "moyenne", url))
    return alertes


def regle_r5_traversal(df):
    alertes = []
    for _, ligne in df.iterrows():
        url = url_complete(ligne)
        if MOTIF_TRAVERSAL.search(url):
            alertes.append(creer_alerte("R5_traversal", "A01 Contrôle d'accès",
                                        ligne["ip"], ligne["horodatage"], "haute", url))
    return alertes


REGLES = [regle_r1_brute_force, regle_r2_injection_sql, regle_r3_xss,
          regle_r4_scan, regle_r5_traversal]


def appliquer_regles(df):
    alertes = []
    for regle in REGLES:
        trouvees = regle(df)
        print(f"  {regle.__name__:<24} {len(trouvees)} alerte(s)")
        alertes += trouvees
    return alertes


# ---------------------------------------------------------------------------
#  Lecture / écriture en base
# ---------------------------------------------------------------------------
def enregistrer_alertes(alertes, moteur):
    """Remplace toutes les alertes (comme l'ETL : relancer = même résultat)."""
    with moteur.begin() as conn:
        conn.execute(text("TRUNCATE dw.alerte RESTART IDENTITY"))
        if alertes:
            # On retrouve id_ip à partir de l'adresse IP (clé naturelle)
            conn.execute(text(
                "INSERT INTO dw.alerte (regle, categorie_owasp, id_ip, horodatage, gravite, preuve) "
                "SELECT :regle, :categorie_owasp, id_ip, :horodatage, :gravite, :preuve "
                "FROM dw.dim_ip WHERE adresse_ip = :ip"
            ), alertes)


def main():
    from etl import creer_moteur   # même connexion que l'ETL

    moteur = creer_moteur()
    df = pd.read_sql("SELECT ip, horodatage, methode, chemin, parametres, statut "
                     "FROM staging.access_log", moteur)
    print(f"{len(df)} requêtes analysées")
    alertes = appliquer_regles(df)
    enregistrer_alertes(alertes, moteur)
    print(f"{len(alertes)} alertes enregistrées dans dw.alerte")


if __name__ == "__main__":
    main()
