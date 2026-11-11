"""ETL du Mini-SIEM : access.log (nginx) -> PostgreSQL.

    E - EXTRACT   : lire access.log ligne par ligne
    T - TRANSFORM : découper chaque ligne (expression régulière), décoder l'URL,
                    convertir la date, écarter les lignes illisibles (pandas)
    L - LOAD      : déposer dans staging.access_log, puis remplir l'étoile dw
                    avec sql/staging_vers_dw.sql (le tout dans UNE transaction)

Traitement par lots : à chaque exécution on relit tout le fichier et on
reconstruit les faits. Relancer l'ETL donne donc toujours le même résultat.

Utilisation :
    python app/etl.py
    python app/etl.py --fichier un_autre_access.log
"""
import argparse
import os
import re
from pathlib import Path
from urllib.parse import unquote, unquote_plus

import pandas as pd
from dotenv import load_dotenv
from sqlalchemy import create_engine, text

RACINE = Path(__file__).resolve().parent.parent
DOSSIER_SQL = RACINE / "sql"
JOURNAL_PAR_DEFAUT = RACINE / "logs" / "access.log"

# Le mot de passe est lu dans .env (jamais écrit dans le code)
load_dotenv(RACINE / ".env")


def creer_moteur():
    """Connexion à PostgreSQL (réutilisée par detect.py et api.py)."""
    url = (
        f"postgresql+psycopg2://{os.getenv('PG_USER')}:{os.getenv('PG_PASSWORD')}"
        f"@{os.getenv('PG_HOST', '127.0.0.1')}:{os.getenv('PG_PORT', '5433')}/{os.getenv('PG_DB')}"
    )
    return create_engine(url)


# ---------------------------------------------------------------------------
#  E - EXTRACT
# ---------------------------------------------------------------------------
def lire_journal(chemin_fichier):
    """Renvoie la liste des lignes du fichier (sans les lignes vides)."""
    with open(chemin_fichier, encoding="utf-8", errors="replace") as fichier:
        return [ligne.rstrip("\n") for ligne in fichier if ligne.strip()]


# ---------------------------------------------------------------------------
#  T - TRANSFORM
# ---------------------------------------------------------------------------
# Format "combined" de nginx :
# IP - utilisateur [date] "METHODE /chemin?params HTTP/1.1" statut taille "referer" "agent"
MOTIF_LIGNE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<date>[^\]]+)\] '
    r'"(?P<requete>[^"]*)" '
    r'(?P<statut>\d{3}) (?P<taille>\d+|-) '
    r'"[^"]*" "(?P<agent>[^"]*)"$'
)


def parser_ligne(ligne):
    """Découpe une ligne du journal en dictionnaire, ou renvoie None si illisible."""
    resultat = MOTIF_LIGNE.match(ligne)
    if resultat is None:
        return None

    # "GET /rest/products/search?q=apple HTTP/1.1" -> 3 morceaux
    morceaux = resultat["requete"].split(" ")
    if len(morceaux) != 3:
        return None  # requête mal formée (ex : un outil qui envoie n'importe quoi)
    methode, url, _protocole = morceaux

    chemin, _, parametres = url.partition("?")
    return {
        "ligne_brute": ligne,
        "ip": resultat["ip"],
        "date_texte": resultat["date"],
        "methode": methode,
        # On DÉCODE l'URL : %27 -> '   %3C -> <   %2F -> /
        # Sinon les règles de détection ne verraient pas les motifs d'attaque.
        "chemin": unquote(chemin),
        "parametres": unquote_plus(parametres) if parametres else None,  # "+" = espace
        "statut": int(resultat["statut"]),
        "taille": 0 if resultat["taille"] == "-" else int(resultat["taille"]),
        "agent_utilisateur": None if resultat["agent"] == "-" else resultat["agent"],
    }


def transformer(lignes):
    """Transforme les lignes brutes en DataFrame propre, prêt pour staging."""
    lisibles = []
    rejetees = []
    for ligne in lignes:
        dico = parser_ligne(ligne)
        if dico is None:
            rejetees.append(ligne)
        else:
            lisibles.append(dico)

    print(f"[T] {len(lignes)} lignes lues, {len(lisibles)} lisibles, {len(rejetees)} rejetées")
    for ligne in rejetees[:3]:
        print(f"    rejetée : {ligne[:100]}")

    df = pd.DataFrame(lisibles)
    if df.empty:
        return df

    # "11/Nov/2026:16:49:07 +0000" -> date Python en UTC, sans fuseau (colonne TIMESTAMP)
    df["horodatage"] = (
        pd.to_datetime(df["date_texte"], format="%d/%b/%Y:%H:%M:%S %z", utc=True)
        .dt.tz_localize(None)
    )
    df = df.drop(columns=["date_texte"])
    return df


# ---------------------------------------------------------------------------
#  L - LOAD
# ---------------------------------------------------------------------------
def executer_script(conn, nom_fichier):
    """Exécute un fichier .sql du dossier sql/ (plusieurs requêtes d'un coup)."""
    sql = (DOSSIER_SQL / nom_fichier).read_text(encoding="utf-8")
    with conn.connection.cursor() as curseur:
        curseur.execute(sql)


def charger(df, moteur):
    # moteur.begin() = UNE transaction : si une étape plante, rien n'est écrit
    with moteur.begin() as conn:
        executer_script(conn, "schema.sql")              # crée les tables si besoin
        conn.execute(text("TRUNCATE staging.access_log RESTART IDENTITY"))
        df.to_sql("access_log", conn, schema="staging", if_exists="append", index=False)
        executer_script(conn, "staging_vers_dw.sql")     # remplit l'étoile

        for table in ["staging.access_log", "dw.dim_temps", "dw.dim_ip",
                      "dw.dim_url", "dw.dim_statut", "dw.fait_requete"]:
            nb = conn.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar()
            print(f"[L] {table:<20} {nb} lignes")


def main():
    parser = argparse.ArgumentParser(description="ETL access.log -> PostgreSQL")
    parser.add_argument("--fichier", default=JOURNAL_PAR_DEFAUT)
    args = parser.parse_args()

    lignes = lire_journal(args.fichier)
    print(f"[E] {len(lignes)} lignes dans {args.fichier}")
    df = transformer(lignes)
    if df.empty:
        print("Aucune ligne lisible : rien à charger.")
        return
    charger(df, creer_moteur())
    print("ETL terminé.")


if __name__ == "__main__":
    main()
