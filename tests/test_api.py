"""Tests de l'API FastAPI.

Ces tests interrogent la vraie base : il faut que le labo tourne
(docker compose up -d) et que etl.py + detect.py aient été lancés.
Si la base n'est pas joignable, les tests sont ignorés (skipped) au lieu d'échouer.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from api import app, moteur

try:
    with moteur.connect():
        pass
except OperationalError:
    pytest.skip("PostgreSQL non joignable : lancer le labo d'abord", allow_module_level=True)

client = TestClient(app)   # simule un navigateur, sans lancer de serveur


def test_accueil():
    reponse = client.get("/")
    assert reponse.status_code == 200
    assert "/alertes" in reponse.json()["routes"]


def test_alertes_renvoie_une_liste_au_bon_format():
    reponse = client.get("/alertes?limite=5")
    assert reponse.status_code == 200
    alertes = reponse.json()
    assert isinstance(alertes, list)
    assert len(alertes) <= 5
    for alerte in alertes:
        assert {"regle", "ip", "horodatage", "gravite", "preuve"} <= alerte.keys()


def test_filtre_gravite():
    alertes = client.get("/alertes?gravite=haute").json()
    assert all(alerte["gravite"] == "haute" for alerte in alertes)


def test_gravite_inconnue_refusee():
    assert client.get("/alertes?gravite=critique").status_code == 422


def test_limite_trop_grande_refusee():
    assert client.get("/alertes?limite=100000").status_code == 422


def test_injection_sql_dans_le_filtre_ip_ne_marche_pas():
    # Si la requête SQL était construite en collant le texte, "' OR 1=1--"
    # renverrait TOUTES les alertes. Avec les paramètres : aucune IP ne s'appelle ainsi.
    reponse = client.get("/alertes", params={"ip": "' OR 1=1--"})
    assert reponse.status_code == 200
    assert reponse.json() == []


def test_stats_coherentes():
    stats = client.get("/stats").json()
    # Le total doit être égal à la somme par règle et à la somme par gravité
    assert stats["nb_alertes"] == sum(r["nb"] for r in stats["alertes_par_regle"])
    assert stats["nb_alertes"] == sum(g["nb"] for g in stats["alertes_par_gravite"])
    assert len(stats["top_ip"]) <= 10
