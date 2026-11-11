"""Tests des règles de détection R1 à R5.

Principe : pour chaque règle, au moins une ligne qui DOIT déclencher l'alerte
et une ligne normale qui ne doit PAS. Les lignes sont de vraies lignes au
format nginx, passées dans l'ETL (parser + transformer) comme en vrai.

Lancer : python -m pytest
"""
from etl import transformer
from detect import (regle_r1_brute_force, regle_r2_injection_sql, regle_r3_xss,
                    regle_r4_scan, regle_r5_traversal)


def ligne_nginx(ip, url, statut=200, methode="GET", heure="16:49:07"):
    """Fabrique une ligne de journal au format combined de nginx."""
    return (f'{ip} - - [11/Nov/2026:{heure} +0000] "{methode} {url} HTTP/1.1" '
            f'{statut} 100 "-" "Mozilla/5.0"')


def preparer(lignes):
    """Passe les lignes dans l'ETL pour obtenir le même DataFrame que staging."""
    return transformer(lignes)


# ---------------------------------------------------------------- R1 brute force
def test_r1_detecte_11_echecs_en_une_minute():
    lignes = [ligne_nginx("203.0.113.66", "/rest/user/login", 401, "POST", f"16:49:{s:02d}")
              for s in range(11)]
    alertes = regle_r1_brute_force(preparer(lignes))
    assert len(alertes) == 1
    assert alertes[0]["ip"] == "203.0.113.66"
    assert alertes[0]["gravite"] == "haute"


def test_r1_ignore_10_echecs_seuil_non_depasse():
    lignes = [ligne_nginx("203.0.113.66", "/rest/user/login", 401, "POST", f"16:49:{s:02d}")
              for s in range(10)]
    assert regle_r1_brute_force(preparer(lignes)) == []


def test_r1_ignore_echecs_de_plusieurs_ip():
    # 15 utilisateurs différents qui se trompent chacun une fois : pas une attaque
    lignes = [ligne_nginx(f"192.0.2.{n}", "/rest/user/login", 401, "POST") for n in range(15)]
    assert regle_r1_brute_force(preparer(lignes)) == []


def test_r1_ignore_401_sur_une_autre_route():
    lignes = [ligne_nginx("203.0.113.66", "/rest/basket/1", 401) for _ in range(20)]
    assert regle_r1_brute_force(preparer(lignes)) == []


def test_r1_ignore_connexions_reussies():
    lignes = [ligne_nginx("192.0.2.10", "/rest/user/login", 200, "POST") for _ in range(20)]
    assert regle_r1_brute_force(preparer(lignes)) == []


# ---------------------------------------------------------------- R2 injection SQL
def test_r2_detecte_or_1_egal_1():
    lignes = [ligne_nginx("203.0.113.77", "/rest/products/search?q=%27+OR+1%3D1--", 500)]
    alertes = regle_r2_injection_sql(preparer(lignes))
    assert len(alertes) == 1
    assert alertes[0]["gravite"] == "haute"
    assert "' OR 1=1--" in alertes[0]["preuve"]


def test_r2_detecte_union_select():
    url = "/rest/products/search?q=%27%29%29+UNION+SELECT+id%2C+email+FROM+Users--"
    alertes = regle_r2_injection_sql(preparer([ligne_nginx("203.0.113.77", url)]))
    assert len(alertes) == 1
    assert alertes[0]["gravite"] == "haute"


def test_r2_ignore_recherche_normale():
    lignes = [ligne_nginx("192.0.2.10", "/rest/products/search?q=apple")]
    assert regle_r2_injection_sql(preparer(lignes)) == []


def test_r2_melange_lignes_avec_et_sans_parametres():
    # Bug trouvé sur les vraies données : sans paramètres, pandas met NaN (pas None),
    # et "if NaN" est vrai en Python -> le code plantait.
    lignes = [ligne_nginx("192.0.2.10", "/"),
              ligne_nginx("203.0.113.77", "/rest/products/search?q=%27+OR+1%3D1--")]
    assert len(regle_r2_injection_sql(preparer(lignes))) == 1


def test_r2_apostrophe_seule_donne_alerte_faible():
    # Faux positif connu : un visiteur cherche « l'orange »
    lignes = [ligne_nginx("192.0.2.10", "/rest/products/search?q=l%27orange")]
    alertes = regle_r2_injection_sql(preparer(lignes))
    assert len(alertes) == 1
    assert alertes[0]["gravite"] == "faible"


# ---------------------------------------------------------------- R3 XSS
def test_r3_detecte_balise_script():
    url = "/rest/products/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
    alertes = regle_r3_xss(preparer([ligne_nginx("203.0.113.88", url)]))
    assert len(alertes) == 1
    assert "<script>" in alertes[0]["preuve"]


def test_r3_detecte_iframe_javascript():
    url = "/rest/products/search?q=%3Ciframe+src%3D%22javascript%3Aalert%281%29%22%3E"
    assert len(regle_r3_xss(preparer([ligne_nginx("203.0.113.88", url)]))) == 1


def test_r3_detecte_double_encodage():
    # %253C -> %3C -> <   (encodé deux fois pour tromper un filtre)
    url = "/rest/products/search?q=%253Cscript%253Ealert(1)"
    assert len(regle_r3_xss(preparer([ligne_nginx("203.0.113.88", url)]))) == 1


def test_r3_ignore_recherche_normale():
    lignes = [ligne_nginx("192.0.2.10", "/rest/products/search?q=lemon"),
              ligne_nginx("192.0.2.10", "/rest/products/search?q=monkey%3Dbanana")]  # "on...=" piège
    assert regle_r3_xss(preparer(lignes)) == []


# ---------------------------------------------------------------- R4 scan
def test_r4_detecte_31_pages_absentes():
    lignes = [ligne_nginx("198.51.100.99", f"/ftp/fichier{n}.md", 404) for n in range(31)]
    alertes = regle_r4_scan(preparer(lignes))
    assert len(alertes) == 1
    assert alertes[0]["ip"] == "198.51.100.99"


def test_r4_ignore_30_pages_absentes_seuil_non_depasse():
    lignes = [ligne_nginx("198.51.100.99", f"/ftp/fichier{n}.md", 404) for n in range(30)]
    assert regle_r4_scan(preparer(lignes)) == []


def test_r4_ignore_navigation_normale():
    lignes = [ligne_nginx("192.0.2.10", f"/api/Products/{n}", 200) for n in range(50)]
    assert regle_r4_scan(preparer(lignes)) == []


def test_r4_ignore_404_etales_sur_plusieurs_minutes():
    # 40 erreurs 404, mais 10 par minute : en dessous du seuil chaque minute
    lignes = [ligne_nginx("198.51.100.99", f"/ftp/f{n}.md", 404, heure=f"16:{40 + n // 10}:{n % 10:02d}")
              for n in range(40)]
    assert regle_r4_scan(preparer(lignes)) == []


# ---------------------------------------------------------------- R5 traversal
def test_r5_detecte_slash_encode():
    lignes = [ligne_nginx("198.51.100.111", "/ftp/..%2F..%2Fetc%2Fpasswd", 400)]
    assert len(regle_r5_traversal(preparer(lignes))) == 1


def test_r5_detecte_double_encodage():
    lignes = [ligne_nginx("198.51.100.111", "/ftp/%252e%252e%252fpackage.json", 403)]
    assert len(regle_r5_traversal(preparer(lignes))) == 1


def test_r5_detecte_variante_quatre_points():
    lignes = [ligne_nginx("198.51.100.111", "/ftp/....//....//etc/passwd", 403)]
    assert len(regle_r5_traversal(preparer(lignes))) == 1


def test_r5_ignore_chemins_normaux():
    lignes = [ligne_nginx("192.0.2.10", "/ftp/legal.md"),
              ligne_nginx("192.0.2.10", "/assets/public/images/fichier..png")]  # ".." sans "/"
    assert regle_r5_traversal(preparer(lignes)) == []
