# Mini-SIEM

Un petit SIEM fait maison pour détecter des attaques web simples dans les logs d'un serveur nginx.

Je voulais relier deux choses qui m'intéressent : les bases de données (ETL, entrepôt en étoile)
et la cybersécurité. L'idée : envoyer du trafic normal et des attaques contre une application
volontairement vulnérable, récupérer les logs nginx, les charger dans PostgreSQL, puis voir ce
qu'on arrive à détecter avec quelques règles simples.

> Projet éducatif : tout tourne en local (`127.0.0.1`), contre OWASP Juice Shop.
> Le script d'attaque refuse toute autre cible.

![Dashboard](docs/captures/1_dashboard_vue_ensemble.png)

## Comment ça marche

```
attack_sim.py -> nginx (devant Juice Shop) -> logs/access.log
              -> etl.py -> PostgreSQL (staging, puis schéma en étoile)
              -> detect.py -> table des alertes
              -> API FastAPI -> dashboard Streamlit
```

- `app/attack_sim.py` envoie du trafic normal et 5 types d'attaques. Il vérifie d'abord que la cible est bien localhost.
- `app/etl.py` lit `access.log` avec une regex, décode les URL (`%27` devient `'`) et charge
  `staging.access_log`, puis le schéma en étoile : une table de faits `fait_requete`
  (une ligne = une requête) et quatre dimensions (temps, IP, URL, statut).
- `app/detect.py` applique les règles et remplit `dw.alerte`.
- `app/api.py` expose `/alertes` et `/stats` ; `dashboard/dashboard.py` les affiche.

Quelques requêtes d'analyse sont dans [`sql/requetes_analyse.sql`](sql/requetes_analyse.sql)
(404 par IP et par minute, top 10 des IP, alertes par règle et par heure).

## Lancer le projet

Il faut Docker Desktop, Python 3.12 et Git.

```bash
git clone https://github.com/AYOUBSK7/mini-siem.git
cd mini-siem
copy .env.example .env
```

Dans `.env`, remplacer `changez_moi` par un mot de passe (sous Linux / macOS : `cp` au lieu de `copy`).

```bash
docker compose up -d --build          # labo + API + dashboard (le premier lancement est long)

python -m venv .venv
.venv\Scripts\activate                # Linux / macOS : source .venv/bin/activate
pip install -r requirements.txt

python app/attack_sim.py              # génère le trafic
docker compose run --rm pipeline      # ETL + détection
python -m pytest                      # les tests
```

Ensuite :

- dashboard : http://127.0.0.1:8501
- API : http://127.0.0.1:8000/docs
- Juice Shop (via nginx) : http://127.0.0.1:8080

Les ports ne sont ouverts que sur `127.0.0.1`. Pour tout arrêter : `docker compose down`.

![Documentation de l'API](docs/captures/3_api_swagger.png)

## Les règles

- **R1 brute force** : plus de 10 réponses 401 sur `/rest/user/login` pour la même IP en une minute.
- **R2 injection SQL** : motifs comme `' OR 1=1`, `UNION SELECT` ou `--` dans l'URL décodée.
  Une apostrophe seule donne une alerte de gravité faible.
- **R3 XSS** : `<script`, `javascript:`, `onerror=`…
- **R4 scan** : plus de 30 réponses 404 pour la même IP en une minute.
- **R5 remontée de dossiers** : `../` dans l'URL, même encodé deux fois (`%252e%252e%252f`).

Chaque règle a ses tests dans `tests/test_rules.py` : au moins une ligne de log qui doit
déclencher l'alerte et une ligne normale qui ne doit pas. L'API a aussi ses tests
(`tests/test_api.py`), dont un qui vérifie qu'on ne peut pas faire d'injection SQL via ses filtres.

![Tests](docs/captures/4_tests_pytest.png)

## Résultats

Sur mon dernier jeu de test (882 requêtes, dont 575 de visiteurs normaux), il y a 83 alertes.
Chaque IP attaquante est trouvée par la bonne règle, et aucune alerte de gravité haute ne
tombe sur un visiteur normal.

Par contre, les 36 recherches « l'orange » déclenchent R2 en gravité faible à cause de
l'apostrophe. J'ai préféré les garder en alerte faible plutôt que d'ignorer les apostrophes,
sinon des injections simples passeraient. Le détail est dans le [rapport](docs/rapport.pdf).

![Alertes](docs/captures/2_dashboard_ip_et_alertes.png)

## Limites

- nginx n'écrit pas le corps des requêtes POST : une injection envoyée dans un formulaire ne se voit pas.
- Les IP sont simulées avec l'en-tête `X-Forwarded-For`, que nginx accepte de n'importe qui.
  C'est pratique en labo, mais à ne pas faire en production.
- Quand un chemin sort de la racine du site (`/../../etc/passwd`), nginx répond 400 avant de lire
  les en-têtes : la ligne de log a alors l'IP de Docker, pas celle de l'attaquant.
- R1 et R4 comptent par minute fixe (pas de fenêtre glissante) : 8 échecs à 16:49:55 puis 8 à
  16:50:05 ne déclenchent rien.
- Juice Shop répond 200 pour une page inconnue comme `/admin.php`, donc R4 ne voit qu'une
  partie d'un scan.
- Tout est en traitement par lots, pas en temps réel.

Pistes pour la suite : une fenêtre glissante de 60 s, compter aussi les 403, journaliser le
corps des POST de connexion, comparer avec un scan OWASP ZAP.

## Structure

```
mini-siem/
├── docker-compose.yml
├── Dockerfile
├── .env.example
├── nginx/nginx.conf
├── app/            attack_sim.py, etl.py, detect.py, api.py
├── dashboard/      dashboard.py
├── sql/            schema.sql, staging_vers_dw.sql, requetes_analyse.sql
├── tests/          test_rules.py, test_api.py
└── docs/           rapport.pdf, captures/
```

---

Ayoub BOUSSOUKAYA, projet personnel, 2026
