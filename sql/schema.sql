-- =====================================================================
--  Mini-SIEM : création des tables
--  Idempotent (IF NOT EXISTS) : on peut l'exécuter plusieurs fois sans erreur.
-- =====================================================================
--
--  staging : zone de transit. Une ligne de access.log = une ligne ici,
--            découpée en colonnes mais sans autre transformation.
--  dw      : l'entrepôt en schéma en étoile (dimensions + table de faits)
--            et la table des alertes produites par les règles de détection.

CREATE SCHEMA IF NOT EXISTS staging;
CREATE SCHEMA IF NOT EXISTS dw;

-- ---------------------------------------------------------------------
--  STAGING
-- ---------------------------------------------------------------------
-- On garde la ligne brute : c'est la preuve d'origine (utile pour une alerte).
CREATE TABLE IF NOT EXISTS staging.access_log (
    id                SERIAL PRIMARY KEY,
    ligne_brute       TEXT        NOT NULL,
    ip                VARCHAR(45) NOT NULL,     -- 45 caractères : assez pour une IPv6
    horodatage        TIMESTAMP   NOT NULL,     -- heure UTC (nginx écrit +0000)
    methode           VARCHAR(10) NOT NULL,     -- GET, POST...
    chemin            TEXT        NOT NULL,     -- ex : /rest/products/search
    parametres        TEXT,                     -- ex : q=apple (NULL si aucun)
    statut            SMALLINT    NOT NULL,     -- code HTTP : 200, 401, 404...
    taille            INTEGER     NOT NULL,     -- octets renvoyés
    agent_utilisateur TEXT,                     -- navigateur / outil
    charge_le         TIMESTAMP   NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------
--  DIMENSIONS : le contexte d'une requête (quand ? qui ? quoi ? résultat ?)
--  id_xxx = clé de substitution (technique, générée par PostgreSQL)
--  UNIQUE sur la clé naturelle (la valeur métier) pour éviter les doublons
-- ---------------------------------------------------------------------

-- Quand ? Une ligne par minute (le grain le plus fin dont on a besoin).
CREATE TABLE IF NOT EXISTS dw.dim_temps (
    id_temps      SERIAL PRIMARY KEY,
    date          DATE        NOT NULL,
    heure         SMALLINT    NOT NULL CHECK (heure BETWEEN 0 AND 23),
    minute        SMALLINT    NOT NULL CHECK (minute BETWEEN 0 AND 59),
    jour_semaine  VARCHAR(10) NOT NULL,          -- lundi, mardi...
    UNIQUE (date, heure, minute)
);

-- Qui ? Une ligne par adresse IP.
CREATE TABLE IF NOT EXISTS dw.dim_ip (
    id_ip         SERIAL PRIMARY KEY,
    adresse_ip    VARCHAR(45) NOT NULL UNIQUE,
    nb_requetes   INTEGER                        -- calculé après le chargement des faits
);

-- Quoi ? Une ligne par chemin demandé (sans les paramètres).
CREATE TABLE IF NOT EXISTS dw.dim_url (
    id_url        SERIAL PRIMARY KEY,
    chemin        TEXT        NOT NULL UNIQUE,
    famille       VARCHAR(10) NOT NULL
                  CHECK (famille IN ('api', 'static', 'ftp', 'autre'))
);

-- Résultat ? Une ligne par code HTTP.
CREATE TABLE IF NOT EXISTS dw.dim_statut (
    id_statut     SERIAL PRIMARY KEY,
    code          SMALLINT   NOT NULL UNIQUE,
    categorie     VARCHAR(3) NOT NULL            -- 2xx, 3xx, 4xx, 5xx
);

-- ---------------------------------------------------------------------
--  TABLE DE FAITS
--  Grain : 1 ligne = 1 requête HTTP reçue par nginx.
--  methode et taille sont stockées directement dans le fait :
--    - taille  = la mesure (on peut la sommer : volume envoyé par IP, par heure...)
--    - methode = « dimension dégénérée » (trop petite pour mériter sa propre table)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dw.fait_requete (
    id_fait       BIGSERIAL PRIMARY KEY,
    id_temps      INTEGER     NOT NULL REFERENCES dw.dim_temps(id_temps),
    id_ip         INTEGER     NOT NULL REFERENCES dw.dim_ip(id_ip),
    id_url        INTEGER     NOT NULL REFERENCES dw.dim_url(id_url),
    id_statut     INTEGER     NOT NULL REFERENCES dw.dim_statut(id_statut),
    methode       VARCHAR(10) NOT NULL,
    taille        INTEGER     NOT NULL
);

-- Index sur les clés étrangères les plus utilisées dans les analyses
-- (ex : « nombre de 404 par IP et par minute »).
CREATE INDEX IF NOT EXISTS idx_fait_ip    ON dw.fait_requete (id_ip);
CREATE INDEX IF NOT EXISTS idx_fait_temps ON dw.fait_requete (id_temps);

-- ---------------------------------------------------------------------
--  ALERTES : écrites par detect.py (une ligne = une attaque détectée)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dw.alerte (
    id_alerte        SERIAL PRIMARY KEY,
    regle            VARCHAR(30) NOT NULL,       -- ex : R1_brute_force
    categorie_owasp  VARCHAR(40) NOT NULL,       -- ex : A07 Authentification
    id_ip            INTEGER     NOT NULL REFERENCES dw.dim_ip(id_ip),
    horodatage       TIMESTAMP   NOT NULL,       -- moment de l'attaque (UTC)
    gravite          VARCHAR(10) NOT NULL
                     CHECK (gravite IN ('faible', 'moyenne', 'haute')),
    preuve           TEXT        NOT NULL        -- ce qui a déclenché l'alerte
);
