-- =====================================================================
--  staging.access_log  ->  schéma en étoile dw
--  Exécuté par etl.py, dans la même transaction que le chargement de staging.
-- =====================================================================
--
--  1. DIMENSIONS : on ajoute seulement les valeurs nouvelles
--     (ON CONFLICT DO NOTHING grâce aux contraintes UNIQUE).
--     On ne les vide jamais : dw.alerte pointe vers dim_ip.
--  2. FAITS : on vide et on reconstruit tout à partir de staging
--     (rechargement complet = simple, et relancer donne le même résultat).

-- ---------- 1. Dimensions -------------------------------------------

-- Une ligne par minute où il y a eu au moins une requête
INSERT INTO dw.dim_temps (date, heure, minute, jour_semaine)
SELECT DISTINCT
    horodatage::date,
    EXTRACT(HOUR   FROM horodatage)::smallint,
    EXTRACT(MINUTE FROM horodatage)::smallint,
    -- ISODOW : 1 = lundi ... 7 = dimanche
    (ARRAY['lundi','mardi','mercredi','jeudi','vendredi','samedi','dimanche'])
        [EXTRACT(ISODOW FROM horodatage)::int]
FROM staging.access_log
ON CONFLICT (date, heure, minute) DO NOTHING;

INSERT INTO dw.dim_ip (adresse_ip)
SELECT DISTINCT ip
FROM staging.access_log
ON CONFLICT (adresse_ip) DO NOTHING;

-- La famille sert à regrouper les URL dans les analyses
INSERT INTO dw.dim_url (chemin, famille)
SELECT DISTINCT
    chemin,
    CASE
        WHEN chemin LIKE '/api/%' OR chemin LIKE '/rest/%'          THEN 'api'
        WHEN chemin LIKE '/ftp%'                                    THEN 'ftp'
        WHEN chemin LIKE '/assets/%'
          OR chemin ~ '\.(js|css|ico|png|jpg|svg|woff2?)$'          THEN 'static'
        ELSE 'autre'
    END
FROM staging.access_log
ON CONFLICT (chemin) DO NOTHING;

-- 404 / 100 = 4 (division entière) -> '4xx'
INSERT INTO dw.dim_statut (code, categorie)
SELECT DISTINCT statut, (statut / 100)::text || 'xx'
FROM staging.access_log
ON CONFLICT (code) DO NOTHING;

-- ---------- 2. Faits ------------------------------------------------

TRUNCATE dw.fait_requete RESTART IDENTITY;

-- Pour chaque ligne de staging, on retrouve les clés de substitution
-- en faisant la jointure sur les clés naturelles (date+heure+minute, IP, chemin, code).
INSERT INTO dw.fait_requete (id_temps, id_ip, id_url, id_statut, methode, taille)
SELECT t.id_temps, i.id_ip, u.id_url, s.id_statut, a.methode, a.taille
FROM staging.access_log a
JOIN dw.dim_temps  t ON t.date   = a.horodatage::date
                    AND t.heure  = EXTRACT(HOUR   FROM a.horodatage)
                    AND t.minute = EXTRACT(MINUTE FROM a.horodatage)
JOIN dw.dim_ip     i ON i.adresse_ip = a.ip
JOIN dw.dim_url    u ON u.chemin     = a.chemin
JOIN dw.dim_statut s ON s.code       = a.statut;

-- ---------- 3. Colonne calculée -------------------------------------

UPDATE dw.dim_ip d
SET nb_requetes = (SELECT COUNT(*) FROM dw.fait_requete f WHERE f.id_ip = d.id_ip);
