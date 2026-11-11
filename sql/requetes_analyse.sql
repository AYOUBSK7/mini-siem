-- =====================================================================
--  Requêtes d'analyse (OLAP) sur l'entrepôt en étoile
--  Principe : la table de faits + une jointure par dimension utilisée,
--             puis GROUP BY sur les colonnes des dimensions.
-- =====================================================================

-- 1. Nombre de réponses 404 par IP et par minute
--    -> une IP avec beaucoup de 404 dans la même minute = probable scan (règle R4)
SELECT i.adresse_ip,
       t.date,
       LPAD(t.heure::text, 2, '0') || ':' || LPAD(t.minute::text, 2, '0') AS minute,
       COUNT(*) AS nb_404
FROM dw.fait_requete f
JOIN dw.dim_ip     i ON i.id_ip     = f.id_ip
JOIN dw.dim_temps  t ON t.id_temps  = f.id_temps
JOIN dw.dim_statut s ON s.id_statut = f.id_statut
WHERE s.code = 404
GROUP BY i.adresse_ip, t.date, t.heure, t.minute
ORDER BY nb_404 DESC;

-- 2. Top 10 des IP : nombre de requêtes et part des erreurs (4xx et 5xx)
SELECT i.adresse_ip,
       COUNT(*) AS nb_requetes,
       ROUND(100.0 * COUNT(*) FILTER (WHERE s.categorie IN ('4xx', '5xx')) / COUNT(*), 1)
           AS pct_erreurs
FROM dw.fait_requete f
JOIN dw.dim_ip     i ON i.id_ip     = f.id_ip
JOIN dw.dim_statut s ON s.id_statut = f.id_statut
GROUP BY i.adresse_ip
ORDER BY nb_requetes DESC
LIMIT 10;

-- 3. Répartition des requêtes par famille d'URL et catégorie de statut
SELECT u.famille, s.categorie, COUNT(*) AS nb_requetes
FROM dw.fait_requete f
JOIN dw.dim_url    u ON u.id_url    = f.id_url
JOIN dw.dim_statut s ON s.id_statut = f.id_statut
GROUP BY u.famille, s.categorie
ORDER BY u.famille, s.categorie;
