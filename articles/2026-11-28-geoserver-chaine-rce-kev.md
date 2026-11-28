---
title: "Cinq failles GeoServer enchaînées, deux déjà exploitées"
description: "CVE-2026-120705 et CVE-2026-129243 sont au KEV depuis le 27 novembre. Versions corrigées, image Docker, recherche des requêtes stockées suspectes."
image: images/2026-11-28-geoserver-chaine-couverture.webp
---

![Schéma en cinq cases reliées par des flèches : étape 1, CVE-2026-129244, chemin du data directory dans une erreur WFS, CVSS 6,9 ; étape 2, CVE-2026-129243, contrôle de service contourné par service=x/WFS, CVSS 8,8 ; étape 3, CVE-2026-120705, injection XML, lecture de fichiers et SSRF, CVSS 8,6 ; étape 4, CVE-2026-129245, cookie remember-me forgé donnant une session administrateur, CVSS 9,2 ; étape 5, CVE-2026-129242, désérialisation JDBC et exécution de code, CVSS 8,6. Les étapes 2 et 3 sont encadrées en orange avec la mention « au KEV »](images/2026-11-28-geoserver-chaine-couverture.webp)
*La chaîne décrite dans les avis GeoServer, et les deux maillons que la CISA dit exploités. Schéma Wardpod, d'après les avis GitHub de geoserver/geoserver du 23 novembre 2026 et le catalogue KEV de la CISA (version 2026.11.27).*

Le 27 novembre au soir, la CISA a ajouté deux failles de GeoServer à son [catalogue KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) : CVE-2026-120705 et CVE-2026-129243. Prises seules, elles permettent de lire des fichiers et de contourner un contrôle d'accès. Les fiches de la CISA précisent qu'elles s'enchaînent avec trois autres failles du même produit pour exécuter du code sans authentification. GeoServer, le serveur Java qui publie des cartes et des données géographiques (WMS, WFS), sert des données à des clients extérieurs : dans un cluster, il est en général publié par un Ingress. Si vous en avez un, la mise à jour passe avant le reste de la semaine.

## La chaîne, maillon par maillon

Les cinq avis ont été publiés le 23 novembre sur le dépôt GitHub du projet. Celui de la [faille de l'étape 4](https://github.com/geoserver/geoserver/security/advisories/GHSA-hgm3-wq4h-8vvq) donne l'ordre complet, chaque étape ayant été corrigée séparément.

1. [CVE-2026-129244](https://github.com/geoserver/geoserver/security/advisories/GHSA-4v26-c537-jvxc) (CVSS 4.0 de 6,9) : une requête de requête stockée WFS avec un identifiant trop long renvoie une erreur qui contient le chemin absolu du data directory. L'avis le juge inoffensif seul, mais les étapes suivantes en ont besoin.
2. [CVE-2026-129243](https://github.com/geoserver/geoserver/security/advisories/GHSA-rv5g-g2r9-58rj) (CVSS 4.0 de 8,8) : un paramètre `service=x/WFS` est résolu en WFS par le dispatcher, alors que le contrôle de sécurité compare les règles au nom brut, qui ne correspond à rien. Avec la configuration par défaut, un anonyme peut créer et supprimer des requêtes stockées WFS, normalement réservées aux administrateurs. Toute opération protégée seulement par une règle de service perd sa protection, y compris WFS Transaction si vous l'aviez restreinte ainsi.
3. [CVE-2026-120705](https://github.com/geoserver/geoserver/security/advisories/GHSA-39mw-5chv-jh47) (CVSS 3.1 de 8,6) : la requête stockée intégrée `GetFeatureById` insère l'identifiant fourni dans un modèle XML sans échappement. Une seule requête WFS sans compte suffit pour faire lire au serveur un fichier texte local, ou lui faire chercher une URL HTTP ou HTTPS choisie par l'attaquant. Le contenu n'est renvoyé dans le message d'erreur que si une couche est publiée pour les anonymes ; sinon, le fichier est lu sans être affiché.
4. [CVE-2026-129245](https://github.com/geoserver/geoserver/security/advisories/GHSA-hgm3-wq4h-8vvq) (CVSS 4.0 de 9,2) : le cookie remember-me est signé avec une clé lue dans `security/config.xml`, et le data directory livré par défaut contient une valeur connue que la plupart des installations ne changent pas. Avec cette clé et l'empreinte du mot de passe d'un administrateur, obtenue par la lecture de fichiers de l'étape 3, on forge un cookie qui ouvre une session administrateur.
5. [CVE-2026-129242](https://github.com/geoserver/geoserver/security/advisories/GHSA-9wf2-fcgq-vxhq) (CVSS 4.0 de 8,6) : un administrateur peut configurer un service d'utilisateurs JDBC adossé à une base HSQLDB téléversée, dont les valeurs sont des objets Java sérialisés. Leur chargement exécute du code avec les droits du processus GeoServer.

D'après [SecurityWeek](https://www.securityweek.com/two-newly-disclosed-geoserver-vulnerabilities-under-attack/), la chaîne a été trouvée par Jonah Burgess (CryptoCat), chercheur chez Rapid7, qui a publié les détails techniques et un code de preuve de concept. Le même article rapporte qu'Eye Security a montré une autre chaîne, plus courte, qui combine CVE-2026-120705, CVE-2026-129245 et CVE-2026-120704 (chargement d'une extension SQLite par les services de sécurité JDBC), et qu'elle a compté plus de 3 000 instances GeoServer joignables depuis internet.

## Versions touchées et corrigées

Les trois branches maintenues sont concernées : 2.27.6 et antérieures, 2.28.0 à 2.28.5, 3.0.0 et 3.0.1. Les avis donnent comme corrigées les versions 3.0.2, 2.28.6 et 2.27.7. Pour CVE-2026-120705, la correction touche aussi GeoTools, en 33.7, 34.6 et 35.2.

![Frise du 17 octobre au 30 novembre 2026 : GeoServer 3.0.2 publié le 17 octobre, 2.27.7 le 18 octobre, 2.28.6 le 2 novembre ; une bande indique 37 jours entre 3.0.2 et la publication des avis le 23 novembre ; en orange, les sondes de watchTowr rapportées le 25 novembre, l'ajout au KEV le 27 novembre et l'échéance fédérale du 30 novembre](images/2026-11-28-geoserver-chaine-frise.webp)
*Les correctifs étaient en ligne plus d'un mois avant les avis. Graphique Wardpod, données des versions GitHub de geoserver/geoserver, de SecurityWeek (25 novembre 2026) et du catalogue KEV de la CISA (version 2026.11.27).*

Les correctifs ne sont pas neufs. Sur la [page des versions](https://github.com/geoserver/geoserver/releases), 3.0.2 est sortie le 17 octobre, 2.27.7 le 18 octobre et 2.28.6 le 2 novembre. Un serveur passé à l'une de ces versions est protégé depuis ; un serveur resté en 3.0.1, 2.28.5 ou 2.27.6, les versions du 14 août, ne l'est pas.

Un point à vérifier sur les branches 2.x : l'avis de CVE-2026-129245 liste 2.28.6 et 2.27.7 parmi les versions corrigées, mais les notes de [2.28.6](https://github.com/geoserver/geoserver/releases/tag/2.28.6) et de 2.27.7 ne mentionnent pas cette CVE, alors que celles de [3.0.2](https://github.com/geoserver/geoserver/releases/tag/3.0.2) la citent. Faute de pouvoir trancher entre les deux sources, appliquez sur les 2.x le contournement de l'avis en plus de la mise à jour : retirer le filtre remember-me de la chaîne `web` (Security > Authentication), ou mettre une clé longue et aléatoire dans `security/config.xml`.

## Pourquoi c'est prioritaire

L'exploitation est confirmée par la CISA, qui fixe aux agences fédérales une échéance au 30 novembre. Ce qui a été observé reste pour l'instant de la reconnaissance. SecurityWeek cite watchTowr : « les attaquants ont envoyé des sondes d'exploitation basées sur les erreurs pour vérifier que le serveur est vulnérable, en créant et en invoquant des requêtes stockées » (traduction). watchTowr n'a pas signalé d'exécution de code réussie. Les trois premières étapes ne demandent aucun compte, et une preuve de concept de la chaîne est publique.

L'API EPSS de FIRST ne renvoie encore [aucun score](https://api.first.org/data/v1/epss?cve=CVE-2026-120705) pour ces CVE au 28 novembre. Ce score viendra ; l'ajout au KEV suffit pour décider.

Dans un cluster, deux facteurs aggravent le cas. Le serveur est publié par un Ingress dès qu'il sert des clients hors du cluster. Et l'image officielle `docker.osgeo.org/geoserver` [tourne en root par défaut](https://github.com/geoserver/docker), « pour des raisons de rétrocompatibilité » (traduction) : le code exécuté à l'étape 5 tourne alors en root dans le conteneur.

## Que faire dans un cluster Kubernetes

Repérez les pods GeoServer, y compris ceux embarqués dans une autre application :

```sh
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}' | grep -i geoserver
```

Le tag de l'image ne suffit pas pour une image maison. Un SBOM donne la version réelle des jars :

```sh
trivy image --format cyclonedx --output geoserver-sbom.json <image>
grep -oE 'pkg:maven/org.geoserver/gs-(main|wfs-core|wfs|ows)@[^"?]+' geoserver-sbom.json | sort -u
```

Passez ensuite à 3.0.2, 2.28.6 ou 2.27.7, en reconstruisant l'image si elle part d'une base figée. Profitez-en pour définir `RUN_UNPRIVILEGED=true`, que le README de l'image prévoit pour faire tourner Tomcat sous l'utilisateur `tomcat` (uid et gid 999), et pour vérifier que le mot de passe `admin` n'est plus celui par défaut (`GEOSERVER_ADMIN_PASSWORD` ou `GEOSERVER_ADMIN_PASSWORD_FILE`).

Avant de redémarrer, cherchez des requêtes stockées que vous n'avez pas créées, comme le demande l'avis de CVE-2026-129243. Le data directory est par défaut dans `/opt/geoserver_data` :

```sh
kubectl exec -n <namespace> <pod> -- sh -c 'd="${GEOSERVER_DATA_DIR:-/opt/geoserver_data}"; ls -la "$d"/wfs/query "$d"/workspaces/*/wfs/query 2>/dev/null'
```

Si vous ne pouvez pas mettre à jour tout de suite, les avis proposent deux mesures. Pour CVE-2026-129243, rejeter au proxy les requêtes dont le paramètre `service` contient un `/`, dans la query string comme dans l'attribut `service` des requêtes XML envoyées en POST : un filtre qui ne regarde que l'URL ne couvre que la moitié des cas. Pour CVE-2026-120705, qui se passe de la première faille, restreindre ou désactiver WFS pour les anonymes dans la sécurité des services, ou couper WFS si vous ne vous en servez pas. Bloquer CVE-2026-129243 seul ne ferme pas la lecture de fichiers.

Enfin, l'avis de l'étape 5 conseille de limiter à des réseaux de confiance les API REST `/rest/resource` et `/rest/security`. Dans un cluster, ces chemins n'ont aucune raison de passer par l'Ingress public : sortez-les de la règle de routage, et réservez l'administration à un accès interne ou à un `kubectl port-forward`.

Wardpod place en P1 une vulnérabilité au KEV dont l'image est publiée par un Ingress, une Gateway ou un LoadBalancer, et signale à côté si le conteneur tourne en root ; sa recherche par purl retrouve `org.geoserver/gs-main` et sa version sur tous les clusters.

## Sources

- [Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), CISA, version 2026.11.27 du 27 novembre 2026, fiches CVE-2026-120705 et CVE-2026-129243
- [Unauthenticated WFS GetFeatureById XML injection, GHSA-39mw-5chv-jh47](https://github.com/geoserver/geoserver/security/advisories/GHSA-39mw-5chv-jh47), GeoServer, 23 novembre 2026
- [Service security rules bypassed with a prefixed service name such as x/WFS, GHSA-rv5g-g2r9-58rj](https://github.com/geoserver/geoserver/security/advisories/GHSA-rv5g-g2r9-58rj), GeoServer, 23 novembre 2026
- [WFS stored query exception discloses data directory path, GHSA-4v26-c537-jvxc](https://github.com/geoserver/geoserver/security/advisories/GHSA-4v26-c537-jvxc), GeoServer, 23 novembre 2026
- [Predictable remember-me key allows administrator session forgery, GHSA-hgm3-wq4h-8vvq](https://github.com/geoserver/geoserver/security/advisories/GHSA-hgm3-wq4h-8vvq), GeoServer, 23 novembre 2026
- [Deserialization in JDBC user and role services allows administrator code execution, GHSA-9wf2-fcgq-vxhq](https://github.com/geoserver/geoserver/security/advisories/GHSA-9wf2-fcgq-vxhq), GeoServer, 23 novembre 2026
- [Versions de GeoServer](https://github.com/geoserver/geoserver/releases), GeoServer, notes de 3.0.2 (17 octobre 2026), 2.27.7 (18 octobre 2026) et [2.28.6](https://github.com/geoserver/geoserver/releases/tag/2.28.6) (2 novembre 2026)
- [Two Newly Disclosed GeoServer Vulnerabilities Under Attack](https://www.securityweek.com/two-newly-disclosed-geoserver-vulnerabilities-under-attack/), Eduard Kovacs, SecurityWeek, 25 novembre 2026
- [API EPSS, CVE-2026-120705](https://api.first.org/data/v1/epss?cve=CVE-2026-120705), FIRST, consultée le 28 novembre 2026
- [geoserver/docker, README](https://github.com/geoserver/docker), GeoServer

## Crédits des images

- 2026-11-28-geoserver-chaine-couverture.webp : schéma Wardpod, d'après les avis GitHub de geoserver/geoserver du 23 novembre 2026 et le catalogue KEV de la CISA (version 2026.11.27).
- 2026-11-28-geoserver-chaine-frise.webp : graphique Wardpod, données de la page des versions de geoserver/geoserver, de l'article de SecurityWeek du 25 novembre 2026 et du catalogue KEV de la CISA (version 2026.11.27).
