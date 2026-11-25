---
title: "Drupal : l'installeur install.php exploité, la CISA l'ajoute au KEV"
description: "CVE-2026-132165 permet de relancer l'installation de Drupal sans authentification. Versions corrigées, images Docker, blocage d'install.php."
image: images/2026-11-25-drupal-install-php-couverture.webp
---

![Schéma d'exposition : depuis internet, un attaquant non authentifié passe par l'Ingress ou un LoadBalancer jusqu'au fichier /core/install.php du pod Drupal ; une flèche en pointillés vers la base MySQL ou PostgreSQL porte la mention « ne répond pas ? ». Sous le schéma, le texte rappelle qu'avant 11.4.13, 11.3.22 et 10.6.22, l'installeur continue si la vérification de la base échoue](images/2026-11-25-drupal-install-php-couverture.webp)
*Le chemin d'exposition de CVE-2026-132165 dans un cluster. Schéma Wardpod, d'après le catalogue KEV de la CISA et le commit SA-CORE-2026-017 de Drupal.*

Le 24 novembre, la CISA a [ajouté CVE-2026-132165 à son catalogue KEV](https://github.com/cisagov/kev-data), la liste des failles dont l'exploitation a été constatée. La faille touche Drupal core. D'après la fiche de la CISA, un attaquant non authentifié peut prendre le contrôle d'un site existant ou exécuter du code par l'installeur de Drupal : « sous certaines conditions », il peut se servir de `install.php` pour tenter de réinstaller Drupal sur le site (traduction). Drupal avait publié les correctifs le 18 novembre avec l'avis [SA-CORE-2026-017](https://www.drupal.org/sa-core-2026-017), classé « Highly critical ». Un site Drupal servi depuis un cluster, avec un Ingress public, est donc exposé tant que l'image n'a pas été reconstruite.

## Ce qui est touché

[L'avis de Drupal](https://www.drupal.org/sa-core-2026-017) donne les versions touchées sous la forme `<10.6.22 || >=11.0.0 <11.3.22 || >=11.4.0 <11.4.13`, corrigées par 11.4.13, 11.3.22 et 10.6.22. Les branches 11.2.x et antérieures, comme 10.5.x et antérieures, sont en fin de vie : touchées, elles ne recevront pas de correctif, et il faut changer de branche. Dans le [miroir GitHub de Drupal core](https://github.com/drupal/drupal/tags), chacune des trois versions corrigées contient un commit « fix: SA-CORE-2026-017 » (voir la [comparaison entre 11.4.12 et 11.4.13](https://github.com/drupal/drupal/compare/11.4.12...11.4.13) et celle [entre 10.6.21 et 10.6.22](https://github.com/drupal/drupal/compare/10.6.21...10.6.22)), ainsi que le correctif d'un second avis, SA-CORE-2026-018.

![Frise du 6 au 27 novembre 2026 : le 6 novembre, versions 11.4.12, 11.3.21 et 10.6.21 encore touchées ; le 18 novembre, versions corrigées 11.4.13, 11.3.22 et 10.6.22 ; le 24 novembre, ajout au catalogue KEV ; le 27 novembre, échéance des agences fédérales américaines](images/2026-11-25-drupal-install-php-frise.webp)
*Les dates de CVE-2026-132165. Graphique Wardpod, données : tags du dépôt drupal/drupal, versions.json de docker-library/drupal et catalogue KEV de la CISA, version 2026.11.24.*

Le fichier `core/install.php` fait partie de Drupal core et reste en place après l'installation. Il charge `core/includes/install.core.inc`, le seul fichier modifié par le [commit du correctif](https://github.com/drupal/drupal/commit/1c977e1e8e6c4f9a6678d5aeb783542bd4d863c4) (53 lignes ajoutées, 14 retirées). Ce commit modifie l'installeur sur quatre points :

- quand la requête qui vérifie la présence d'une installation existante échoue, l'ancien code ignorait l'erreur ; le nouveau lève « The configured database could not be verified. » et bloque l'installation ;
- l'installeur refuse de continuer si l'état enregistré indique une installation terminée (tâche `done` ou valeur `install_time` présente) ;
- une installation interactive ne peut plus être poursuivie que par la session de navigateur qui l'a commencée, grâce à un jeton aléatoire ;
- les vérifications de lecture et d'écriture de `settings.php` passent en `auto_fix: FALSE` : l'installeur ne tente plus de corriger lui-même les droits du fichier.

Ce que nous en tirons. [L'avis](https://www.drupal.org/sa-core-2026-017) ne détaille pas les « conditions spécifiques » de l'attaque ; il précise seulement que certains chemins d'exploitation, « mais pas tous », sont bloqués si le serveur web ne peut ni écrire dans `settings.php` ni en changer les droits. Notre lecture du diff, qui reste une hypothèse : une requête qui échoue sur la base pouvait faire croire à l'installeur qu'il n'y avait rien d'installé, ce qu'une base qui redémarre ou bascule dans un cluster peut provoquer. Protéger `settings.php` aide donc, mais ne remplace pas la mise à jour.

## Pourquoi c'est prioritaire

La fiche du KEV ne dit ni qui exploite la faille ni combien de sites sont touchés. [L'avis de Drupal](https://www.drupal.org/sa-core-2026-017), mis à jour, signale des exploitations sur des sites en production dès le 19 novembre à 19 h UTC, le lendemain des correctifs. Aucun compte n'est nécessaire (`A:None` dans le vecteur de l'avis) et le fichier visé est joignable dès que le site l'est. La CISA a fixé aux agences fédérales américaines une échéance au 27 novembre, trois jours après l'ajout, et la fiche porte la mention `forensicTriage: Yes` : la CISA leur demande aussi un examen des systèmes concernés. Le champ sur l'usage par des groupes de rançongiciel indique « Unknown ».

L'avis note la faille 20 sur 25 sur l'échelle de risque de Drupal, distincte du CVSS. Au 25 novembre, l'[API EPSS de FIRST](https://api.first.org/data/v1/epss?cve=CVE-2026-132165) ne donne encore aucun score pour cette CVE (données les plus récentes : 24 novembre).

Dans l'image Docker officielle, le [Dockerfile](https://github.com/docker-library/drupal/blob/master/11.4/php8.4/apache-trixie/Dockerfile) installe Drupal dans `/opt/drupal`, publie `/opt/drupal/web` comme racine du serveur web, et donne à l'utilisateur `www-data` la propriété de `web/sites`, le répertoire qui contient `settings.php`. Un serveur web qui tourne sous `www-data` peut donc y écrire.

## Que faire dans le cluster

D'abord, retrouver les pods Drupal et leur version :

```sh
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}' | grep -i drupal
kubectl exec -n <namespace> <pod> -- grep "const VERSION" /opt/drupal/web/core/lib/Drupal.php
```

Pour une image maison, adaptez le chemin `/opt/drupal/web` de l'image officielle. Les images qui n'ont pas « drupal » dans leur nom se retrouvent par le SBOM, en cherchant le paquet Composer `pkg:composer/drupal/core`.

Ensuite, mettre à jour. Le fichier [versions.json de l'image officielle](https://github.com/docker-library/drupal/blob/master/versions.json) pointe déjà vers 11.4.13, 11.3.22 et 10.6.22 pour les branches 11.4, 11.3 et 10.6. Pour une image construite avec Composer, mettez à jour `drupal/core` (ou `drupal/core-recommended`) vers l'une de ces versions puis reconstruisez et redéployez. Avec une étiquette flottante, le pod peut redémarrer sur une ancienne image restée en cache sur le nœud : vérifiez la version dans le conteneur après le déploiement.

Enfin, fermer `install.php`, comme [l'avis](https://www.drupal.org/sa-core-2026-017) le recommande, surtout si la mise à jour doit attendre ([sa page de référence](https://www.drupal.org/docs/administering-a-drupal-site/security-in-drupal/securing-the-installer-installphp)). Avec l'image Apache, une configuration montée depuis une ConfigMap fait l'affaire :

```apache
<Location "/core/install.php">
    Require all denied
</Location>
```

Avec une variante FPM derrière nginx :

```nginx
location = /core/install.php {
    return 404;
}
```

Puis vérifiez de l'extérieur que l'adresse renvoie 403 ou 404 :

```sh
curl -s -o /dev/null -w '%{http_code}\n' https://<votre-site>/core/install.php
```

Deux mesures réduisent encore l'exposition : monter `settings.php` en lecture seule (`readOnly: true` sur le volume) ce qui, selon l'avis, bloque une partie des chemins d'exploitation, et limiter par NetworkPolicy l'accès à la base aux seuls pods Drupal. Si un site non corrigé était joignable depuis internet, faites comme la CISA le demande aux agences fédérales et cherchez des traces avant de passer à autre chose : date de modification de `settings.php`, comptes administrateurs récents, accès à `/core/install.php` dans les journaux de l'Ingress.

Dans Wardpod, une CVE au KEV sur une image servie par un Ingress ou un LoadBalancer remonte en P1, et la recherche dans les SBOM retrouve `drupal/core` et sa version sur chacun de vos clusters, y compris dans les images maison.

## Sources

- [SA-CORE-2026-017, Drupal core, Highly critical, Remote code execution](https://www.drupal.org/sa-core-2026-017), Drupal Security Team, 18 novembre 2026, avec sa mise à jour sur l'exploitation
- [API EPSS, CVE-2026-132165](https://api.first.org/data/v1/epss?cve=CVE-2026-132165), FIRST, consultée le 25 novembre 2026
- [Known Exploited Vulnerabilities, dépôt kev-data](https://github.com/cisagov/kev-data), CISA, version 2026.11.24 du 24 novembre 2026, fiche CVE-2026-132165
- [fix: SA-CORE-2026-017, commit 1c977e1](https://github.com/drupal/drupal/commit/1c977e1e8e6c4f9a6678d5aeb783542bd4d863c4), Drupal core, miroir GitHub, 18 novembre 2026
- [Comparaison 11.4.12...11.4.13](https://github.com/drupal/drupal/compare/11.4.12...11.4.13), Drupal core, miroir GitHub, 18 novembre 2026
- [Comparaison 10.6.21...10.6.22](https://github.com/drupal/drupal/compare/10.6.21...10.6.22), Drupal core, miroir GitHub, 18 novembre 2026
- [Tags de drupal/drupal](https://github.com/drupal/drupal/tags), Drupal core, miroir GitHub
- [versions.json](https://github.com/docker-library/drupal/blob/master/versions.json), image Docker officielle de Drupal, docker-library
- [Dockerfile 11.4, php8.4, apache-trixie](https://github.com/docker-library/drupal/blob/master/11.4/php8.4/apache-trixie/Dockerfile), image Docker officielle de Drupal, docker-library

## Crédits des images

- 2026-11-25-drupal-install-php-couverture.webp : schéma Wardpod, d'après la fiche CVE-2026-132165 du catalogue KEV de la CISA et le commit SA-CORE-2026-017 de Drupal core.
- 2026-11-25-drupal-install-php-frise.webp : graphique Wardpod, données des tags du dépôt drupal/drupal, du fichier versions.json de docker-library/drupal et du catalogue KEV de la CISA (version 2026.11.24).
