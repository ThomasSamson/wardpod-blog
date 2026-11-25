---
title: "Drupal : l'installeur install.php exploité, la CISA l'ajoute au KEV"
description: "CVE-2026-132165 permet de relancer l'installation de Drupal sans authentification. Versions corrigées, images Docker, blocage d'install.php."
image: images/2026-11-25-drupal-install-php-couverture.webp
---

![Schéma d'exposition : depuis internet, un attaquant non authentifié passe par l'Ingress ou un LoadBalancer jusqu'au fichier /core/install.php du pod Drupal ; une flèche en pointillés vers la base MySQL ou PostgreSQL porte la mention « ne répond pas ? ». Sous le schéma, le texte rappelle qu'avant 11.4.13, 11.3.22 et 10.6.22, l'installeur continue si la vérification de la base échoue](images/2026-11-25-drupal-install-php-couverture.webp)
*Le chemin d'exposition de CVE-2026-132165 dans un cluster. Schéma Wardpod, d'après le catalogue KEV de la CISA et le commit SA-CORE-2026-017 de Drupal.*

Le 24 novembre, la CISA a [ajouté CVE-2026-132165 à son catalogue KEV](https://github.com/cisagov/kev-data), la liste des failles dont l'exploitation a été constatée. La faille touche Drupal core. D'après la fiche de la CISA, un attaquant non authentifié peut prendre le contrôle d'un site existant ou exécuter du code par l'installeur de Drupal : « sous certaines conditions », il peut se servir de `install.php` pour tenter de réinstaller Drupal sur le site (traduction). Les correctifs sont sortis le 18 novembre. Un site Drupal servi depuis un cluster, avec un Ingress public, est donc exposé tant que l'image n'a pas été reconstruite.

## Ce qui est touché

La CISA renvoie vers l'avis SA-CORE-2026-017 de Drupal. Dans le [miroir GitHub de Drupal core](https://github.com/drupal/drupal/tags), les versions 11.4.13, 11.3.22 et 10.6.22 sont datées du 18 novembre, et chacune contient un commit intitulé « fix: SA-CORE-2026-017 » (voir la [comparaison entre 11.4.12 et 11.4.13](https://github.com/drupal/drupal/compare/11.4.12...11.4.13) et celle [entre 10.6.21 et 10.6.22](https://github.com/drupal/drupal/compare/10.6.21...10.6.22)). Les versions précédentes de ces trois branches, 11.4.12, 11.3.21 et 10.6.21, publiées le 6 novembre, n'ont pas ce correctif. Les mêmes versions contiennent aussi le correctif d'un second avis, SA-CORE-2026-018, commité le même jour.

![Frise du 6 au 27 novembre 2026 : le 6 novembre, versions 11.4.12, 11.3.21 et 10.6.21 encore touchées ; le 18 novembre, versions corrigées 11.4.13, 11.3.22 et 10.6.22 ; le 24 novembre, ajout au catalogue KEV ; le 27 novembre, échéance des agences fédérales américaines](images/2026-11-25-drupal-install-php-frise.webp)
*Les dates de CVE-2026-132165. Graphique Wardpod, données : tags du dépôt drupal/drupal, versions.json de docker-library/drupal et catalogue KEV de la CISA, version 2026.11.24.*

Le fichier `core/install.php` fait partie de Drupal core et reste en place après l'installation. Il charge `core/includes/install.core.inc`, le seul fichier modifié par le [commit du correctif](https://github.com/drupal/drupal/commit/1c977e1e8e6c4f9a6678d5aeb783542bd4d863c4) (53 lignes ajoutées, 14 retirées). Ce commit modifie l'installeur sur quatre points :

- quand la requête qui vérifie la présence d'une installation existante échoue, l'ancien code ignorait l'erreur, avec ce commentaire : « Do not trigger an error if the database query fails, since the database might not be set up yet ». Le nouveau code lève une erreur « The configured database could not be verified. » et bloque l'installation ;
- l'installeur refuse de continuer si l'état enregistré indique une installation terminée (tâche `done` ou valeur `install_time` présente) ;
- une installation interactive ne peut plus être poursuivie que par la session de navigateur qui l'a commencée, grâce à un jeton aléatoire ;
- les vérifications de lecture et d'écriture de `settings.php` passent en `auto_fix: FALSE` : l'installeur ne tente plus de corriger lui-même les droits du fichier.

Ce que nous en tirons, sans plus de détails publics sur l'exploitation : sur une version non corrigée, une base momentanément injoignable ou une requête qui échoue suffisait à faire croire à l'installeur qu'il n'y avait rien d'installé. Dans un cluster, une base qui redémarre ou bascule produit justement ce genre de fenêtre.

## Pourquoi c'est prioritaire

La fiche du KEV ne dit ni qui exploite la faille ni combien de sites sont touchés. Elle suffit pourtant à placer la correction en tête de liste : l'exploitation est constatée, aucun compte n'est nécessaire, et le fichier visé est joignable dès que le site l'est. La CISA a fixé aux agences fédérales américaines une échéance au 27 novembre, trois jours après l'ajout, et la fiche porte la mention `forensicTriage: Yes` : la CISA leur demande aussi un examen des systèmes concernés. Le champ sur l'usage par des groupes de rançongiciel indique « Unknown ».

L'image Docker officielle ajoute un détail utile. Son [Dockerfile](https://github.com/docker-library/drupal/blob/master/11.4/php8.4/apache-trixie/Dockerfile) installe Drupal dans `/opt/drupal`, publie `/opt/drupal/web` comme racine du serveur web, et donne à l'utilisateur `www-data` la propriété de `web/sites`, le répertoire qui contient `settings.php`. Si le serveur web tourne sous `www-data`, il peut écrire dans ce répertoire.

## Que faire dans le cluster

D'abord, retrouver les pods Drupal et leur version :

```sh
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}' | grep -i drupal
kubectl exec -n <namespace> <pod> -- grep "const VERSION" /opt/drupal/web/core/lib/Drupal.php
```

Le chemin `/opt/drupal/web` est celui de l'image officielle ; adaptez-le pour une image maison construite avec Composer. Les images qui n'ont pas « drupal » dans leur nom se retrouvent par le SBOM, en cherchant le paquet Composer `pkg:composer/drupal/core`.

Ensuite, mettre à jour. Le fichier [versions.json de l'image officielle](https://github.com/docker-library/drupal/blob/master/versions.json) pointe déjà vers 11.4.13, 11.3.22 et 10.6.22 pour les branches 11.4, 11.3 et 10.6. Pour une image construite avec Composer, il faut mettre à jour `drupal/core` (ou `drupal/core-recommended`) vers l'une de ces versions, reconstruire et redéployer. Avec une étiquette flottante, sans numéro de version complet, le pod peut redémarrer sur une ancienne image restée en cache sur le nœud : vérifiez la version dans le conteneur après le déploiement.

Enfin, fermer `install.php`, qui ne sert plus une fois le site installé. Avec l'image Apache, une configuration montée depuis une ConfigMap fait l'affaire :

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

Puis contrôlez depuis l'extérieur du cluster que l'adresse renvoie bien 403 ou 404 :

```sh
curl -s -o /dev/null -w '%{http_code}\n' https://<votre-site>/core/install.php
```

Deux mesures réduisent encore l'exposition : monter `settings.php` en lecture seule (`readOnly: true` sur le volume) pour que le processus web ne puisse pas le réécrire, et limiter par NetworkPolicy l'accès à la base aux seuls pods Drupal. Si un site non corrigé était joignable depuis internet, faites comme la CISA le demande aux agences fédérales et cherchez des traces avant de passer à autre chose : date de modification de `settings.php`, comptes administrateurs récents, accès à `/core/install.php` dans les journaux de l'Ingress.

Dans Wardpod, une CVE au KEV sur une image servie par un Ingress ou un LoadBalancer remonte en P1, et la recherche dans les SBOM retrouve `drupal/core` et sa version sur chacun de vos clusters, y compris dans les images maison.

## Sources

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
