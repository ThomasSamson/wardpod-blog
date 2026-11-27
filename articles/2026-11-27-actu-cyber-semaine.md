---
title: "L'actu cyber de la semaine du 20 au 27 novembre 2026"
description: "Xen Orchestra et MONAI Label exploités d'après la CISA, sept avis corrigés dans Argo CD : les mises à jour de la semaine pour vos clusters."
image: images/2026-11-27-actu-cyber-semaine-couverture.webp
---

![Tableau de cinq lignes : Xen Orchestra (CVE-2026-133469), MONAI Label (CVE-2026-133968) et Idunno.AntiCsrf (CVE-2026-131914) marqués « exploitée » en orange ; Argo CD (sept avis GHSA) et Drupal core (SA-CORE-2026-019) marqués « corrigée » en vert, avec pour chacun la version à déployer](images/2026-11-27-actu-cyber-semaine-couverture.webp)
*Les cinq événements de la semaine et la version à déployer. Schéma Wardpod, d'après le catalogue KEV de la CISA (version 2026.11.25), les GitHub Security Advisories et les tags du dépôt drupal/drupal.*

Deux failles exploitées cette semaine visent des outils qu'on croise autour de Kubernetes : Xen Orchestra, qui administre les hyperviseurs XCP-ng sur lesquels tournent parfois les nœuds, et MONAI Label, un serveur Python d'annotation d'images médicales souvent déployé en conteneur. Argo CD a corrigé sept failles d'un coup le 24 novembre, et Drupal a publié un deuxième correctif de son installeur. Entre le 23 et le 25 novembre, le [catalogue KEV de la CISA](https://github.com/cisagov/kev-data) a reçu quinze entrées.

## Xen Orchestra : un jeton vide suffit pour devenir administrateur

La CISA a [ajouté CVE-2026-133469 au KEV](https://github.com/cisagov/kev-data) le 25 novembre, avec une échéance au 28 novembre pour les agences fédérales et une demande d'examen forensique. Sa fiche décrit un contournement d'authentification sans compte, par un jeton d'authentification qui contient un objet JSON vide. L'[avis GHSA-2r3w-c2vx-fv5g](https://github.com/vatesfr/xen-orchestra/security/advisories/GHSA-2r3w-c2vx-fv5g), publié le 20 novembre sur le dépôt de Vates et noté 9,8 en CVSS 3.1, donne le mécanisme : un cookie `authenticationToken` qui vaut `{}` arrive tel quel dans la recherche de jetons, qui le traite comme une requête sans filtre et renvoie le premier jeton trouvé. Si ce jeton n'a pas expiré, l'attaquant est connecté avec les droits de son propriétaire. L'avis indique que cela peut mener à l'exécution de code sur les pools gérés et à un accès root sur un nœud XCP-ng.

L'avis liste le paquet `xo-server` 5.213.0 comme touché et 5.213.1 et 5.211.2 comme corrigés ; le [journal des modifications](https://github.com/vatesfr/xen-orchestra/blob/master/CHANGELOG.md) du projet mentionne « Fix authentication token validation » dans sa section du 24 novembre. Le raisonnement est celui de [vCenter la semaine dernière](/blog/2026-11-21-actu-cyber-semaine) : si vos nœuds Kubernetes sont des VM XCP-ng, l'administrateur de Xen Orchestra a la main sur leurs disques et leurs secrets. Mettez à jour Xen Orchestra, puis vérifiez que son interface n'est joignable que depuis le réseau d'administration.

## MONAI Label : écriture de fichiers sans authentification

[CVE-2026-133968](https://github.com/cisagov/kev-data) est entrée au KEV le 23 novembre. La CISA la décrit comme un path traversal qui permet à un attaquant non authentifié d'écrire des fichiers hors du datastore, avec une exécution de code possible. L'[avis du projet](https://github.com/Project-MONAI/MONAILabel/security/advisories/GHSA-qc22-rmgc-vg94), publié le 18 novembre et classé critique, vise le paquet `monailabel` 0.8.5 et antérieurs : les endpoints `PUT /datastore/image` et `PUT /datastore/label` construisent le chemin d'écriture à partir d'un identifiant fourni par le client, sans refuser les `../`. L'avis rappelle que l'authentification est désactivée par défaut (`MONAI_LABEL_AUTH_ENABLE=False`) et que, quand elle est active, le rôle `ANNOTATOR` suffit. La page de l'avis n'affiche pas de CVE ; c'est la fiche du KEV qui relie les deux.

Le correctif, la [pull request #1915](https://github.com/Project-MONAI/MONAILabel/pull/1915), a été fusionné le 19 octobre, mais [PyPI](https://pypi.org/project/monailabel/#history) n'a reçu la version 0.8.6 que le 22 novembre, la veille de l'ajout au KEV ; la précédente, 0.8.5, datait de novembre 2024. Les versions 0.8.7 et 0.8.8 ont suivi le 25 novembre. Pour retrouver les serveurs et leur réglage d'authentification :

```sh
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}' | grep -i monai
kubectl exec -n <namespace> <pod> -- python -c "import importlib.metadata as m; print(m.version('monailabel'))"
kubectl exec -n <namespace> <pod> -- printenv MONAI_LABEL_AUTH_ENABLE
```

En attendant l'image reconstruite, l'avis conseille d'activer l'authentification, de ne pas exposer le serveur à des réseaux non fiables et de le faire tourner avec un utilisateur qui ne peut écrire que dans le datastore. Dans un pod, cela donne un `runAsNonRoot`, un système de fichiers racine en lecture seule et un volume dédié au datastore, sans Ingress public.

## Argo CD : sept avis corrigés dans 3.6.3, 3.5.9 et 3.4.15

Le 24 novembre, Argo CD a publié les [versions 3.6.3, 3.5.9 et 3.4.15](https://github.com/argoproj/argo-cd/releases), qui corrigent les mêmes sept avis. Aucune n'est au KEV. Celui qui inquiète le plus pour un `argocd-server` exposé est [GHSA-w7rw-fg89-2cjf](https://github.com/argoproj/argo-cd/security/advisories/GHSA-w7rw-fg89-2cjf) (CVSS 3.1 de 7,5) : une seule requête gRPC ou gRPC-Web sans authentification fait planter le processus, parce que la réécriture des URL de dépôt, faite avant le contrôle d'authentification, ne vérifie pas que le champ est présent. Kubernetes redémarre le pod, et la requête suivante le fait retomber. [GHSA-q4f6-wc8m-r246](https://github.com/argoproj/argo-cd/security/advisories/GHSA-q4f6-wc8m-r246) se passe aussi de compte : si `webhook.bitbucket.uuid` est défini, un faux événement envoyé à `/api/webhook` peut faire partir les identifiants du dépôt vers l'hôte indiqué dans le payload.

![Barres horizontales des sept avis Argo CD du 24 novembre par score CVSS 3.1 : upsert de dépôt 7,7, crash de l'API server 7,5, XSS par le lien home d'un chart Helm 7,3, suppression d'ApplicationSet hors namespace 7,1, webhook Bitbucket 6,8, releaseName Helm templaté 6,5, dex.yaml lisible par tous 6,5 ; les deux avis exploitables sans compte sont en orange](images/2026-11-27-actu-cyber-semaine-argocd.webp)
*Deux des sept avis ne demandent aucun compte Argo CD. Graphique Wardpod, données des GitHub Security Advisories d'argoproj/argo-cd du 24 novembre 2026.*

Les autres demandent un compte ou un accès local. Avec [GHSA-mfgm-4p7x-3ccr](https://github.com/argoproj/argo-cd/security/advisories/GHSA-mfgm-4p7x-3ccr) (7,7), un rôle qui a `repositories, create` sans `update` peut écraser un dépôt existant et le faire passer par un proxy qu'il contrôle, qui sert alors ses propres manifestes aux applications synchronisées. Les avis [v2hj](https://github.com/argoproj/argo-cd/security/advisories/GHSA-v2hj-322q-6cg4) et [8cfq](https://github.com/argoproj/argo-cd/security/advisories/GHSA-8cfq-7w4v-ggm3) exposent des secrets : variables d'environnement du repo-server, dont le mot de passe Redis, et configuration Dex écrite en `0644` dans `/tmp/dex.yaml`. Aucune version 2.x n'est corrigée. Vérifiez la version déployée :

```sh
kubectl get deploy -n argocd argocd-server -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
```

En attendant la mise à jour, l'avis GHSA-w7rw conseille de bloquer à l'Ingress les chemins gRPC des quatre méthodes touchées (l'interface web passe par `/api/v1/`) ; pour Bitbucket, retirez l'UUID si vous n'utilisez pas ces webhooks et restreignez l'accès à `/api/webhook`.

## Drupal : SA-CORE-2026-019, suite du correctif de l'installeur

Une semaine après l'avis traité [mercredi](/blog/2026-11-25-drupal-install-php-kev), Drupal a publié le 25 novembre les versions [11.4.14, 11.3.23 et 10.6.23](https://github.com/drupal/drupal/tags). Le [commit « fix: SA-CORE-2026-019 »](https://github.com/drupal/drupal/commit/cc92f32f4a8c49d6cf7de4c0d6aa5e45deef08e7) retouche encore `core/includes/install.core.inc`, qui refuse désormais une installation interactive en cours sans jeton de session, et ajoute une mise à jour `system_post_update_mark_installation_finished` qui marque l'installation comme terminée sur les sites dont l'état est incomplet. Les [images Docker officielles](https://github.com/docker-library/drupal/blob/master/versions.json) sont passées aux trois versions : reconstruisez, déployez, puis lancez `drush updatedb` pour que cette mise à jour s'applique.

## Idunno.AntiCsrf : une bibliothèque .NET de 2008, exploitée et sans correctif

Entrée au [KEV](https://github.com/cisagov/kev-data) le 24 novembre, CVE-2026-131914 touche un module anti-CSRF pour ASP.NET WebForms publié sur CodePlex en 2008. L'[avis MNDT-2026-0048 de Mandiant](https://github.com/mandiant/Vulnerability-Disclosures/blob/master/2026/MNDT-2026-0048.md) explique que le module désérialise le jeton du formulaire avec un `ObjectStateFormatter` sans vérification de MAC : un seul `POST` sans authentification exécute du code dans `w3wp.exe`. Mandiant écrit qu'« une exploitation active dans la nature a été observée » (traduction) et note la faille 9,3 en CVSS 4.0. Il n'y aura pas de correctif. Si vous faites tourner des conteneurs Windows avec de vieilles applications WebForms, cherchez `Idunno.AntiCsrf` dans les `Web.config` et les répertoires `bin/`, retirez le module et changez les secrets du `Web.config` si l'application a été exposée.

## Les autres ajouts au KEV

La fiche du [KEV](https://github.com/cisagov/kev-data) pour CVE-2026-103406 décrit une injection de commande en root dans Juniper Session Smart Router et Conductor, par un identifiant de minion Salt forgé. Celle d'Optimizely Web Experimentation (CVE-2026-132224) concerne les équipes web : une faille du parcours d'inscription permettait d'usurper des utilisateurs clients et de modifier le JavaScript de leurs projets, servi ensuite depuis les ressources hébergées par Optimizely aux visiteurs de leurs sites. Le reste vise N-able MailAssure, Mitel MiCollab (cinq CVE) et les contrôleurs Danfoss AK-SM 800A (trois CVE).

## À corriger en premier

1. Xen Orchestra : `xo-server` 5.213.1 ou 5.211.2, interface limitée au réseau d'administration.
2. MONAI Label : 0.8.6 au minimum, authentification activée, aucun Ingress public.
3. Argo CD : 3.6.3, 3.5.9 ou 3.4.15 ; sortir de la branche 2.x ; d'ici là, filtrage des chemins gRPC et de `/api/webhook`.
4. Drupal : 11.4.14, 11.3.23 ou 10.6.23, puis `drush updatedb`.
5. Applications WebForms : recherche et retrait d'Idunno.AntiCsrf.

Pour savoir lesquelles de ces images tournent chez vous, Wardpod lit les SBOM de tous vos clusters et place en tête ce qui est au KEV et exposé par un Ingress, une Gateway ou un LoadBalancer.

## Sources

- [Known Exploited Vulnerabilities, dépôt kev-data](https://github.com/cisagov/kev-data), CISA, version 2026.11.25 du 25 novembre 2026
- [Empty-object login token, GHSA-2r3w-c2vx-fv5g](https://github.com/vatesfr/xen-orchestra/security/advisories/GHSA-2r3w-c2vx-fv5g), Vates, 20 novembre 2026
- [CHANGELOG.md de Xen Orchestra](https://github.com/vatesfr/xen-orchestra/blob/master/CHANGELOG.md), Vates, section du 24 novembre 2026
- [Path traversal in datastore upload endpoints allows arbitrary file write, GHSA-qc22-rmgc-vg94](https://github.com/Project-MONAI/MONAILabel/security/advisories/GHSA-qc22-rmgc-vg94), Project MONAI, 18 novembre 2026
- [fix: confine datastore write paths, Project-MONAI/MONAILabel#1915](https://github.com/Project-MONAI/MONAILabel/pull/1915), Project MONAI, fusionnée le 19 octobre 2026
- [monailabel, historique des versions](https://pypi.org/project/monailabel/#history), PyPI
- [Versions d'Argo CD](https://github.com/argoproj/argo-cd/releases), Argo Project, 24 novembre 2026
- [A single unauthenticated request crashes the API server, GHSA-w7rw-fg89-2cjf](https://github.com/argoproj/argo-cd/security/advisories/GHSA-w7rw-fg89-2cjf), Argo Project, 24 novembre 2026
- [Bitbucket Cloud webhook sends stored repository credentials to a host taken from the webhook payload, GHSA-q4f6-wc8m-r246](https://github.com/argoproj/argo-cd/security/advisories/GHSA-q4f6-wc8m-r246), Argo Project, 24 novembre 2026
- [Repository create with upsert overwrites existing repositories without the update permission, GHSA-mfgm-4p7x-3ccr](https://github.com/argoproj/argo-cd/security/advisories/GHSA-mfgm-4p7x-3ccr), Argo Project, 24 novembre 2026
- [Helm chart home link allows stored XSS in the application details view, GHSA-rxm8-qc6h-3c8h](https://github.com/argoproj/argo-cd/security/advisories/GHSA-rxm8-qc6h-3c8h), Argo Project, 24 novembre 2026
- [ApplicationSet delete API ignores the allowed ApplicationSet namespaces, GHSA-rvmf-gjc9-wjgq](https://github.com/argoproj/argo-cd/security/advisories/GHSA-rvmf-gjc9-wjgq), Argo Project, 24 novembre 2026
- [Helm release name is evaluated as a template, GHSA-v2hj-322q-6cg4](https://github.com/argoproj/argo-cd/security/advisories/GHSA-v2hj-322q-6cg4), Argo Project, 24 novembre 2026
- [Generated Dex configuration containing SSO secrets is written world-readable, GHSA-8cfq-7w4v-ggm3](https://github.com/argoproj/argo-cd/security/advisories/GHSA-8cfq-7w4v-ggm3), Argo Project, 24 novembre 2026
- [Tags de drupal/drupal](https://github.com/drupal/drupal/tags), Drupal, 25 novembre 2026
- [fix: SA-CORE-2026-019, commit cc92f32](https://github.com/drupal/drupal/commit/cc92f32f4a8c49d6cf7de4c0d6aa5e45deef08e7), Drupal, 25 novembre 2026
- [versions.json, docker-library/drupal](https://github.com/docker-library/drupal/blob/master/versions.json), Docker Official Images
- [MNDT-2026-0048, Idunno.AntiCsrf](https://github.com/mandiant/Vulnerability-Disclosures/blob/master/2026/MNDT-2026-0048.md), Mandiant, 18 novembre 2026
- [L'actu cyber de la semaine du 13 au 21 novembre 2026](/blog/2026-11-21-actu-cyber-semaine), Wardpod, 21 novembre 2026
- [Drupal : l'installeur install.php exploité, la CISA l'ajoute au KEV](/blog/2026-11-25-drupal-install-php-kev), Wardpod, 25 novembre 2026

## Crédits des images

- 2026-11-27-actu-cyber-semaine-couverture.webp : schéma Wardpod, d'après le catalogue KEV de la CISA (version 2026.11.25), les GitHub Security Advisories et les tags du dépôt drupal/drupal.
- 2026-11-27-actu-cyber-semaine-argocd.webp : graphique Wardpod, données des GitHub Security Advisories d'argoproj/argo-cd du 24 novembre 2026.
