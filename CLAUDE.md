# Consignes communes aux tâches qui écrivent dans ce dépôt

Trois articles par semaine, deux formats qui cohabitent :

- mercredi et samedi, 7 h : un article sur un sujet (tâche « articles du blog ») ;
- vendredi, 7 h : « L'actu cyber de la semaine », le condensé de la semaine (tâche « actu cyber de la semaine »).

Le jour même à 10 h, une autre tâche prépare un post LinkedIn qui résume l'article du jour et renvoie vers lui. Ces consignes complètent celles de chaque tâche et priment en cas de contradiction sur l'organisation de la semaine.

## Ne pas se répéter

Avant de choisir un sujet, fais l'inventaire de ce qui est déjà publié :

```sh
for f in articles/*.md; do echo "$f | $(grep -m1 '^title:' "$f")"; grep -oE 'CVE-[0-9]{4}-[0-9]+' "$f" | sort -u | tr '\n' ' '; echo; done
```

Règles pour les articles sur un sujet (mercredi, samedi) :

- Le sujet principal n'a pas déjà fait l'objet d'un article sur un sujet, ni d'une section d'un rewind des deux dernières semaines. Seule exception : un fait nouveau important, lu dans une source primaire (exploitation confirmée, ajout au KEV, nouveau correctif, contournement qui change). L'article porte alors sur ce fait nouveau, renvoie vers l'ancien article par un lien relatif `/blog/<slug>` et n'en répète pas le contenu.
- Le samedi, ne reprends pas un événement du rewind de la veille, sauf pour une analyse nettement plus poussée appuyée sur des faits que le rewind n'a pas : dans ce cas, renvoie vers le rewind.
- Deux articles qui se suivent ne portent pas sur le même composant ni sur le même type de sujet (deux CVE nginx de suite, deux articles réglementaires de suite).

Règles pour le rewind du vendredi :

- Un événement déjà traité par l'article du mercredi tient en une ou deux phrases avec un lien vers lui, sans répéter ses versions, commandes ou sources.
- Un événement déjà présent dans le rewind précédent n'y revient que s'il a évolué, et seulement pour dire ce qui a changé (« suite de… », avec un lien vers le rewind précédent).

Règles pour tous :

- Les titres ne réutilisent pas la tournure des six derniers titres (par exemple « X : ce que … change pour Kubernetes »). Le titre du rewind garde sa forme fixe.
- L'introduction et la mention finale de Wardpod ne reprennent pas mot pour mot celles des articles précédents.
- Les images de couverture changent de forme d'un article à l'autre (tableau, barres, frise, schéma d'exposition) quand le sujet le permet.
