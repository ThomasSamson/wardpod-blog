# Articles du blog de Wardpod

Chaque fichier `articles/AAAA-MM-JJ-sujet.md` devient une page de https://wardpod.com/blog/AAAA-MM-JJ-sujet.
Le site relit la branche `main` toutes les 15 minutes : un commit suffit pour publier, modifier ou retirer un article.

Format :

```markdown
---
title: Titre de l'article
description: Résumé d'une ou deux phrases (moteurs de recherche, partages).
---

Corps en Markdown (titres ##, listes, liens, tableaux, code). Le HTML brut est ignoré, les images externes ne s'affichent pas.
```

Le nom du fichier : date de publication puis minuscules, chiffres et tirets. Une date future publie l'article ce jour-là.
