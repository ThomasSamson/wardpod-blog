# Articles du blog de Wardpod

Chaque fichier `articles/AAAA-MM-JJ-sujet.md` devient une page de https://wardpod.com/blog/AAAA-MM-JJ-sujet.
Le site relit la branche `main` toutes les 15 minutes : un commit suffit pour publier, modifier ou retirer un article.
Une date future publie l'article ce jour-là.

## Article

```markdown
---
title: "Titre de l'article"
description: "Résumé d'une ou deux phrases (moteurs de recherche, partages)."
image: images/2026-11-25-ingress-nginx-couverture.webp
---

Corps en Markdown : intertitres ##, listes, liens, tableaux, code.

![Texte alternatif qui décrit l'image](images/2026-11-25-ingress-nginx-couverture.webp)
*Légende. Crédit : auteur, titre, licence, lien vers la source.*

## Sources
```

Le HTML brut est ignoré et les images externes ne s'affichent pas.

## Images

- Dans `articles/images/`, nom en minuscules, chiffres et tirets, `.webp`, `.jpg` ou `.png` (pas de SVG), 1 Mio au plus. Le contenu doit correspondre à l'extension, sinon l'image est écartée.
- `image` dans le front matter : aperçu affiché par LinkedIn et la liste du blog, idéalement 1200 × 630.
- Chaque image est suivie d'une ligne en italique avec sa légende et son crédit (auteur, licence, lien). Seulement des images qu'on a le droit de reprendre (licence libre, domaine public, image officielle mise à disposition par l'éditeur avec mention) ou des schémas et graphiques faits pour l'article à partir de données citées.
