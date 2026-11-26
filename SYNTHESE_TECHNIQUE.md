# Synthèse technique — TP4 Supply chain et Policy-as-Code

## 1. Vulnérabilités corrigées dans les manifestes IaC

| Mauvaise pratique | Risque | Correction | Contrôle qui l'empêche de revenir |
|---|---|---|---|
| Conteneur exécuté en **root** | Évasion de conteneur et écriture sur l'hôte facilitées | `runAsNonRoot: true`, UID/GID 101 dans le Pod et `USER 101:101` dans le Dockerfile | Kyverno `require-hardened-app-pods` |
| Mode **privilégié** | Accès à tous les périphériques et au noyau de l'hôte : équivaut à root sur le nœud | `privileged: false` | Trivy `KSV-0017` (HIGH, bloquant en CI) + Kyverno |
| **Escalade de privilèges** | Binaires setuid → root dans le conteneur | `allowPrivilegeEscalation: false` | Trivy + Kyverno |
| **Capacités Linux** par défaut | `NET_RAW`, `CHOWN`, `SETUID`… exploitables | `capabilities.drop: ["ALL"]` | Trivy + Kyverno |
| Système de fichiers **inscriptible** | Persistance d'un attaquant, binaire modifié | `readOnlyRootFilesystem: true` ; `emptyDir` pour `/tmp` et le cache nginx | Trivy + Kyverno |
| Tag mutable **`:latest`** | L'image exécutée peut différer de l'image analysée | Image référencée par **digest SHA-256** | Kyverno (motif `*@sha256:*`) |
| **Aucune limite** de ressources | Déni de service par épuisement du nœud | `requests`/`limits` CPU et mémoire | Trivy + Kyverno |
| **Aucun cloisonnement réseau** | Mouvement latéral, exfiltration | NetworkPolicy *deny-all* : entrée depuis `ingress-nginx` sur 8080, sortie DNS uniquement | Test statique en CI |
| Jeton ServiceAccount monté | Vol du jeton pour attaquer l'API Kubernetes | ServiceAccount dédié, `automountServiceAccountToken: false` | Trivy |
| Pas de profil seccomp | Surface d'appels système complète | `seccompProfile: RuntimeDefault` | Trivy |

Autres failles corrigées au passage : image de base vulnérable (5 CRITICAL et 15 HIGH, bloquées par le scan d'image), remplacée par une image *slim* épinglée par digest et mise à jour au build ; actions GitHub épinglées par SHA de commit plutôt que par tag modifiable ; secrets applicatifs chiffrés avec SOPS/Age au lieu d'être en clair.

## 2. Comment la chaîne cryptographique empêche de contourner la CI

```
 code ──► CI : Gitleaks ─► Trivy IaC ─► SAST/SCA ─► build ─► scan image ─► SBOM ─► cosign sign (clé PRIVÉE)
                                                                                      │
                                     registre : image@sha256:digest + signature ◄─────┘
                                                                                      │
 kubectl apply ──► API Kubernetes ──► Kyverno (Enforce, clé PUBLIQUE) ── signature valide ? ── non ─► REFUS
                                                                          └── oui ─► Pod admis
```

1. **Seule la CI peut signer.** La clé privée Cosign est un secret GitHub, accessible uniquement au job `publish` sur `main`, après la réussite de tous les contrôles. Aucun développeur ne la possède, et les pull requests n'y ont pas accès.
2. **La signature est liée au contenu.** Cosign signe le *digest* SHA-256 de l'image, pas un tag. Modifier un seul octet de l'image change son digest et invalide la signature ; republier un tag existant ne sert donc à rien.
3. **Le contrôle a lieu au niveau de l'API Kubernetes, pas dans la CI.** Kyverno, en mode `Enforce`, intercepte chaque création de Pod (et de Deployment, via ses règles générées automatiquement) dans le namespace applicatif. Il vérifie la signature avec la clé **publique** du pipeline. Une image construite et poussée à la main n'a pas de signature valide : elle est refusée, quel que soit l'outil utilisé (`kubectl`, Helm…). C'est le scénario T3.
4. **Pas de porte dérobée.** Une règle restreint les images au seul dépôt de la CI : sans elle, une image d'un autre registre n'aurait pas été vérifiée. `mutateDigest` remplace un tag par le digest vérifié. Enfin, la policy de durcissement refuse un Pod privilégié même si son image est signée.
5. **Traçabilité.** Les signatures et l'attestation SBOM sont inscrites dans le journal de transparence public Sigstore (Rekor). La SBOM attestée permet de savoir immédiatement si une image en production embarque un composant touché par une nouvelle CVE.

**Limite** : cette protection ne tient que si le RBAC empêche les développeurs de modifier les ClusterPolicies, la clé publique de confiance ou les labels du namespace, et si l'accès aux secrets CI est restreint.
