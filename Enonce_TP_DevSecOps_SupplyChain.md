## Sécurisation de la Supply Chain Logicielle et Gouvernance « Policy-as-Code »

Prérequis acquis : SAST, SCA, DAST, RASP et analyse de vulnérabilités des images de conteneurs.

Contexte opérationnel : L'équipe produit d'une application web (API REST et interface front-end) a déjà intégré des contrôles SAST, SCA, DAST, un scan d'images Docker ainsi qu'une protection RASP en exécution. Toutefois, un audit de sécurité révèle deux failles critiques : un développeur peut déployer manuellement une image non vérifiée directement sur le cluster de production, et l'infrastructure de déploiement expose des configurations trop permissives ainsi que des secrets en clair.

## 1. Objectifs Pédagogiques et Architecture Cible

L'objectif de ce TP est de dépasser la simple détection de vulnérabilités applicatives pour instaurer une chaîne de livraison logicielle Zero-Trust et une gouvernance automatisée. Vous devez garantir cryptographiquement qu'aucun artefact ne puisse être exécuté sur le cluster Kubernetes s'il n'a pas été produit, analysé et signé par le pipeline CI/CD.

|   | Domaine de sécurité Outils de référence Rôle dans la chaîne DevSecOps |
| --- | --- |
|   | Gestion des secrets Gitleaks, SOPS / Age Détection préventive avant commit, blocage en ou Vault CI et chiffrement des secrets applicatifs. Sécurité IaC Checkov ou Trivy Audit statique des manifestes Kubernetes et durcissement des contextes d'exécution. Supply Chain & SBOM Syft, Cosign Génération de l'inventaire logiciel (SBOM) et (Sigstore) signature cryptographique des images. Policy-as-Code Kubernetes (Kind/K3s), Contrôle d'admission bloquant (Enforce) Kyverno vérifiant signatures et conformité des pods. Gouvernance (Bonus) DefectDojo Agrégation centralisée, déduplication et suivi des vulnérabilités multi-outils. |

## 2. Travail Demandé — Étapes de Mise en Œuvre

## Étape 1 : Verrouillage des secrets (Pre-commit et CI)

À partir du dépôt de départ fourni contenant volontairement une clé API exposée dans le code et l'historique Git, vous devez éliminer toute fuite d'identifiants :


- Configurer Gitleaks en hook local pre-commit afin d'empêcher tout commit contenant un secret.

- Intégrer une étape bloquante secret-scan dès le début du pipeline CI (GitLab CI ou GitHub Actions), incluant l'analyse de l'historique des commits.

- Révoquer/remplacer les secrets exposés et externaliser les variables sensibles via SOPS (chiffrées dans le dépôt avec une clé Age) ou HashiCorp Vault.

## Étape 2 : Sécurisation de l'Infrastructure as Code (IaC)

Les manifestes de déploiement Kubernetes fournis contiennent plusieurs mauvaises pratiques (exécution en root, mode privilégié, absence de cloisonnement réseau, tag mutable :latest).

- Ajouter une étape d'analyse IaC dans le pipeline avec trivy config ou checkov configurée pour faire échouer le build en cas de non-conformité critique ou élevée.

- Durcir les manifestes Kubernetes : imposer runAsNonRoot: true, privileged: false, capabilities Linux (drop: ["ALL"]). allowPrivilegeEscalation: false, readOnlyRootFilesystem: true et supprimer toutes les

- Définir des limites de ressources (CPU/Mémoire), référencer l'image par digest SHA-256 ou version immuable, et ajouter une NetworkPolicy restreignant les flux entrants et sortants.

## Étape 3 : Chaîne de confiance — SBOM et Signature Cryptographique

Après le passage des contrôles applicatifs (SAST, SCA et scan d'image via Trivy ou Grype), l'artefact validé doit être rendu traçable et infalsifiable :

- Générer automatiquement un SBOM (format CycloneDX ou SPDX) de l'image Docker construite à l'aide de Syft et le conserver comme artefact de build (ou l'attacher à l'image).

- Générer une paire de clés asymétriques Cosign (cosign generate-key-pair) et stocker la clé privée de manière sécurisée dans les variables protégées de la CI.

- Signer l'image poussée sur le registre de conteneurs avec cosign sign avant la phase de déploiement.

## Étape 4 : Gouvernance au déploiement (Policy-as-Code avec Kyverno)

Déployez un cluster Kubernetes local (Kind ou K3s) et installez le moteur de politiques Kyverno afin de verrouiller l'API Kubernetes :

- Rédiger et appliquer une ClusterPolicy en mode Enforce (verifyImages) exigeant que toute image déployée dans le namespace applicatif soit signée avec la clé publique de votre pipeline CI.

- Appliquer une seconde ClusterPolicy en mode Enforce rejetant tout Pod ne respectant pas les règles de durcissement définies à l'étape 2 (interdiction du privilège root, interdiction du tag :latest).


## Étape 5 (Bonus) : Agrégation et gestion de la dette de sécurité

Configurez l'envoi automatisé des rapports JSON générés par vos outils (SAST, SCA, IaC, Container) vers une instance DefectDojo via son API REST (/api/v2/import-scan/) afin de centraliser le triage et la déduplication des alertes.

## 3. Scénarios de Validation (Tests de Résilience)

Pour valider votre architecture, vous devez exécuter et documenter les quatre scénarios de test suivants :

| Test Action simulée | Contrôle sollicité Résultat attendu |   |
| --- | --- | --- |
| T1 Pousser un commit contenant une | Hook pre-commit / | Rejet immédiat du commit ou |
| fausse clé d'accès cloud | Stage CI Gitleaks | échec du pipeline CI. |
| (AWS/API). |   |   |
| T2 Modifier le manifeste K8s avec | Stage CI IaC | Échec du pipeline avant toute |
| privileged: true et lancer la | (Checkov / Trivy) | construction d'image. |
| CI. |   |   |
| T3 Construire une image localement, | Admission Controller | Blocage par l'API K8s |
| la pousser et exécuter kubectl | Kyverno | (signature Cosign absente ou |
| apply. |   | invalide). |
| T4 Exécuter le pipeline complet sur | CI complète + | Déploiement autorisé, SBOM |
| du code sain et conforme. | Cosign + Kyverno | généré et pod actif. |

## 4. Livrables Attendus

À l'issue de la séance, chaque binôme ou groupe devra remettre :

- Le dépôt Git complet incluant le fichier de configuration CI/CD, les manifestes Kubernetes durcis, le fichier de secrets chiffrés (SOPS) et les politiques ClusterPolicy Kyverno.

- Les preuves d'exécution (journaux de pipeline et captures d'écran de terminal) démontrant clairement le comportement du système sur chacun des 4 scénarios de validation (T1 à T4).

- Une synthèse technique courte détaillant les vulnérabilités corrigées dans les manifestes IaC et expliquant comment la chaîne cryptographique empêche le contournement de la CI.
