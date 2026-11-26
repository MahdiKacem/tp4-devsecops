# TP4 — Sécurisation de la Supply Chain et Policy-as-Code

## 1. Objectif et périmètre

Cette solution met en place une chaîne de livraison où :

1. les secrets sont détectés avant commit et dans l'historique Git ;
2. les manifestes Kubernetes sont contrôlés par Trivy avant le build ;
3. l'image est analysée, inventoriée (SBOM), puis signée avec Cosign ;
4. Kyverno bloque les images non signées et les Pods non conformes ;
5. les rapports peuvent être importés dans DefectDojo (bonus).

Les configurations sont maintenant matérialisées dans le dépôt de démonstration : workflow dans `.github/workflows/secure-build.yml`, application et image dans `app/` et `Dockerfile`, manifestes dans `k8s/`, politiques Kyverno dans `k8s/policies/` et `templates/`, scripts dans `scripts/`, tests dans `tests/`. Le manifeste de vérification Kyverno est rendu par script à partir de la clé publique Cosign pour éviter de commiter une clé générée ou un template invalide.

État d'avancement (26/11/2026) :

- **Exécuté localement et prouvé** (journaux dans `evidence/`, voir §9) : T1 (hook pre-commit), T2 (Trivy IaC), T3 (rejet Kyverno d'une image non signée) et T4 (pipeline rejoué localement : build → scan → SBOM → signature Cosign → admission Kyverno → Pod `Running`).
- **Exécuté en CI sur GitHub** (https://github.com/MahdiKacem/tp4-devsecops, preuves dans `evidence/ci/`) : T1 et T2 font échouer le pipeline avant tout build ; sur `main`, le pipeline complet est vert, y compris le job `deploy-e2e` qui rejoue T3/T4 dans un cluster Kind éphémère avec Kyverno.
- Le registre local (`kind-registry:5000`, exposé en `localhost:5001`) remplace GHCR pour la démonstration locale ; il est en HTTP et hors ligne, donc la signature locale n'est pas publiée dans Rekor (`ignoreTlog: true` uniquement dans ce mode). En CI, la signature est publiée dans Rekor et vérifiée avec le journal de transparence.

## 2. Secrets : Gitleaks, révocation et SOPS

### 2.1 Hook pre-commit

Installer Gitleaks et pre-commit, puis ajouter `.pre-commit-config.yaml` à la racine :

```yaml
repos:
  - repo: local
    hooks:
      - id: gitleaks
        name: Detect hardcoded secrets
        entry: gitleaks protect --staged --redact --no-banner
        language: system
        pass_filenames: false
        always_run: true
```

Installer le hook :

```powershell
python -m pip install --user pre-commit
python -m pre_commit install
```

Le hook analyse les changements staged et bloque le commit si un secret est détecté. L'analyse locale ne remplace pas l'analyse de l'historique dans la CI.

### 2.2 Remédiation d'une fuite

Si une clé a été exposée :

1. la révoquer dans le service émetteur ; supprimer le secret du code et le remplacer par une variable d'environnement ou un gestionnaire de secrets ;
2. rechercher la fuite dans l'historique complet avec Gitleaks ;
3. si la politique de l'organisation le demande, réécrire l'historique avec l'outil approuvé par l'équipe, puis coordonner le push forcé avec tous les contributeurs ;
4. considérer la clé comme compromise même si le commit a été supprimé ou réécrit.

Une réécriture Git n'annule jamais la nécessité de révoquer la clé.

### 2.3 Chiffrement avec SOPS et Age

Générer une clé Age locale et la garder hors du dépôt :

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\.config\sops\age" | Out-Null
age-keygen -o "$env:USERPROFILE\.config\sops\age\keys.txt"
age-keygen -y "$env:USERPROFILE\.config\sops\age\keys.txt"
```

Copier la clé publique `age1...` produite dans `.sops.yaml` :

```yaml
creation_rules:
  - path_regex: ^secrets/.*\.enc\.yaml$
    age: age1REMPLACER_PAR_LE_RECIPIENT_PUBLIC
```

Créer localement `secrets/app.yaml` avec les valeurs réelles, puis chiffrer vers le fichier qui sera commité :

```powershell
New-Item -ItemType Directory -Force secrets | Out-Null
sops --encrypt --input-type yaml --output secrets/app.enc.yaml secrets/app.yaml
```

Vérifier que `secrets/app.yaml` (plaintext) est ignoré par Git et ne l'ajouter jamais au dépôt. Le fichier `secrets/app.enc.yaml` peut être commité. Enregistrer la clé privée Age comme secret CI `SOPS_AGE_KEY` dans le gestionnaire de secrets du dépôt ; ne jamais la placer dans le dépôt. La clé Age privée doit être sauvegardée de façon sécurisée.

Pour déchiffrer localement :

```powershell
$env:SOPS_AGE_KEY_FILE = "$env:USERPROFILE\.config\sops\age\keys.txt"
sops --decrypt secrets/app.enc.yaml
```

Dans une étape de déploiement CI, fournir `SOPS_AGE_KEY` à SOPS et écrire le résultat uniquement dans l'espace temporaire du runner. Ne pas afficher le contenu déchiffré dans les logs et supprimer le fichier temporaire à la fin du job.

## 3. IaC et manifeste Kubernetes durci

### 3.1 Namespace et workload

Exemple de `k8s/app.yaml`. Remplacer le digest d'image par celui produit par le workflow. L'image est référencée par digest plutôt que par un tag mutable.

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: app
  labels:
    security.example.com/enforced: "true"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: api
          image: ghcr.io/OWNER/APP@sha256:REMPLACER_PAR_LE_DIGEST_SHA256
          ports:
            - name: http
              containerPort: 8080
              protocol: TCP
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: app
spec:
  selector:
    app: api
  ports:
    - name: http
      port: 80
      targetPort: http
      protocol: TCP
  type: ClusterIP
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-restrict-traffic
  namespace: app
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8080
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
```

Cette NetworkPolicy refuse par défaut les autres flux entrants et sortants vers les Pods `api`. Adapter l'étiquette du contrôleur d'entrée au cluster utilisé et ajouter une règle de sortie strictement limitée si l'API doit joindre une base de données ou un autre service. Vérifier que le CNI du cluster prend en charge les NetworkPolicies.

### 3.2 Scan IaC bloquant

La commande utilisée par le workflow est :

```bash
trivy config --severity CRITICAL,HIGH --exit-code 1 k8s/
```

Elle fait échouer le job si Trivy trouve une anomalie de sévérité HIGH ou CRITICAL. Le rapport doit être corrigé ou faire l'objet d'une exception documentée et limitée ; ne pas désactiver le contrôle pour obtenir un build vert.

## 4. SBOM et signature Cosign

### 4.1 Générer la paire de clés

Dans un environnement sécurisé, générer la paire :

```bash
cosign generate-key-pair
```

Conserver `cosign.key` et sa phrase secrète hors du dépôt. Enregistrer le contenu de la clé privée comme secret CI `COSIGN_PRIVATE_KEY`, la phrase secrète comme `COSIGN_PASSWORD`, et stocker la clé publique `cosign.pub` dans le dépôt ou dans un emplacement de configuration approuvé. Limiter l'accès aux secrets CI aux workflows et branches autorisés.

### 4.2 Workflow GitHub Actions

> **Version effective** : le fichier `.github/workflows/secure-build.yml` du dépôt fait foi. Il reprend l'exemple ci-dessous avec ces durcissements :
>
> - toutes les actions sont **épinglées par SHA de commit** (le tag `trivy-action` a fait l'objet d'une réécriture malveillante en 2026 ; un tag est mutable, un SHA ne l'est pas). Dependabot les met à jour avec un délai de 7 jours (`cooldown`) ;
> - job `checks` : Gitleaks (historique complet) → Trivy IaC bloquant → SAST Semgrep (image épinglée par digest, l'action `semgrep-action` étant dépréciée) → SCA Trivy fs → tests structurels, puis export JSON des rapports ;
> - job `publish` (uniquement `main`, après `checks`) : build/push → scan Trivy de l'image → SBOM Syft → `cosign sign` + `cosign attest` (SBOM) → `cosign verify` avec la `cosign.pub` versionnée. Cosign est épinglé en v2.6.5 pour produire le format de signature lu par Kyverno ;
> - job `deploy-e2e` : cluster Kind éphémère + Kyverno en Enforce, déploiement du digest signé et tests d'admission (T3/T4 en CI) ;
> - job `defectdojo` (bonus) : import des rapports si la variable `DEFECTDOJO_URL` est définie.

Exemple initial `.github/workflows/secure-build.yml`. Il suppose que les étapes existantes de tests, SAST et SCA sont ajoutées avant le build. Le scan Gitleaks est le premier contrôle après checkout ; `fetch-depth: 0` rend l'historique disponible. Le workflow publie l'image, scanne l'image publiée, génère la SBOM et signe exactement le digest produit.

```yaml
name: Secure build

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  secure-build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    env:
      IMAGE: ghcr.io/${{ github.repository }}

    steps:
      - name: Checkout complete history
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Scan secrets and Git history
        uses: gitleaks/gitleaks-action@v2

      - name: Scan Kubernetes and IaC
        uses: aquasecurity/trivy-action@0.28.0
        with:
          scan-type: config
          scan-ref: k8s/
          severity: CRITICAL,HIGH
          exit-code: "1"

      # Ajouter ici les tests, le SAST et le SCA déjà utilisés par le projet.

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to GHCR
        if: github.event_name == 'push' && github.ref == 'refs/heads/main'
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push image
        if: github.event_name == 'push' && github.ref == 'refs/heads/main'
        id: build
        uses: docker/build-push-action@v6
        with:
          context: .
          push: true
          tags: ${{ env.IMAGE }}:${{ github.sha }}

      - name: Scan pushed image
        if: github.event_name == 'push' && github.ref == 'refs/heads/main'
        uses: aquasecurity/trivy-action@0.28.0
        with:
          image-ref: ${{ env.IMAGE }}@${{ steps.build.outputs.digest }}
          severity: CRITICAL,HIGH
          exit-code: "1"

      - name: Install Syft
        if: github.event_name == 'push' && github.ref == 'refs/heads/main'
        uses: anchore/sbom-action/download-syft@v0

      - name: Generate CycloneDX SBOM
        if: github.event_name == 'push' && github.ref == 'refs/heads/main'
        run: syft "${IMAGE}@${{ steps.build.outputs.digest }}" -o cyclonedx-json=sbom.cdx.json

      - name: Upload SBOM artifact
        if: github.event_name == 'push' && github.ref == 'refs/heads/main'
        uses: actions/upload-artifact@v4
        with:
          name: sbom-cyclonedx
          path: sbom.cdx.json
          if-no-files-found: error

      - name: Install Cosign
        if: github.event_name == 'push' && github.ref == 'refs/heads/main'
        uses: sigstore/cosign-installer@v3

      - name: Sign immutable image digest
        if: github.event_name == 'push' && github.ref == 'refs/heads/main'
        env:
          COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}
          COSIGN_PASSWORD: ${{ secrets.COSIGN_PASSWORD }}
        run: |
          set -eu
          printf '%s' "$COSIGN_PRIVATE_KEY" > "$RUNNER_TEMP/cosign.key"
          chmod 600 "$RUNNER_TEMP/cosign.key"
          cosign sign --yes --key "$RUNNER_TEMP/cosign.key" \
            "${IMAGE}@${{ steps.build.outputs.digest }}"
          rm -f "$RUNNER_TEMP/cosign.key"
```

Dans un dépôt réel, épingler les GitHub Actions à des SHA de commit approuvés plutôt qu'à des tags, puis mettre à jour ces SHA selon le processus de maintenance du projet. Les secrets Cosign ne doivent être disponibles qu'aux événements de confiance. Pour les pull requests externes, le workflow ne publie ni ne signe d'image et n'a pas accès aux secrets.

La SBOM est ici conservée comme artefact de build. La signature porte sur le digest immuable ; le job d'admission vérifie ce digest. Si le build échoue au scan d'image, il ne doit pas être signé ni déployé.

## 5. Cluster local et policies Kyverno

### 5.1 Démarrer Kind et installer Kyverno

Prérequis : Docker, `kind`, `kubectl` et Helm installés.

```bash
kind create cluster --name tp4
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm install kyverno kyverno/kyverno --namespace kyverno --create-namespace
kubectl wait --for=condition=Available deployment --all -n kyverno --timeout=180s
```

Enregistrer la clé publique Cosign issue de la paire de clés précédente dans le fichier de policy ci-dessous. Le contenu PEM complet doit être conservé, y compris les lignes `BEGIN` et `END`.

### 5.2 Vérification de signature en mode Enforce

Fichier `k8s/policies/verify-signed-images.yaml` :

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-signed-app-images
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: verify-app-image-signature
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaceSelector:
                matchLabels:
                  security.example.com/enforced: "true"
      verifyImages:
        - imageReferences:
            - "ghcr.io/OWNER/APP:*"
          required: true
          verifyDigest: true
          mutateDigest: true
          attestors:
            - count: 1
              entries:
                - keys:
                    publicKeys: |-
                      -----BEGIN PUBLIC KEY-----
                      REMPLACER_PAR_LE_CONTENU_DE_cosign.pub
                      -----END PUBLIC KEY-----
```

> **Version effective** : `templates/verify-signed-images.yaml.in`, rendu par `scripts/apply-policies.ps1` (dépôt d'image + contenu de `cosign.pub`). Elle ajoute une règle `restrict-to-pipeline-repository` : `verifyImages` ne vérifie **que** les images correspondant à `imageReferences`, donc sans cette règle une image d'un autre registre (`docker.io/...`) n'était tout simplement pas vérifiée — contournement trivial de la chaîne de confiance. Le motif se termine par `@*` (`<dépôt>@*`) pour qu'un dépôt nommé `<dépôt>-evil` ne corresponde pas.
>
> Kyverno est installé en version épinglée (chart 3.6.4, Kyverno 1.16.4). Le nœud Kind est épinglé en Kubernetes 1.33 : le noyau WSL2 de Docker Desktop utilisé ici est en cgroup v1, que Kubernetes 1.35 refuse.

Cette règle s'applique aux Pods des namespaces portant le label choisi, et non aux composants système. Remplacer le motif d'image et la clé publique. Garder `verifyDigest: true` pour exiger une vérification liée au digest et `required: true` pour refuser une image sans signature valide.

### 5.3 Exigences de durcissement

Fichier `k8s/policies/require-hardened-pods.yaml` :

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-hardened-app-pods
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    - name: require-non-root-and-restricted-containers
      match:
        any:
          - resources:
              kinds:
                - Pod
              namespaceSelector:
                matchLabels:
                  security.example.com/enforced: "true"
      validate:
        message: >-
          Les Pods applicatifs doivent fonctionner sans root, sans privilèges,
          avec un système de fichiers en lecture seule et des ressources limitées.
        pattern:
          spec:
            securityContext:
              runAsNonRoot: true
            containers:
              - image: "!*:latest"
                securityContext:
                  privileged: false
                  allowPrivilegeEscalation: false
                  readOnlyRootFilesystem: true
                  capabilities:
                    drop:
                      - ALL
                resources:
                  requests:
                    cpu: "?*"
                    memory: "?*"
                  limits:
                    cpu: "?*"
                    memory: "?*"
            =(initContainers):
              - image: "!*:latest"
                securityContext:
                  privileged: false
                  allowPrivilegeEscalation: false
                  readOnlyRootFilesystem: true
                  capabilities:
                    drop:
                      - ALL
```

Le motif est volontairement appliqué au namespace marqué ; le label doit être posé uniquement sur les namespaces applicatifs gouvernés par ces exigences. Valider les patterns avec la version de Kyverno installée avant le passage en production, notamment si les Pods ont des init containers ou si le schéma des ressources diffère. Ajouter les demandes/limites de ressources aux init containers si le projet en utilise.

Appliquer le namespace, les policies et le workload :

```bash
kubectl apply -f k8s/policies/verify-signed-images.yaml
kubectl apply -f k8s/policies/require-hardened-pods.yaml
kubectl apply -f k8s/app.yaml
kubectl get clusterpolicy
kubectl get pods -n app
```

Ne pas considérer un `kubectl apply` des policies comme preuve suffisante : vérifier leur état `Ready`/sans erreur dans `kubectl describe clusterpolicy ...`, puis exécuter les tests d'admission.

## 6. Scénarios de validation

Faire les essais sur un environnement de test, avec un dépôt de démonstration et des valeurs fictives. Conserver les sorties de commandes ou les logs de CI comme preuves. Le document ne prétend pas que ces commandes ont déjà été exécutées dans le dossier fourni.

### T1 — Commit contenant une fausse clé

Depuis PowerShell, créer un fichier de test avec une valeur de test reconnue par le détecteur, le staged, puis tenter un commit :

```powershell
$alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$bytes = New-Object byte[] 36
$rng.GetBytes($bytes)
$token = 'GITHUB_TOKEN=ghp_' + (-join ($bytes | ForEach-Object { $alphabet[[int]$_ % $alphabet.Length] }))
$rng.Dispose()
$token | Set-Content .gitleaks-test.txt
git add -f .gitleaks-test.txt
git commit -m "test: verify secret scanning"
```

Résultat attendu : le hook pre-commit refuse le commit. Dans la CI, le job Gitleaks doit aussi échouer. Après le test, retirer le fichier de l'index et du répertoire :

```powershell
git reset -- .gitleaks-test.txt
Remove-Item .gitleaks-test.txt
```

Le fichier de test ne doit pas avoir été commité. Pour valider spécifiquement la recherche d'historique, exécuter le scan CI sur une branche de test contenant le commit de démonstration, puis supprimer cette branche conformément au processus du dépôt.

### T2 — Manifeste privilégié

Dans une branche jetable, modifier temporairement le Pod pour inclure `privileged: true`, puis exécuter :

```bash
trivy config --severity CRITICAL,HIGH --exit-code 1 k8s/
```

Résultat attendu : code de sortie non nul et job CI en échec avant le build. Ne pas appliquer ce manifeste au cluster de production.

### T3 — Image non signée

Pousser une image de test non signée sous le registre et le motif surveillés par la policy (avec une référence de test qui n'utilise pas `latest`), puis tenter de créer un Pod dans le namespace marqué :

```bash
kubectl run unsigned-test -n app \
  --image=ghcr.io/OWNER/APP:unsigned-test \
  --restart=Never
```

Résultat attendu : rejet par Kyverno car aucune signature valide correspondant à la clé publique n'est disponible. Vérifier le message d'admission dans la sortie de `kubectl` et les événements/policies Kyverno. Utiliser un tag de test réellement poussé ; remplacer le nom d'image par celui surveillé.

### T4 — Artefact conforme et signé

Lancer le workflow sur la branche autorisée. Vérifier que :

- Gitleaks, Trivy IaC, tests, SAST/SCA et scan d'image passent ;
- l'artefact SBOM CycloneDX est disponible dans les artefacts du workflow ;
- la signature Cosign concerne exactement le digest poussé ;
- le Deployment référence ce même digest ;
- Kyverno accepte le Pod et celui-ci devient `Ready`.

Commandes de vérification :

```bash
cosign verify --key cosign.pub ghcr.io/OWNER/APP@sha256:DIGEST
kubectl rollout status deployment/api -n app
kubectl get pods -n app
kubectl describe clusterpolicy require-signed-app-images
kubectl describe clusterpolicy require-hardened-app-pods
```

### Tableau de preuves à compléter après exécution

| Test | Résultat local (`evidence/`) | Résultat CI GitHub (`evidence/ci/`, dépôt MahdiKacem/tp4-devsecops) |
|---|---|---|
| T1 | `T1-precommit-gitleaks.log` : commit refusé par le hook (`leaks found: 3`), aucun commit créé. | Clé AWS factice : **push refusé par GitHub Push Protection** (`T1-github-push-protection.log`). Clé API factice commitée avec `--no-verify` : job `checks` en échec à l'étape Gitleaks (`RuleID: generic-api-key`, `app/config.js`), aucune étape suivante (`T1-ci-gitleaks-checks.log`, run 45829330323). |
| T2 | `T2-test-static.log` : manifeste conforme accepté, variante `privileged: true` rejetée. | Job `checks` en échec à l'étape Trivy IaC : `KSV-0017 (HIGH) ... should set 'securityContext.privileged' to false` ; `publish` et `deploy-e2e` sautés, aucune image construite (`T2-ci-trivy-iac-checks.log`, run 45829267958). |
| T3 | `T3-kubectl-unsigned.log` : `require-signed-app-images ... no signatures found`. `T3-admission-tests.log` : image non signée, Pod privilégié, `:latest` et registre tiers refusés. | Job `deploy-e2e` : les mêmes 5 tests d'admission réussis contre GHCR (`T4-ci-deploy-e2e.log`). |
| T4 | `T4-*.log` : 0 HIGH/CRITICAL, SBOM attestée, `cosign verify` OK, Deployment `1/1`, HTTP 200. | Run 45828547561 entièrement vert : `checks` → `publish` (image `ghcr.io/mahdikacem/tp4-devsecops@sha256:0d482baf…`, signature et attestation inscrites dans Rekor, `cosign verify` OK, artefact `sbom-cyclonedx` → `ci/sbom.cdx.json`) → `deploy-e2e` (rollout réussi, Pod `1/1 Running`) (`T4-ci-publish.log`, `T4-ci-deploy-e2e.log`). |

Les branches de test T1/T2 ont été supprimées après collecte des preuves.

## 7. Bonus — Import DefectDojo

Créer un produit et un engagement dans DefectDojo, puis conserver l'API key dans un secret CI `DEFECTDOJO_API_KEY`. Exporter les rapports des outils au format accepté par la version de DefectDojo utilisée. Le nom `scan_type` doit correspondre exactement à un parser activé dans cette instance.

Exemple d'appel depuis un runner Linux, à adapter au type de rapport et à l'URL de l'instance :

```bash
curl --fail-with-body --request POST \
  "$DEFECTDOJO_URL/api/v2/import-scan/" \
  --header "Authorization: Token $DEFECTDOJO_API_KEY" \
  --form "scan_type=Trivy Scan" \
  --form "engagement=$DEFECTDOJO_ENGAGEMENT_ID" \
  --form "file=@trivy-report.json" \
  --form "active=true" \
  --form "verified=false"
```

Ne pas passer la clé API en clair dans le dépôt ou dans les arguments affichés des scripts. Restreindre l'API key à l'import des scans si l'instance permet cette granularité, et vérifier la réponse HTTP ainsi que l'apparition du rapport dans l'engagement.

## 8. Synthèse technique

### 8.1 Vulnérabilités corrigées dans les manifestes IaC

| Mauvaise pratique | Risque | Correction (`k8s/app.yaml`) | Contrôles (Trivy ne bloque que HIGH/CRITICAL ; Kyverno bloque toujours) |
|---|---|---|---|
| Exécution en root | Évasion de conteneur facilitée, écriture sur l'hôte via volumes | `runAsNonRoot: true`, `runAsUser/runAsGroup: 101`, `USER 101:101` dans le Dockerfile | Trivy (KSV012), Kyverno `require-hardened-app-pods` |
| `privileged: true` | Accès complet aux devices et au noyau de l'hôte | `privileged: false` | Trivy (KSV017), Kyverno |
| Escalade de privilèges | Binaires setuid → root | `allowPrivilegeEscalation: false` | Trivy (KSV001), Kyverno |
| Capacités Linux par défaut | `NET_RAW`, `CHOWN`… exploitables | `capabilities.drop: [ALL]` | Trivy (KSV003), Kyverno |
| FS racine inscriptible | Persistance / modification du binaire | `readOnlyRootFilesystem: true` + `emptyDir` pour `/tmp`, cache et run nginx | Trivy (KSV014), Kyverno |
| Tag mutable `:latest` | Image remplaçable après validation | Image par digest `@sha256:` | Kyverno (motif `*@sha256:*`), test statique |
| Pas de limites | Déni de service par épuisement du nœud | `requests`/`limits` CPU et mémoire | Trivy (KSV011/015/016/018), Kyverno |
| Pas de cloisonnement réseau | Mouvement latéral, exfiltration | NetworkPolicy deny-all sauf entrée depuis l'ingress et sortie DNS | Test statique |
| Token SA monté | Vol de jeton pour attaquer l'API | ServiceAccount dédié, `automountServiceAccountToken: false` | Trivy |
| Profil seccomp absent | Surface d'appels système complète | `seccompProfile: RuntimeDefault` | Trivy |

Constats supplémentaires pendant l'exécution :

- l'image de base épinglée initialement (`nginx-unprivileged:stable-alpine`) portait 5 CVE CRITICAL et 15 HIGH corrigées en amont : le scan d'image a bloqué la signature. Correction : variante `mainline-alpine-slim` épinglée par digest + `apk upgrade` au build → 0 HIGH/CRITICAL ;
- le SAST (Semgrep) signalait les actions GitHub référencées par tag mutable et l'absence de `cooldown` Dependabot : corrigé (SHA + cooldown 7 jours) ;
- un fichier parasite nommé `GITHUB_TOKEN=ghp_…` (reste d'un premier essai T1) se trouvait à la racine ; il a été supprimé avant tout commit. Le token étant généré aléatoirement, il n'y a rien à révoquer.

### 8.2 Pourquoi la CI ne peut pas être contournée

1. La clé privée Cosign n'existe que dans les secrets GitHub (accessibles au seul job `publish`, sur `main`, après réussite de tous les contrôles). Un développeur ne la possède pas.
2. La signature porte sur le **digest** (empreinte SHA-256 du manifeste) : modifier un seul octet de l'image change le digest et invalide la signature ; réutiliser un tag ne sert à rien.
3. Kyverno, en mode `Enforce` au niveau de l'API Kubernetes, vérifie chaque Pod du namespace gouverné avec la clé **publique** : une image construite localement et poussée (T3) n'a aucune signature valide → refus, quel que soit l'outil (`kubectl`, Helm, Argo…). `mutateDigest` réécrit les tags en digest pour que ce soit l'image vérifiée qui soit exécutée.
4. La règle `restrict-to-pipeline-repository` ferme la porte des registres tiers ; la policy de durcissement refuse les Pods privilégiés même si l'image est signée.
5. La SBOM attestée (`cosign attest`) relie l'inventaire des composants au même digest, ce qui permet de savoir rapidement si une image en production est concernée par une nouvelle CVE.

Les risques initiaux sont traités à plusieurs niveaux :

- **Secrets** : Gitleaks bloque les nouvelles fuites au commit et analyse l'historique en CI. Les secrets déjà exposés sont révoqués ; SOPS chiffre les secrets au repos dans Git et la clé Age privée reste dans le gestionnaire de secrets.
- **IaC** : Trivy bloque les manifestes comportant des problèmes critiques/élevés. Les Pods sont exécutés sans root ni privilèges, avec capacités supprimées, système de fichiers en lecture seule et limites de ressources.
- **Réseau** : la NetworkPolicy limite les flux au DNS et au contrôleur d'entrée explicitement autorisé ; les dépendances applicatives doivent faire l'objet de règles minimales dédiées.
- **Supply chain** : la SBOM donne l'inventaire des composants. Cosign signe le digest immuable de l'image produite par le pipeline ; Kyverno n'admet que les images correspondant au registre attendu et vérifiées avec la clé publique.
- **Anti-contournement** : un déploiement manuel d'une image non signée ou d'un Pod non conforme est rejeté au niveau de l'API Kubernetes, indépendamment du chemin utilisé pour soumettre le manifeste.

La protection n'est complète que si les droits RBAC empêchent les développeurs non autorisés de modifier les policies, leur clé de confiance et les labels de namespace, et si les secrets, clés, images et workflows sont administrés selon le principe du moindre privilège.

## 9. Rejouer la démonstration locale

```powershell
pwsh -File .\tests\test-static.ps1                                   # T2 (+ contrôle Gitleaks)
pwsh -File .\scripts\setup-kind.ps1 -LocalRegistry                   # Kind + registre + Kyverno
pwsh -File .\scripts\local-pipeline.ps1 -Tag local-signed  -DigestFile signed.txt     # T4 : build/scan/SBOM/signature
pwsh -File .\scripts\local-pipeline.ps1 -Tag unsigned-test -NoSign -DigestFile unsigned.txt  # T3 : image hors CI
pwsh -File .\tests\test-admission.ps1 -ImageRepository kind-registry:5000/tp4-secure-app `
  -SignedImage (Get-Content signed.txt) -UnsignedImage (Get-Content unsigned.txt) -SkipTransparencyLog
pwsh -File .\scripts\deploy.ps1 -Image (Get-Content signed.txt) -LocalRegistry      # T4 : déploiement
```

Clés hors dépôt : Age dans `~/.config/sops/age/keys.txt`, Cosign dans `~/.cosign/tp4/` (`cosign.key` + `password.txt`). Seuls `cosign.pub`, `.sops.yaml` et `secrets/app.enc.yaml` sont versionnés.
