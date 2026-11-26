# TP4 DevSecOps — Supply chain et Policy-as-Code

Application web statique de démonstration et chaîne de contrôles : Gitleaks, SOPS/Age, Trivy (IaC, SCA, image), Semgrep (SAST), SBOM Syft, signature Cosign et admission Kyverno. Le rapport complet, la synthèse technique et le tableau de preuves sont dans [Solution_TP4_DevSecOps.md](./Solution_TP4_DevSecOps.md) ; les journaux d'exécution des scénarios T1 à T4 sont dans [`evidence/`](./evidence).

**Livrables** : [preuves d'exécution T1–T4 (captures + journaux)](./PREUVES_EXECUTION.md) · [synthèse technique](./SYNTHESE_TECHNIQUE.md) · [rapport détaillé](./Solution_TP4_DevSecOps.md)

| Élément | Emplacement |
|---|---|
| Pipeline CI/CD | `.github/workflows/secure-build.yml` (checks → publish → deploy-e2e → defectdojo) |
| Hook pre-commit | `.pre-commit-config.yaml` (Gitleaks) |
| Secrets chiffrés | `secrets/app.enc.yaml` (SOPS + Age, règle dans `.sops.yaml`) |
| Manifestes durcis | `k8s/app.yaml` |
| Policies Kyverno | `k8s/policies/require-hardened-pods.yaml`, `templates/verify-signed-images.yaml.in` (rendue avec `cosign.pub`) |
| Clé publique Cosign | `cosign.pub` |

## Prérequis (Windows / PowerShell 7)

Git, Docker Desktop, Kind, kubectl, Helm, Gitleaks, Trivy, Cosign, Syft, SOPS, Age et Python.

```powershell
python -m pip install --user pre-commit
python -m pre_commit install
pwsh -File .\tests\test-static.ps1
```

## Secrets

- Age : `pwsh -File .\scripts\new-age-key.ps1` (clé privée dans `~/.config/sops/age/keys.txt`, destinataire public écrit dans `.sops.yaml`).
- Chiffrer : `sops --encrypt --filename-override secrets/app.enc.yaml --output secrets/app.enc.yaml secrets/app.yaml` — `secrets/app.yaml` (clair) est ignoré par Git.
- Déchiffrer : `$env:SOPS_AGE_KEY_FILE = "$env:USERPROFILE\.config\sops\age\keys.txt"; sops --decrypt secrets/app.enc.yaml`.

## Démonstration locale complète (T3/T4 sans registre distant)

```powershell
pwsh -File .\scripts\setup-kind.ps1 -LocalRegistry
pwsh -File .\scripts\local-pipeline.ps1 -Tag local-signed -DigestFile signed.txt
pwsh -File .\scripts\local-pipeline.ps1 -Tag unsigned-test -NoSign -DigestFile unsigned.txt
pwsh -File .\tests\test-admission.ps1 -ImageRepository kind-registry:5000/tp4-secure-app `
  -SignedImage (Get-Content signed.txt) -UnsignedImage (Get-Content unsigned.txt) -SkipTransparencyLog
pwsh -File .\scripts\deploy.ps1 -Image (Get-Content signed.txt) -LocalRegistry
```

`local-pipeline.ps1` lit la clé privée hors dépôt (`~/.cosign/tp4/cosign.key`, phrase secrète dans `COSIGN_PASSWORD` ou `~/.cosign/tp4/password.txt`).

## Pipeline GitHub

Déclarer les secrets du dépôt `COSIGN_PRIVATE_KEY` (contenu de `cosign.key`) et `COSIGN_PASSWORD`. Sur `main`, le workflow publie l'image dans GHCR, la scanne, génère et atteste la SBOM, signe le digest, vérifie la signature avec `cosign.pub`, puis le job `deploy-e2e` la déploie dans un cluster Kind éphémère protégé par Kyverno et rejoue les tests d'admission. Les pull requests n'ont accès ni aux secrets ni à la publication.

## Bonus DefectDojo

Variables de dépôt `DEFECTDOJO_URL` et `DEFECTDOJO_ENGAGEMENT_ID`, secret `DEFECTDOJO_API_KEY` : le job `defectdojo` importe alors les rapports Semgrep et Trivy via `/api/v2/import-scan/`. En local :

```powershell
$env:DEFECTDOJO_URL = "https://defectdojo.example"
$env:DEFECTDOJO_API_KEY = "<clé injectée par le gestionnaire de secrets>"
pwsh -File .\scripts\import-defectdojo.ps1 -ReportPath .\evidence\trivy-image-report.json -ScanType "Trivy Scan" -EngagementId 123
```
