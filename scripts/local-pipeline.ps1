<#
.SYNOPSIS
  Rejoue localement le job "publish" du workflow CI (build -> push -> scan -> SBOM -> signature)
  contre le registre local créé par setup-kind.ps1 -LocalRegistry.

.DESCRIPTION
  -NoSign construit et pousse une image SANS signature (scénario T3).
  La clé privée Cosign est lue hors du dépôt (par défaut ~/.cosign/tp4/cosign.key) et la
  phrase secrète via COSIGN_PASSWORD ou ~/.cosign/tp4/password.txt.
  Écrit la référence par digest dans -DigestFile pour l'enchaîner avec deploy.ps1.
#>
param(
    [string]$Repository = 'tp4-secure-app',
    [string]$Tag = 'local-' + (Get-Date -Format 'yyyyMMddHHmmss'),
    [string]$PushRegistry = 'localhost:5001',
    [string]$ClusterRegistry = 'kind-registry:5000',
    [string]$CosignKey = (Join-Path $env:USERPROFILE '.cosign\tp4\cosign.key'),
    [string]$EvidenceDir = (Join-Path (Resolve-Path (Join-Path $PSScriptRoot '..')).Path 'evidence'),
    [string]$DigestFile,
    [switch]$NoSign
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
foreach ($tool in @('docker', 'trivy', 'syft', 'cosign')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) { throw "Outil requis absent : $tool" }
}
New-Item -ItemType Directory -Force $EvidenceDir | Out-Null

$pushRef = "$PushRegistry/${Repository}:$Tag"
Write-Output "==> Build $pushRef"
$buildArgs = @('build', '--pull', '-t', $pushRef)
if ($NoSign) {
    # Variante construite hors pipeline : un label suffit à produire un digest distinct.
    $buildArgs += @('--label', "tp4.unsigned-test=$Tag")
}
& docker @buildArgs $root
if ($LASTEXITCODE -ne 0) { throw 'docker build a échoué.' }
& docker push $pushRef
if ($LASTEXITCODE -ne 0) { throw 'docker push a échoué.' }

$repoDigest = (& docker inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' $pushRef) |
    Where-Object { $_ -like "$PushRegistry/$Repository@sha256:*" } | Select-Object -First 1
if (-not $repoDigest) { throw 'Digest introuvable après le push.' }
$digest = $repoDigest.Split('@')[1]
$hostImage = "$PushRegistry/$Repository@$digest"
$clusterImage = "$ClusterRegistry/$Repository@$digest"
Write-Output "==> Digest : $digest"

if ($NoSign) {
    Write-Output "Image NON signée poussée : $clusterImage"
    if ($DigestFile) { Set-Content -NoNewline -Path $DigestFile -Value $clusterImage }
    return
}

Write-Output '==> Scan de l''image (Trivy, HIGH/CRITICAL bloquants)'
& trivy image --severity CRITICAL,HIGH --exit-code 1 --format json --output (Join-Path $EvidenceDir 'trivy-image-report.json') $hostImage
$trivyExit = $LASTEXITCODE
& trivy image --severity CRITICAL,HIGH --format table $hostImage
if ($trivyExit -ne 0) { throw 'Vulnérabilités HIGH/CRITICAL détectées : image non signée.' }

Write-Output '==> SBOM CycloneDX (Syft)'
$sbomPath = Join-Path $EvidenceDir 'sbom.cdx.json'
& syft $hostImage -o "cyclonedx-json=$sbomPath"
if ($LASTEXITCODE -ne 0) { throw 'La génération de la SBOM a échoué.' }

Write-Output '==> Signature Cosign du digest + attestation SBOM'
if (-not (Test-Path $CosignKey -PathType Leaf)) { throw "Clé privée Cosign absente : $CosignKey" }
if (-not $env:COSIGN_PASSWORD) {
    $pwFile = Join-Path (Split-Path $CosignKey) 'password.txt'
    if (-not (Test-Path $pwFile)) { throw 'Définir COSIGN_PASSWORD.' }
    $env:COSIGN_PASSWORD = (Get-Content -Raw $pwFile).Trim()
}
# Registre local HTTP et hors ligne : pas d'envoi au journal de transparence public (Rekor),
# format de signature classique (.sig) lu par Kyverno.
$cosignArgs = @('--key', $CosignKey, '--yes', '--allow-http-registry', '--tlog-upload=false',
    '--new-bundle-format=false', '--use-signing-config=false')
& cosign sign @cosignArgs $hostImage
if ($LASTEXITCODE -ne 0) { throw 'cosign sign a échoué.' }
& cosign attest @cosignArgs --type cyclonedx --predicate $sbomPath $hostImage
if ($LASTEXITCODE -ne 0) { throw 'cosign attest a échoué.' }

Write-Output "Image signée : $clusterImage"
if ($DigestFile) { Set-Content -NoNewline -Path $DigestFile -Value $clusterImage }
