param(
    [Parameter(Mandatory = $true)]
    [string]$Image,

    # Démonstration locale : l'image est référencée kind-registry:5000 dans le cluster,
    # vérifiée via localhost:5001 depuis le poste, sans journal de transparence.
    [switch]$LocalRegistry,

    # Secret docker-registry (namespace app) pour un registre privé, ex. GHCR en CI.
    [string]$PullSecret
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

if ($Image -notmatch '^([a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+)@sha256:([a-f0-9]{64})$') {
    throw 'Image doit être <registre>/<dépôt>@sha256:<64 caractères hexadécimaux>.'
}
if ($Matches[4] -eq ('0' * 64)) {
    throw 'Le digest exemple doit être remplacé par le digest réel du pipeline.'
}

$imageRepository = $Matches[1]
$publicKey = Join-Path $root 'cosign.pub'
if (-not (Test-Path $publicKey -PathType Leaf)) {
    throw "Clé publique absente : $publicKey"
}
if (-not (Get-Command cosign -ErrorAction SilentlyContinue)) {
    throw 'cosign est requis pour vérifier la signature avant déploiement.'
}

$verifyRef = $Image
$verifyArgs = @('verify', '--key', $publicKey)
if ($LocalRegistry) {
    $verifyRef = $Image.Replace('kind-registry:5000/', 'localhost:5001/')
    $verifyArgs += @('--allow-http-registry', '--insecure-ignore-tlog')
}
& cosign @verifyArgs $verifyRef
if ($LASTEXITCODE -ne 0) {
    throw 'La vérification Cosign a échoué ; aucun déploiement effectué.'
}

$policyArgs = @{ ImageRepository = $imageRepository }
if ($LocalRegistry) { $policyArgs.SkipTransparencyLog = $true }
& (Join-Path $PSScriptRoot 'apply-policies.ps1') @policyArgs

$manifestPath = Join-Path (Join-Path $root 'k8s') 'app.yaml'
$manifest = Get-Content -Raw $manifestPath
$manifest = $manifest.Replace(
    'ghcr.io/example/tp4-secure-app@sha256:' + ('0' * 64),
    $Image
)
if ($PullSecret) {
    if ($PullSecret -notmatch '^[a-z0-9][a-z0-9.-]*$') { throw 'Nom de secret invalide.' }
    $manifest = $manifest.Replace('      serviceAccountName: api', "      serviceAccountName: api`n      imagePullSecrets:`n        - name: $PullSecret")
}
if ($manifest -match 'ghcr\.io/example/tp4-secure-app@sha256:') {
    throw 'Le manifeste conserve son image de démonstration.'
}

$renderedPath = Join-Path ([System.IO.Path]::GetTempPath()) ("tp4-app-" + [guid]::NewGuid().ToString('N') + '.yaml')
try {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($renderedPath, $manifest, $utf8NoBom)
    & kubectl apply -f $renderedPath
    if ($LASTEXITCODE -ne 0) { throw 'Echec d''application des ressources applicatives.' }
    & kubectl rollout status deployment/api -n app --timeout=180s
    if ($LASTEXITCODE -ne 0) { throw 'Le Deployment n''est pas Ready.' }
}
finally {
    Remove-Item -LiteralPath $renderedPath -Force -ErrorAction SilentlyContinue
}
