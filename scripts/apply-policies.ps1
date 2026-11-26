param(
    [Parameter(Mandatory = $true)]
    [string]$ImageRepository,

    # Registre local hors ligne : les signatures ne sont pas publiées dans Rekor.
    [switch]$SkipTransparencyLog
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

if ($ImageRepository -notmatch '^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+$') {
    throw 'ImageRepository doit être un dépôt en minuscules, par ex. ghcr.io/organisation/application.'
}

$publicKeyPath = Join-Path $root 'cosign.pub'
$templatePath = Join-Path (Join-Path $root 'templates') 'verify-signed-images.yaml.in'
if (-not (Test-Path $publicKeyPath -PathType Leaf)) {
    throw "Clé publique absente : $publicKeyPath. Générer la paire Cosign et placer cosign.pub à la racine."
}

$publicKey = (Get-Content -Raw $publicKeyPath).Trim()
if ($publicKey -notmatch '^-----BEGIN PUBLIC KEY-----[\s\S]+-----END PUBLIC KEY-----$') {
    throw 'cosign.pub ne contient pas une clé publique PEM valide.'
}

$renderedKey = ($publicKey -split '\r?\n') -join "`n                      "
$policy = Get-Content -Raw $templatePath
# Le "@" final interdit les dépôts dont le nom commence par celui attendu (ex. app-evil).
$policy = $policy.Replace('__IMAGE_REPOSITORY__*', "$ImageRepository@*")
$policy = $policy.Replace('__IMAGE_REPOSITORY__', $ImageRepository)
$policy = $policy.Replace('__COSIGN_PUBLIC_KEY__', $renderedKey)
$policy = $policy.Replace('__IGNORE_TLOG__', $SkipTransparencyLog.IsPresent.ToString().ToLowerInvariant())
$renderedPath = Join-Path ([System.IO.Path]::GetTempPath()) ("tp4-verify-" + [guid]::NewGuid().ToString('N') + '.yaml')

try {
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($renderedPath, $policy, $utf8NoBom)
    $hardenedPolicy = Join-Path (Join-Path (Join-Path $root 'k8s') 'policies') 'require-hardened-pods.yaml'
    & kubectl apply -f $hardenedPolicy
    if ($LASTEXITCODE -ne 0) { throw 'Echec d''application de la policy de durcissement.' }
    & kubectl apply -f $renderedPath
    if ($LASTEXITCODE -ne 0) { throw 'Echec d''application de la policy de signature.' }
    & kubectl wait --for=condition=Ready clusterpolicy/require-hardened-app-pods --timeout=120s
    if ($LASTEXITCODE -ne 0) { throw 'La policy de durcissement n''est pas prête.' }
    & kubectl wait --for=condition=Ready clusterpolicy/require-signed-app-images --timeout=120s
    if ($LASTEXITCODE -ne 0) { throw 'La policy de signature n''est pas prête.' }
}
finally {
    Remove-Item -LiteralPath $renderedPath -Force -ErrorAction SilentlyContinue
}
