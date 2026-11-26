param(
    [switch]$StructureOnly
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function Assert-Contains {
    param([string]$Text, [string]$Pattern, [string]$Description)
    if ($Text -notmatch $Pattern) {
        throw "Echec : $Description"
    }
}

$manifestPath = Join-Path (Join-Path $root 'k8s') 'app.yaml'
$policyPath = Join-Path (Join-Path (Join-Path $root 'k8s') 'policies') 'require-hardened-pods.yaml'
$workflowPath = Join-Path (Join-Path (Join-Path $root '.github') 'workflows') 'secure-build.yml'
$hookPath = Join-Path $root '.pre-commit-config.yaml'
$dockerfilePath = Join-Path $root 'Dockerfile'
$javascriptPath = Join-Path (Join-Path $root 'app') 'main.js'
$templatePath = Join-Path (Join-Path $root 'templates') 'verify-signed-images.yaml.in'

foreach ($path in @($manifestPath, $policyPath, $workflowPath, $hookPath, $dockerfilePath, $javascriptPath, $templatePath)) {
    if (-not (Test-Path $path -PathType Leaf)) {
        throw "Fichier requis absent : $path"
    }
}

$manifest = Get-Content -Raw $manifestPath
$policy = Get-Content -Raw $policyPath
$workflow = Get-Content -Raw $workflowPath
$hook = Get-Content -Raw $hookPath
$dockerfile = Get-Content -Raw $dockerfilePath
$signatureTemplate = Get-Content -Raw $templatePath

Assert-Contains $manifest 'runAsNonRoot:\s*true' 'runAsNonRoot doit être activé'
Assert-Contains $manifest 'privileged:\s*false' 'privileged doit être désactivé'
Assert-Contains $manifest 'allowPrivilegeEscalation:\s*false' 'l''escalade de privilèges doit être désactivée'
Assert-Contains $manifest 'readOnlyRootFilesystem:\s*true' 'le système de fichiers doit être en lecture seule'
Assert-Contains $manifest 'drop:\s*(?:\r?\n)\s*-\s*ALL' 'toutes les capacités Linux doivent être supprimées'
Assert-Contains $manifest 'NetworkPolicy' 'une NetworkPolicy est requise'
Assert-Contains $manifest '@sha256:[0-9a-f]{64}' 'l''image doit être référencée par digest'
if ($manifest -match ':\s*latest(?:\s|$)') {
    throw 'Le manifeste ne doit pas référencer le tag latest'
}

Assert-Contains $policy 'validationFailureAction:\s*Enforce' 'la policy de durcissement doit être en mode Enforce'
Assert-Contains $policy 'image:\s*"\*@sha256:\*"' 'la policy doit imposer les images par digest'
Assert-Contains $signatureTemplate '__IMAGE_REPOSITORY__' 'le template de signature doit paramétrer le dépôt'
Assert-Contains $signatureTemplate '__COSIGN_PUBLIC_KEY__' 'le template de signature doit injecter la clé publique'
Assert-Contains $hook 'gitleaks' 'le hook pre-commit doit exécuter Gitleaks'
Assert-Contains $workflow 'fetch-depth:\s*0' 'la CI doit récupérer tout l''historique'
Assert-Contains $workflow 'gitleaks/gitleaks-action' 'la CI doit scanner les secrets'
Assert-Contains $workflow 'trivy-action' 'la CI doit exécuter Trivy'
Assert-Contains $workflow 'semgrep scan' 'la CI doit exécuter le SAST'
Assert-Contains $workflow 'cosign verify' 'la CI doit vérifier la signature produite'
if ($workflow -match 'uses:\s*[^\s#]+@(?![0-9a-f]{40}\b)') {
    throw 'Echec : toutes les actions GitHub doivent être épinglées par SHA de commit'
}
Assert-Contains $workflow 'scanners:\s*vuln,secret' 'la CI doit analyser les dépendances et secrets'
Assert-Contains $workflow 'syft' 'la CI doit générer une SBOM'
Assert-Contains $workflow 'cosign sign' 'la CI doit signer l''image'
Assert-Contains $dockerfile 'USER\s+101:101' 'l''image doit s''exécuter en utilisateur non-root'
Assert-Contains (Get-Content -Raw $javascriptPath) 'addEventListener' 'l''application de démonstration doit contenir du JavaScript analysable par le SAST'

Write-Output 'Tests structurels réussis.'

if ($StructureOnly) {
    exit 0
}

foreach ($tool in @('gitleaks', 'trivy')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "Outil requis absent : $tool. Installer les outils ou utiliser -StructureOnly."
    }
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("tp4-tests-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tempRoot | Out-Null
try {
    $secretFixture = Join-Path $tempRoot 'secret-fixture.txt'
    $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 36
    $random.GetBytes($bytes)
    $tokenBody = -join ($bytes | ForEach-Object { $alphabet[[int]$_ % $alphabet.Length] })
    $random.Dispose()
    $testSecret = 'GITHUB_TOKEN=ghp_' + $tokenBody
    Set-Content -NoNewline -Path $secretFixture -Value $testSecret

    $gitleaksOutput = & gitleaks dir $tempRoot --redact --exit-code 1 2>&1
    if ($LASTEXITCODE -eq 0) {
        throw 'Gitleaks aurait dû détecter la clé de test.'
    }
    if (($gitleaksOutput -join "`n") -notmatch 'AWS|GitHub|token|secret|leak') {
        throw "Gitleaks a échoué sans signaler de secret :`n$($gitleaksOutput -join "`n")"
    }
    Write-Output 'Test Gitleaks positif réussi (la fausse clé a été détectée).'

    & trivy config --severity CRITICAL,HIGH --exit-code 1 $root
    if ($LASTEXITCODE -ne 0) {
        throw 'Trivy a trouvé des problèmes HIGH/CRITICAL dans les manifestes conformes.'
    }
    Write-Output 'Test Trivy négatif réussi (les manifestes conformes passent).'

    $badDir = Join-Path $tempRoot 'bad-k8s'
    New-Item -ItemType Directory -Path $badDir | Out-Null
    $badManifest = $manifest.Replace('privileged: false', 'privileged: true')
    Set-Content -Path (Join-Path $badDir 'app.yaml') -Value $badManifest
    $trivyOutput = & trivy config --severity CRITICAL,HIGH --exit-code 1 $badDir 2>&1
    if ($LASTEXITCODE -eq 0) {
        throw 'Trivy aurait dû échouer sur le manifeste privilégié.'
    }
    if (($trivyOutput -join "`n") -notmatch 'privileged|KSV|AVD') {
        throw "Trivy a échoué sans rapporter la configuration privilégiée :`n$($trivyOutput -join "`n")"
    }
    Write-Output 'Test Trivy positif réussi (le manifeste privilégié est bloqué).'
}
finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
