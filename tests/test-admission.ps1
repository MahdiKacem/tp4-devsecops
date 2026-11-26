param(
    [Parameter(Mandatory = $true)]
    [string]$SignedImage,

    [Parameter(Mandatory = $true)]
    [string]$UnsignedImage,

    [Parameter(Mandatory = $true)]
    [string]$ImageRepository,

    [switch]$SkipTransparencyLog
)

$ErrorActionPreference = 'Stop'
$digestPattern = '^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+@sha256:[a-f0-9]{64}$'
foreach ($image in @($SignedImage, $UnsignedImage)) {
    if ($image -notmatch $digestPattern) {
        throw "Image de test invalide : $image. Utiliser une référence par digest."
    }
    if (-not $image.StartsWith("$ImageRepository@", [System.StringComparison]::Ordinal)) {
        throw "L'image $image n'appartient pas au dépôt surveillé $ImageRepository."
    }
}

$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
& (Join-Path (Join-Path $root 'scripts') 'apply-policies.ps1') -ImageRepository $ImageRepository -SkipTransparencyLog:$SkipTransparencyLog

$appManifest = Join-Path (Join-Path $root 'k8s') 'app.yaml'
& kubectl apply --dry-run=client -f $appManifest
if ($LASTEXITCODE -ne 0) { throw 'kubectl ou le manifeste applicatif est invalide.' }
& kubectl create namespace app --dry-run=client -o yaml | kubectl apply -f -
if ($LASTEXITCODE -ne 0) { throw 'Impossible de préparer le namespace de test.' }
& kubectl label namespace app security.example.com/enforced=true --overwrite
if ($LASTEXITCODE -ne 0) { throw 'Impossible de marquer le namespace applicatif.' }

function New-PodManifest {
    param([string]$Name, [string]$Image, [bool]$Privileged)
    $privilegedValue = $Privileged.ToString().ToLowerInvariant()
    return @"
apiVersion: v1
kind: Pod
metadata:
  name: $Name
  namespace: app
spec:
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 101
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: test
      image: $Image
      securityContext:
        privileged: $privilegedValue
        allowPrivilegeEscalation: $privilegedValue
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      resources:
        requests:
          cpu: 10m
          memory: 16Mi
        limits:
          cpu: 100m
          memory: 64Mi
"@
}

function Assert-KyvernoRejects {
    param([string]$Name, [string]$Image, [bool]$Privileged, [string]$ExpectedPolicy)
    $path = Join-Path ([System.IO.Path]::GetTempPath()) ("$Name-" + [guid]::NewGuid().ToString('N') + '.yaml')
    try {
        Set-Content -Path $path -Value (New-PodManifest -Name $Name -Image $Image -Privileged $Privileged)
        $output = & kubectl apply -f $path 2>&1
        $exitCode = $LASTEXITCODE
        if ($exitCode -eq 0) {
            & kubectl delete pod $Name -n app --ignore-not-found
            throw "Kyverno a accepté le Pod $Name alors qu'il devait le refuser."
        }
        $message = $output -join "`n"
        if ($message -notmatch $ExpectedPolicy) {
            throw "Le Pod a été refusé, mais la sortie ne confirme pas la policy $ExpectedPolicy :`n$message"
        }
        Write-Output "Test admission réussi : $ExpectedPolicy a refusé $Name."
    }
    finally {
        Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
    }
}

$acceptedPath = Join-Path ([System.IO.Path]::GetTempPath()) ("signed-" + [guid]::NewGuid().ToString('N') + '.yaml')
try {
    Set-Content -Path $acceptedPath -Value (New-PodManifest -Name 'signed-test' -Image $SignedImage -Privileged $false)
    & kubectl apply -f $acceptedPath
    if ($LASTEXITCODE -ne 0) { throw 'Kyverno a refusé le Pod conforme signé.' }
    Write-Output 'Test admission réussi : le Pod conforme signé est accepté.'
}
finally {
    & kubectl delete pod signed-test -n app --ignore-not-found 2>$null | Out-Null
    Remove-Item -LiteralPath $acceptedPath -Force -ErrorAction SilentlyContinue
}

Assert-KyvernoRejects -Name 'unsigned-test' -Image $UnsignedImage -Privileged $false -ExpectedPolicy 'require-signed-app-images'
Assert-KyvernoRejects -Name 'privileged-test' -Image $SignedImage -Privileged $true -ExpectedPolicy 'require-hardened-app-pods'
# Tag mutable :latest interdit (durcissement) même sur le dépôt de la CI.
Assert-KyvernoRejects -Name 'latest-test' -Image "${ImageRepository}:latest" -Privileged $false -ExpectedPolicy 'require-hardened-app-pods|require-signed-app-images'
# Contournement par un autre registre : image par digest mais hors du dépôt signé par la CI.
Assert-KyvernoRejects -Name 'foreign-registry-test' -Image ('docker.io/library/busybox@sha256:' + ('a' * 64)) -Privileged $false -ExpectedPolicy 'restrict-to-pipeline-repository'
