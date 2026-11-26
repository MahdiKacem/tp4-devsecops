$ErrorActionPreference = 'Stop'
$ageKeygen = Get-Command age-keygen -ErrorAction SilentlyContinue
if (-not $ageKeygen) {
    throw 'age-keygen est absent. Installer Age avant de générer la clé.'
}

$configDir = Join-Path $env:USERPROFILE '.config\sops\age'
$keyPath = Join-Path $configDir 'keys.txt'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$sopsConfig = Join-Path $repoRoot '.sops.yaml'

if (Test-Path $keyPath) {
    throw "La clé existe déjà : $keyPath. Elle n'a pas été remplacée."
}
New-Item -ItemType Directory -Force $configDir | Out-Null
& age-keygen -o $keyPath
if ($LASTEXITCODE -ne 0) { throw 'La génération de la clé Age a échoué.' }

$recipient = (& age-keygen -y $keyPath).Trim()
if ($LASTEXITCODE -ne 0 -or $recipient -notmatch '^age1[0-9a-z]+$') {
    throw 'Impossible de dériver le destinataire Age depuis la clé générée.'
}

$config = Get-Content -Raw $sopsConfig
$config = $config.Replace('age1REPLACE_WITH_YOUR_PUBLIC_RECIPIENT', $recipient)
Set-Content -Path $sopsConfig -Value $config -NoNewline
Write-Output "Destinataire Age ajouté à .sops.yaml. La clé privée reste dans $keyPath."
Write-Output 'Conserver une sauvegarde sécurisée de la clé privée et l''enregistrer dans les secrets CI.'
