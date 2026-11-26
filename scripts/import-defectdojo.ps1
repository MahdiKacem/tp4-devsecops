param(
    [Parameter(Mandatory = $true)]
    [string]$ReportPath,

    [Parameter(Mandatory = $true)]
    [string]$ScanType,

    [Parameter(Mandatory = $true)]
    [int]$EngagementId,

    [string]$BaseUrl = $env:DEFECTDOJO_URL
)

$ErrorActionPreference = 'Stop'
if (-not $BaseUrl) { throw 'Fournir -BaseUrl ou définir DEFECTDOJO_URL.' }
if (-not $env:DEFECTDOJO_API_KEY) { throw 'Définir DEFECTDOJO_API_KEY dans l''environnement.' }
if (-not (Test-Path $ReportPath -PathType Leaf)) { throw "Rapport absent : $ReportPath" }

$uri = ([uri]$BaseUrl).AbsoluteUri.TrimEnd('/') + '/api/v2/import-scan/'
$headers = @{ Authorization = "Token $env:DEFECTDOJO_API_KEY" }
$form = @{
    scan_type  = $ScanType
    engagement = "$EngagementId"
    file       = Get-Item -LiteralPath $ReportPath
    active     = 'true'
    verified   = 'false'
}

$response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -Form $form
if (-not $response) { throw 'DefectDojo a retourné une réponse vide.' }
Write-Output "Rapport importé dans DefectDojo (engagement $EngagementId)."
