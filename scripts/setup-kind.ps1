param(
    [string]$ClusterName = 'tp4',
    [string]$KyvernoChartVersion = '3.6.4',
    # Kubernetes 1.35+ refuse cgroup v1 (noyau WSL2 de Docker Desktop) : 1.33 reste compatible.
    [string]$NodeImage = 'kindest/node:v1.33.1',
    # Crée un registre OCI local (kind-registry:5000, exposé sur localhost:5001)
    # pour rejouer la chaîne build -> signature -> admission sans registre distant.
    [switch]$LocalRegistry,
    # Registre privé (ex. GHCR en CI) : secret docker-registry créé dans kyverno et app,
    # utilisé par Kyverno pour lire les signatures et par les Pods pour tirer l'image.
    [string]$RegistryPullSecret,
    [string]$RegistryServer = 'ghcr.io',
    [string]$RegistryUsername,
    # Nom de la variable d'environnement contenant le mot de passe/token (jamais en argument).
    [string]$RegistryPasswordEnv
)

$ErrorActionPreference = 'Stop'
$registryName = 'kind-registry'
$registryHostPort = 5001

foreach ($tool in @('docker', 'kind', 'kubectl', 'helm')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "Outil requis absent : $tool"
    }
}

& docker info --format '{{.ServerVersion}}' 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'Docker Desktop ne répond pas. Démarrer le moteur Linux avant de créer Kind.'
}

if ($LocalRegistry) {
    $running = & docker inspect -f '{{.State.Running}}' $registryName 2>$null
    if ($running -ne 'true') {
        & docker run -d --restart=always -p "127.0.0.1:${registryHostPort}:5000" --name $registryName registry:2
        if ($LASTEXITCODE -ne 0) { throw 'Impossible de démarrer le registre local.' }
    }
}

$clusters = & kind get clusters 2>$null
if ($clusters -notcontains $ClusterName) {
    # config_path permet de déclarer le registre local HTTP via hosts.toml plus bas.
    $kindConfig = @'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
  - |-
    [plugins."io.containerd.grpc.v1.cri".registry]
      config_path = "/etc/containerd/certs.d"
'@
    $configPath = Join-Path ([System.IO.Path]::GetTempPath()) ("kind-" + [guid]::NewGuid().ToString('N') + '.yaml')
    try {
        Set-Content -Path $configPath -Value $kindConfig
        & kind create cluster --name $ClusterName --image $NodeImage --config $configPath
        if ($LASTEXITCODE -ne 0) { throw 'La création du cluster Kind a échoué.' }
    }
    finally {
        Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue
    }
}
& kubectl config use-context "kind-$ClusterName" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Contexte kind-$ClusterName introuvable." }

$kyvernoArgs = @()
if ($LocalRegistry) {
    & docker network connect kind $registryName 2>$null
    $hostsToml = "server = `"http://${registryName}:5000`"`n`n[host.`"http://${registryName}:5000`"]`n  capabilities = [`"pull`", `"resolve`"]`n"
    foreach ($node in (& kind get nodes --name $ClusterName)) {
        & docker exec $node mkdir -p "/etc/containerd/certs.d/${registryName}:5000"
        $hostsToml | & docker exec -i $node sh -c "cat > /etc/containerd/certs.d/${registryName}:5000/hosts.toml"
        if ($LASTEXITCODE -ne 0) { throw "Configuration du registre impossible sur $node." }
    }
    # Le registre de démonstration est en HTTP : Kyverno doit être autorisé à le lire.
    $kyvernoArgs = @('--set', 'admissionController.container.extraArgs.allowInsecureRegistry=true')
}

if ($RegistryPullSecret) {
    $password = [Environment]::GetEnvironmentVariable($RegistryPasswordEnv)
    if (-not $RegistryUsername -or -not $password) {
        throw 'RegistryUsername et la variable désignée par RegistryPasswordEnv sont requis.'
    }
    foreach ($ns in @('kyverno', 'app')) {
        & kubectl create namespace $ns --dry-run=client -o yaml | kubectl apply -f -
        & kubectl create secret docker-registry $RegistryPullSecret -n $ns --docker-server=$RegistryServer `
            --docker-username=$RegistryUsername --docker-password=$password --dry-run=client -o yaml | kubectl apply -f - | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Création du secret de registre impossible dans $ns." }
    }
    & kubectl label namespace app security.example.com/enforced=true --overwrite | Out-Null
    $kyvernoArgs += @('--set', "admissionController.container.extraArgs.imagePullSecrets=$RegistryPullSecret")
}

& helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update
if ($LASTEXITCODE -ne 0) { throw 'Impossible d''ajouter le dépôt Helm Kyverno.' }
& helm repo update kyverno
if ($LASTEXITCODE -ne 0) { throw 'Impossible de mettre à jour le dépôt Helm Kyverno.' }
& helm upgrade --install kyverno kyverno/kyverno --version $KyvernoChartVersion `
    --namespace kyverno --create-namespace --wait --timeout 5m @kyvernoArgs
if ($LASTEXITCODE -ne 0) { throw 'L''installation de Kyverno a échoué.' }
& kubectl wait --for=condition=Available deployment --all -n kyverno --timeout=180s
if ($LASTEXITCODE -ne 0) { throw 'Les deployments Kyverno ne sont pas disponibles.' }

Write-Output "Cluster Kind '$ClusterName' prêt avec Kyverno (chart $KyvernoChartVersion)."
if ($LocalRegistry) {
    Write-Output "Registre local : push via localhost:$registryHostPort, référence cluster ${registryName}:5000."
}
