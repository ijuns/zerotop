[CmdletBinding()]
param(
    [ValidateSet('Auto', 'Docker', 'Desktop', 'Local')]
    [string]$Mode = 'Auto',
    [switch]$IncludeAi,
    [switch]$SkipInstall,
    [switch]$SkipDesktopImagePull,
    [ValidateRange(1024, 65535)]
    [int]$WebPort = 3000,
    [ValidateRange(1024, 65535)]
    [int]$ApiPort = 8080
)

$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$composeFile = Join-Path $projectRoot 'infra\docker-compose.yml'
$apiDirectory = Join-Path $projectRoot 'services\api'
$webDirectory = Join-Path $projectRoot 'apps\web'
$runtimeServiceDirectory = Join-Path $projectRoot 'services\runtime'
$runtimeDirectory = Join-Path $PSScriptRoot '.runtime'
$desktopNetwork = 'codegate-local-desktops'
$desktopGatewayContainer = 'codegate-local-desktop-gateway'
$desktopGatewayImage = 'codegate/desktop-gateway:local'
$runtimeInternalToken = 'local-runtime-token'
$desktopGatewayInternalToken = 'desktop-gateway-dev-token'
$desktopSessionSigningKey = 'codegate-local-desktop-session-signing-key-change-me'
$runtimePort = 9000
$desktopGatewayPort = 9001
$localTargetDigest = 'sha256:' + ('0' * 64)
$dockerBin = 'C:\Program Files\Docker\Docker\resources\bin'
if ((Test-Path -LiteralPath (Join-Path $dockerBin 'docker.exe')) -and -not (($env:PATH -split ';') -contains $dockerBin)) {
    $env:PATH = "$dockerBin;$env:PATH"
}

if ($WebPort -eq $ApiPort) {
    throw 'WebPort and ApiPort must be different.'
}

function Test-DockerReady {
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if ($null -eq $docker) {
        return $false
    }

    try {
        & $docker.Source info --format '{{.ServerVersion}}' *> $null
        return $LASTEXITCODE -eq 0
    }
    catch {
        return $false
    }
}

function Test-DockerObject([string[]]$Arguments) {
    try {
        & docker @Arguments *> $null
        return $LASTEXITCODE -eq 0
    }
    catch {
        return $false
    }
}

function Test-PortInUse([int]$Port) {
    $listeners = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners()
    return ($listeners | Where-Object { $_.Port -eq $Port }).Count -gt 0
}

function Restore-EnvironmentVariable([string]$Name, [object]$PreviousValue) {
    if ($null -eq $PreviousValue) {
        Remove-Item -LiteralPath "Env:$Name" -ErrorAction SilentlyContinue
    }
    else {
        Set-Item -LiteralPath "Env:$Name" -Value ([string]$PreviousValue)
    }
}

function Install-Dependencies([string]$WorkingDirectory, [string]$PnpmPath) {
    if ($SkipInstall -or (Test-Path -LiteralPath (Join-Path $WorkingDirectory 'node_modules'))) {
        return
    }

    Write-Host "Installing workspace dependencies in $WorkingDirectory ..."
    Push-Location $WorkingDirectory
    try {
        & $PnpmPath install --frozen-lockfile
        if ($LASTEXITCODE -ne 0) {
            throw "pnpm install failed in $WorkingDirectory"
        }
    }
    finally {
        Pop-Location
    }
}

function Start-HiddenPnpmProcess {
    param(
        [string]$Name,
        [string]$WorkingDirectory,
        [string]$PnpmPath,
        [string]$Script,
        [hashtable]$EnvironmentVariables
    )

    $stdout = Join-Path $runtimeDirectory "$Name.stdout.log"
    $stderr = Join-Path $runtimeDirectory "$Name.stderr.log"
    $previousValues = @{}

    foreach ($entry in $EnvironmentVariables.GetEnumerator()) {
        $previousValues[$entry.Key] = [System.Environment]::GetEnvironmentVariable($entry.Key, 'Process')
        [System.Environment]::SetEnvironmentVariable($entry.Key, [string]$entry.Value, 'Process')
    }

    try {
        # A background service must not open an extra console window on Windows.
        return Start-Process `
            -FilePath $PnpmPath `
            -ArgumentList @('run', $Script) `
            -WorkingDirectory $WorkingDirectory `
            -WindowStyle Hidden `
            -RedirectStandardOutput $stdout `
            -RedirectStandardError $stderr `
            -PassThru
    }
    finally {
        foreach ($entry in $previousValues.GetEnumerator()) {
            Restore-EnvironmentVariable -Name $entry.Key -PreviousValue $entry.Value
        }
    }
}

$dockerReady = Test-DockerReady
if (($Mode -eq 'Docker' -or $Mode -eq 'Desktop') -and -not $dockerReady) {
    Write-Warning @'
Docker Desktop and a running Docker engine are required for -Mode Docker and -Mode Desktop.
Install Docker Desktop, start it, then run:
  .\scripts\local-dev.ps1 -Mode Desktop
For the zero-infrastructure fallback, install Node.js 24 and run:
  .\scripts\local-dev.ps1 -Mode Local
'@
    exit 2
}

if ($Mode -eq 'Docker') {
    if ($WebPort -ne 3000 -or $ApiPort -ne 8080) {
        throw 'Custom WebPort and ApiPort values are currently supported only with -Mode Local.'
    }
    $previousAiAdapter = [System.Environment]::GetEnvironmentVariable('AI_ADAPTER', 'Process')
    if ($IncludeAi) {
        [System.Environment]::SetEnvironmentVariable('AI_ADAPTER', 'http', 'Process')
    }
    $dockerArguments = @('compose', '-f', $composeFile)
    if ($IncludeAi) {
        $dockerArguments += @('--profile', 'ai')
    }
    $dockerArguments += @('up', '--build', '-d')

    Write-Host 'Starting the isolated local Docker environment ...'
    try {
        & docker @dockerArguments
        if ($LASTEXITCODE -ne 0) {
            throw 'Docker Compose failed. Run docker compose logs to inspect the failing health check.'
        }
    }
    finally {
        if ($IncludeAi) {
            Restore-EnvironmentVariable -Name 'AI_ADAPTER' -PreviousValue $previousAiAdapter
        }
    }

    Write-Host 'Web:      http://localhost:3000'
    Write-Host 'API:      http://localhost:8080/health'
    Write-Host 'Runtime:  http://localhost:9000/health'
    Write-Host 'Keycloak: http://localhost:8081'
    Write-Host 'Kibana:   http://localhost:5601'
    if ($IncludeAi) {
        Write-Host 'AI:       http://localhost:8001/health'
    }
    Write-Warning 'Compose credentials are development placeholders. Do not expose this stack to a shared network.'
    exit 0
}

$desktopMode = $Mode -eq 'Desktop' -or ($Mode -eq 'Auto' -and $dockerReady)
if ($desktopMode) {
    Write-Host 'Docker is available; preparing the real local Ubuntu/Kali desktop runtime.'
}
else {
    Write-Warning 'Docker is unavailable or Local mode was selected; using the zero-infrastructure simulator.'
}
$node = Get-Command node -ErrorAction SilentlyContinue
$pnpm = Get-Command pnpm.cmd -ErrorAction SilentlyContinue
if ($null -eq $pnpm) {
    $pnpm = Get-Command pnpm -ErrorAction SilentlyContinue
}
if ($null -eq $node -and $null -ne $pnpm) {
    $bundledNode = [System.IO.Path]::GetFullPath((Join-Path (Split-Path $pnpm.Source -Parent) '..\..\node\bin\node.exe'))
    if (Test-Path -LiteralPath $bundledNode) {
        $node = [pscustomobject]@{ Source = $bundledNode }
    }
}

if ($null -eq $node -or $null -eq $pnpm) {
    Write-Warning @'
Neither a ready Docker engine nor Node.js 24 plus pnpm was found.
Install Node.js 24, then enable the repository's pinned package manager:
  corepack enable
  corepack prepare pnpm@11.9.0 --activate
Reopen PowerShell, then run:
  .\scripts\local-dev.ps1 -Mode Local
Docker Desktop is optional for this fallback.
'@
    exit 2
}

$nodeDirectory = Split-Path $node.Source -Parent
if (-not (($env:PATH -split ';') -contains $nodeDirectory)) {
    $env:PATH = "$nodeDirectory;$env:PATH"
}

$nodeVersionText = & $node.Source -p 'process.versions.node'
$nodeMajor = [int]($nodeVersionText -split '\.')[0]
if ($nodeMajor -lt 24) {
    Write-Warning "Node.js 24 or newer is required; found $nodeVersionText. Upgrade Node.js and retry."
    exit 2
}

foreach ($requiredFile in @(
    (Join-Path $apiDirectory 'package.json'),
    (Join-Path $webDirectory 'package.json'),
    (Join-Path $runtimeServiceDirectory 'package.json')
)) {
    if (-not (Test-Path -LiteralPath $requiredFile)) {
        Write-Warning "Required application file is missing: $requiredFile"
        exit 2
    }
}

if (Test-PortInUse -Port $ApiPort) {
    Write-Warning "API port $ApiPort is already in use. Stop the existing process or select -ApiPort with a free port."
    exit 3
}
if (Test-PortInUse -Port $WebPort) {
    Write-Warning "Web port $WebPort is already in use. Stop the existing process or select -WebPort with a free port."
    exit 3
}
if ($desktopMode -and (Test-PortInUse -Port $runtimePort)) {
    Write-Warning "Runtime port $runtimePort is already in use. Stop the existing process before starting Desktop mode."
    exit 3
}
if ($desktopMode -and (Test-PortInUse -Port $desktopGatewayPort)) {
    Write-Warning "Desktop gateway port $desktopGatewayPort is already in use. Stop the existing process before starting Desktop mode."
    exit 3
}

New-Item -ItemType Directory -Path $runtimeDirectory -Force | Out-Null
Install-Dependencies -WorkingDirectory $projectRoot -PnpmPath $pnpm.Source

$apiProcess = $null
$webProcess = $null
$runtimeProcess = $null
$gatewayStarted = $false
try {
    if ($desktopMode) {
        if (-not (Test-DockerObject -Arguments @('network', 'inspect', $desktopNetwork))) {
            & docker network create --internal $desktopNetwork *> $null
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to create the isolated Docker network $desktopNetwork."
            }
        }

        $ubuntuDesktopImage = if ($env:LOCAL_UBUNTU_DESKTOP_IMAGE) { $env:LOCAL_UBUNTU_DESKTOP_IMAGE } else { 'lscr.io/linuxserver/webtop:ubuntu-xfce' }
        $kaliDesktopImage = if ($env:LOCAL_KALI_DESKTOP_IMAGE) { $env:LOCAL_KALI_DESKTOP_IMAGE } else { 'lscr.io/linuxserver/kali-linux:latest' }
        if (-not $SkipDesktopImagePull) {
            foreach ($desktopImage in @($ubuntuDesktopImage, $kaliDesktopImage)) {
                if (-not (Test-DockerObject -Arguments @('image', 'inspect', $desktopImage))) {
                    Write-Host "Pulling desktop image $desktopImage ..."
                    & docker pull $desktopImage
                    if ($LASTEXITCODE -ne 0) {
                        throw "Failed to pull desktop image $desktopImage."
                    }
                }
            }
        }

        Write-Host 'Building the local desktop gateway and connectivity target ...'
        Push-Location $projectRoot
        try {
            & docker build -f services/desktop-gateway/Dockerfile -t $desktopGatewayImage .
            if ($LASTEXITCODE -ne 0) {
                throw 'Failed to build the local desktop gateway image.'
            }
            & docker build -f services/local-target/Dockerfile -t codegate/local-target:development .
            if ($LASTEXITCODE -ne 0) {
                throw 'Failed to build the local connectivity target image.'
            }
        }
        finally {
            Pop-Location
        }

        if (Test-DockerObject -Arguments @('container', 'inspect', $desktopGatewayContainer)) {
            & docker rm -f $desktopGatewayContainer *> $null
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to replace the existing $desktopGatewayContainer container."
            }
        }

        $gatewayArguments = @(
            'run', '-d',
            '--name', $desktopGatewayContainer,
            '--label', 'io.codegate.local-gateway=true',
            '--network', 'bridge',
            '--publish', "127.0.0.1:${desktopGatewayPort}:9001",
            '--read-only',
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m',
            '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges:true',
            '--memory', '256m',
            '--cpus', '0.50',
            '--pids-limit', '128',
            '--env', "PLATFORM_API_URL=http://host.docker.internal:$ApiPort",
            '--env', 'PORT=9001',
            '--env', 'DESKTOP_UPSTREAM_PORT=6080',
            '--env', "DESKTOP_GATEWAY_INTERNAL_TOKEN=$desktopGatewayInternalToken",
            '--env', "DESKTOP_SESSION_SIGNING_KEY=$desktopSessionSigningKey",
            '--env', 'DESKTOP_CLIENT=webtop',
            '--env', 'DESKTOP_PRESERVE_UPSTREAM_PATH=true',
            '--env', 'DESKTOP_COOKIE_SECURE=false',
            $desktopGatewayImage
        )
        $gatewayId = & docker @gatewayArguments
        if ($LASTEXITCODE -ne 0 -or -not $gatewayId) {
            throw 'Failed to start the local desktop gateway.'
        }
        $gatewayStarted = $true
        & docker network connect $desktopNetwork $desktopGatewayContainer
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to attach the desktop gateway to $desktopNetwork."
        }

        $runtimeProcess = Start-HiddenPnpmProcess `
            -Name 'runtime' `
            -WorkingDirectory $runtimeServiceDirectory `
            -PnpmPath $pnpm.Source `
            -Script 'dev' `
            -EnvironmentVariables @{
                PORT = [string]$runtimePort
                RUNTIME_MODE = 'docker'
                RUNTIME_INTERNAL_TOKEN = $runtimeInternalToken
                TARGET_IMAGE_REGISTRIES = 'local.codegate.invalid'
                LOCAL_DESKTOP_NETWORK = $desktopNetwork
                LOCAL_UBUNTU_DESKTOP_IMAGE = $ubuntuDesktopImage
                LOCAL_KALI_DESKTOP_IMAGE = $kaliDesktopImage
                LOCAL_TARGET_IMAGE = 'codegate/local-target:development'
                LOCAL_DESKTOP_PORT = '6080'
            }
    }

    $apiEnvironment = @{
        PORT = [string]$ApiPort
        AUTH_MODE = 'dev'
        REPOSITORY_MODE = 'sqlite'
        RUNTIME_ADAPTER = $(if ($desktopMode) { 'service' } else { 'simulator' })
        CODEGATE_DB_PATH = (Join-Path $runtimeDirectory 'codegate.db')
        ALLOWED_ORIGINS = "http://localhost:$WebPort,http://127.0.0.1:$WebPort"
    }
    if ($desktopMode) {
        $apiEnvironment.RUNTIME_SERVICE_URL = "http://localhost:$runtimePort"
        $apiEnvironment.RUNTIME_INTERNAL_TOKEN = $runtimeInternalToken
        $apiEnvironment.RUNTIME_TARGET_IMAGE = "local.codegate.invalid/codegate/local-target@$localTargetDigest"
        $apiEnvironment.TARGET_IMAGE_REGISTRIES = 'local.codegate.invalid'
        $apiEnvironment.DESKTOP_GATEWAY_PUBLIC_URL = "http://localhost:$desktopGatewayPort"
        $apiEnvironment.DESKTOP_GATEWAY_INTERNAL_TOKEN = $desktopGatewayInternalToken
    }

    $apiProcess = Start-HiddenPnpmProcess `
        -Name 'api' `
        -WorkingDirectory $apiDirectory `
        -PnpmPath $pnpm.Source `
        -Script 'dev' `
        -EnvironmentVariables $apiEnvironment

    $webProcess = Start-HiddenPnpmProcess `
        -Name 'web' `
        -WorkingDirectory $webDirectory `
        -PnpmPath $pnpm.Source `
        -Script 'dev' `
        -EnvironmentVariables @{
            PORT = [string]$WebPort
            CODEGATE_WEB_API_URL = "http://localhost:$ApiPort"
            CODEGATE_WEB_DEVELOPMENT_IDENTITY = 'true'
            CODEGATE_WEB_DEV_USER_ID = 'user_dev'
        }

    Start-Sleep -Seconds 2
    if ($null -ne $runtimeProcess) {
        $runtimeProcess.Refresh()
    }
    $apiProcess.Refresh()
    $webProcess.Refresh()
    if ($null -ne $runtimeProcess -and $runtimeProcess.HasExited) {
        throw "Runtime exited during startup. See $runtimeDirectory\runtime.stderr.log"
    }
    if ($apiProcess.HasExited) {
        throw "API exited during startup. See $runtimeDirectory\api.stderr.log"
    }
    if ($webProcess.HasExited) {
        throw "Web exited during startup. See $runtimeDirectory\web.stderr.log"
    }

    $processMetadata = @{
        api = @{ pid = $apiProcess.Id; startedAtUtc = $apiProcess.StartTime.ToUniversalTime().ToString('O') }
        web = @{ pid = $webProcess.Id; startedAtUtc = $webProcess.StartTime.ToUniversalTime().ToString('O') }
        mode = $(if ($desktopMode) { 'desktop' } else { 'local' })
    }
    if ($null -ne $runtimeProcess) {
        $processMetadata.runtime = @{
            pid = $runtimeProcess.Id
            startedAtUtc = $runtimeProcess.StartTime.ToUniversalTime().ToString('O')
        }
        $processMetadata.desktopGatewayContainer = $desktopGatewayContainer
    }
    $processMetadata | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $runtimeDirectory 'processes.json') -Encoding UTF8
}
catch {
    if ($null -ne $webProcess -and -not $webProcess.HasExited) {
        Stop-Process -Id $webProcess.Id -ErrorAction SilentlyContinue
    }
    if ($null -ne $apiProcess -and -not $apiProcess.HasExited) {
        Stop-Process -Id $apiProcess.Id -ErrorAction SilentlyContinue
    }
    if ($null -ne $runtimeProcess -and -not $runtimeProcess.HasExited) {
        Stop-Process -Id $runtimeProcess.Id -ErrorAction SilentlyContinue
    }
    if ($gatewayStarted) {
        & docker rm -f $desktopGatewayContainer *> $null
    }
    throw
}

Write-Host $(if ($desktopMode) { 'Local services with real Ubuntu/Kali desktop provisioning are running.' } else { 'Zero-infrastructure development services are running in hidden windows.' })
Write-Host "Web: http://localhost:$WebPort"
Write-Host "API: http://localhost:$ApiPort/health"
if ($desktopMode) {
    Write-Host "Runtime: http://localhost:$runtimePort/health"
    Write-Host "Desktop gateway: http://localhost:$desktopGatewayPort/health"
}
Write-Host "Logs and process IDs: $runtimeDirectory"
if ($desktopMode) {
    Write-Host 'Browser desktop runs are real disposable Docker containers. OpenVPN remains disabled in this local mode.'
}
else {
    Write-Host 'This mode uses the simulator and a local SQLite file; Keycloak, ELK, Redis, VM, and VPN services are unavailable.'
}
