[CmdletBinding()]
param(
    [string]$EnvFile = '',
    [ValidateRange(1024, 65535)]
    [int]$ApiPort = 18080,
    [ValidateRange(1024, 65535)]
    [int]$WebPort = 3000,
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$composeFile = Join-Path $projectRoot 'infra\docker-compose.yml'
$runtimeDirectory = Join-Path $PSScriptRoot '.runtime'
$processFile = Join-Path $runtimeDirectory 'processes.json'
$apiDirectory = Join-Path $projectRoot 'services\api'
$resolvedEnvFile = if ([string]::IsNullOrWhiteSpace($EnvFile)) {
    Join-Path $projectRoot '.env.claude.local'
}
elseif ([System.IO.Path]::IsPathRooted($EnvFile)) {
    [System.IO.Path]::GetFullPath($EnvFile)
}
else {
    [System.IO.Path]::GetFullPath((Join-Path $projectRoot $EnvFile))
}

$runtimeInternalToken = 'local-runtime-token'
$desktopGatewayInternalToken = 'desktop-gateway-dev-token'
$sensitiveProviderVariables = @(
    'ANTHROPIC_API_KEY',
    'OPENAI_API_KEY',
    'MODEL_GATEWAY_INTERNAL_TOKEN'
)

function Read-DotEnvFile([string]$Path) {
    $result = @{}
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $Path -Encoding UTF8) {
        $lineNumber++
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) {
            continue
        }
        if ($trimmed.StartsWith('export ')) {
            $trimmed = $trimmed.Substring(7).TrimStart()
        }
        $separator = $trimmed.IndexOf('=')
        if ($separator -lt 1) {
            throw "Invalid dotenv entry at line $lineNumber. Expected NAME=value."
        }
        $name = $trimmed.Substring(0, $separator).Trim()
        if ($name -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
            throw "Invalid environment variable name at line $lineNumber."
        }
        if ($result.ContainsKey($name)) {
            throw "Duplicate environment variable '$name' at line $lineNumber."
        }
        $value = $trimmed.Substring($separator + 1).Trim()
        if ($value.Length -ge 2 -and $value.StartsWith('"') -and $value.EndsWith('"')) {
            try {
                $value = $value | ConvertFrom-Json
            }
            catch {
                throw "Invalid double-quoted value for '$name' at line $lineNumber."
            }
        }
        elseif ($value.Length -ge 2 -and $value.StartsWith("'") -and $value.EndsWith("'")) {
            $value = $value.Substring(1, $value.Length - 2)
        }
        $result[$name] = [string]$value
    }
    return $result
}

function Assert-RequiredValue([hashtable]$Values, [string]$Name) {
    if (-not $Values.ContainsKey($Name) -or [string]::IsNullOrWhiteSpace([string]$Values[$Name])) {
        throw "$Name is required in $resolvedEnvFile."
    }
}

function Assert-JsonObject([hashtable]$Values, [string]$Name, [switch]$RequireEntry) {
    Assert-RequiredValue -Values $Values -Name $Name
    try {
        $parsed = $Values[$Name] | ConvertFrom-Json
    }
    catch {
        throw "$Name must be valid one-line JSON."
    }
    if ($null -eq $parsed -or $parsed -is [Array] -or $parsed -is [string] -or $parsed -is [ValueType]) {
        throw "$Name must be a JSON object."
    }
    if ($RequireEntry -and @($parsed.PSObject.Properties).Count -eq 0) {
        throw "$Name must contain at least one reviewed entry."
    }
}

function Assert-SecretFileIgnored([string]$Path) {
    $rootWithSeparator = $projectRoot.TrimEnd('\') + '\'
    if (-not $Path.StartsWith($rootWithSeparator, [System.StringComparison]::OrdinalIgnoreCase)) {
        return
    }

    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($null -ne $git) {
        & $git.Source -C $projectRoot check-ignore --quiet -- $Path
        if ($LASTEXITCODE -ne 0) {
            throw "The secret file is inside the repository but is not ignored by Git: $Path"
        }
        return
    }

    $ignoreFile = Join-Path $projectRoot '.gitignore'
    $fileName = [System.IO.Path]::GetFileName($Path)
    $hasEnvWildcard = (Test-Path -LiteralPath $ignoreFile) -and
        @((Get-Content -LiteralPath $ignoreFile) | Where-Object { $_.Trim() -eq '.env.*' }).Count -gt 0
    if (-not ($fileName -like '.env.*' -and $hasEnvWildcard)) {
        throw 'Git is unavailable and the secret file could not be proven to match the repository .env.* ignore rule.'
    }
}

function Test-RecordedProcess([object]$Record, [string]$Name, [switch]$AllowMissing) {
    if ($null -eq $Record) {
        if ($AllowMissing) {
            return $null
        }
        throw "The recorded $Name process is missing. Start .\scripts\local-dev.ps1 -Mode Desktop first."
    }
    $process = Get-Process -Id ([int]$Record.pid) -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        if ($AllowMissing) {
            return $null
        }
        throw "The recorded $Name process is no longer running. Start Desktop mode again before enabling Claude."
    }
    $expectedStart = [DateTimeOffset]::Parse([string]$Record.startedAtUtc).UtcDateTime
    $actualStart = $process.StartTime.ToUniversalTime()
    if ([Math]::Abs(($actualStart - $expectedStart).TotalSeconds) -gt 2) {
        throw "Refusing to use PID $($Record.pid) because it has been reused by another process."
    }
    return $process
}

function Stop-RecordedProcess([object]$Record, [string]$Name) {
    $process = Test-RecordedProcess -Record $Record -Name $Name
    & taskkill.exe /PID ([string]$process.Id) /T /F *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to stop the recorded $Name process."
    }
}

function Restore-EnvironmentVariable([string]$Name, [object]$PreviousValue) {
    if ($null -eq $PreviousValue) {
        Remove-Item -LiteralPath "Env:$Name" -ErrorAction SilentlyContinue
    }
    else {
        Set-Item -LiteralPath "Env:$Name" -Value ([string]$PreviousValue)
    }
}

function Invoke-WithEnvironment([hashtable]$Variables, [scriptblock]$Action) {
    $previous = @{}
    foreach ($entry in $Variables.GetEnumerator()) {
        $previous[$entry.Key] = [System.Environment]::GetEnvironmentVariable($entry.Key, 'Process')
        [System.Environment]::SetEnvironmentVariable($entry.Key, [string]$entry.Value, 'Process')
    }
    try {
        & $Action
    }
    finally {
        foreach ($entry in $previous.GetEnumerator()) {
            Restore-EnvironmentVariable -Name $entry.Key -PreviousValue $entry.Value
        }
    }
}

function Resolve-PnpmPath {
    $pnpm = Get-Command pnpm.cmd -ErrorAction SilentlyContinue
    if ($null -eq $pnpm) {
        $pnpm = Get-Command pnpm -ErrorAction SilentlyContinue
    }
    if ($null -eq $pnpm) {
        throw 'pnpm was not found. Use the same PowerShell environment that starts local-dev.ps1.'
    }
    $bundledNodeDirectory = [System.IO.Path]::GetFullPath((Join-Path (Split-Path $pnpm.Source -Parent) '..\..\node\bin'))
    if ((Test-Path -LiteralPath (Join-Path $bundledNodeDirectory 'node.exe')) -and -not (($env:PATH -split ';') -contains $bundledNodeDirectory)) {
        $env:PATH = "$bundledNodeDirectory;$env:PATH"
    }
    return $pnpm.Source
}

function Start-ApiProcess([hashtable]$EnvironmentVariables, [string]$PnpmPath) {
    $stdout = Join-Path $runtimeDirectory 'api.stdout.log'
    $stderr = Join-Path $runtimeDirectory 'api.stderr.log'
    $previous = @{}
    foreach ($name in $sensitiveProviderVariables) {
        $previous[$name] = [System.Environment]::GetEnvironmentVariable($name, 'Process')
        [System.Environment]::SetEnvironmentVariable($name, $null, 'Process')
    }
    foreach ($entry in $EnvironmentVariables.GetEnumerator()) {
        $previous[$entry.Key] = [System.Environment]::GetEnvironmentVariable($entry.Key, 'Process')
        [System.Environment]::SetEnvironmentVariable($entry.Key, [string]$entry.Value, 'Process')
    }
    try {
        return Start-Process `
            -FilePath $PnpmPath `
            -ArgumentList @('run', 'dev') `
            -WorkingDirectory $apiDirectory `
            -WindowStyle Hidden `
            -RedirectStandardOutput $stdout `
            -RedirectStandardError $stderr `
            -PassThru
    }
    finally {
        foreach ($entry in $previous.GetEnumerator()) {
            Restore-EnvironmentVariable -Name $entry.Key -PreviousValue $entry.Value
        }
    }
}

function Wait-HttpOk([string]$Url, [int]$TimeoutSeconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 3
            if ($response.StatusCode -eq 200) {
                return
            }
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for $Url."
}

function Update-ApiMetadata([object]$Metadata, [System.Diagnostics.Process]$Process) {
    $Metadata.api = [pscustomobject]@{
        pid = $Process.Id
        startedAtUtc = $Process.StartTime.ToUniversalTime().ToString('O')
    }
    $Metadata | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $processFile -Encoding UTF8
}

if (-not (Test-Path -LiteralPath $resolvedEnvFile -PathType Leaf)) {
    throw "Claude configuration file not found: $resolvedEnvFile"
}
if (-not (Test-Path -LiteralPath $composeFile -PathType Leaf)) {
    throw "Compose file not found: $composeFile"
}
if (-not (Test-Path -LiteralPath $processFile -PathType Leaf)) {
    throw 'Desktop process metadata is missing. Start .\scripts\local-dev.ps1 -Mode Desktop first.'
}

Assert-SecretFileIgnored -Path $resolvedEnvFile
$values = Read-DotEnvFile -Path $resolvedEnvFile
foreach ($name in @(
    'AI_INTERNAL_TOKEN',
    'AI_GENERATION_TIMEOUT_MS',
    'MODEL_GATEWAY_INTERNAL_TOKEN',
    'MODEL_PROVIDER',
    'ANTHROPIC_API_KEY',
    'ANTHROPIC_MODEL',
    'AI_GENERATION_MODE',
    'AI_ALLOW_UNCURATED_CVE_SIMULATION',
    'AI_REVIEW_MODE',
    'AI_RUBRIC_MODE',
    'GENERATION_PROVIDER_TIMEOUT_SECONDS',
    'AI_TARGET_BASE_IMAGE',
    'AI_OUTPUT_REPOSITORY',
    'PACKAGE_CATALOG_JSON',
    'ARTIFACT_CATALOG_JSON',
    'MODEL_GATEWAY_GENERATION_TIMEOUT_MS',
    'RUBRIC_CATALOG_JSON'
)) {
    Assert-RequiredValue -Values $values -Name $name
}
if ($values.MODEL_PROVIDER -ne 'anthropic') {
    throw 'MODEL_PROVIDER must be anthropic for this helper.'
}
if ($values.ANTHROPIC_API_KEY.Length -lt 32 -or $values.ANTHROPIC_API_KEY -match '\s') {
    throw 'ANTHROPIC_API_KEY is malformed.'
}
if ($values.MODEL_GATEWAY_INTERNAL_TOKEN.Length -lt 32 -or $values.MODEL_GATEWAY_INTERNAL_TOKEN -match '\s') {
    throw 'MODEL_GATEWAY_INTERNAL_TOKEN must contain at least 32 non-whitespace characters.'
}
if ($values.AI_INTERNAL_TOKEN.Length -lt 24 -or $values.AI_INTERNAL_TOKEN -match '\s') {
    throw 'AI_INTERNAL_TOKEN must contain at least 24 non-whitespace characters.'
}
foreach ($modeName in @('AI_GENERATION_MODE', 'AI_REVIEW_MODE', 'AI_RUBRIC_MODE')) {
    if ($values[$modeName] -ne 'external') {
        throw "$modeName must be external."
    }
}
if ($values.AI_ALLOW_UNCURATED_CVE_SIMULATION -ne 'true') {
    throw 'AI_ALLOW_UNCURATED_CVE_SIMULATION must be true for the local Claude helper.'
}
if ($values.AI_GENERATION_TIMEOUT_MS -ne '1260000' -or
    $values.GENERATION_PROVIDER_TIMEOUT_SECONDS -ne '1230' -or
    $values.MODEL_GATEWAY_GENERATION_TIMEOUT_MS -ne '1200000') {
    throw 'Claude generation timeouts must be API 1260000ms > Python provider 1230s > model gateway 1200000ms.'
}
if ($values.AI_TARGET_BASE_IMAGE -notmatch '@sha256:[0-9a-f]{64}$') {
    throw 'AI_TARGET_BASE_IMAGE must be pinned by a lowercase sha256 digest.'
}
Assert-JsonObject -Values $values -Name 'PACKAGE_CATALOG_JSON'
Assert-JsonObject -Values $values -Name 'ARTIFACT_CATALOG_JSON'
Assert-JsonObject -Values $values -Name 'RUBRIC_CATALOG_JSON' -RequireEntry

$metadata = Get-Content -LiteralPath $processFile -Raw -Encoding UTF8 | ConvertFrom-Json
if ([string]$metadata.mode -ne 'desktop') {
    throw 'This helper only supports an existing local-dev.ps1 -Mode Desktop session.'
}
$recordedApi = Test-RecordedProcess -Record $metadata.api -Name 'api' -AllowMissing
$null = Test-RecordedProcess -Record $metadata.web -Name 'web'
$null = Test-RecordedProcess -Record $metadata.runtime -Name 'runtime'

$docker = Get-Command docker -ErrorAction SilentlyContinue
if ($null -eq $docker) {
    $installedDocker = 'C:\Program Files\Docker\Docker\resources\bin\docker.exe'
    if (Test-Path -LiteralPath $installedDocker) {
        $docker = [pscustomobject]@{ Source = $installedDocker }
    }
}
if ($null -eq $docker) {
    throw 'Docker was not found.'
}
$dockerDirectory = Split-Path -Parent $docker.Source
if ((Test-Path -LiteralPath (Join-Path $dockerDirectory 'docker-credential-desktop.exe')) -and -not (($env:PATH -split ';') -contains $dockerDirectory)) {
    $env:PATH = "$dockerDirectory;$env:PATH"
}
& $docker.Source info --format '{{.ServerVersion}}' *> $null
if ($LASTEXITCODE -ne 0) {
    throw 'Docker Desktop is not ready.'
}

$localTargetRepository = 'codegate/local-target'
$localTargetImage = "${localTargetRepository}:development"
$localTargetInspect = @(& $docker.Source image inspect --format '{{.Id}}' $localTargetImage)
if ($LASTEXITCODE -ne 0 -or $localTargetInspect.Count -ne 1) {
    throw "The Desktop target image is missing: $localTargetImage. Start Desktop mode before enabling Claude."
}
$localTargetDigest = ([string]$localTargetInspect[0]).Trim().ToLowerInvariant()
if ($localTargetDigest -notmatch '^sha256:[0-9a-f]{64}$') {
    throw "Docker returned an invalid image digest for $localTargetImage."
}
$localTargetSourceImage = "$localTargetRepository@$localTargetDigest"
if ($values.AI_TARGET_BASE_IMAGE -cne $localTargetSourceImage -or $values.AI_OUTPUT_REPOSITORY -cne $localTargetRepository) {
    throw 'The Claude catalog does not match the current local target image. Run .\scripts\init-claude-config.ps1 -Force, then retry.'
}

$composeArguments = @(
    'compose',
    '--env-file', $resolvedEnvFile,
    '-f', $composeFile,
    '--profile', 'ai',
    '--profile', 'external-ai',
    'up', '-d', '--wait', '--wait-timeout', '240'
)
if (-not $SkipBuild) {
    $composeArguments += '--build'
}
$composeArguments += @('ai', 'model-gateway')

Write-Host 'Starting the isolated AI service and Claude model gateway. No Lab generation request is sent during startup.'
Invoke-WithEnvironment -Variables $values -Action {
    & $docker.Source @composeArguments
    if ($LASTEXITCODE -ne 0) {
        throw 'Docker Compose failed to start the AI services.'
    }
}
Wait-HttpOk -Url 'http://localhost:8001/health' -TimeoutSeconds 30

$pnpmPath = Resolve-PnpmPath
$baseApiEnvironment = @{
    PORT = [string]$ApiPort
    AUTH_MODE = 'dev'
    REPOSITORY_MODE = 'sqlite'
    RUNTIME_ADAPTER = 'service'
    CODEGATE_DB_PATH = (Join-Path $runtimeDirectory 'codegate.db')
    ALLOWED_ORIGINS = "http://localhost:$WebPort,http://127.0.0.1:$WebPort"
    RUNTIME_SERVICE_URL = 'http://localhost:9000'
    RUNTIME_INTERNAL_TOKEN = $runtimeInternalToken
    RUNTIME_TARGET_IMAGE = $localTargetSourceImage
    TARGET_IMAGE_REGISTRIES = 'codegate'
    DESKTOP_GATEWAY_PUBLIC_URL = 'http://localhost:9001'
    DESKTOP_GATEWAY_INTERNAL_TOKEN = $desktopGatewayInternalToken
}
$externalApiEnvironment = @{}
foreach ($entry in $baseApiEnvironment.GetEnumerator()) {
    $externalApiEnvironment[$entry.Key] = $entry.Value
}
$externalApiEnvironment.AI_ADAPTER = 'http'
$externalApiEnvironment.AI_LAB_GENERATOR = 'http'
$externalApiEnvironment.AI_SERVICE_URL = 'http://localhost:8001'
$externalApiEnvironment.AI_INTERNAL_TOKEN = $values.AI_INTERNAL_TOKEN
$externalApiEnvironment.AI_GENERATION_TIMEOUT_MS = if ($values.ContainsKey('AI_GENERATION_TIMEOUT_MS')) {
    $values.AI_GENERATION_TIMEOUT_MS
}
else {
    '1260000'
}

Write-Host 'Restarting only the Desktop API with the HTTP AI adapter. Runtime, gateway, web, and active Lab containers remain running.'
if ($null -ne $recordedApi) {
    Stop-RecordedProcess -Record $metadata.api -Name 'api'
}
else {
    Write-Host 'The previous API process is already stopped; continuing with a clean API start.'
}
$newApi = $null
try {
    $newApi = Start-ApiProcess -EnvironmentVariables $externalApiEnvironment -PnpmPath $pnpmPath
    Wait-HttpOk -Url "http://localhost:$ApiPort/health" -TimeoutSeconds 30
    Update-ApiMetadata -Metadata $metadata -Process $newApi
}
catch {
    if ($null -ne $newApi -and -not $newApi.HasExited) {
        & taskkill.exe /PID ([string]$newApi.Id) /T /F *> $null
    }
    Write-Warning 'External-AI API startup failed. Restoring the local deterministic API adapter.'
    $rollbackEnvironment = @{}
    foreach ($entry in $baseApiEnvironment.GetEnumerator()) {
        $rollbackEnvironment[$entry.Key] = $entry.Value
    }
    $rollbackEnvironment.AI_ADAPTER = 'local'
    $rollbackApi = Start-ApiProcess -EnvironmentVariables $rollbackEnvironment -PnpmPath $pnpmPath
    Wait-HttpOk -Url "http://localhost:$ApiPort/health" -TimeoutSeconds 30
    Update-ApiMetadata -Metadata $metadata -Process $rollbackApi
    throw
}

Write-Host 'Claude is connected to the Desktop API.'
Write-Host "Web: http://localhost:$WebPort"
Write-Host "API: http://localhost:$ApiPort/health"
Write-Host 'AI:  http://localhost:8001/health'
Write-Host 'The provider is called only when you submit an AI generation, review, or rubric request.'
