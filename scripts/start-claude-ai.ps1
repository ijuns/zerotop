[CmdletBinding()]
param(
    [string]$EnvFile = '',
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$composeFile = Join-Path $projectRoot 'infra\docker-compose.yml'
$resolvedEnvFile = if ([string]::IsNullOrWhiteSpace($EnvFile)) {
    Join-Path $projectRoot '.env.claude.local'
}
else {
    [System.IO.Path]::GetFullPath($EnvFile)
}

& (Join-Path $PSScriptRoot 'check-claude-config.ps1') -EnvFile $resolvedEnvFile

$docker = Get-Command docker -ErrorAction SilentlyContinue
if ($null -eq $docker) {
    $installedDocker = 'C:\Program Files\Docker\Docker\resources\bin\docker.exe'
    if (Test-Path -LiteralPath $installedDocker) {
        $docker = [pscustomobject]@{ Source = $installedDocker }
    }
}
if ($null -eq $docker) {
    throw 'Docker Desktop is required to start the Claude-backed AI services.'
}
$dockerDirectory = Split-Path -Parent $docker.Source
if ((Test-Path -LiteralPath (Join-Path $dockerDirectory 'docker-credential-desktop.exe')) -and -not (($env:PATH -split ';') -contains $dockerDirectory)) {
    $env:PATH = "$dockerDirectory;$env:PATH"
}

& $docker.Source info --format '{{.ServerVersion}}' *> $null
if ($LASTEXITCODE -ne 0) {
    throw 'Docker Desktop is installed but its engine is not running.'
}

$arguments = @(
    'compose',
    '--env-file', $resolvedEnvFile,
    '-f', $composeFile,
    '--profile', 'ai',
    '--profile', 'external-ai',
    'up', '-d'
)
if (-not $SkipBuild) {
    $arguments += '--build'
}

Push-Location $projectRoot
try {
    & $docker.Source @arguments
    if ($LASTEXITCODE -ne 0) {
        throw 'Docker Compose failed to start the Claude-backed ZeroTOP topology.'
    }
}
finally {
    Pop-Location
}

Write-Host 'ZeroTOP and the Claude model gateway are running with the Git-ignored local configuration.'
Write-Host 'Web: http://localhost:3000'
Write-Host 'API: http://localhost:8080/health'
Write-Host 'AI: http://localhost:8001/health'
Write-Host 'Model gateway health is internal to the Compose network; no Claude generation request was sent.'
