[CmdletBinding()]
param(
    [string]$EnvFile = '',
    [string]$LocalTargetImage = 'codegate/local-target:development',
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$resolvedEnvFile = if ([string]::IsNullOrWhiteSpace($EnvFile)) {
    Join-Path $projectRoot '.env.claude.local'
}
else {
    [System.IO.Path]::GetFullPath($EnvFile)
}

function Resolve-DockerPath {
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    if ($null -ne $docker) {
        return $docker.Source
    }
    $installedDocker = 'C:\Program Files\Docker\Docker\resources\bin\docker.exe'
    if (Test-Path -LiteralPath $installedDocker) {
        return $installedDocker
    }
    throw 'Docker Desktop is required to resolve the approved local target image.'
}

function New-LocalToken([string]$Prefix) {
    $bytes = [byte[]]::new(32)
    $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $generator.GetBytes($bytes)
    }
    finally {
        $generator.Dispose()
    }
    $encoded = [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    return "$Prefix$encoded"
}

function Read-AnthropicKey {
    $key = [Environment]::GetEnvironmentVariable('ANTHROPIC_API_KEY', 'Process')
    if ([string]::IsNullOrWhiteSpace($key)) {
        $key = [Environment]::GetEnvironmentVariable('ANTHROPIC_API_KEY', 'User')
    }
    if ([string]::IsNullOrWhiteSpace($key)) {
        $secure = Read-Host 'Anthropic API key' -AsSecureString
        $pointer = [IntPtr]::Zero
        try {
            $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
            $key = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
        }
        finally {
            if ($pointer -ne [IntPtr]::Zero) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
            }
        }
    }
    if ([string]::IsNullOrWhiteSpace($key) -or -not $key.StartsWith('sk-ant-', [StringComparison]::Ordinal) -or $key -match '\s') {
        throw 'A valid ANTHROPIC_API_KEY is required. It is never printed by this script.'
    }
    return $key
}

if ((Test-Path -LiteralPath $resolvedEnvFile) -and -not $Force) {
    throw "Claude config already exists: $resolvedEnvFile. Use -Force only when intentionally replacing it."
}

$dockerPath = Resolve-DockerPath
& $dockerPath image inspect $LocalTargetImage *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Local target image is missing: $LocalTargetImage. Start Desktop mode once before initializing Claude."
}
$imageDigest = (& $dockerPath image inspect $LocalTargetImage --format '{{.Id}}').Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $imageDigest -notmatch '^sha256:[a-f0-9]{64}$') {
    throw 'The local target image did not resolve to an immutable sha256 digest.'
}
$localRepository = $LocalTargetImage.Split(':')[0]
$canonicalTarget = "$localRepository@$imageDigest"
& $dockerPath image inspect $canonicalTarget *> $null
if ($LASTEXITCODE -ne 0) {
    throw 'Docker could not resolve the digest-pinned local target reference.'
}

$anthropicKey = Read-AnthropicKey
$gatewayToken = [Environment]::GetEnvironmentVariable('MODEL_GATEWAY_INTERNAL_TOKEN', 'Process')
if ([string]::IsNullOrWhiteSpace($gatewayToken)) {
    $gatewayToken = [Environment]::GetEnvironmentVariable('MODEL_GATEWAY_INTERNAL_TOKEN', 'User')
}
if ([string]::IsNullOrWhiteSpace($gatewayToken) -or $gatewayToken.Length -lt 32 -or $gatewayToken -match '\s') {
    $gatewayToken = New-LocalToken -Prefix 'zt_gateway_'
}
$aiToken = New-LocalToken -Prefix 'zt_ai_'

$rubricCatalog = '{"incident-analysis-v1":{"policyVersion":"incident-analysis-2026.07","passThreshold":0.7,"criteria":[{"id":"evidence","description":"Uses concrete evidence from the isolated exercise data.","weight":0.6},{"id":"mitigation","description":"Explains a proportionate detection or mitigation action.","weight":0.4}]}}'
$lines = @(
    '# ZeroTOP local Claude configuration. Contains secrets; never commit this file.',
    'AI_ADAPTER=http',
    "AI_INTERNAL_TOKEN=$aiToken",
    'AI_GENERATION_TIMEOUT_MS=1260000',
    'AI_GENERATION_MODE=external',
    'AI_ALLOW_UNCURATED_CVE_SIMULATION=true',
    'AI_REVIEW_MODE=external',
    'AI_RUBRIC_MODE=external',
    'GENERATION_PROVIDER_URL=http://model-gateway:9010/v1/generate',
    'GENERATION_PROVIDER_TIMEOUT_SECONDS=1230',
    'REVIEW_PROVIDER_URL=http://model-gateway:9010/v1/review',
    'RUBRIC_PROVIDER_URL=http://model-gateway:9010/v1/rubric',
    "MODEL_GATEWAY_INTERNAL_TOKEN=$gatewayToken",
    'MODEL_PROVIDER=anthropic',
    "ANTHROPIC_API_KEY=$anthropicKey",
    'ANTHROPIC_BASE_URL=https://api.anthropic.com/v1',
    'ANTHROPIC_MODEL=claude-sonnet-4-6',
    'ANTHROPIC_VERSION=2023-06-01',
    'MODEL_GATEWAY_GENERATION_TIMEOUT_MS=1200000',
    'MODEL_GATEWAY_GENERATION_MAX_ATTEMPTS=1',
    'MODEL_GATEWAY_REVIEW_TIMEOUT_MS=25000',
    'MODEL_GATEWAY_RUBRIC_TIMEOUT_MS=9000',
    'MODEL_GATEWAY_MAX_CONCURRENCY=2',
    "AI_TARGET_BASE_IMAGE=$canonicalTarget",
    "AI_OUTPUT_REPOSITORY=$localRepository",
    'PACKAGE_CATALOG_JSON={}',
    'ARTIFACT_CATALOG_JSON={}',
    "RUBRIC_CATALOG_JSON=$rubricCatalog"
)

$parent = Split-Path -Parent $resolvedEnvFile
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    throw "Claude config directory does not exist: $parent"
}
[System.IO.File]::WriteAllLines(
    $resolvedEnvFile,
    $lines,
    [System.Text.UTF8Encoding]::new($false)
)

try {
    & (Join-Path $PSScriptRoot 'check-claude-config.ps1') -EnvFile $resolvedEnvFile
}
catch {
    Remove-Item -LiteralPath $resolvedEnvFile -Force -ErrorAction SilentlyContinue
    throw
}

Write-Host "Claude config created at $resolvedEnvFile. Secrets were not printed and no external API request was made."
