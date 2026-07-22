[CmdletBinding()]
param(
    [string]$EnvFile = ''
)

$ErrorActionPreference = 'Stop'
$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$resolvedEnvFile = if ([string]::IsNullOrWhiteSpace($EnvFile)) {
    Join-Path $projectRoot '.env.claude.local'
}
else {
    [System.IO.Path]::GetFullPath($EnvFile)
}

function Read-DotEnv([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Claude config is missing. Copy .env.claude.example to .env.claude.local and edit the local copy."
    }

    $values = @{}
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $Path) {
        $lineNumber += 1
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith('#')) {
            continue
        }
        if ($line -notmatch '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$') {
            throw "Claude config line $lineNumber is not a KEY=VALUE entry."
        }

        $name = $Matches[1]
        $value = $Matches[2].Trim()
        if ($values.ContainsKey($name)) {
            throw "Claude config contains duplicate variable $name."
        }
        if ($value.Length -ge 2) {
            $first = $value.Substring(0, 1)
            $last = $value.Substring($value.Length - 1, 1)
            if (($first -eq '"' -and $last -eq '"') -or ($first -eq "'" -and $last -eq "'")) {
                $value = $value.Substring(1, $value.Length - 2)
            }
        }
        $values[$name] = $value
    }
    return $values
}

function Require-Value([hashtable]$Values, [string]$Name) {
    if (-not $Values.ContainsKey($Name) -or [string]::IsNullOrWhiteSpace([string]$Values[$Name])) {
        throw "Claude config is missing required variable $Name."
    }
    return [string]$Values[$Name]
}

function Assert-Exact([hashtable]$Values, [string]$Name, [string]$Expected) {
    $value = Require-Value -Values $Values -Name $Name
    if ($value -cne $Expected) {
        throw "$Name must be $Expected for the local Claude topology."
    }
}

function Assert-Secret([hashtable]$Values, [string]$Name, [string]$Prefix = '') {
    $value = Require-Value -Values $Values -Name $Name
    if ($value.Length -lt 32 -or $value.Length -gt 512 -or $value -match '\s') {
        throw "$Name must contain 32-512 non-whitespace characters."
    }
    if ($value -match '(?i)REPLACE_WITH|YOUR_[A-Z_]*|CHANGE_ME|EXAMPLE') {
        throw "$Name still contains an example placeholder."
    }
    if ($Prefix -and -not $value.StartsWith($Prefix, [System.StringComparison]::Ordinal)) {
        throw "$Name does not have the expected provider key prefix."
    }
}

function Assert-JsonObject([hashtable]$Values, [string]$Name) {
    $raw = Require-Value -Values $Values -Name $Name
    try {
        $parsed = $raw | ConvertFrom-Json
    }
    catch {
        throw "$Name must be valid one-line JSON."
    }
    if ($null -eq $parsed -or $parsed -is [System.Array] -or $parsed -isnot [psobject]) {
        throw "$Name must be a JSON object."
    }
    return $parsed
}

function Find-Git {
    $command = Get-Command git -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }
    if ($env:USERPROFILE) {
        $bundled = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\native\git\cmd\git.exe'
        if (Test-Path -LiteralPath $bundled) {
            return $bundled
        }
    }
    return $null
}

$values = Read-DotEnv -Path $resolvedEnvFile

Assert-Exact -Values $values -Name 'AI_ADAPTER' -Expected 'http'
Assert-Exact -Values $values -Name 'AI_GENERATION_MODE' -Expected 'external'
Assert-Exact -Values $values -Name 'AI_REVIEW_MODE' -Expected 'external'
Assert-Exact -Values $values -Name 'AI_RUBRIC_MODE' -Expected 'external'
Assert-Exact -Values $values -Name 'GENERATION_PROVIDER_URL' -Expected 'http://model-gateway:9010/v1/generate'
Assert-Exact -Values $values -Name 'AI_GENERATION_TIMEOUT_MS' -Expected '1260000'
Assert-Exact -Values $values -Name 'GENERATION_PROVIDER_TIMEOUT_SECONDS' -Expected '1230'
Assert-Exact -Values $values -Name 'REVIEW_PROVIDER_URL' -Expected 'http://model-gateway:9010/v1/review'
Assert-Exact -Values $values -Name 'RUBRIC_PROVIDER_URL' -Expected 'http://model-gateway:9010/v1/rubric'
Assert-Exact -Values $values -Name 'MODEL_PROVIDER' -Expected 'anthropic'
Assert-Exact -Values $values -Name 'ANTHROPIC_BASE_URL' -Expected 'https://api.anthropic.com/v1'
Assert-Exact -Values $values -Name 'MODEL_GATEWAY_GENERATION_TIMEOUT_MS' -Expected '1200000'
Assert-Exact -Values $values -Name 'AI_ALLOW_UNCURATED_CVE_SIMULATION' -Expected 'true'
Assert-Secret -Values $values -Name 'AI_INTERNAL_TOKEN'
Assert-Secret -Values $values -Name 'MODEL_GATEWAY_INTERNAL_TOKEN'
Assert-Secret -Values $values -Name 'ANTHROPIC_API_KEY' -Prefix 'sk-ant-'

if ($values['AI_INTERNAL_TOKEN'] -ceq $values['MODEL_GATEWAY_INTERNAL_TOKEN']) {
    throw 'AI_INTERNAL_TOKEN and MODEL_GATEWAY_INTERNAL_TOKEN must be distinct.'
}

$model = Require-Value -Values $values -Name 'ANTHROPIC_MODEL'
if ($model -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$') {
    throw 'ANTHROPIC_MODEL is malformed.'
}
$version = Require-Value -Values $values -Name 'ANTHROPIC_VERSION'
if ($version -notmatch '^\d{4}-\d{2}-\d{2}$') {
    throw 'ANTHROPIC_VERSION must use YYYY-MM-DD format.'
}

$targetBase = Require-Value -Values $values -Name 'AI_TARGET_BASE_IMAGE'
if ($targetBase -notmatch '^[a-z0-9.-]+(?::\d+)?/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}$') {
    throw 'AI_TARGET_BASE_IMAGE must be a lowercase, digest-pinned OCI image reference.'
}
$outputRepository = Require-Value -Values $values -Name 'AI_OUTPUT_REPOSITORY'
if ($outputRepository -notmatch '^[a-z0-9.-]+(?::\d+)?/[a-z0-9]+(?:[._/-][a-z0-9]+)*$') {
    throw 'AI_OUTPUT_REPOSITORY must be a lowercase OCI repository reference without a tag.'
}

$packages = Assert-JsonObject -Values $values -Name 'PACKAGE_CATALOG_JSON'
$artifacts = Assert-JsonObject -Values $values -Name 'ARTIFACT_CATALOG_JSON'
foreach ($entry in $packages.PSObject.Properties) {
    if ($entry.Name -notmatch '^[a-z0-9][a-z0-9._-]*@[a-z0-9][a-z0-9.+_~-]*$') {
        throw 'PACKAGE_CATALOG_JSON contains a malformed package identifier.'
    }
    $package = $entry.Value
    if ($null -eq $package -or $package.imageRef -notmatch '^[a-z0-9.-]+(?::\d+)?/[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[a-f0-9]{64}$') {
        throw 'PACKAGE_CATALOG_JSON contains a package without a digest-pinned imageRef.'
    }
    $packageName = $entry.Name.Split('@')[0]
    if ($package.sourcePath -cne '/opt/codegate/package/' -or $package.destination -cne "/opt/codegate/packages/$packageName/" -or $package.runtimeKind -notin @('declarative-http-v1', 'signed-node-handler-v1')) {
        throw 'PACKAGE_CATALOG_JSON contains a package that does not match the ZeroTOP component ABI.'
    }
}
foreach ($entry in $artifacts.PSObject.Properties) {
    if ($entry.Name -notmatch '^[a-f0-9]{64}$' -or $entry.Value.url -notmatch '^https://') {
        throw 'ARTIFACT_CATALOG_JSON contains a malformed digest or non-HTTPS URL.'
    }
}

$rubrics = Assert-JsonObject -Values $values -Name 'RUBRIC_CATALOG_JSON'
if (@($rubrics.PSObject.Properties).Count -lt 1) {
    throw 'RUBRIC_CATALOG_JSON must contain at least one operator-owned grading policy.'
}

$git = Find-Git
$rootPrefix = $projectRoot.TrimEnd('\') + '\'
if ($null -ne $git -and $resolvedEnvFile.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    $relativePath = $resolvedEnvFile.Substring($rootPrefix.Length).Replace('\', '/')
    Push-Location $projectRoot
    try {
        & $git check-ignore --quiet -- $relativePath
        if ($LASTEXITCODE -ne 0) {
            throw "The local Claude config is not ignored by Git: $relativePath"
        }
        $trackedPath = @(& $git ls-files -- $relativePath)
        if ($LASTEXITCODE -ne 0) {
            throw 'Unable to verify whether the local Claude config is tracked by Git.'
        }
        if ($trackedPath.Count -gt 0) {
            throw "The local Claude config is already tracked by Git: $relativePath"
        }
    }
    finally {
        Pop-Location
    }
}

Write-Host 'Claude config check passed. Required values, catalogs, and Git-ignore protection are valid; no external API request was made.'
