[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$runtimeDirectory = Join-Path $PSScriptRoot '.runtime'
$processFile = Join-Path $runtimeDirectory 'processes.json'

$metadata = if (Test-Path -LiteralPath $processFile) {
    Get-Content -LiteralPath $processFile -Raw | ConvertFrom-Json
}
else {
    $null
}
$stoppedAny = $false

foreach ($name in @('web', 'api', 'runtime')) {
    if ($null -eq $metadata) {
        continue
    }
    $record = $metadata.$name
    if ($null -eq $record) {
        continue
    }

    $process = Get-Process -Id ([int]$record.pid) -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        continue
    }

    $expectedStart = [DateTimeOffset]::Parse([string]$record.startedAtUtc).UtcDateTime
    $actualStart = $process.StartTime.ToUniversalTime()
    if ([Math]::Abs(($actualStart - $expectedStart).TotalSeconds) -gt 2) {
        Write-Warning "Refusing to stop PID $($record.pid): it has been reused by a different process."
        continue
    }

    # /T stops the pnpm wrapper and only its child process tree after PID/start-time validation.
    & taskkill.exe /PID ([string]$record.pid) /T /F *> $null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Stopped $name (PID $($record.pid))."
        $stoppedAny = $true
    }
}

if (Test-Path -LiteralPath $processFile) {
    Remove-Item -LiteralPath $processFile -Force
}

$docker = Get-Command docker -ErrorAction SilentlyContinue
if ($null -eq $docker) {
    $installedDocker = 'C:\Program Files\Docker\Docker\resources\bin\docker.exe'
    if (Test-Path -LiteralPath $installedDocker) {
        $docker = [pscustomobject]@{ Source = $installedDocker }
    }
}
if ($null -ne $docker) {
    $managedContainers = @(& $docker.Source container ls -aq --filter 'label=codegate.ai.managed-by=codegate-runtime')
    $managedContainers = @($managedContainers | Where-Object { $_ -match '^[a-f0-9]{12,64}$' })
    if ($managedContainers.Count -gt 0) {
        & $docker.Source rm -f @managedContainers *> $null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Removed $($managedContainers.Count) disposable Lab container(s)."
            $stoppedAny = $true
        }
    }

    $gatewayExists = try {
        & $docker.Source container inspect codegate-local-desktop-gateway *> $null
        $LASTEXITCODE -eq 0
    }
    catch {
        $false
    }
    if ($gatewayExists) {
        & $docker.Source rm -f codegate-local-desktop-gateway *> $null
        if ($LASTEXITCODE -eq 0) {
            Write-Host 'Removed the local desktop gateway container.'
            $stoppedAny = $true
        }
    }

    $networkExists = try {
        & $docker.Source network inspect codegate-local-desktops *> $null
        $LASTEXITCODE -eq 0
    }
    catch {
        $false
    }
    if ($networkExists) {
        & $docker.Source network rm codegate-local-desktops *> $null
        if ($LASTEXITCODE -eq 0) {
            Write-Host 'Removed the isolated local desktop network.'
        }
    }
}

if (-not $stoppedAny) {
    Write-Host 'The recorded development processes were already stopped.'
}
