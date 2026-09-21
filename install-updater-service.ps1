# install-updater-service.ps1
# This script installs the updater-bin as a Windows Service.
# Must be run as Administrator.

$ServiceName = "AgentUpdater"
$BinaryPath = "C:\ProgramData\agente-monitoramento\updater-bin.exe"
$ConfigDir = "C:\ProgramData\agente-monitoramento"
$SourceBinary = Join-Path $PSScriptRoot "target\debug\updater-bin.exe"

Write-Host "Checking administrative privileges..." -ForegroundColor Cyan
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# 1. Ensure directory exists
if (!(Test-Path $ConfigDir)) {
    Write-Host "Creating configuration directory: $ConfigDir" -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
}

# 2. Update binary from build folder
Write-Host "Updating service binary..." -ForegroundColor Cyan

# Check if service is running to avoid "file in use" error
$currentService = Get-Service $ServiceName -ErrorAction SilentlyContinue
if ($currentService -and $currentService.Status -eq 'Running') {
    Write-Host "Service is running. Stopping service to update binary..." -ForegroundColor Yellow
    Stop-Service $ServiceName -Force

    $timeout = 10
    while ($timeout -gt 0) {
        $status = (Get-Service $ServiceName).Status
        if ($status -eq 'Stopped') { break }
        Start-Sleep -Seconds 1
        $timeout--
    }
    if ($timeout -eq 0) {
        Write-Error "Service failed to stop within 10 seconds. Please stop it manually."
        exit 1
    }
}

if (!(Test-Path $SourceBinary)) {
    Write-Error "Source binary not found at $SourceBinary - please run 'cargo build -p updater-bin' first."
    exit 1
}

try {
    Copy-Item -Path $SourceBinary -Destination $BinaryPath -Force -ErrorAction Stop
    Write-Host "Binary updated successfully to $BinaryPath" -ForegroundColor Green
} catch {
    Write-Error "Failed to copy binary to ${BinaryPath}: $($_.Exception.Message)"
    exit 1
}

# 3. Create or Update the service
Write-Host "Processing service $ServiceName..." -ForegroundColor Cyan

$serviceExists = Get-Service $ServiceName -ErrorAction SilentlyContinue

if ($serviceExists) {
    Write-Host "Service $ServiceName already exists. Updating configuration..." -ForegroundColor Yellow
    # Updating binPath via sc.exe for precision with quoted paths and arguments
    sc.exe config $ServiceName binPath= "`"$BinaryPath`" --service"
} else {
    Write-Host "Installing new service $ServiceName..." -ForegroundColor Cyan
    $serviceParams = @{
        Name = $ServiceName
        BinaryPathName = "`"$BinaryPath`" --service"
        DisplayName = "Agent Monitoring Updater"
        StartupType = "Manual"
        Description = "Monitors and applies updates to the Monitoring Agent binary."
    }
    try {
        New-Service @serviceParams -ErrorAction Stop
        Write-Host "Successfully installed $ServiceName." -ForegroundColor Green
    } catch {
        Write-Error "Failed to install service: $($_.Exception.Message)"
        exit 1
    }
}

Write-Host "Installation complete. You can now start the service manually with: Start-Service $ServiceName" -ForegroundColor Green
