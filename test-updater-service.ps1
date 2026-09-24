# test-updater-service.ps1
# This script helps verify the status of the AgentUpdater service.
# Must be run as Administrator.
#
# NOTE: Start-Service and Stop-Service should be run manually by the user
# in a separate terminal to allow observation of logs and status transitions.

$ServiceName = "AgentUpdater"

Write-Host "--- AgentUpdater Service Status Check ---" -ForegroundColor Cyan

# 1. Check administrative privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# 2. Check if service exists
if (!(Get-Service $ServiceName -ErrorAction SilentlyContinue)) {
    Write-Error "Service $ServiceName is not installed. Please run install-updater-service.ps1 first."
    exit 1
}

# 3. Show current status
$status = Get-Service $ServiceName
Write-Host "Service Name: $($status.Name)"
Write-Host "Display Name: $($status.DisplayName)"
Write-Host "Status:       $($status.Status)" -ForegroundColor ($status.Status -eq 'Running' ? "Green" : "Yellow")
Write-Host "Start Type:   $($status.StartType)"

Write-Host "`nManual Testing Guide:" -ForegroundColor Gray
Write-Host "1. To start the service: Start-Service $ServiceName"
Write-Host "2. To stop the service:  Stop-Service $ServiceName"
Write-Host "3. Check logs in C:\ProgramData\agente-monitoramento (if configured)"
