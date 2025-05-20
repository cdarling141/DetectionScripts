# PowerShell script to validate digital signatures of executables in scheduled tasks
# Handles environment variables in executable paths
# Warns about unsigned or invalid executables with file details
# Exports results to CSV

# Ensure running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit
}

# Define output CSV path
$outputCsv = "C:\capture\ScheduledTaskSignatureStatus.csv"
$logDir = Split-Path $outputCsv -Parent
if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

# Get all non-disabled scheduled tasks
$tasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' }

# Initialize array for results
$taskResults = @()

# Counter for unsigned/invalid tasks
$unsignedCount = 0

Write-Host "Checking digital signatures for executables in scheduled tasks..." -ForegroundColor Cyan

foreach ($task in $tasks) {
    $actions = $task.Actions
    foreach ($action in $actions) {
        # Check if the action executes an .exe
        if ($action.Execute -and $action.Execute -like "*.exe") {
            $rawExePath = $action.Execute

            # Handle quoted paths or arguments
            if ($rawExePath -match '^"([^"]+)"') {
                $rawExePath = $matches[1]
            }

            # Expand environment variables in the path
            $exePath = [Environment]::ExpandEnvironmentVariables($rawExePath)

            $result = [PSCustomObject]@{
                TaskName        = $task.TaskName
                TaskPath        = $task.TaskPath
                RawExecutable   = $rawExePath
                ExpandedExecutable = $exePath
                SignatureStatus = $null
                Signer          = $null
                FileHash        = $null
                FileExists      = $false
                LastWriteTime   = $null
                Trigger         = ($task.Triggers | ForEach-Object { $_.CimClass.CimClassName -replace 'MSFT_Task', '' }) -join ', '
            }

            # Check if the file exists
            if (Test-Path $exePath -PathType Leaf) {
                $result.FileExists = $true
                try {
                    # Get digital signature
                    $signature = Get-AuthenticodeSignature -FilePath $exePath
                    $result.SignatureStatus = if ($signature.SignerCertificate -eq $null) { "NotSigned" } else { $signature.Status }
                    $result.Signer = if ($signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { "None" }

                    # Get file hash (SHA256)
                    $hash = Get-FileHash -Path $exePath -Algorithm SHA256 -ErrorAction SilentlyContinue
                    $result.FileHash = if ($hash) { $hash.Hash } else { "N/A" }

                    # Get last write time
                    $fileInfo = Get-Item $exePath
                    $result.LastWriteTime = $fileInfo.LastWriteTime

                    # Warn if unsigned or invalid
                    if ($result.SignatureStatus -ne "Valid") {
                        $unsignedCount++
                        Write-Warning "Unsigned or invalid executable found in task:"
                        Write-Host ("  Task Name: " + $result.TaskName) -ForegroundColor Yellow
                        Write-Host ("  Task Path: " + $result.TaskPath) -ForegroundColor Yellow
                        Write-Host ("  Raw Executable: " + $result.RawExecutable) -ForegroundColor Yellow
                        Write-Host ("  Expanded Executable: " + $exePath) -ForegroundColor Yellow
                        Write-Host ("  Signature Status: " + $result.SignatureStatus) -ForegroundColor Yellow
                        Write-Host ("  Signer: " + $result.Signer) -ForegroundColor Yellow
                        Write-Host ("  SHA256 Hash: " + $result.FileHash) -ForegroundColor Yellow
                        Write-Host ("  Last Modified: " + $result.LastWriteTime) -ForegroundColor Yellow
                        Write-Host ("  Triggers: " + $result.Trigger) -ForegroundColor Yellow
                        Write-Host "  Recommendation: Investigate this task and executable for potential malicious activity." -ForegroundColor Red
                    }
                } catch {
                    $result.SignatureStatus = "Error: $_"
                    $result.Signer = "None"
                    $unsignedCount++
                    Write-Warning "Error checking executable in task:"
                    Write-Host ("  Task Name: " + $result.TaskName) -ForegroundColor Yellow
                    Write-Host ("  Task Path: " + $result.TaskPath) -ForegroundColor Yellow
                    Write-Host ("  Raw Executable: " + $result.RawExecutable) -ForegroundColor Yellow
                    Write-Host ("  Expanded Executable: " + $exePath) -ForegroundColor Yellow
                    Write-Host ("  Error: " + $_) -ForegroundColor Yellow
                    Write-Host "  Recommendation: Verify if the file exists and has correct permissions." -ForegroundColor Red
                }
            } else {
                $result.SignatureStatus = "File not found"
                $result.Signer = "None"
                $unsignedCount++
                Write-Warning "Executable not found for task:"
                Write-Host ("  Task Name: " + $result.TaskName) -ForegroundColor Yellow
                Write-Host ("  Task Path: " + $result.TaskPath) -ForegroundColor Yellow
                Write-Host ("  Raw Executable: " + $result.RawExecutable) -ForegroundColor Yellow
                Write-Host ("  Expanded Executable: " + $exePath) -ForegroundColor Yellow
                Write-Host ("  Triggers: " + $result.Trigger) -ForegroundColor Yellow
                Write-Host "  Recommendation: Investigate why the executable is missing; it may indicate a broken or malicious task." -ForegroundColor Red
            }

            $taskResults += $result
        }
    }
}

# Summary
Write-Host "`nSummary:" -ForegroundColor Cyan
Write-Host "Total tasks checked: $($tasks.Count)" -ForegroundColor Green
Write-Host "Tasks with unsigned/invalid/missing executables: $unsignedCount" -ForegroundColor $(if ($unsignedCount -gt 0) { "Red" } else { "Green" })

# Export results to CSV
if ($taskResults.Count -gt 0) {
    $taskResults | Export-Csv -Path $outputCsv -NoTypeInformation
    Write-Host "Results exported to: $outputCsv" -ForegroundColor Green
} else {
    Write-Host "No tasks with executable actions found." -ForegroundColor Yellow
}

# Additional guidance for ransomware context
if ($unsignedCount -gt 0) {
    Write-Host "`nSecurity Note:" -ForegroundColor Red
    Write-Host "Unsigned or missing executables in scheduled tasks may indicate malicious activity, especially given detected DNS queries to known ransomware domains (e.g., sombrat.com, parkerpublic.com, tumbleproperty.com). Recommended actions:" -ForegroundColor Red
    Write-Host "- Investigate tasks listed above, focusing on those with startup triggers." -ForegroundColor Red
    Write-Host "- Check executable paths (e.g., %Temp%, %AppData%) and submit hashes to VirusTotal." -ForegroundColor Red
    Write-Host "- Run antivirus/EDR scans and isolate the system if malware is suspected." -ForegroundColor Red
    Write-Host "- Block malicious domains at the firewall/DNS level." -ForegroundColor Red
    Write-Host "- Report to CISA (cisa.gov/report) if ransomware is confirmed." -ForegroundColor Red
}