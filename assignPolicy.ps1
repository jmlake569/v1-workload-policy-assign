# PowerShell script to assign Trend Micro policies to computers
# Usage: .\Assign-Policy.ps1 -Policy "Policy Name" -CsvPath "path\to\computers.csv" [-DryRun] [-ApiKey "your-api-key"]

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0, HelpMessage="Name of the policy to assign")]
    [ValidateNotNullOrEmpty()]
    [string]$Policy,
    
    [Parameter(Mandatory=$true, Position=1, HelpMessage="Path to CSV file containing hostnames")]
    [ValidateNotNullOrEmpty()]
    [ValidateScript({
        if (-not (Test-Path $_)) {
            throw "CSV file not found at path: $_"
        }
        if (-not $_.EndsWith('.csv')) {
            throw "File must be a CSV file"
        }
        return $true
    })]
    [string]$CsvPath,
    
    [Parameter(Mandatory=$false, HelpMessage="Show what would be done without making changes")]
    [switch]$DryRun,
    
    [Parameter(Mandatory=$false, HelpMessage="Trend Micro API key (can also use TREND_API_KEY environment variable)")]
    [ValidateNotNullOrEmpty()]
    [string]$ApiKey
)

# Function to set up logging
function Initialize-Logging {
    param(
        [bool]$DryRun
    )
    
    # Create logs directory if it doesn't exist
    $logDir = "logs"
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir | Out-Null
    }
    
    # Generate log filename with timestamp
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $runType = if ($DryRun) { "dry_run" } else { "run" }
    $logFile = Join-Path $logDir "policy_assignment_${runType}_${timestamp}.log"
    
    # Set up logging configuration
    $script:LogFile = $logFile
    
    # Log initial information
    Write-Log "Logging initialized. File: $logFile" -Level Info
    if ($DryRun) {
        Write-Log "Running in DRY RUN mode - no changes will be made" -Level Info
        Write-Log "----------------------------------------" -Level Info
    }
}

# Function to write to both console and log file
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Debug', 'Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Level - $Message"
    
    # Write to console with appropriate color
    switch ($Level) {
        'Debug'   { Write-Host $logMessage -ForegroundColor Gray }
        'Info'    { Write-Host $logMessage -ForegroundColor White }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
    }
    
    # Write to log file
    Add-Content -Path $script:LogFile -Value $logMessage
    
    # Check log file size and rotate if necessary
    $maxSize = 10MB
    $maxBackups = 5
    
    if ((Get-Item $script:LogFile).Length -gt $maxSize) {
        $logDir = Split-Path $script:LogFile
        $logBase = [System.IO.Path]::GetFileNameWithoutExtension($script:LogFile)
        $logExt = [System.IO.Path]::GetExtension($script:LogFile)
        
        # Remove oldest backup if it exists
        $oldestBackup = Join-Path $logDir "${logBase}_backup${maxBackups}${logExt}"
        if (Test-Path $oldestBackup) {
            Remove-Item $oldestBackup -Force
        }
        
        # Rotate existing backups
        for ($i = $maxBackups - 1; $i -ge 1; $i--) {
            $oldFile = Join-Path $logDir "${logBase}_backup${i}${logExt}"
            $newFile = Join-Path $logDir "${logBase}_backup$($i + 1)${logExt}"
            if (Test-Path $oldFile) {
                Move-Item $oldFile $newFile -Force
            }
        }
        
        # Rename current log file
        $backupFile = Join-Path $logDir "${logBase}_backup1${logExt}"
        Move-Item $script:LogFile $backupFile -Force
        
        # Create new log file
        New-Item -ItemType File -Path $script:LogFile | Out-Null
        Write-Log "Log file rotated due to size limit" -Level Info
    }
}

# Error handling function
function Write-ErrorWithExit {
    param(
        [string]$Message,
        [int]$ExitCode = 1
    )
    Write-Log $Message -Level Error
    exit $ExitCode
}

# Function to sanitize hostname
function Test-Hostname {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Hostname
    )
    
    # Trim whitespace
    $Hostname = $Hostname.Trim()
    
    # Check if hostname is empty after trimming
    if ([string]::IsNullOrWhiteSpace($Hostname)) {
        Write-Log "Empty hostname found" -Level Warning
        return $false
    }
    
    # Check if hostname is too long (RFC 1035 specifies 255 characters max)
    if ($Hostname.Length -gt 255) {
        Write-Log "Hostname exceeds maximum length of 255 characters: $Hostname" -Level Warning
        return $false
    }
    
    # Check for invalid characters
    $invalidChars = [regex]::Escape('!@#$%^&*()+=[]{}|;:"<>?/')
    if ($Hostname -match "[$invalidChars]") {
        Write-Log "Hostname contains invalid characters: $Hostname" -Level Warning
        return $false
    }
    
    return $true
}

# API Configuration
$API_VERSION = "v1"
$BASE_URL = "https://cloudone.trendmicro.com/api"

# Function to get API key
function Get-ApiKey {
    try {
        if ($ApiKey) {
            Write-Log "Using API key from command line arguments" -Level Debug
            return $ApiKey
        }
        elseif ($env:TREND_API_KEY) {
            Write-Log "Using API key from environment variable" -Level Debug
            return $env:TREND_API_KEY
        }
        else {
            Write-ErrorWithExit "API key not provided. Please provide it via -ApiKey parameter or TREND_API_KEY environment variable."
        }
    }
    catch {
        Write-ErrorWithExit "Error retrieving API key: $_"
    }
}

# Function to validate API response
function Test-ApiResponse {
    param(
        [Parameter(Mandatory=$true)]
        [object]$Response,
        
        [Parameter(Mandatory=$true)]
        [string]$Operation
    )
    
    if (-not $Response) {
        Write-Log "No response received from API during $Operation" -Level Error
        Write-ErrorWithExit "No response received from API during $Operation"
    }
    
    if ($Response -is [System.Management.Automation.ErrorRecord]) {
        Write-Log "API Error during $Operation`: $($Response.Exception.Message)" -Level Error
        Write-ErrorWithExit "API Error during $Operation`: $($Response.Exception.Message)"
    }
    
    Write-Log "API $Operation successful" -Level Debug
}

# Function to get policy ID
function Get-PolicyId {
    param(
        [string]$PolicyName,
        [string]$ApiKey,
        [bool]$DryRun
    )
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would search for policy with name: $PolicyName" -Level Info
    }
    
    $headers = @{
        "api-version" = $API_VERSION
        "api-secret-key" = $ApiKey
        "Content-Type" = "application/json"
    }
    
    $url = "$BASE_URL/policies"
    $params = @{
        "expand" = "none"
    }
    
    try {
        Write-Log "Requesting policy list from $url" -Level Debug
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
        Test-ApiResponse -Response $response -Operation "policy lookup"
        
        $policy = $response.policies | Where-Object { $_.name -eq $PolicyName } | Select-Object -First 1
        
        if ($policy) {
            if ($DryRun) {
                Write-Log "[DRY RUN] Found policy ID: $($policy.ID)" -Level Info
            }
            Write-Log "Found policy '$PolicyName' with ID: $($policy.ID)" -Level Debug
            return $policy.ID
        }
        
        Write-Log "Policy '$PolicyName' not found" -Level Error
        Write-ErrorWithExit "Policy '$PolicyName' not found"
    }
    catch [System.Net.WebException] {
        Write-Log "Network error during policy lookup: $($_.Exception.Message)" -Level Error
        Write-ErrorWithExit "Network error during policy lookup: $($_.Exception.Message)"
    }
    catch {
        Write-Log "Error getting policy ID: $_" -Level Error
        Write-ErrorWithExit "Error getting policy ID: $_"
    }
}

# Function to assign policy to computer
function Set-ComputerPolicy {
    param(
        [string]$ComputerId,
        [string]$PolicyId,
        [string]$ApiKey,
        [bool]$DryRun
    )
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would assign policy ID $PolicyId to computer ID $ComputerId" -Level Info
        return $true
    }
    
    $headers = @{
        "api-version" = $API_VERSION
        "api-secret-key" = $ApiKey
        "Content-Type" = "application/json"
    }
    
    $url = "$BASE_URL/computers/$ComputerId"
    $body = @{
        "policyID" = $PolicyId
    } | ConvertTo-Json
    
    try {
        Write-Log "Assigning policy $PolicyId to computer $ComputerId" -Level Debug
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $body -ErrorAction Stop
        Test-ApiResponse -Response $response -Operation "policy assignment"
        return $true
    }
    catch [System.Net.WebException] {
        Write-Log "Network error assigning policy to computer $ComputerId`: $($_.Exception.Message)" -Level Error
        return $false
    }
    catch {
        Write-Log "Error assigning policy to computer $ComputerId`: $_" -Level Error
        return $false
    }
}

# Function to list computers
function Get-Computers {
    param(
        [string]$ApiKey,
        [bool]$DryRun
    )
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Fetching list of computers..." -Level Info
    }
    
    $headers = @{
        "api-version" = $API_VERSION
        "api-secret-key" = $ApiKey
        "Content-Type" = "application/json"
    }
    
    $params = @{
        "expand" = "none"
    }
    
    $url = "$BASE_URL/computers"
    
    try {
        Write-Log "Requesting computer list from $url" -Level Debug
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
        Test-ApiResponse -Response $response -Operation "computer listing"
        Write-Log "Retrieved $($response.computers.Count) computers" -Level Debug
        return $response
    }
    catch [System.Net.WebException] {
        Write-Log "Network error fetching computer list: $($_.Exception.Message)" -Level Error
        Write-ErrorWithExit "Network error fetching computer list: $($_.Exception.Message)"
    }
    catch {
        Write-Log "Error making request: $_" -Level Error
        Write-ErrorWithExit "Error making request: $_"
    }
}

# Main execution
try {
    # Initialize logging
    Initialize-Logging -DryRun $DryRun
    
    $apiKey = Get-ApiKey

    # Get policy ID
    $policyId = Get-PolicyId -PolicyName $Policy -ApiKey $apiKey -DryRun $DryRun
    if (-not $policyId) {
        Write-ErrorWithExit "Failed to get policy ID"
    }

    # Get list of computers
    $computers = Get-Computers -ApiKey $apiKey -DryRun $DryRun
    if (-not $computers) {
        Write-ErrorWithExit "Failed to get computer list"
    }

    # Create a mapping of hostname to computer ID
    $computerMap = @{}
    foreach ($comp in $computers.computers) {
        if (-not $comp.hostName) {
            Write-Log "Found computer without hostname, skipping..." -Level Warning
            continue
        }
        
        # Sanitize and validate hostname from API
        if (-not (Test-Hostname -Hostname $comp.hostName)) {
            Write-Log "Found computer with invalid hostname, skipping..." -Level Warning
            continue
        }
        
        $computerMap[$comp.hostName] = $comp.ID
    }
    
    Write-Log "Created mapping for $($computerMap.Count) valid computers" -Level Debug

    # Read CSV and assign policy
    $successCount = 0
    $failCount = 0
    $notFoundCount = 0
    $invalidHostnameCount = 0

    try {
        Write-Log "Reading CSV file: $CsvPath" -Level Debug
        $csvData = Import-Csv -Path $CsvPath -ErrorAction Stop
    }
    catch {
        Write-Log "Error reading CSV file: $_" -Level Error
        Write-ErrorWithExit "Error reading CSV file: $_"
    }

    foreach ($row in $csvData) {
        if (-not $row.hostName) {
            Write-Log "Found row without hostname, skipping..." -Level Warning
            $failCount++
            continue
        }

        $hostname = $row.hostName.Trim()
        
        # Validate hostname from CSV
        if (-not (Test-Hostname -Hostname $hostname)) {
            Write-Log "Invalid hostname in CSV: $hostname" -Level Warning
            $invalidHostnameCount++
            $failCount++
            continue
        }

        if ($computerMap.ContainsKey($hostname)) {
            if (Set-ComputerPolicy -ComputerId $computerMap[$hostname] -PolicyId $policyId -ApiKey $apiKey -DryRun $DryRun) {
                Write-Log "Successfully assigned policy to $hostname" -Level Info
                $successCount++
            }
            else {
                Write-Log "Failed to assign policy to $hostname" -Level Error
                $failCount++
            }
        }
        else {
            Write-Log "Computer $hostname not found in the system" -Level Warning
            $notFoundCount++
            $failCount++
        }
    }

    Write-Log "`nSummary:" -Level Info
    Write-Log "Successfully assigned policy to $successCount computers" -Level Info
    Write-Log "Failed to assign policy to $failCount computers" -Level Info
    if ($notFoundCount -gt 0) {
        Write-Log "Computers not found in system: $notFoundCount" -Level Info
    }
    if ($invalidHostnameCount -gt 0) {
        Write-Log "Invalid hostnames in CSV: $invalidHostnameCount" -Level Info
    }

    if ($DryRun) {
        Write-Log "`nThis was a DRY RUN - no actual changes were made" -Level Info
    }
}
catch {
    Write-Log "Unexpected error: $_" -Level Error
    Write-ErrorWithExit "Unexpected error: $_"
} 