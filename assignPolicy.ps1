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

# Function to initialize logging
function Initialize-Logging {
    param(
        [bool]$DryRun
    )
    
    # Create logs directory if it doesn't exist
    if (-not (Test-Path "logs")) {
        New-Item -ItemType Directory -Path "logs" | Out-Null
    }
    
    # Generate log filename with timestamp
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $runType = if ($DryRun) { "dry_run" } else { "run" }
    $logFile = "logs/policy_assignment_${runType}_${timestamp}.log"
    
    # Set up logging
    $script:LogFile = $logFile
    Write-Host "Logging to: $logFile"
}

# Function to write log messages
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Debug", "Info", "Warning", "Error")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Level - $Message"
    
    # Write to log file
    Add-Content -Path $script:LogFile -Value $logMessage
    
    # Write to console with appropriate color
    switch ($Level) {
        "Debug"   { Write-Host $logMessage -ForegroundColor Gray }
        "Info"    { Write-Host $logMessage }
        "Warning" { Write-Host $logMessage -ForegroundColor Yellow }
        "Error"   { Write-Host $logMessage -ForegroundColor Red }
    }
}

# Error handling function
function Write-ErrorWithExit {
    param(
        [string]$Message,
        [int]$ExitCode = 1
    )
    Write-Log -Message $Message -Level Error
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
        return $false
    }
    
    # Check if hostname is too long (RFC 1035 specifies 255 characters max)
    if ($Hostname.Length -gt 255) {
        Write-Warning "Hostname exceeds maximum length of 255 characters: $Hostname"
        return $false
    }
    
    # Check for invalid characters
    $invalidChars = [regex]::Escape('!@#$%^&*()+=[]{}|;:"<>?/')
    if ($Hostname -match "[$invalidChars]") {
        Write-Warning "Hostname contains invalid characters: $Hostname"
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
            return $ApiKey
        }
        elseif ($env:TREND_API_KEY) {
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
        Write-ErrorWithExit "No response received from API during $Operation"
    }
    
    if ($Response -is [System.Management.Automation.ErrorRecord]) {
        Write-ErrorWithExit "API Error during $Operation`: $($Response.Exception.Message)"
    }
}

# Function to handle rate limiting
function Start-SleepWithLog {
    param(
        [int]$Seconds,
        [string]$Reason
    )
    Write-Log "Rate limit detected. Waiting $Seconds seconds before retrying... Reason: $Reason" -Level Warning
    Start-Sleep -Seconds $Seconds
}

# Function to make API request with rate limiting
function Invoke-ApiRequest {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Uri,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$Headers,
        
        [Parameter(Mandatory=$false)]
        [string]$Method = "Get",
        
        [Parameter(Mandatory=$false)]
        [object]$Body,
        
        [Parameter(Mandatory=$false)]
        [int]$MaxRetries = 5,
        
        [Parameter(Mandatory=$false)]
        [int]$InitialDelay = 5
    )
    
    $retryCount = 0
    $delay = $InitialDelay
    
    while ($retryCount -lt $MaxRetries) {
        try {
            $params = @{
                Uri = $Uri
                Headers = $Headers
                Method = $Method
                ErrorAction = "Stop"
            }
            
            if ($Body) {
                $params.Body = $Body
            }
            
            Write-Log "Making API request to $Uri" -Level Debug
            
            # Add a longer delay between requests to prevent hitting rate limits
            Start-Sleep -Seconds 2
            
            $response = Invoke-RestMethod @params
            return $response
        }
        catch [System.Net.WebException] {
            $statusCode = $_.Exception.Response.StatusCode.value__
            
            # Check for rate limit (429) or connection issues
            if ($statusCode -eq 429 -or $_.Exception.Message -like "*connection was forcibly closed*") {
                $retryCount++
                if ($retryCount -lt $MaxRetries) {
                    Write-Log "Rate limit or connection issue detected. Attempt $retryCount of $MaxRetries" -Level Warning
                    # Use exponential backoff with a longer initial delay
                    $delay = [math]::Pow(2, $retryCount) * $InitialDelay
                    Start-SleepWithLog -Seconds $delay -Reason "Rate limit/Connection issue"
                    continue
                }
            }
            throw
        }
        catch {
            throw
        }
    }
    
    throw "Maximum retry attempts reached"
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
        $response = Invoke-ApiRequest -Uri $url -Headers $headers -Method Get
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
        $response = Invoke-ApiRequest -Uri $url -Headers $headers -Method Post -Body $body
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
        $response = Invoke-ApiRequest -Uri $url -Headers $headers -Method Get
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

# Function to process computers in batches
function Process-ComputerBatch {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Computers,
        
        [Parameter(Mandatory=$true)]
        [string]$PolicyId,
        
        [Parameter(Mandatory=$true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory=$true)]
        [bool]$DryRun,
        
        [Parameter(Mandatory=$false)]
        [int]$BatchSize = 10
    )
    
    $successCount = 0
    $failCount = 0
    $notFoundCount = 0
    $invalidHostnameCount = 0
    
    # Process computers in batches
    for ($i = 0; $i -lt $Computers.Count; $i += $BatchSize) {
        $batch = $Computers | Select-Object -Skip $i -First $BatchSize
        
        Write-Log "Processing batch of $($batch.Count) computers (batch $([math]::Floor($i/$BatchSize) + 1) of $([math]::Ceiling($Computers.Count/$BatchSize)))" -Level Info
        
        foreach ($computer in $batch) {
            $hostname = $computer.hostName.Trim()
            
            if (-not $hostname) {
                Write-Log "Found computer without hostname, skipping..." -Level Warning
                $failCount++
                continue
            }
            
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
        
        # Add a delay between batches to prevent rate limiting
        if ($i + $BatchSize -lt $Computers.Count) {
            Write-Log "Waiting 5 seconds before processing next batch..." -Level Info
            Start-Sleep -Seconds 5
        }
    }
    
    return @{
        SuccessCount = $successCount
        FailCount = $failCount
        NotFoundCount = $notFoundCount
        InvalidHostnameCount = $invalidHostnameCount
    }
}

# Main execution
try {
    # Initialize logging
    Initialize-Logging -DryRun $DryRun
    
    $apiKey = Get-ApiKey

    if ($DryRun) {
        Write-Log "Running in DRY RUN mode - no changes will be made" -Level Info
        Write-Log "----------------------------------------" -Level Info
    }

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
            Write-Warning "Found computer without hostname, skipping..."
            continue
        }
        
        # Sanitize and validate hostname from API
        if (-not (Test-Hostname -Hostname $comp.hostName)) {
            Write-Warning "Found computer with invalid hostname, skipping..."
            continue
        }
        
        $computerMap[$comp.hostName] = $comp.ID
    }

    # Read CSV and process in batches
    try {
        $csvData = Import-Csv -Path $CsvPath -ErrorAction Stop
        $results = Process-ComputerBatch -Computers $csvData -PolicyId $policyId -ApiKey $apiKey -DryRun $DryRun -BatchSize 10
    }
    catch {
        Write-ErrorWithExit "Error reading CSV file: $_"
    }

    # Print summary
    Write-Host "`nSummary:"
    Write-Host "Successfully assigned policy to $($results.SuccessCount) computers"
    Write-Host "Failed to assign policy to $($results.FailCount) computers"
    if ($results.NotFoundCount -gt 0) {
        Write-Host "Computers not found in system: $($results.NotFoundCount)"
    }
    if ($results.InvalidHostnameCount -gt 0) {
        Write-Host "Invalid hostnames in CSV: $($results.InvalidHostnameCount)"
    }

    if ($DryRun) {
        Write-Log "`nThis was a DRY RUN - no actual changes were made" -Level Info
    }
}
catch {
    Write-ErrorWithExit "Unexpected error: $_"
}