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

# Function to get a specific computer by hostname
function Get-ComputerByHostname {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Hostname,
        
        [Parameter(Mandatory=$true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory=$false)]
        [bool]$DryRun = $false
    )
    
    $headers = @{
        "api-version" = $API_VERSION
        "api-secret-key" = $ApiKey
        "Content-Type" = "application/json"
    }
    
    # Use computers endpoint instead of search
    $url = "$BASE_URL/computers?expand=none"
    
    try {
        Write-Log ("Searching for computer with hostname: {0}" -f $Hostname) -Level Debug
        
        $response = Invoke-ApiRequest -Uri $url -Headers $headers -Method Get
        
        if ($response.computers -and $response.computers.Count -gt 0) {
            # Find computer by hostname in the response
            $matchingComputer = $response.computers | Where-Object { $_.hostName -eq $Hostname } | Select-Object -First 1
            
            if ($matchingComputer) {
                Write-Log ("Found computer with hostname: {0}" -f $Hostname) -Level Info
                Write-Log ("  - ID: {0}, Hostname: {1}, PolicyID: {2}" -f $matchingComputer.ID, $matchingComputer.hostName, $matchingComputer.policyID) -Level Info
                return $matchingComputer
            }
            else {
                # Try case-insensitive match
                $matchingComputer = $response.computers | Where-Object { $_.hostName -ieq $Hostname } | Select-Object -First 1
                if ($matchingComputer) {
                    Write-Log ("Found case-insensitive match: {0}" -f $matchingComputer.hostName) -Level Info
                    return $matchingComputer
                }
            }
        }
        
        Write-Log ("Computer not found with hostname: {0}" -f $Hostname) -Level Warning
        return $null
    }
    catch {
        Write-Log ("Error searching for computer: {0}" -f $_) -Level Error
        return $null
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
        Write-Log ("[DRY RUN] Would assign policy ID {0} to computer ID {1}" -f $PolicyId, $ComputerId) -Level Info
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
        Write-Log ("Assigning policy {0} to computer {1}" -f $PolicyId, $ComputerId) -Level Debug
        $response = Invoke-ApiRequest -Uri $url -Headers $headers -Method Post -Body $body
        Test-ApiResponse -Response $response -Operation "policy assignment"
        return $true
    }
    catch [System.Net.WebException] {
        Write-Log ("Network error assigning policy to computer {0}: {1}" -f $ComputerId, $_.Exception.Message) -Level Error
        return $false
    }
    catch {
        Write-Log ("Error assigning policy to computer {0}: {1}" -f $ComputerId, $_) -Level Error
        return $false
    }
}

# Function to process computers in batches
function Process-ComputerBatch {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CsvPath,
        
        [Parameter(Mandatory=$true)]
        [string]$PolicyId,
        
        [Parameter(Mandatory=$true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory=$true)]
        [bool]$DryRun,
        
        [Parameter(Mandatory=$false)]
        [int]$BatchSize = 100  # Increased batch size for efficiency
    )
    
    $script:successCount = 0
    $script:failCount = 0
    $script:notFoundCount = 0
    $script:invalidHostnameCount = 0
    $currentComputer = 0
    
    # Get total number of lines in CSV (excluding header)
    $totalLines = (Get-Content $CsvPath).Count - 1
    Write-Log ("Found {0} computers in CSV file" -f $totalLines) -Level Info
    
    # Process CSV in batches using Get-Content for streaming
    $batch = @()
    $header = $null
    
    Get-Content $CsvPath | ForEach-Object {
        if (-not $header) {
            $header = $_
            return
        }
        
        $batch += [PSCustomObject]@{
            hostName = $_.Split(',')[0].Trim('"')  # Assuming hostname is first column
        }
        
        if ($batch.Count -eq $BatchSize) {
            Process-Batch -Batch $batch -PolicyId $PolicyId -ApiKey $ApiKey -DryRun $DryRun -CurrentComputer $currentComputer -TotalLines $totalLines
            $currentComputer += $batch.Count
            $batch = @()
            
            # Add a delay between batches to prevent rate limiting
            if ($currentComputer -lt $totalLines) {
                Write-Log "Waiting 5 seconds before processing next batch..." -Level Info
                Start-Sleep -Seconds 5
            }
        }
    }
    
    # Process any remaining computers
    if ($batch.Count -gt 0) {
        Process-Batch -Batch $batch -PolicyId $PolicyId -ApiKey $ApiKey -DryRun $DryRun -CurrentComputer $currentComputer -TotalLines $totalLines
    }
    
    return @{
        SuccessCount = $script:successCount
        FailCount = $script:failCount
        NotFoundCount = $script:notFoundCount
        InvalidHostnameCount = $script:invalidHostnameCount
    }
}

# Function to process a single batch
function Process-Batch {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Batch,
        
        [Parameter(Mandatory=$true)]
        [string]$PolicyId,
        
        [Parameter(Mandatory=$true)]
        [string]$ApiKey,
        
        [Parameter(Mandatory=$true)]
        [bool]$DryRun,
        
        [Parameter(Mandatory=$true)]
        [int]$CurrentComputer,
        
        [Parameter(Mandatory=$true)]
        [int]$TotalLines
    )
    
    $batchNumber = [math]::Floor($CurrentComputer/$Batch.Count) + 1
    $totalBatches = [math]::Ceiling($TotalLines/$Batch.Count)
    Write-Log ("Processing batch of {0} computers (batch {1} of {2})" -f $Batch.Count, $batchNumber, $totalBatches) -Level Info
    
    foreach ($computer in $Batch) {
        $currentComputer++
        $hostname = $computer.hostName.Trim()
        
        Write-Log ("Processing computer {0} of {1}: {2}" -f $currentComputer, $TotalLines, $hostname) -Level Info
        
        if (-not $hostname) {
            Write-Log "Found computer without hostname, skipping..." -Level Warning
            $script:failCount++
            continue
        }
        
        if (-not (Test-Hostname -Hostname $hostname)) {
            Write-Log ("Invalid hostname in CSV: {0}" -f $hostname) -Level Warning
            $script:invalidHostnameCount++
            $script:failCount++
            continue
        }
        
        # Search for specific computer
        $computerInfo = Get-ComputerByHostname -Hostname $hostname -ApiKey $apiKey -DryRun $DryRun
        
        if ($computerInfo) {
            if ($DryRun) {
                Write-Log ("[DRY RUN] Would assign policy ID {0} to computer ID {1}" -f $PolicyId, $computerInfo.ID) -Level Info
                $script:successCount++
            }
            else {
                if (Set-ComputerPolicy -ComputerId $computerInfo.ID -PolicyId $policyId -ApiKey $apiKey -DryRun $DryRun) {
                    Write-Log ("Successfully assigned policy to {0}" -f $hostname) -Level Info
                    $script:successCount++
                }
                else {
                    Write-Log ("Failed to assign policy to {0}" -f $hostname) -Level Error
                    $script:failCount++
                }
            }
        }
        else {
            $script:notFoundCount++
            $script:failCount++
        }
        
        # Add a small delay between individual computers to prevent rate limiting
        if ($currentComputer -lt $TotalLines) {
            Start-Sleep -Seconds 1
        }
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

    # Process CSV in batches
    try {
        $results = Process-ComputerBatch -CsvPath $CsvPath -PolicyId $policyId -ApiKey $apiKey -DryRun $DryRun -BatchSize 100
    }
    catch {
        Write-ErrorWithExit "Error processing CSV file: $_"
    }

    # Print summary
    Write-Log "`nSummary:" -Level Info
    Write-Log ("Successfully assigned policy to {0} computers" -f $results.SuccessCount) -Level Info
    Write-Log ("Failed to assign policy to {0} computers" -f $results.FailCount) -Level Info
    if ($results.NotFoundCount -gt 0) {
        Write-Log ("Computers not found in system: {0}" -f $results.NotFoundCount) -Level Info
    }
    if ($results.InvalidHostnameCount -gt 0) {
        Write-Log ("Invalid hostnames in CSV: {0}" -f $results.InvalidHostnameCount) -Level Info
    }

    if ($DryRun) {
        Write-Log "`nThis was a DRY RUN - no actual changes were made" -Level Info
    }
}
catch {
    Write-ErrorWithExit "Unexpected error: $_"
}