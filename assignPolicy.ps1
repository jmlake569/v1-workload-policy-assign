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

# Error handling function
function Write-ErrorWithExit {
    param(
        [string]$Message,
        [int]$ExitCode = 1
    )
    Write-Error $Message
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

# Function to get policy ID
function Get-PolicyId {
    param(
        [string]$PolicyName,
        [string]$ApiKey,
        [bool]$DryRun
    )
    
    if ($DryRun) {
        Write-Host "[DRY RUN] Would search for policy with name: $PolicyName"
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
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
        Test-ApiResponse -Response $response -Operation "policy lookup"
        
        $policy = $response.policies | Where-Object { $_.name -eq $PolicyName } | Select-Object -First 1
        
        if ($policy) {
            if ($DryRun) {
                Write-Host "[DRY RUN] Found policy ID: $($policy.ID)"
            }
            return $policy.ID
        }
        
        Write-ErrorWithExit "Policy '$PolicyName' not found"
    }
    catch [System.Net.WebException] {
        Write-ErrorWithExit "Network error during policy lookup: $($_.Exception.Message)"
    }
    catch {
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
        Write-Host "[DRY RUN] Would assign policy ID $PolicyId to computer ID $ComputerId"
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
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $body -ErrorAction Stop
        Test-ApiResponse -Response $response -Operation "policy assignment"
        return $true
    }
    catch [System.Net.WebException] {
        Write-Error "Network error assigning policy to computer $ComputerId`: $($_.Exception.Message)"
        return $false
    }
    catch {
        Write-Error "Error assigning policy to computer $ComputerId`: $_"
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
        Write-Host "[DRY RUN] Fetching list of computers..."
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
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
        Test-ApiResponse -Response $response -Operation "computer listing"
        return $response
    }
    catch [System.Net.WebException] {
        Write-ErrorWithExit "Network error fetching computer list: $($_.Exception.Message)"
    }
    catch {
        Write-ErrorWithExit "Error making request: $_"
    }
}

# Main execution
try {
    $apiKey = Get-ApiKey

    if ($DryRun) {
        Write-Host "Running in DRY RUN mode - no changes will be made"
        Write-Host "----------------------------------------"
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

    # Read CSV and assign policy
    $successCount = 0
    $failCount = 0
    $notFoundCount = 0
    $invalidHostnameCount = 0

    try {
        $csvData = Import-Csv -Path $CsvPath -ErrorAction Stop
    }
    catch {
        Write-ErrorWithExit "Error reading CSV file: $_"
    }

    foreach ($row in $csvData) {
        if (-not $row.hostName) {
            Write-Warning "Found row without hostname, skipping..."
            $failCount++
            continue
        }

        $hostname = $row.hostName.Trim()
        
        # Validate hostname from CSV
        if (-not (Test-Hostname -Hostname $hostname)) {
            Write-Warning "Invalid hostname in CSV: $hostname"
            $invalidHostnameCount++
            $failCount++
            continue
        }

        if ($computerMap.ContainsKey($hostname)) {
            if (Set-ComputerPolicy -ComputerId $computerMap[$hostname] -PolicyId $policyId -ApiKey $apiKey -DryRun $DryRun) {
                Write-Host "Successfully assigned policy to $hostname"
                $successCount++
            }
            else {
                Write-Host "Failed to assign policy to $hostname"
                $failCount++
            }
        }
        else {
            Write-Host "Computer $hostname not found in the system"
            $notFoundCount++
            $failCount++
        }
    }

    Write-Host "`nSummary:"
    Write-Host "Successfully assigned policy to $successCount computers"
    Write-Host "Failed to assign policy to $failCount computers"
    if ($notFoundCount -gt 0) {
        Write-Host "Computers not found in system: $notFoundCount"
    }
    if ($invalidHostnameCount -gt 0) {
        Write-Host "Invalid hostnames in CSV: $invalidHostnameCount"
    }

    if ($DryRun) {
        Write-Host "`nThis was a DRY RUN - no actual changes were made"
    }
}
catch {
    Write-ErrorWithExit "Unexpected error: $_"
} 