# PowerShell script to assign Trend Micro policies to computers
# Usage: .\Assign-Policy.ps1 -Policy "Policy Name" -CsvPath "path\to\computers.csv" [-DryRun] [-ApiKey "your-api-key"]

param(
    [Parameter(Mandatory=$true)]
    [string]$Policy,
    
    [Parameter(Mandatory=$true)]
    [string]$CsvPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$DryRun,
    
    [Parameter(Mandatory=$false)]
    [string]$ApiKey
)

# API Configuration
$API_VERSION = "v1"
$BASE_URL = "https://cloudone.trendmicro.com/api"

# Function to get API key
function Get-ApiKey {
    if ($ApiKey) {
        return $ApiKey
    }
    elseif ($env:TREND_API_KEY) {
        return $env:TREND_API_KEY
    }
    else {
        Write-Error "API key not provided. Please provide it via -ApiKey parameter or TREND_API_KEY environment variable."
        exit 1
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
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
        $policy = $response.policies | Where-Object { $_.name -eq $PolicyName } | Select-Object -First 1
        
        if ($policy) {
            if ($DryRun) {
                Write-Host "[DRY RUN] Found policy ID: $($policy.ID)"
            }
            return $policy.ID
        }
        
        Write-Host "Policy '$PolicyName' not found"
        return $null
    }
    catch {
        Write-Error "Error getting policy ID: $_"
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
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $body
        return $true
    }
    catch {
        Write-Error "Error assigning policy to computer $ComputerId : $_"
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
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
        
        # Generate filename with timestamp
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $filename = "computers_list_$timestamp.json"
        
        # Save to file
        $response | ConvertTo-Json -Depth 10 | Out-File $filename
        
        Write-Host "Response saved to $filename"
        return $response
    }
    catch {
        Write-Error "Error making request: $_"
        return $null
    }
}

# Main execution
$apiKey = Get-ApiKey

if ($DryRun) {
    Write-Host "Running in DRY RUN mode - no changes will be made"
    Write-Host "----------------------------------------"
}

# Get policy ID
$policyId = Get-PolicyId -PolicyName $Policy -ApiKey $apiKey -DryRun $DryRun
if (-not $policyId) {
    exit 1
}

# Get list of computers
$computers = Get-Computers -ApiKey $apiKey -DryRun $DryRun
if (-not $computers) {
    exit 1
}

# Create a mapping of hostname to computer ID
$computerMap = @{}
foreach ($comp in $computers.computers) {
    $computerMap[$comp.hostName] = $comp.ID
}

# Read CSV and assign policy
$successCount = 0
$failCount = 0

$csvData = Import-Csv -Path $CsvPath
foreach ($row in $csvData) {
    $hostname = $row.hostName
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
        $failCount++
    }
}

Write-Host "`nSummary:"
Write-Host "Successfully assigned policy to $successCount computers"
Write-Host "Failed to assign policy to $failCount computers"

if ($DryRun) {
    Write-Host "`nThis was a DRY RUN - no actual changes were made"
} 