# Trend Micro Policy Assignment Script

This repository contains scripts to assign policies to multiple computers in Vision One Workload Security using a CSV file containing hostnames. Both Python and PowerShell versions are available.

## Prerequisites

### Python Version
- Python 3.x
- `requests` library
- Vision One Workload Security API access
- API key with appropriate permissions

### PowerShell Version
- PowerShell 5.1 or later
- Vision One Workload Security API access
- API key with appropriate permissions

## Installation

### Python Version
1. Clone this repository or download the script
2. Install required Python package:
```bash
pip install requests
```

### PowerShell Version
1. Clone this repository or download the script
2. No additional installation required

## Configuration

The scripts require an API key which can be provided in two ways:

1. Command line argument:
```bash
# Python
--api-key "your-api-key"

# PowerShell
-ApiKey "your-api-key"
```

2. Environment variable:
```bash
# Python
export TREND_API_KEY="your-api-key"

# PowerShell
$env:TREND_API_KEY="your-api-key"
```

## Usage

### Python Version

#### Basic Usage
```bash
python assignPolicy.py --policy "Policy Name" --csv computers.csv
```

#### Command Line Arguments
- `--policy`: (Required) Name of the policy to assign
- `--csv`: (Required) Path to CSV file containing hostnames
- `--dry-run`: (Optional) Show what would be done without making changes
- `--api-key`: (Required if not set in environment) Vision One API key

### PowerShell Version

#### Basic Usage
```powershell
.\Assign-Policy.ps1 -Policy "Policy Name" -CsvPath computers.csv
```

#### Command Line Arguments
- `-Policy`: (Required) Name of the policy to assign
- `-CsvPath`: (Required) Path to CSV file containing hostnames
- `-DryRun`: (Optional) Show what would be done without making changes
- `-ApiKey`: (Required if not set in environment) Vision One API key

### CSV File Format

The CSV file should have a header row with "hostName" as the column name, followed by one hostname per line:

```csv
hostName
computer1.example.com
computer2.example.com
computer3.example.com
```

### Examples

#### Python Examples

1. Basic policy assignment (using environment variable for API key):
```bash
export TREND_API_KEY="your-api-key"
python assignPolicy.py --policy "Windows Server 2022" --csv computers.csv
```

2. Dry run (no changes made):
```bash
python assignPolicy.py --policy "Windows Server 2022" --csv computers.csv --api-key "your-api-key" --dry-run
```

#### PowerShell Examples

1. Basic policy assignment (using environment variable for API key):
```powershell
$env:TREND_API_KEY="your-api-key"
.\Assign-Policy.ps1 -Policy "Windows Server 2022" -CsvPath computers.csv
```

2. Dry run (no changes made):
```powershell
.\Assign-Policy.ps1 -Policy "Windows Server 2022" -CsvPath computers.csv -ApiKey "your-api-key" -DryRun
```

## Output

Both scripts will:
1. Save a list of computers to a JSON file with timestamp
2. Process each hostname in the CSV file
3. Display success/failure messages for each computer
4. Show a summary of successful and failed assignments

Example output:
```
Response saved to computers_list_20250506_123456.json
Successfully assigned policy to computer1.example.com
Successfully assigned policy to computer2.example.com

Summary:
Successfully assigned policy to 2 computers
Failed to assign policy to 0 computers
```

## Error Handling

Both scripts handle various error conditions:
- Invalid API key
- Policy not found
- Computer not found in system
- CSV file format issues
- API communication errors

## Security Notes

- Never commit API keys to version control
- Use environment variables or secure key management in production
- Consider using the dry run option to verify changes before applying them
- Always use secure methods to provide the API key (environment variable or command line)
