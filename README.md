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
.\assignPolicy.ps1 -Policy "Policy Name" -CsvPath computers.csv
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
.\assignPolicy.ps1 -Policy "Windows Server 2022" -CsvPath computers.csv
```

2. Dry run (no changes made):
```powershell
.\assignPolicy.ps1 -Policy "Windows Server 2022" -CsvPath computers.csv -ApiKey "your-api-key" -DryRun
```

## Logging

Both scripts implement comprehensive logging systems that write to both console and log files.

### Log File Location
- Logs are stored in a `logs` directory (created automatically)
- Each run creates a new timestamped log file
- Format: `policy_assignment_[run_type]_[timestamp].log`
- Example: `policy_assignment_run_20240321_143022.log`

### Log Rotation
- Maximum file size: 10MB
- Keeps 5 backup files
- Automatic rotation when size limit is reached
- Backup files are named with sequential numbers (e.g., `policy_assignment_run_20240321_143022_backup1.log`)

### Log Levels
- Debug: Detailed technical information (gray in console)
- Info: General operational messages (white in console)
- Warning: Potential issues (yellow in console)
- Error: Critical problems (red in console)

### Log Format
```
yyyy-MM-dd HH:mm:ss - [Level] - [Message]
```

Example log entries:
```
2024-03-21 14:30:22 - Info - Logging initialized. File: logs/policy_assignment_run_20240321_143022.log
2024-03-21 14:30:23 - Debug - Requesting policy list from https://cloudone.trendmicro.com/api/policies
2024-03-21 14:30:24 - Warning - Invalid hostname in CSV: server@123
2024-03-21 14:30:25 - Error - Failed to assign policy to computer1.example.com
```

## Error Handling

Both scripts implement robust error handling:

### API Errors
- Invalid API key detection
- Network connectivity issues
- API response validation
- Rate limiting handling

### Input Validation
- CSV file format validation
- Hostname validation (RFC 1035 standards)
- Policy name validation
- Required parameter checking

### Runtime Errors
- File system errors
- Permission issues
- Memory constraints
- Unexpected API responses

### Error Recovery
- Graceful failure handling
- Detailed error messages
- Operation summary on completion
- Dry run mode for safe testing

## Security Notes

- Never commit API keys to version control
- Use environment variables or secure key management in production
- Consider using the dry run option to verify changes before applying them
- Always use secure methods to provide the API key (environment variable or command line)
- Log files may contain sensitive information - ensure proper access controls
- Regularly rotate and archive log files
- Consider implementing log file encryption for sensitive environments
