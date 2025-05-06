# Trend Micro Policy Assignment Script

This script allows you to assign policies to multiple computers in Vision One Workload Security using a CSV file containing hostnames.

## Prerequisites

- Python 3.x
- `requests` library
- Vision One Workload Security API access
- API key with appropriate permissions

## Installation

1. Clone this repository or download the script
2. Install required Python package:
```bash
pip install requests
```

## Configuration

The script requires an API key which can be provided in two ways:

1. Command line argument:
```bash
--api-key "your-api-key"
```

2. Environment variable:
```bash
export TREND_API_KEY="your-api-key"
```

## Usage

### Basic Usage

```bash
python assignPolicy.py --policy "Policy Name" --csv computers.csv
```

### Command Line Arguments

- `--policy`: (Required) Name of the policy to assign
- `--csv`: (Required) Path to CSV file containing hostnames
- `--dry-run`: (Optional) Show what would be done without making changes
- `--api-key`: (Required if not set in environment) Vision One API key

### CSV File Format

The CSV file should have a header row with "hostName" as the column name, followed by one hostname per line:

```csv
hostName
computer1.example.com
computer2.example.com
computer3.example.com
```

### Examples

1. Basic policy assignment (using environment variable for API key):
```bash
export TREND_API_KEY="your-api-key"
python assignPolicy.py --policy "Windows Server 2022" --csv computers.csv
```

2. Dry run (no changes made):
```bash
python assignPolicy.py --policy "Windows Server 2022" --csv computers.csv --api-key "your-api-key" --dry-run
```

## Output

The script will:
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

The script handles various error conditions:
- Invalid API key
- Policy not found
- Computer not found in system
- CSV file format issues
- API communication errors

## Security Notes

- Never commit API keys to version control
- Use environment variables or secure key management in production
- Consider using the `--dry-run` option to verify changes before applying them
- Always use secure methods to provide the API key (environment variable or command line)
