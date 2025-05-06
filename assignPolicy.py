import requests
import json
import csv
import argparse
import os
from datetime import datetime

# API Configuration
API_VERSION = "v1"
BASE_URL = "https://cloudone.trendmicro.com/api"

def get_api_key(args):
    # Priority: 1. Command line argument, 2. Environment variable, 3. Default
    if args.api_key:
        return args.api_key
    elif os.environ.get('TREND_API_KEY'):
        return os.environ.get('TREND_API_KEY')
    else:
        return DEFAULT_API_KEY

def get_policy_id(policy_name, api_key, dry_run=False):
    if dry_run:
        print(f"[DRY RUN] Would search for policy with name: {policy_name}")
    
    headers = {
        "api-version": API_VERSION,
        "api-secret-key": api_key,
        "Content-Type": "application/json"
    }
    
    url = f"{BASE_URL}/policies"
    params = {
        "expand": "none"  # Get only basic policy information
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        
        policies = response.json()
        for policy in policies.get('policies', []):
            if policy.get('name') == policy_name:
                if dry_run:
                    print(f"[DRY RUN] Found policy ID: {policy.get('ID')}")
                return policy.get('ID')
        
        print(f"Policy '{policy_name}' not found")
        return None
        
    except requests.exceptions.RequestException as e:
        print(f"Error getting policy ID: {e}")
        return None

def assign_policy_to_computer(computer_id, policy_id, api_key, dry_run=False):
    if dry_run:
        print(f"[DRY RUN] Would assign policy ID {policy_id} to computer ID {computer_id}")
        return True
    
    headers = {
        "api-version": API_VERSION,
        "api-secret-key": api_key,
        "Content-Type": "application/json"
    }
    
    url = f"{BASE_URL}/computers/{computer_id}"
    data = {
        "policyID": policy_id
    }
    
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error assigning policy to computer {computer_id}: {e}")
        return False

def list_computers(api_key, dry_run=False):
    if dry_run:
        print("[DRY RUN] Fetching list of computers...")
    
    headers = {
        "api-version": API_VERSION,
        "api-secret-key": api_key,
        "Content-Type": "application/json"
    }
    
    params = {
        "expand": "none"
    }
    
    url = f"{BASE_URL}/computers"
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        
        computers = response.json()
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"computers_list_{timestamp}.json"
        
        # Save to file
        with open(filename, 'w') as f:
            json.dump(computers, f, indent=2)
            
        print(f"Response saved to {filename}")
        return computers
        
    except requests.exceptions.RequestException as e:
        print(f"Error making request: {e}")
        return None

def main():
    parser = argparse.ArgumentParser(description='Assign policy to computers listed in a CSV file')
    parser.add_argument('--policy', required=True, help='Name of the policy to assign')
    parser.add_argument('--csv', required=True, help='Path to CSV file containing hostnames')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without making changes')
    parser.add_argument('--api-key', help='Trend Micro API key (can also use TREND_API_KEY environment variable)')
    args = parser.parse_args()

    # Get API key from args, environment, or default
    api_key = get_api_key(args)

    if args.dry_run:
        print("Running in DRY RUN mode - no changes will be made")
        print("----------------------------------------")

    # Get policy ID
    policy_id = get_policy_id(args.policy, api_key, args.dry_run)
    if not policy_id:
        return

    # Get list of computers
    computers = list_computers(api_key, args.dry_run)
    if not computers:
        return

    # Create a mapping of hostname to computer ID
    computer_map = {comp['hostName']: comp['ID'] for comp in computers.get('computers', [])}

    # Read CSV and assign policy
    success_count = 0
    fail_count = 0
    
    with open(args.csv, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            hostname = row['hostName']
            if hostname in computer_map:
                if assign_policy_to_computer(computer_map[hostname], policy_id, api_key, args.dry_run):
                    print(f"Successfully assigned policy to {hostname}")
                    success_count += 1
                else:
                    print(f"Failed to assign policy to {hostname}")
                    fail_count += 1
            else:
                print(f"Computer {hostname} not found in the system")
                fail_count += 1

    print(f"\nSummary:")
    print(f"Successfully assigned policy to {success_count} computers")
    print(f"Failed to assign policy to {fail_count} computers")
    
    if args.dry_run:
        print("\nThis was a DRY RUN - no actual changes were made")

if __name__ == "__main__":
    main()
