import requests
import json
import csv
import argparse
import os
import logging
import re
import time
from datetime import datetime
from typing import Optional, Dict, List, Any
from logging.handlers import RotatingFileHandler
from requests.exceptions import RequestException

# Configure logging
def setup_logging(dry_run: bool = False) -> None:
    """
    Set up logging configuration with both file and console handlers.
    
    Args:
        dry_run: Whether this is a dry run, affects log file name
    """
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    # Generate log filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_type = "dry_run" if dry_run else "run"
    log_filename = f"logs/policy_assignment_{run_type}_{timestamp}.log"
    
    # Create formatters
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Create and configure file handler
    file_handler = RotatingFileHandler(
        log_filename,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)  # More verbose logging for file
    file_handler.setFormatter(file_formatter)
    
    # Create and configure console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)  # Less verbose for console
    console_handler.setFormatter(console_formatter)
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Capture all levels
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    # Log initial information
    logger.info(f"Logging initialized. File: {log_filename}")
    if dry_run:
        logger.info("Running in DRY RUN mode - no changes will be made")
        logger.info("----------------------------------------")

# API Configuration
API_VERSION = "v1"
BASE_URL = "https://cloudone.trendmicro.com/api"

def validate_hostname(hostname: str) -> bool:
    """
    Validate a hostname according to RFC 1035 standards.
    
    Args:
        hostname: The hostname to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    # Trim whitespace
    hostname = hostname.strip()
    
    # Check if empty after trimming
    if not hostname:
        logger.warning("Empty hostname found")
        return False
    
    # Check length (RFC 1035 specifies 255 characters max)
    if len(hostname) > 255:
        logger.warning(f"Hostname exceeds maximum length of 255 characters: {hostname}")
        return False
    
    # Check for invalid characters
    invalid_chars = r'[!@#$%^&*()+=[]{}|;:"<>?/]'
    if re.search(invalid_chars, hostname):
        logger.warning(f"Hostname contains invalid characters: {hostname}")
        return False
    
    return True

def get_api_key(args: argparse.Namespace) -> str:
    """
    Get API key from command line arguments or environment variable.
    
    Args:
        args: Command line arguments
        
    Returns:
        str: API key
        
    Raises:
        ValueError: If no API key is found
    """
    try:
        if args.api_key:
            logger.debug("Using API key from command line arguments")
            return args.api_key
        elif os.environ.get('TREND_API_KEY'):
            logger.debug("Using API key from environment variable")
            return os.environ.get('TREND_API_KEY')
        else:
            raise ValueError("API key not provided. Please provide it via --api-key or TREND_API_KEY environment variable.")
    except Exception as e:
        logger.error(f"Error retrieving API key: {str(e)}")
        raise

def validate_api_response(response: requests.Response, operation: str) -> None:
    """
    Validate API response and raise appropriate exceptions.
    
    Args:
        response: API response object
        operation: Name of the operation being performed
        
    Raises:
        requests.exceptions.RequestException: If response indicates an error
    """
    try:
        response.raise_for_status()
        logger.debug(f"API {operation} successful. Status code: {response.status_code}")
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error during {operation}: {str(e)}")
        logger.debug(f"Response content: {response.text}")
        raise
    except requests.exceptions.RequestException as e:
        logger.error(f"Request error during {operation}: {str(e)}")
        raise

def make_api_request(url: str, headers: Dict[str, str], method: str = "GET", 
                    data: Optional[Dict[str, Any]] = None, 
                    max_retries: int = 3,
                    initial_delay: int = 2) -> Dict[str, Any]:
    """
    Make an API request with rate limiting and retry logic.
    
    Args:
        url: The API endpoint URL
        headers: Request headers
        method: HTTP method (GET, POST, etc.)
        data: Request body data
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay between retries in seconds
    
    Returns:
        API response as dictionary
    
    Raises:
        RequestException: If the request fails after all retries
    """
    retry_count = 0
    delay = initial_delay
    
    while retry_count < max_retries:
        try:
            logging.debug(f"Making API request to {url}")
            response = requests.request(method, url, headers=headers, json=data)
            
            # Check for rate limit
            if response.status_code == 429:
                retry_count += 1
                if retry_count < max_retries:
                    logging.warning(f"Rate limit hit. Waiting {delay} seconds before retry {retry_count}/{max_retries}")
                    time.sleep(delay)
                    delay *= 2  # Exponential backoff
                    continue
                else:
                    raise RequestException(f"Rate limit exceeded after {max_retries} retries")
            
            # Check for other errors
            response.raise_for_status()
            
            # Add a small delay between successful requests to avoid hitting rate limits
            time.sleep(1)
            
            return response.json()
            
        except RequestException as e:
            if retry_count < max_retries - 1:
                retry_count += 1
                logging.warning(f"Request failed: {str(e)}. Retrying in {delay} seconds...")
                time.sleep(delay)
                delay *= 2  # Exponential backoff
            else:
                raise

def get_policy_id(policy_name: str, api_key: str, dry_run: bool = False) -> Optional[int]:
    """Get policy ID from policy name."""
    if dry_run:
        logging.info(f"[DRY RUN] Would search for policy with name: {policy_name}")
        return None
        
    headers = {
        "api-version": API_VERSION,
        "api-secret-key": api_key,
        "Content-Type": "application/json"
    }
    
    url = f"{BASE_URL}/policies"
    params = {"expand": "none"}
    
    try:
        response = make_api_request(url, headers, params=params)
        validate_api_response(response, "policy lookup")
        
        for policy in response.get("policies", []):
            if policy["name"] == policy_name:
                logging.debug(f"Found policy '{policy_name}' with ID: {policy['ID']}")
                return policy["ID"]
        
        logging.error(f"Policy '{policy_name}' not found")
        raise ValueError(f"Policy '{policy_name}' not found")
        
    except RequestException as e:
        logging.error(f"Error getting policy ID: {str(e)}")
        raise

def assign_policy_to_computer(computer_id: int, policy_id: int, api_key: str, dry_run: bool = False) -> bool:
    """Assign policy to computer."""
    if dry_run:
        logging.info(f"[DRY RUN] Would assign policy ID {policy_id} to computer ID {computer_id}")
        return True
        
    headers = {
        "api-version": API_VERSION,
        "api-secret-key": api_key,
        "Content-Type": "application/json"
    }
    
    url = f"{BASE_URL}/computers/{computer_id}"
    data = {"policyID": policy_id}
    
    try:
        response = make_api_request(url, headers, method="POST", data=data)
        validate_api_response(response, "policy assignment")
        return True
        
    except RequestException as e:
        logging.error(f"Error assigning policy to computer {computer_id}: {str(e)}")
        return False

def list_computers(api_key: str, dry_run: bool = False) -> Optional[Dict[str, Any]]:
    """Get list of computers."""
    if dry_run:
        logging.info("[DRY RUN] Would fetch list of computers")
        return None
        
    headers = {
        "api-version": API_VERSION,
        "api-secret-key": api_key,
        "Content-Type": "application/json"
    }
    
    url = f"{BASE_URL}/computers"
    params = {"expand": "none"}
    
    try:
        response = make_api_request(url, headers, params=params)
        validate_api_response(response, "computer listing")
        logging.debug(f"Retrieved {len(response.get('computers', []))} computers")
        return response
        
    except RequestException as e:
        logging.error(f"Error listing computers: {str(e)}")
        raise

def main():
    parser = argparse.ArgumentParser(description='Assign policy to computers listed in a CSV file')
    parser.add_argument('--policy', required=True, help='Name of the policy to assign')
    parser.add_argument('--csv', required=True, help='Path to CSV file containing hostnames')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be done without making changes')
    parser.add_argument('--api-key', help='Trend Micro API key (can also use TREND_API_KEY environment variable)')
    args = parser.parse_args()

    try:
        # Set up logging
        setup_logging(args.dry_run)
        logger = logging.getLogger(__name__)
        
        # Get API key
        api_key = get_api_key(args)

        # Get policy ID
        policy_id = get_policy_id(args.policy, api_key, args.dry_run)
        if not policy_id:
            return

        # Get list of computers
        computers = list_computers(api_key, args.dry_run)
        if not computers:
            return

        # Create a mapping of hostname to computer ID
        computer_map = {}
        for comp in computers.get('computers', []):
            hostname = comp.get('hostName')
            if not hostname:
                logger.warning("Found computer without hostname, skipping...")
                continue
            
            if not validate_hostname(hostname):
                logger.warning(f"Found computer with invalid hostname, skipping...")
                continue
                
            computer_map[hostname] = comp.get('ID')
        
        logger.debug(f"Created mapping for {len(computer_map)} valid computers")

        # Read CSV and assign policy
        success_count = 0
        fail_count = 0
        not_found_count = 0
        invalid_hostname_count = 0

        try:
            logger.debug(f"Reading CSV file: {args.csv}")
            with open(args.csv, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    hostname = row.get('hostName', '').strip()
                    
                    if not hostname:
                        logger.warning("Found row without hostname, skipping...")
                        fail_count += 1
                        continue
                    
                    if not validate_hostname(hostname):
                        logger.warning(f"Invalid hostname in CSV: {hostname}")
                        invalid_hostname_count += 1
                        fail_count += 1
                        continue

                    if hostname in computer_map:
                        if assign_policy_to_computer(computer_map[hostname], policy_id, api_key, args.dry_run):
                            logger.info(f"Successfully assigned policy to {hostname}")
                            success_count += 1
                        else:
                            logger.error(f"Failed to assign policy to {hostname}")
                            fail_count += 1
                    else:
                        logger.warning(f"Computer {hostname} not found in the system")
                        not_found_count += 1
                        fail_count += 1

        except (IOError, csv.Error) as e:
            logger.error(f"Error reading CSV file: {str(e)}")
            return

        # Print summary
        logger.info("\nSummary:")
        logger.info(f"Successfully assigned policy to {success_count} computers")
        logger.info(f"Failed to assign policy to {fail_count} computers")
        if not_found_count > 0:
            logger.info(f"Computers not found in system: {not_found_count}")
        if invalid_hostname_count > 0:
            logger.info(f"Invalid hostnames in CSV: {invalid_hostname_count}")

        if args.dry_run:
            logger.info("\nThis was a DRY RUN - no actual changes were made")

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        raise

if __name__ == "__main__":
    main()
