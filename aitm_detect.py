#!/usr/bin/env python3
"""
Anti-AiTM CSS Branding Detector

This script checks for custom CSS company branding that might be used
as anti-AiTM (Adversary-in-the-Middle) measures in Microsoft login pages.
"""

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import requests
from requests.exceptions import RequestException, Timeout

logger = logging.getLogger(__name__)

class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    ORANGE = "\033[33m"
    RESET = "\033[0m"

BANNER = f"""============================================================
{Colors.GREEN}Looking for Anti-AiTM measures? ;) {Colors.RESET}
{Colors.GREEN}By Icex0{Colors.RESET}
============================================================"""

REQUEST_TIMEOUT = 30
BASE_URL = "https://login.microsoftonline.com"
CSS_URL_PATTERN = r'customCssUrl":"(https://[^"]+)'
IMAGE_URL_PATTERN = r'url\([\'"]?(https?://[^\'")]+|//[^\'")]+|data:image[^\'")]+|/[^\'")]+)[\'"]?\)'


def is_valid_domain(domain: str) -> bool:
    if not domain or not isinstance(domain, str):
        return False
    
    domain = domain.strip()
    if not domain:
        return False

    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$'
    
    return bool(re.match(domain_pattern, domain))


def extract_custom_css_url(response_text: str) -> Optional[str]:
    """
    Extract custom CSS URL from response text.
    
    Args:
        response_text: The response text to search in
        
    Returns:
        Optional[str]: The custom CSS URL if found, None otherwise
    """
    try:
        match = re.search(CSS_URL_PATTERN, response_text)
        return match.group(1) if match else None
    except Exception as e:
        logger.error(f"Error extracting CSS URL: {e}")
        return None


def extract_image_urls(css_content: str) -> List[str]:
    """
    Extract image URLs from CSS content.
    
    Args:
        css_content: The CSS content to search in
        
    Returns:
        List[str]: List of image URLs found
    """
    try:
        matches = re.findall(IMAGE_URL_PATTERN, css_content)
        cleaned_urls = []
        for url in matches:
            url = url.strip()
            if url:
                if url.startswith('//'):
                    url = 'https:' + url
                cleaned_urls.append(url)
        return cleaned_urls
    except Exception as e:
        logger.error(f"Error extracting image URLs: {e}")
        return []


def make_request(url: str, timeout: int = REQUEST_TIMEOUT) -> Optional[requests.Response]:
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        return response
    except Timeout:
        logger.error(f"Request timeout for URL: {url}")
    except RequestException as e:
        logger.error(f"Request failed for URL {url}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error for URL {url}: {e}")
    return None


def check_domain_branding(domain: str) -> bool:
    """
    Check a single domain for custom CSS branding.
    
    Args:
        domain: The domain to check
        
    Returns:
        bool: True if branding found, False otherwise
    """
    
    print(f"\n{'='*60}")
    print(f"Checking domain: {domain}")
    print(f"{'='*60}")
    

    if not domain.strip():
        logger.warning("Empty domain provided, skipping...")
        return False
    
    # Validate domain format
    if not is_valid_domain(domain):
        logger.error(f"Invalid domain format: {domain}")
        return False
    
    full_url = f"{BASE_URL}/?whr={domain}"
    logger.info(f"Checking domain: {domain}")
    
    # Make initial request
    response = make_request(full_url)
    if not response:
        print(f"[{Colors.RED}-{Colors.RESET}] Failed to fetch content. Status code: {response.status_code if response else 'N/A'}")
        return False
    
    # Extract custom CSS URL
    custom_css_url = extract_custom_css_url(response.text)
    if not custom_css_url:
        print(f"[{Colors.RED}-{Colors.RESET}] No 'customCssUrl' found in the response. There is most likely no custom CSS company branding!")
        return False
    
    print(f"[{Colors.GREEN}+{Colors.RESET}] Custom CSS company branding found! Fetching Custom CSS content from:\n{custom_css_url}")
    
    # Fetch CSS content
    css_response = make_request(custom_css_url)
    if not css_response:
        print(f"[{Colors.RED}-{Colors.RESET}] Failed to fetch custom CSS content. Status code: {css_response.status_code if css_response else 'N/A'}")
        return False
    
    # Extract image URLs
    image_urls = extract_image_urls(css_response.text)
    
    if image_urls:
        print(f"[{Colors.GREEN}+{Colors.RESET}] External (image) URLs found in CSS content, possibly used as anti-AiTM measure(s):")
        for img_url in image_urls:
            print(img_url.strip('\'"'))
        return True
    else:
        print(f"[{Colors.RED}-{Colors.RESET}] No (image) URLs found in the CSS content. Manually review the CSS content!")
        print(f"[{Colors.ORANGE}!{Colors.RESET}] Printing company branding custom CSS content:\n{css_response.text}")
        return False


def process_domains_from_file(file_path: str) -> None:
    """
    Process multiple domains from a file.
    
    Args:
        file_path: Path to the file containing domains
    """
    try:
        path = Path(file_path)
        if not path.exists():
            logger.error(f"File not found: {file_path}")
            return
        
        with open(path, 'r', encoding='utf-8') as file:
            domains = [line.strip() for line in file if line.strip()]
        
        logger.info(f"Processing {len(domains)} domains from {file_path}")
        
        for domain in domains:
            try:
                check_domain_branding(domain)
            except Exception as e:
                logger.error(f"Error processing domain {domain}: {e}")
                
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check custom CSS company branding for AiTM measures",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -d example.com
  %(prog)s -l domains.txt
        """
    )
    
    parser.add_argument(
        '-d', '--domain',
        help="Domain to check for company branding CSS files"
    )
    parser.add_argument(
        '-l', '--list',
        help="File containing a list of domains to check"
    )

    
    args = parser.parse_args()
    
    print(BANNER)
    
    if not args.domain and not args.list:
        print(f"[{Colors.RED}-{Colors.RESET}] Provide either --domain or --list")
        parser.print_help()
        sys.exit(1)
    
    if args.domain and args.list:
        print(f"[{Colors.RED}-{Colors.RESET}] Provide either --domain or --list, not both")
        sys.exit(1)
    
    try:
        if args.domain:
            check_domain_branding(args.domain)
        elif args.list:
            process_domains_from_file(args.list)
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 