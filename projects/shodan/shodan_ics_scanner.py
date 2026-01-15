#!/usr/bin/env python3
"""
Shodan ICS Scanner for Malaysia Devices

This script uses the Shodan API to identify exposed ICS devices in Malaysia.
It authenticates using a SHODAN API key, accepts CLI arguments for port and output format,
performs a search, processes the results, and exports them as JSON, CSV, or prints them.
Supports scanning for VNC servers and IoT/CCTV cameras.

Features:
- Scan for VNC servers (port 5900) with authentication status
- Scan for IoT/CCTV cameras from various brands (Hikvision, Dahua, Axis, etc.)
- Filter by camera brand or scan all cameras
- Check for authentication status
- Export results in JSON, CSV, or print format
- Includes device details, location, and vulnerability information

Usage:
    python shodan_ics_scanner.py --scan-type [vnc|camera] [options]

Options:
    --port PORT           Port to scan (default: 5900 for VNC)
    --output FORMAT      Output format: json, csv, or print
    --cve CVE_ID         Optional CVE ID to filter results
    --no-auth            Search for services without authentication
    --scan-type TYPE     Type of scan: vnc or camera
    --camera-brand BRAND Specific camera brand to search for

Example:
    # Scan for all cameras
    python shodan_ics_scanner.py --scan-type camera --output json

    # Scan for Hikvision cameras without authentication
    python shodan_ics_scanner.py --scan-type camera --camera-brand hikvision --no-auth --output json

    # Scan for VNC servers
    python shodan_ics_scanner.py --scan-type vnc --output json
"""

import os
import sys
import json
import csv
import logging
import argparse
from typing import List, Dict, Any
from dotenv import load_dotenv
import shodan
from tabulate import tabulate

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Common camera brands and their identifiers
CAMERA_BRANDS = {
    'hikvision': ['hikvision', 'hik-connect'],
    'dahua': ['dahua', 'dahua-technology'],
    'axis': ['axis', 'axis-communications'],
    'uniview': ['uniview'],
    'hanwha': ['hanwha', 'samsung-techwin'],
    'bosch': ['bosch', 'bosch-security'],
    'sony': ['sony', 'sony-camera'],
    'tp-link': ['tp-link', 'tapo', 'tapo-camera']
}

# Common camera ports
CAMERA_PORTS = {
    'rtsp': 554,
    'http': 80,
    'https': 443,
    'onvif': 8000,
    'hikvision': 8000,
    'dahua': 37777
}

def load_api_key() -> str:
    """Load the SHODAN API key from environment variable or .env file."""
    load_dotenv()
    api_key = os.getenv('SHODAN_API_KEY')
    if not api_key:
        logger.error("SHODAN_API_KEY not found in environment or .env file.")
        sys.exit(1)
    return api_key

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Shodan ICS Scanner for Malaysia Devices')
    parser.add_argument('--port', type=int, help='Service/port to scan (default: 5900 for VNC)')
    parser.add_argument('--output', type=str, choices=['json', 'csv', 'print'], default='print', help='Output format: json, csv, or print')
    parser.add_argument('--cve', type=str, help='Optional CVE ID to filter results')
    parser.add_argument('--no-auth', action='store_true', help='Search for services without authentication')
    parser.add_argument('--scan-type', type=str, choices=['vnc', 'camera'], default='camera',
                      help='Type of scan to perform: vnc or camera')
    parser.add_argument('--camera-brand', type=str, choices=list(CAMERA_BRANDS.keys()) + ['all'],
                      default='all', help='Specific camera brand to search for')
    return parser.parse_args()

def build_camera_query(brand: str, no_auth: bool) -> str:
    """Build a query string for camera search using Shodan's supported syntax."""
    query_parts = ['country:MY']
    
    # Add port filters - use most common ports
    query_parts.append('port:"554,80,443"')
    
    # Add brand-specific filters
    if brand != 'all':
        # Use just the main brand identifier
        query_parts.append(CAMERA_BRANDS[brand][0])
    else:
        # Use just the most common terms
        query_parts.append('camera OR cctv')
    
    if no_auth:
        query_parts.append('authentication disabled')
    
    return ' '.join(query_parts)

def search_shodan(api_key: str, args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Perform a search on Shodan API with the specified filters."""
    try:
        api = shodan.Shodan(api_key)
        
        if args.scan_type == 'vnc':
            query = f"port:{args.port or 5900} country:MY"
            if args.no_auth:
                query += " authentication disabled"
        else:  # camera scan
            query = build_camera_query(args.camera_brand, args.no_auth)
            
        if args.cve:
            query += f" vuln:{args.cve}"
            
        logger.info(f"Executing Shodan search with query: {query}")
        results = api.search(query)
        return results['matches']
    except shodan.APIError as e:
        logger.error(f"Shodan API error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error during Shodan search: {e}")
        sys.exit(1)

def extract_camera_info(result: Dict[str, Any]) -> Dict[str, Any]:
    """Extract camera-specific information from the result."""
    camera_info = {
        'brand': 'Unknown',
        'model': 'N/A',
        'firmware': 'N/A',
        'protocols': [],
        'authentication': 'Enabled',
        'stream_url': 'N/A'
    }
    
    # Try to identify brand
    for brand, identifiers in CAMERA_BRANDS.items():
        if any(identifier in result.get('product', '').lower() for identifier in identifiers):
            camera_info['brand'] = brand
            break
    
    # Extract model and firmware if available
    if 'version' in result:
        camera_info['firmware'] = result['version']
    
    # Check for authentication
    if 'authentication disabled' in result.get('data', '').lower():
        camera_info['authentication'] = 'Disabled'
    
    # Identify protocols
    if result.get('port') in CAMERA_PORTS.values():
        for protocol, port in CAMERA_PORTS.items():
            if result.get('port') == port:
                camera_info['protocols'].append(protocol)
    
    # Try to extract stream URL
    if 'rtsp' in camera_info['protocols']:
        ip = result.get('ip_str', '')
        camera_info['stream_url'] = f"rtsp://{ip}:554/stream"
    
    return camera_info

def process_results(results: List[Dict[str, Any]], args: argparse.Namespace) -> List[Dict[str, Any]]:
    """Process and mask the results, extracting required fields."""
    processed_results = []
    for result in results:
        processed_result = {
            'ip': result.get('ip_str', 'N/A'),
            'port': result.get('port', 'N/A'),
            'hostnames': result.get('hostnames', []),
            'organization': result.get('org', 'N/A'),
            'location': {
                'city': result.get('location', {}).get('city', 'N/A'),
                'country': result.get('location', {}).get('country_name', 'N/A')
            },
            'timestamp': result.get('timestamp', 'N/A'),
            'product': result.get('product', 'N/A'),
            'banner': result.get('data', 'N/A'),
            'vulnerabilities': result.get('vulns', []),
            'https_enabled': 'https' in result.get('ssl', {}).get('versions', [])
        }

        if args.scan_type == 'vnc':
            vnc_info = {}
            if result.get('product') == 'VNC':
                vnc_info = {
                    'vnc_version': result.get('version', 'N/A'),
                    'authentication': 'Disabled' if 'authentication disabled' in result.get('data', '').lower() else 'Enabled',
                    'screen_resolution': result.get('screen', {}).get('resolution', 'N/A'),
                    'color_depth': result.get('screen', {}).get('color_depth', 'N/A')
                }
            processed_result['vnc_details'] = vnc_info if result.get('product') == 'VNC' else {}
        else:  # camera scan
            processed_result['camera_details'] = extract_camera_info(result)

        processed_results.append(processed_result)
    return processed_results

def export_results(results: List[Dict[str, Any]], output_format: str) -> None:
    """Export the results in the specified format."""
    if output_format == 'json':
        with open('shodan_results.json', 'w') as f:
            json.dump(results, f, indent=4)
        logger.info("Results exported to shodan_results.json")
    elif output_format == 'csv':
        with open('shodan_results.csv', 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
        logger.info("Results exported to shodan_results.csv")
    elif output_format == 'print':
        print(tabulate(results, headers='keys', tablefmt='grid'))

def main() -> None:
    """Main entry point for the script."""
    api_key = load_api_key()
    args = parse_arguments()
    results = search_shodan(api_key, args)
    processed_results = process_results(results, args)
    export_results(processed_results, args.output)

if __name__ == '__main__':
    main() 