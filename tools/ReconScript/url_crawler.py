#!/usr/bin/env python3

import subprocess
import requests
import json
import sys
import argparse
from typing import Set, List, Dict
from urllib.parse import urlparse, parse_qs, urljoin
from pathlib import Path
import concurrent.futures
from bs4 import BeautifulSoup
import re


class URLCrawler:
    def __init__(self, subdomains_file: str, threads: int = 10):
        self.subdomains_file = subdomains_file
        self.threads = threads
        self.alive_subdomains: Set[str] = set()
        self.urls: Set[str] = set()
        self.urls_with_params: Set[str] = set()
        self.endpoints: List[Dict] = []
        
    # alive subdomain checking
    
    def check_alive_subdomains(self) -> Set[str]:
        """
        Use httpx to check which subdomains are alive
        Returns set of alive subdomains
        """
        print(f"\n[+] Checking Alive Subdomains with httpx")
        print("=" * 60)
        
        try:
            # Check if httpx is installed
            result = subprocess.run(['httpx', '-version'], 
                                  capture_output=True, 
                                  text=True)
            if result.returncode != 0:
                print("[!] httpx not found. Please install it:")
                print("    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
                return self._fallback_alive_check()
        except FileNotFoundError:
            print("[!] httpx not found. Using fallback method...")
            return self._fallback_alive_check()
        
        # Use httpx to check alive subdomains
        try:
            print(f"[*] Running httpx on {self.subdomains_file}...")
            
            cmd = [
                'httpx',
                '-l', self.subdomains_file,
                '-silent',
                '-follow-redirects',
                '-status-code',
                '-title',
                '-tech-detect',
                '-json'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            for line in result.stdout.strip().split('\n'):
                if line:
                    try:
                        data = json.loads(line)
                        url = data.get('url', '')
                        if url:
                            self.alive_subdomains.add(url)
                            status = data.get('status_code', '')
                            title = data.get('title', '')
                            print(f"    [✓] {url} [{status}] - {title[:50]}")
                    except json.JSONDecodeError:
                        pass
            
            print(f"\n[✓] Found {len(self.alive_subdomains)} alive subdomains")
            return self.alive_subdomains
            
        except subprocess.TimeoutExpired:
            print("[!] httpx timeout. Using fallback method...")
            return self._fallback_alive_check()
        except Exception as e:
            print(f"[!] Error running httpx: {e}")
            return self._fallback_alive_check()
    
    def _fallback_alive_check(self) -> Set[str]:
        """
        Fallback method to check alive subdomains using Python requests
        """
        print("[*] Using fallback HTTP check...")
        
        try:
            with open(self.subdomains_file, 'r') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] File not found: {self.subdomains_file}")
            return set()
        
        print(f"[*] Checking {len(subdomains)} subdomains...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_url, subdomain): subdomain 
                      for subdomain in subdomains}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.alive_subdomains.add(result)
                    print(f"    [✓] {result}")
        
        print(f"\n[✓] Found {len(self.alive_subdomains)} alive subdomains")
        return self.alive_subdomains
    
    def _check_url(self, subdomain: str) -> str:
        for protocol in ['https', 'http']:
            url = f"{protocol}://{subdomain}"
            try:
                response = requests.get(url, timeout=5, allow_redirects=True, verify=False)
                if response.status_code < 500:
                    return url
            except:
                continue
        return None
    
    # crawling methods
    def crawl_urls(self) -> Set[str]:
        print(f"\n[+] Starting URL Crawling")
        print("=" * 60)
        
        if not self.alive_subdomains:
            print("[!] No alive subdomains to crawl")
            return set()
        
        # Method 1: Wayback Machine (Passive)
        self._crawl_wayback()
        
        # Method 2: Spider/Crawl pages (Active)
        self._crawl_active()
        
        # Method 3: Common paths
        self._crawl_common_paths()
        
        print(f"\n[✓] URL Crawling Complete: Found {len(self.urls)} total URLs")
        print(f"[✓] URLs with parameters: {len(self.urls_with_params)}")
        return self.urls
    
    def _crawl_wayback(self):
        print("[*] Querying Wayback Machine for historical URLs...")
        
        for url in self.alive_subdomains:
            try:
                domain = urlparse(url).netloc
                wayback_url = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&collapse=urlkey"
                
                response = requests.get(wayback_url, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    count = 0
                    for entry in data[1:]:  # Skip header
                        if len(entry) > 2:
                            historical_url = entry[2]
                            if historical_url not in self.urls:
                                self.urls.add(historical_url)
                                count += 1
                                if '?' in historical_url:
                                    self.urls_with_params.add(historical_url)
                    
                    print(f"    [✓] Found {count} URLs from Wayback for {domain}")
            except Exception as e:
                print(f"    [!] Error querying Wayback for {url}: {e}")
    
    def _crawl_active(self):
        print("[*] Active crawling of pages...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._crawl_page, url): url 
                      for url in self.alive_subdomains}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    print(f"    [✓] Crawled: {result['url']} - Found {result['links']} links")
    
    def _crawl_page(self, base_url: str) -> Dict:
        try:
            response = requests.get(base_url, timeout=10, verify=False, allow_redirects=True)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            links_found = 0
            
            # Extract all links
            for tag in soup.find_all(['a', 'form']):
                if tag.name == 'a':
                    href = tag.get('href')
                    if href:
                        full_url = urljoin(base_url, href)
                        if self._is_valid_url(full_url, base_url):
                            self.urls.add(full_url)
                            links_found += 1
                            if '?' in full_url:
                                self.urls_with_params.add(full_url)
                
                elif tag.name == 'form':
                    action = tag.get('action', '')
                    method = tag.get('method', 'GET').upper()
                    full_url = urljoin(base_url, action) if action else base_url
                    
                    if self._is_valid_url(full_url, base_url):
                        self.urls.add(full_url)
                        links_found += 1
                        
                        # Extract form parameters
                        params = {}
                        for input_tag in tag.find_all('input'):
                            name = input_tag.get('name')
                            if name:
                                params[name] = input_tag.get('value', '')
                        
                        if params:
                            self.endpoints.append({
                                'url': full_url,
                                'method': method,
                                'body_params': params,
                                'extra_headers': {}
                            })
            
            # Extract URLs from JavaScript files
            for script in soup.find_all('script', src=True):
                script_url = urljoin(base_url, script['src'])
                if self._is_valid_url(script_url, base_url):
                    self.urls.add(script_url)
            
            return {'url': base_url, 'links': links_found}
            
        except Exception as e:
            return {'url': base_url, 'links': 0, 'error': str(e)}
    
    def _crawl_common_paths(self):
        print("[*] Checking common paths...")
        
        common_paths = [
            '/admin', '/login', '/api', '/dashboard', '/upload', '/search',
            '/contact', '/profile', '/settings', '/logout', '/register',
            '/api/v1', '/api/v2', '/graphql', '/rest', '/swagger',
            '/admin/login', '/user/login', '/wp-admin', '/phpmyadmin'
        ]
        
        found_count = 0
        for base_url in self.alive_subdomains:
            for path in common_paths:
                url = urljoin(base_url, path)
                try:
                    response = requests.head(url, timeout=5, verify=False, allow_redirects=True)
                    if response.status_code < 500:
                        self.urls.add(url)
                        found_count += 1
                except:
                    pass
        
        print(f"    [✓] Found {found_count} common paths")
    
    def _is_valid_url(self, url: str, base_url: str) -> bool:
        try:
            parsed = urlparse(url)
            base_parsed = urlparse(base_url)
            
            # Must have scheme and netloc
            if not parsed.scheme or not parsed.netloc:
                return False
            
            # Must be same domain
            if parsed.netloc != base_parsed.netloc:
                return False
            
            # Skip certain file extensions
            skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.ico', '.svg', '.woff', '.ttf']
            if any(parsed.path.lower().endswith(ext) for ext in skip_extensions):
                return False
            
            return True
            
        except:
            return False
    
    # parameter extraction methods
    def extract_parameters(self) -> List[Dict]:
        print(f"\n[+] Extracting Parameters for Vulnerability Testing")
        print("=" * 60)
        
        for url in self.urls_with_params:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if params:
                endpoint = {
                    'url': url,
                    'method': 'GET',
                    'body_params': {k: v[0] if len(v) == 1 else v for k, v in params.items()},
                    'extra_headers': {}
                }
                self.endpoints.append(endpoint)
        
        print(f"[✓] Extracted {len(self.endpoints)} endpoints with parameters")
        return self.endpoints
    
    # export methods
    def export_alive_subdomains(self, output_file: str = "alive_subdomains.txt"):
        try:
            with open(output_file, 'w') as f:
                for subdomain in sorted(self.alive_subdomains):
                    f.write(f"{subdomain}\n")
            print(f"\n[✓] Alive subdomains exported to: {output_file}")
        except Exception as e:
            print(f"[!] Error exporting alive subdomains: {e}")
    
    def export_urls(self, output_file: str = "urls.txt"):
        try:
            with open(output_file, 'w') as f:
                for url in sorted(self.urls):
                    f.write(f"{url}\n")
            print(f"[✓] URLs exported to: {output_file}")
        except Exception as e:
            print(f"[!] Error exporting URLs: {e}")
    
    def export_urls_with_params(self, output_file: str = "urls_with_params.txt"):
        try:
            with open(output_file, 'w') as f:
                for url in sorted(self.urls_with_params):
                    f.write(f"{url}\n")
            print(f"[✓] URLs with parameters exported to: {output_file}")
        except Exception as e:
            print(f"[!] Error exporting URLs with params: {e}")
    
    def export_endpoints_json(self, output_file: str = "endpoints.json"):
        try:
            with open(output_file, 'w') as f:
                json.dump(self.endpoints, f, indent=2)
            print(f"[✓] Endpoints exported to: {output_file}")
        except Exception as e:
            print(f"[!] Error exporting endpoints: {e}")
    
    def display_summary(self):
        print(f"\n{'='*60}")
        print("URL CRAWLING SUMMARY")
        print(f"{'='*60}")
        print(f"Alive Subdomains: {len(self.alive_subdomains)}")
        print(f"Total URLs Found: {len(self.urls)}")
        print(f"URLs with Parameters: {len(self.urls_with_params)}")
        print(f"Endpoints for Testing: {len(self.endpoints)}")
        print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="URL Crawler - Extract URLs and Parameters from Subdomains",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Crawl subdomains from file
  python url_crawler.py -f subdomains.txt
  
  # Crawl with custom thread count
  python url_crawler.py -f subdomains.txt -t 20
  
  # Specify output directory
  python url_crawler.py -f subdomains.txt -o output/
        """
    )
    
    parser.add_argument('-f', '--file', required=True,
                       help='File containing subdomains to crawl')
    parser.add_argument('-t', '--threads', type=int, default=10,
                       help='Number of concurrent threads (default: 10)')
    parser.add_argument('-o', '--output-dir', default='.',
                       help='Output directory for results (default: current directory)')
    
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print("\n" + "="*60)
    print("URL CRAWLER")
    print("="*60)
    print(f"Input File: {args.file}")
    print(f"Threads: {args.threads}")
    print(f"Output Directory: {args.output_dir}")
    print("="*60)
    
    # Initialize crawler
    crawler = URLCrawler(args.file, args.threads)
    
    # Check alive subdomains
    crawler.check_alive_subdomains()
    
    # Crawl URLs
    crawler.crawl_urls()
    
    # Extract parameters
    crawler.extract_parameters()
    
    # Display summary
    crawler.display_summary()
    
    # Export results
    crawler.export_alive_subdomains(str(output_dir / "alive_subdomains.txt"))
    crawler.export_urls(str(output_dir / "urls.txt"))
    crawler.export_urls_with_params(str(output_dir / "urls_with_params.txt"))
    crawler.export_endpoints_json(str(output_dir / "endpoints.json"))
    
    print("\n[✓] URL crawling complete!")


if __name__ == "__main__":
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    main()
