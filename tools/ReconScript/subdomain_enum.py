#!/usr/bin/env python3

import subprocess
import requests
import json
import sys
import argparse
import configparser
from typing import Set, List
from urllib.parse import urlparse
from pathlib import Path
import dns.resolver
import concurrent.futures


class SubdomainEnumerator:
    def __init__(self, domain: str, config_file: str = "config.ini"):
        self.domain = domain.lower().strip()
        self.subdomains: Set[str] = set()
        self.api_keys = self._load_api_keys(config_file)
        
    def _load_api_keys(self, config_file: str) -> dict:

        api_keys = {}
        config_path = Path(config_file)
        
        if config_path.exists():
            try:
                config = configparser.ConfigParser()
                config.read(config_file)
                
                if 'API_KEYS' in config:
                    api_keys = dict(config['API_KEYS'])
                    print(f"[✓] Loaded API keys from {config_file}")
                else:
                    print(f"[!] No [API_KEYS] section found in {config_file}")
            except Exception as e:
                print(f"[!] Error reading config file: {e}")
        else:
            print(f"[!] Config file not found: {config_file}")
        
        return api_keys
    
    # passive reconnaissance methods
    
    def run_passive_recon(self) -> Set[str]:
        print(f"\n[+] Starting Passive Reconnaissance for {self.domain}")
        print("=" * 60)
        
        # Run all passive enumeration methods
        self._crtsh()
        self._hackertarget()
        self._threatcrowd()
        self._alienvault()
        
        # API-based passive methods (require API keys)
        if self.api_keys.get('virustotal'):
            self._virustotal()
        else:
            print("[!] Skipping VirusTotal - No API key found")
            
        if self.api_keys.get('securitytrails'):
            self._securitytrails()
        else:
            print("[!] Skipping SecurityTrails - No API key found")
        
        print(f"\n[✓] Passive Recon Complete: Found {len(self.subdomains)} unique subdomains")
        return self.subdomains
    
    def _crtsh(self):
        print("[*] Querying crt.sh (Certificate Transparency)...")
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                count = 0
                for entry in data:
                    name = entry.get('name_value', '')
                    # Handle multiple domains in certificate
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().lower()
                        if subdomain.endswith(self.domain) and subdomain not in self.subdomains:
                            self.subdomains.add(subdomain)
                            count += 1
                print(f"    [✓] Found {count} new subdomains from crt.sh")
            else:
                print(f"    [!] crt.sh returned status code: {response.status_code}")
        except Exception as e:
            print(f"    [!] Error querying crt.sh: {e}")
    
    def _hackertarget(self):
        print("[*] Querying HackerTarget API...")
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = requests.get(url, timeout=20)
            
            if response.status_code == 200:
                count = 0
                for line in response.text.split('\n'):
                    if line and ',' in line:
                        subdomain = line.split(',')[0].strip().lower()
                        if subdomain.endswith(self.domain) and subdomain not in self.subdomains:
                            self.subdomains.add(subdomain)
                            count += 1
                print(f"    [✓] Found {count} new subdomains from HackerTarget")
            else:
                print(f"    [!] HackerTarget returned status code: {response.status_code}")
        except Exception as e:
            print(f"    [!] Error querying HackerTarget: {e}")
    
    def _threatcrowd(self):
        print("[*] Querying ThreatCrowd API...")
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            response = requests.get(url, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                subdomains_list = data.get('subdomains', [])
                count = 0
                for subdomain in subdomains_list:
                    subdomain = subdomain.strip().lower()
                    if subdomain.endswith(self.domain) and subdomain not in self.subdomains:
                        self.subdomains.add(subdomain)
                        count += 1
                print(f"    [✓] Found {count} new subdomains from ThreatCrowd")
            else:
                print(f"    [!] ThreatCrowd returned status code: {response.status_code}")
        except Exception as e:
            print(f"    [!] Error querying ThreatCrowd: {e}")
    
    def _alienvault(self):
        print("[*] Querying AlienVault OTX...")
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            response = requests.get(url, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                count = 0
                for entry in data.get('passive_dns', []):
                    hostname = entry.get('hostname', '').strip().lower()
                    if hostname.endswith(self.domain) and hostname not in self.subdomains:
                        self.subdomains.add(hostname)
                        count += 1
                print(f"    [✓] Found {count} new subdomains from AlienVault OTX")
            else:
                print(f"    [!] AlienVault returned status code: {response.status_code}")
        except Exception as e:
            print(f"    [!] Error querying AlienVault: {e}")
    
    def _virustotal(self):
        print("[*] Querying VirusTotal API...")
        try:
            api_key = self.api_keys.get('virustotal')
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {'apikey': api_key, 'domain': self.domain}
            response = requests.get(url, params=params, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                subdomains_list = data.get('subdomains', [])
                count = 0
                for subdomain in subdomains_list:
                    subdomain = subdomain.strip().lower()
                    if subdomain.endswith(self.domain) and subdomain not in self.subdomains:
                        self.subdomains.add(subdomain)
                        count += 1
                print(f"    [✓] Found {count} new subdomains from VirusTotal")
            else:
                print(f"    [!] VirusTotal returned status code: {response.status_code}")
        except Exception as e:
            print(f"    [!] Error querying VirusTotal: {e}")
    
    def _securitytrails(self):
        print("[*] Querying SecurityTrails API...")
        try:
            api_key = self.api_keys.get('securitytrails')
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            headers = {'APIKEY': api_key}
            response = requests.get(url, headers=headers, timeout=20)
            
            if response.status_code == 200:
                data = response.json()
                subdomains_list = data.get('subdomains', [])
                count = 0
                for sub in subdomains_list:
                    subdomain = f"{sub}.{self.domain}".lower()
                    if subdomain not in self.subdomains:
                        self.subdomains.add(subdomain)
                        count += 1
                print(f"    [✓] Found {count} new subdomains from SecurityTrails")
            else:
                print(f"    [!] SecurityTrails returned status code: {response.status_code}")
        except Exception as e:
            print(f"    [!] Error querying SecurityTrails: {e}")
    
    # active reconnaissance methods    
    def run_active_recon(self, wordlist: str = None) -> Set[str]:
        print(f"\n[+] Starting Active Reconnaissance for {self.domain}")
        print("=" * 60)
        
        if wordlist and Path(wordlist).exists():
            self._dns_bruteforce_wordlist(wordlist)
        else:
            if wordlist:
                print(f"[!] Wordlist not found: {wordlist}")
                print("[*] Falling back to default common subdomains...")
            self._dns_bruteforce_default()
        
        print(f"\n[✓] Active Recon Complete: Found {len(self.subdomains)} unique subdomains")
        return self.subdomains
    
    def _dns_bruteforce_wordlist(self, wordlist_path: str):
        print(f"[*] DNS Brute-forcing with custom wordlist: {wordlist_path}")
        
        try:
            with open(wordlist_path, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
            
            print(f"    [✓] Loaded {len(words)} words from wordlist")
            print(f"    [*] Testing subdomains (this may take a while)...")
            
            self._dns_resolve_list(words)
            
        except FileNotFoundError:
            print(f"    [!] Wordlist file not found: {wordlist_path}")
        except Exception as e:
            print(f"    [!] Error during DNS brute-force: {e}")
    
    def _dns_bruteforce_default(self):
        print("[*] DNS Brute-forcing with default common subdomains...")
        
        common_subs = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
            'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx',
            'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar',
            'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet',
            'portal', 'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4',
            'www3', 'dns', 'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my',
            'svn', 'mail1', 'sites', 'proxy', 'ads', 'host', 'crm', 'cms', 'backup',
            'mx2', 'lyncdiscover', 'info', 'apps', 'download', 'remote', 'db', 'forums',
            'store', 'relay', 'files', 'newsletter', 'app', 'live', 'owa', 'en', 'start',
            'sms', 'office', 'exchange', 'ipv4', 'help', 'git', 'faq', 'status', 'payment'
        ]
        
        print(f"    [*] Testing {len(common_subs)} common subdomains...")
        self._dns_resolve_list(common_subs)
    
    def _dns_resolve_list(self, subdomain_list: List[str]):
        found_count = 0
        total = len(subdomain_list)
        
        # Use threading for faster resolution
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self._resolve_dns, f"{word}.{self.domain}"): word 
                for word in subdomain_list
            }
            
            completed = 0
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                
                # Progress indicator
                if completed % 50 == 0 or completed == total:
                    print(f"    [*] Progress: {completed}/{total} checked ({found_count} found)")
                
                result = future.result()
                if result:
                    if result not in self.subdomains:
                        self.subdomains.add(result)
                        found_count += 1
                        print(f"    [✓] Found: {result}")
        
        print(f"    [✓] DNS brute-force complete: {found_count} new subdomains discovered")
    
    def _resolve_dns(self, hostname: str) -> str:
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            answers = resolver.resolve(hostname, 'A')
            return hostname if answers else None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, 
                dns.exception.DNSException):
            return None
        except Exception:
            return None
    
    
    def export_results(self, output_file: str = None):
        if not output_file:
            output_file = f"subdomains_{self.domain.replace('.', '_')}.txt"
        
        try:
            with open(output_file, 'w') as f:
                for subdomain in sorted(self.subdomains):
                    f.write(f"{subdomain}\n")
            print(f"\n[✓] Results exported to: {output_file}")
            return output_file
        except Exception as e:
            print(f"\n[!] Error exporting results: {e}")
            return None
    
    def display_results(self):
        print(f"\n{'='*60}")
        print(f"SUBDOMAIN ENUMERATION RESULTS FOR: {self.domain}")
        print(f"{'='*60}")
        print(f"Total Unique Subdomains Found: {len(self.subdomains)}\n")
        
        if self.subdomains:
            for subdomain in sorted(self.subdomains):
                print(f"  • {subdomain}")
        else:
            print("  No subdomains discovered.")


def main():
    parser = argparse.ArgumentParser(
        description="Subdomain Enumeration Tool - Passive & Active Recon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Passive reconnaissance only
  python subdomain_enum.py -d example.com --passive
  
  # Active reconnaissance with default wordlist
  python subdomain_enum.py -d example.com --active
  
  # Both passive and active with custom wordlist
  python subdomain_enum.py -d example.com --passive --active -w wordlist.txt
  
  # Specify custom config file
  python subdomain_enum.py -d example.com --config /path/to/config.ini
  
  # Export to specific file
  python subdomain_enum.py -d example.com -o results.txt
        """
    )
    
    parser.add_argument('-d', '--domain', required=True, 
                       help='Target domain (e.g., example.com)')
    parser.add_argument('--passive', action='store_true', 
                       help='Enable passive reconnaissance')
    parser.add_argument('--active', action='store_true', 
                       help='Enable active reconnaissance (DNS brute-force)')
    parser.add_argument('-w', '--wordlist', 
                       help='Path to wordlist for DNS brute-forcing')
    parser.add_argument('-o', '--output', 
                       help='Output file for results')
    parser.add_argument('-c', '--config', default='config.ini',
                       help='Path to config file (default: config.ini)')
    
    args = parser.parse_args()
    
    # Extract domain from URL if provided
    if args.domain.startswith('http'):
        args.domain = urlparse(args.domain).netloc
    
    # If neither passive nor active specified, enable both
    if not args.passive and not args.active:
        args.passive = True
        args.active = True
        print("[*] No mode specified - running both passive and active reconnaissance")
    
    print("\n" + "="*60)
    print("SUBDOMAIN ENUMERATION TOOL")
    print("="*60)
    print(f"Target Domain: {args.domain}")
    print(f"Passive Recon: {'Enabled' if args.passive else 'Disabled'}")
    print(f"Active Recon: {'Enabled' if args.active else 'Disabled'}")
    print(f"Config File: {args.config}")
    print("="*60)
    
    # Initialize enumerator
    enumerator = SubdomainEnumerator(args.domain, args.config)
    
    # Run reconnaissance
    if args.passive:
        enumerator.run_passive_recon()
    
    if args.active:
        enumerator.run_active_recon(args.wordlist)
    
    # Display and export results
    enumerator.display_results()
    enumerator.export_results(args.output)
    
    print("\n[✓] Subdomain enumeration complete!")


if __name__ == "__main__":
    main()
