#!/usr/bin/env python3

import argparse
import sys
import os
from pathlib import Path
from datetime import datetime

# Import our modules
from subdomain_enum import SubdomainEnumerator
from url_crawler import URLCrawler
from database import (
    init_db, get_session, create_scan, update_scan_status,
    save_subdomains_bulk, save_subdomain, save_endpoints_bulk,
    get_scan_results
)


class ReconWorkflow:
    def __init__(self, domain: str, config_file: str = "config.ini", 
                 output_dir: str = "output", wordlist: str = None):
        self.domain = domain
        self.config_file = config_file
        self.output_dir = Path(output_dir)
        self.wordlist = wordlist
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        db_path = f"sqlite:///{self.output_dir}/niledefender.db"
        self.engine = init_db(db_path)
        self.session = get_session(self.engine)
        
        # Create scan entry
        self.scan_id = create_scan(self.session, self.domain, 'recon_only')
        
        print("\n" + "="*70)
        print("NILEDEFENDER - WEB VULNERABILITY SCANNER")
        print("RECONNAISSANCE WORKFLOW")
        print("="*70)
        print(f"Target Domain: {self.domain}")
        print(f"Scan ID: {self.scan_id}")
        print(f"Output Directory: {self.output_dir}")
        print(f"Database: {db_path}")
        print("="*70 + "\n")
    
    def run(self, passive: bool = True, active: bool = True, crawl: bool = True):
        try:
            # Phase 1: Subdomain Enumeration
            print("\n" + "="*70)
            print("PHASE 1: SUBDOMAIN ENUMERATION")
            print("="*70)
            
            subdomains = self.enumerate_subdomains(passive, active)
            
            if not subdomains:
                print("\n[!] No subdomains discovered. Exiting...")
                update_scan_status(self.session, self.scan_id, 'failed')
                return
            
            # Phase 2: Check Alive Subdomains & URL Crawling
            if crawl:
                print("\n" + "="*70)
                print("PHASE 2: URL CRAWLING & PARAMETER EXTRACTION")
                print("="*70)
                
                self.crawl_and_extract(subdomains)
            
            # Phase 3: Generate Report
            print("\n" + "="*70)
            print("PHASE 3: GENERATING FINAL REPORT")
            print("="*70)
            
            self.generate_report()
            
            # Mark scan as completed
            update_scan_status(self.session, self.scan_id, 'completed')
            
            print("\n" + "="*70)
            print("✓ RECONNAISSANCE WORKFLOW COMPLETED SUCCESSFULLY")
            print("="*70)
            print(f"\nResults saved to: {self.output_dir}")
            print(f"Database: {self.output_dir}/niledefender.db\n")
            
        except KeyboardInterrupt:
            print("\n\n[!] Workflow interrupted by user")
            update_scan_status(self.session, self.scan_id, 'failed')
            sys.exit(1)
        except Exception as e:
            print(f"\n[!] Error in workflow: {e}")
            update_scan_status(self.session, self.scan_id, 'failed')
            raise
        finally:
            self.session.close()
    
    def enumerate_subdomains(self, passive: bool, active: bool):
        print("\n[*] Starting subdomain enumeration...")
        
        # Initialize enumerator
        enumerator = SubdomainEnumerator(self.domain, self.config_file)
        
        # Run passive reconnaissance
        if passive:
            enumerator.run_passive_recon()
        
        # Run active reconnaissance
        if active:
            enumerator.run_active_recon(self.wordlist)
        
        # Save to database
        print(f"\n[*] Saving {len(enumerator.subdomains)} subdomains to database...")
        save_subdomains_bulk(self.session, self.scan_id, enumerator.subdomains)
        
        # Export to file
        subdomain_file = self.output_dir / f"subdomains_{self.domain.replace('.', '_')}.txt"
        enumerator.export_results(str(subdomain_file))
        
        print(f"[✓] Subdomain enumeration complete: {len(enumerator.subdomains)} subdomains found")
        
        return enumerator.subdomains
    
    def crawl_and_extract(self, subdomains):
        # Write subdomains to temporary file for crawler
        temp_file = self.output_dir / "temp_subdomains.txt"
        with open(temp_file, 'w') as f:
            for subdomain in subdomains:
                f.write(f"{subdomain}\n")
        
        print("\n[*] Starting URL crawler...")
        
        # Initialize crawler
        crawler = URLCrawler(str(temp_file), threads=10)
        
        # Check alive subdomains
        alive_subdomains = crawler.check_alive_subdomains()
        
        # Update database with alive status
        print(f"\n[*] Updating database with alive subdomain status...")
        for subdomain in alive_subdomains:
            from urllib.parse import urlparse
            domain_only = urlparse(subdomain).netloc or subdomain
            save_subdomain(
                self.session, self.scan_id, 
                subdomain=subdomain,
                is_alive=1
            )
        
        # Crawl URLs
        crawler.crawl_urls()
        
        # Extract parameters
        endpoints = crawler.extract_parameters()
        
        # Save to database
        print(f"\n[*] Saving {len(endpoints)} endpoints to database...")
        save_endpoints_bulk(self.session, self.scan_id, endpoints)
        
        # Export results
        crawler.export_alive_subdomains(str(self.output_dir / "alive_subdomains.txt"))
        crawler.export_urls(str(self.output_dir / "urls.txt"))
        crawler.export_urls_with_params(str(self.output_dir / "urls_with_params.txt"))
        crawler.export_endpoints_json(str(self.output_dir / "endpoints.json"))
        
        # Display summary
        crawler.display_summary()
        
        # Cleanup temp file
        temp_file.unlink()
        
        print(f"[✓] URL crawling complete: {len(crawler.urls)} URLs found")
    
    def generate_report(self):
        print("\n[*] Generating final report...")
        
        # Get scan results from database
        results = get_scan_results(self.session, self.domain)
        
        if not results:
            print("[!] No results found in database")
            return
        
        # Generate text report
        report_file = self.output_dir / f"recon_report_{self.domain.replace('.', '_')}.txt"
        
        with open(report_file, 'w') as f:
            f.write("="*70 + "\n")
            f.write("NILEDEFENDER - RECONNAISSANCE REPORT\n")
            f.write("="*70 + "\n\n")
            
            f.write(f"Domain: {results['scan']['domain']}\n")
            f.write(f"Scan Date: {results['scan']['scan_date']}\n")
            f.write(f"Scan Type: {results['scan']['scan_type']}\n")
            f.write(f"Status: {results['scan']['status']}\n\n")
            
            f.write("="*70 + "\n")
            f.write("SUMMARY\n")
            f.write("="*70 + "\n\n")
            
            total_subdomains = len(results['subdomains'])
            alive_subdomains = sum(1 for s in results['subdomains'] if s['is_alive'] == 1)
            total_endpoints = len(results['endpoints'])
            endpoints_with_params = sum(1 for e in results['endpoints'] 
                                       if e['parameters'] or e['body_params'])
            
            f.write(f"Total Subdomains: {total_subdomains}\n")
            f.write(f"Alive Subdomains: {alive_subdomains}\n")
            f.write(f"Total URLs/Endpoints: {total_endpoints}\n")
            f.write(f"Endpoints with Parameters: {endpoints_with_params}\n\n")
            
            f.write("="*70 + "\n")
            f.write("SUBDOMAINS\n")
            f.write("="*70 + "\n\n")
            
            for subdomain in results['subdomains']:
                status = "✓ ALIVE" if subdomain['is_alive'] == 1 else "✗ DEAD"
                f.write(f"{status} - {subdomain['subdomain']}")
                if subdomain['status_code']:
                    f.write(f" [{subdomain['status_code']}]")
                if subdomain['title']:
                    f.write(f" - {subdomain['title'][:60]}")
                f.write("\n")
            
            f.write("\n" + "="*70 + "\n")
            f.write("ENDPOINTS WITH PARAMETERS (READY FOR VULN TESTING)\n")
            f.write("="*70 + "\n\n")
            
            for endpoint in results['endpoints']:
                if endpoint['parameters'] or endpoint['body_params']:
                    f.write(f"{endpoint['method']} {endpoint['url']}\n")
                    if endpoint['parameters']:
                        f.write(f"  Parameters: {endpoint['parameters']}\n")
                    if endpoint['body_params']:
                        f.write(f"  Body Params: {endpoint['body_params']}\n")
                    f.write("\n")
            
            f.write("="*70 + "\n")
            f.write("END OF REPORT\n")
            f.write("="*70 + "\n")
        
        print(f"[✓] Report generated: {report_file}")
        
        # Print summary to console
        print("\n" + "="*70)
        print("FINAL SUMMARY")
        print("="*70)
        print(f"Total Subdomains: {total_subdomains}")
        print(f"Alive Subdomains: {alive_subdomains}")
        print(f"Total URLs/Endpoints: {total_endpoints}")
        print(f"Endpoints with Parameters: {endpoints_with_params}")
        print("="*70)


def main():
    parser = argparse.ArgumentParser(
        description="NileDefender - Complete Reconnaissance Workflow for Web Vulnerability Scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full reconnaissance (passive + active + crawling)
  python recon_workflow.py -d example.com
  
  # Passive reconnaissance only
  python recon_workflow.py -d example.com --passive-only
  
  # With custom wordlist for active recon
  python recon_workflow.py -d example.com -w wordlist.txt
  
  # Custom output directory
  python recon_workflow.py -d example.com -o /path/to/output
  
  # Skip URL crawling
  python recon_workflow.py -d example.com --no-crawl
        """
    )
    
    parser.add_argument('-d', '--domain', required=True,
                       help='Target domain (e.g., example.com)')
    parser.add_argument('-c', '--config', default='config.ini',
                       help='Path to config file (default: config.ini)')
    parser.add_argument('-o', '--output', default='output',
                       help='Output directory (default: output)')
    parser.add_argument('-w', '--wordlist',
                       help='Path to wordlist for active subdomain enumeration')
    parser.add_argument('--passive-only', action='store_true',
                       help='Run passive reconnaissance only')
    parser.add_argument('--active-only', action='store_true',
                       help='Run active reconnaissance only')
    parser.add_argument('--no-crawl', action='store_true',
                       help='Skip URL crawling phase')
    
    args = parser.parse_args()
    
    # Determine which phases to run
    passive = True
    active = True
    crawl = not args.no_crawl
    
    if args.passive_only:
        active = False
    elif args.active_only:
        passive = False
    
    # Extract domain from URL if provided
    from urllib.parse import urlparse
    if args.domain.startswith('http'):
        args.domain = urlparse(args.domain).netloc
    
    # Initialize and run workflow
    workflow = ReconWorkflow(
        domain=args.domain,
        config_file=args.config,
        output_dir=args.output,
        wordlist=args.wordlist
    )
    
    workflow.run(passive=passive, active=active, crawl=crawl)


if __name__ == "__main__":
    main()
