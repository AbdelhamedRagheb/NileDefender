"""
NileDefender - AI Security Report Generator (HTML → PDF)
Simple: Read vulns → AI generates HTML report → Convert to PDF

Usage:
    python ai_report_pdf.py --db niledefender.db
    python ai_report_pdf.py --db niledefender.db --pdf my_report.pdf
"""

from groq import Groq
import json
import configparser
import argparse
import os
from datetime import datetime
from sqlalchemy import create_engine, text
from weasyprint import HTML


# ============================================================================
# CONFIGURATION (lazy-loaded so importing this module has no side effects)
# ============================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

_client = None

def _get_client():
    """Lazily initialize the Groq client."""
    global _client
    if _client is None:
        config = configparser.ConfigParser()
        config.read(os.path.join(SCRIPT_DIR, 'config.ini'))
        api_key = config.get('API_KEYS', 'groq')
        _client = Groq(api_key=api_key)
    return _client


# ============================================================================
# 1. READ VULNERABILITIES FROM DATABASE
# ============================================================================

def get_all_vulnerabilities(db_path):
    engine = create_engine(f'sqlite:///{db_path}')
    with engine.connect() as conn:
        vulns = conn.execute(text("""
            SELECT vulnerability_type, severity, url, method, parameter, payload, evidence
            FROM vulnerabilities
        """)).fetchall()

        domain_row = conn.execute(text("SELECT domain FROM scan_history LIMIT 1")).fetchone()
        domain = domain_row[0] if domain_row else "Unknown"

    return {
        'domain': domain,
        'total_vulnerabilities': len(vulns),
        'vulnerabilities': [
            {'type': v[0], 'severity': v[1], 'url': v[2], 'method': v[3],
             'parameter': v[4], 'payload': v[5], 'evidence': v[6]}
            for v in vulns
        ]
    }


def get_scan_vulnerabilities(db_path, scan_id):
    """Get vulnerabilities for a specific scan (used by the web server integration)."""
    engine = create_engine(f'sqlite:///{db_path}')
    with engine.connect() as conn:
        vulns = conn.execute(text("""
            SELECT vulnerability_type, severity, url, method, parameter, payload, evidence
            FROM vulnerabilities WHERE scan_id = :scan_id
        """), {'scan_id': scan_id}).fetchall()

        domain_row = conn.execute(text(
            "SELECT domain FROM scan_history WHERE id = :scan_id"
        ), {'scan_id': scan_id}).fetchone()
        domain = domain_row[0] if domain_row else "Unknown"

    return {
        'domain': domain,
        'total_vulnerabilities': len(vulns),
        'vulnerabilities': [
            {'type': v[0], 'severity': v[1], 'url': v[2], 'method': v[3],
             'parameter': v[4], 'payload': v[5], 'evidence': v[6]}
            for v in vulns
        ]
    }


# ============================================================================
# 2. AI GENERATES THE HTML REPORT (AI does everything)
# ============================================================================

def generate_report_html(vuln_data):
    """Send vulns to AI, get back a complete styled HTML report."""
    client = _get_client()
    report_date = datetime.now().strftime("%B %d, %Y")
    vuln_json = json.dumps(vuln_data, indent=2, default=str)

    # Count severities for the prompt context
    sev_counts = {}
    for v in vuln_data['vulnerabilities']:
        s = v['severity']
        sev_counts[s] = sev_counts.get(s, 0) + 1

    prompt = f"""You are a senior penetration tester writing a professional security assessment report.
Generate a COMPLETE, self-contained HTML document. Return ONLY the HTML. No markdown. No explanations.

=== SCAN DATA ===
Target: {vuln_data['domain']}
Date: {report_date}
Total Findings: {vuln_data['total_vulnerabilities']}
Severity Breakdown: {json.dumps(sev_counts)}

Vulnerabilities (raw data):
{vuln_json}

=== REPORT SECTIONS (follow this order exactly) ===

SECTION 0 - COVER PAGE:
- Full page, dark navy background (#0a1628)
- At the top center (padding-top 80px): put exactly this placeholder: {{{{LOGO_PLACEHOLDER}}}}
  (it will be replaced with an SVG shield icon + NileDefender text automatically. Do NOT add any other logo near it)
- Below placeholder, add margin-top 50px, then: "SECURITY ASSESSMENT REPORT" in 36px light blue (#7ec8e3) bold, letter-spacing 3px
- Below that: "Penetration Testing Report" in 18px gray (#8899aa)
- Add margin-top 50px before the info box so nothing overlaps
- Info box: background rgba(126,200,227,0.08), border 1px solid rgba(126,200,227,0.25), border-radius 12px,
  padding 30px, max-width 450px, margin auto centered. Contains:
  * Target Domain | Assessment Date | Findings Count | Overall Risk Level (colored) | Assessor: NileDefender AI
  * Labels in white bold, values in #7ec8e3
- Bottom: "CONFIDENTIAL - Authorized Personnel Only" in 11px, letter-spacing 3px, opacity 0.4
- CSS: page-break-after: always; padding: 80px 40px; text-align: center
- ALL text on cover must be light colored (white, #7ec8e3, or #8899aa) against the dark background

SECTION 1 - EXECUTIVE SUMMARY:
- Write 2-3 professional paragraphs summarizing:
  * What was tested and why
  * Key findings overview (how many vulns, most critical ones)
  * Overall security posture assessment
  * Urgency level for remediation
- This section is for MANAGEMENT - no technical jargon, focus on business risk
- Make it sound like a real consulting firm wrote it

SECTION 2 - RISK OVERVIEW:
- Show a visual severity breakdown using colored horizontal bars:
  * Critical = #dc2626 (red), High = #ea580c (orange), Medium = #ca8a04 (yellow), Low = #16a34a (green), Info = #6b7280 (gray)
- Each bar shows: severity label, colored bar (width proportional to count), count number
- Below the bars, add the overall risk rating in large bold colored text

SECTION 3 - SCOPE & METHODOLOGY:
- Target domain/application
- Assessment date
- Testing type: Automated vulnerability scanning + AI analysis
- Tools: NileDefender Web Vulnerability Scanner
- Methodology: OWASP Testing Guide, automated payload injection, response analysis

SECTION 4 - VULNERABILITY SUMMARY TABLE:
- Clean table with columns: #, Vulnerability Type, Severity, Affected URL, Parameter, CVSS Score
- Severity cell: white text on colored background (use severity colors above), rounded badge style
- Table: alternating row colors (#ffffff and #f8fafc), header row dark navy (#141E46) with white text
- Font size 13px for readability, proper padding (10px 14px)
- URLs should be in monospace font, and truncated if too long (max-width with overflow hidden)

SECTION 5 - DETAILED FINDINGS:
For EACH vulnerability, create a finding card with:
- Card header: gray background (#f1f5f9), vulnerability type as title, severity badge (colored pill), CVSS score
- Card body with these labeled fields:
  * "Affected URL:" - the URL in monospace
  * "Parameter:" - the vulnerable parameter
  * "HTTP Method:" - GET/POST etc
  * "Description:" - Write a PROFESSIONAL, DETAILED 3-4 sentence description explaining what this vulnerability is,
    how it works technically, and why it exists. Reference OWASP categories where applicable.
  * "Evidence:" - Show the payload that was used (in a gray code box, monospace, word-wrap)
  * "Impact:" - 2-3 sentences about what an attacker could achieve (data theft, unauthorized access, etc).
    Style this with a left red border and light red background (#fef2f2)
  * "Remediation:" - 3-4 specific, actionable remediation steps as a numbered list.
    Style this with a left green border and light green background (#f0fdf4)
- Card styling: 1px solid #e2e8f0 border, border-radius 8px, margin 20px 0, box-shadow 0 1px 3px rgba(0,0,0,0.1)
- CSS: page-break-inside: avoid on each card

SECTION 6 - RECOMMENDATIONS:
- Numbered list of 5-7 prioritized security recommendations
- Each recommendation: bold title + 1-2 sentence explanation
- Order by priority (most critical first)
- Include both specific fixes and general security best practices

SECTION 7 - CONCLUSION:
- 2 paragraphs summarizing the assessment
- Restate the overall risk level
- Emphasize the importance of timely remediation
- Note that regular security assessments should be conducted

=== CSS DESIGN RULES ===
- @page {{ margin: 18mm; }}
- body: font-family: 'Segoe UI', -apple-system, sans-serif; color: #1e293b; line-height: 1.7; font-size: 14px
- Section titles: font-size 22px, color #141E46, border-left: 4px solid #7ec8e3, padding-left 14px, margin-top 40px
- Paragraphs: font-size 14px, color #334155, line-height 1.7 (VERY IMPORTANT for readability)
- Finding cards: page-break-inside: avoid
- Code/payload boxes: background #f1f5f9, border 1px solid #e2e8f0, border-radius 4px, padding 10px, font-family monospace, font-size 12px, word-break break-all
- Links/URLs: color #0369a1, font-family monospace
- Use generous whitespace and padding everywhere for easy reading
- The report should look clean, professional, and easy to scan

=== CRITICAL RULES ===
- Output ONLY valid HTML starting with <!DOCTYPE html>
- ALL CSS must be in a <style> tag inside <head>
- No external resources, everything self-contained
- Use {{{{LOGO_PLACEHOLDER}}}} exactly as written for the logo position
- Write PROFESSIONAL English - this report represents a security consulting firm
- Every vulnerability description, impact, and remediation must be SPECIFIC to that vulnerability, not generic
- The report must be EASY TO READ with proper spacing and clear visual hierarchy"""

    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.4,
        max_tokens=8000
    )
    html = response.choices[0].message.content.strip()

    # Clean if AI wraps in code blocks
    if html.startswith("```"):
        html = html.split("\n", 1)[1]
    if html.endswith("```"):
        html = html.rsplit("```", 1)[0]
    if html.startswith("html"):
        html = html[4:]
    html = html.strip()

    # Inject SVG shield logo + NileDefender text (matching the actual logo)
    logo_svg = '''<div style="text-align:center;">
        <svg width="90" height="105" viewBox="0 0 90 105" style="margin-bottom:12px;">
            <!-- Shield outline: rounded top, pointed bottom -->
            <path d="M45 5 Q45 5 75 15 L75 22 Q75 35 75 45 Q75 75 45 100 Q15 75 15 45 Q15 35 15 22 L15 15 Q45 5 45 5 Z"
                  fill="none" stroke="#7ec8e3" stroke-width="2.5" stroke-linejoin="round"/>

            <!-- ND text - bold, centered -->
            <text x="46" y="50" text-anchor="middle"
                  font-family="'Segoe UI', Arial, sans-serif"
                  font-size="30" font-weight="bold" fill="#7ec8e3"
                  letter-spacing="-2">ND</text>

            <!-- Three Nile wave lines (diagonal, parallel) -->
            <line x1="26" y1="68" x2="42" y2="58" stroke="#7ec8e3" stroke-width="2.2" stroke-linecap="round"/>
            <line x1="29" y1="74" x2="45" y2="64" stroke="#7ec8e3" stroke-width="2.2" stroke-linecap="round"/>
            <line x1="32" y1="80" x2="48" y2="70" stroke="#7ec8e3" stroke-width="2.2" stroke-linecap="round"/>
        </svg>
        <div style="font-size:28px;font-weight:bold;color:#7ec8e3;letter-spacing:2px;">NileDefender</div>
        <div style="font-size:13px;color:#8899aa;margin-top:4px;">Web Vulnerability Scanner</div>
    </div>'''
    html = html.replace("{{LOGO_PLACEHOLDER}}", logo_svg)

    return html


# ============================================================================
# 3. CONVERT HTML → PDF (one line)
# ============================================================================

def html_to_pdf(html_content, output_path):
    HTML(string=html_content).write_pdf(output_path)


def html_to_pdf_bytes(html_content):
    """Convert HTML to PDF and return as bytes (for web streaming)."""
    return HTML(string=html_content).write_pdf()


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NileDefender AI Report Generator")
    parser.add_argument("--db", default="output/niledefender.db", help="Database path")
    parser.add_argument("--pdf", default="report.pdf", help="Output PDF path")
    args = parser.parse_args()

    print("\n" + "=" * 50)
    print("  NileDefender - AI Report Generator")
    print("=" * 50)

    # Step 1: Read vulnerabilities
    print(f"\n  Loading vulnerabilities from: {args.db}")
    vuln_data = get_all_vulnerabilities(args.db)
    print(f"  Found: {vuln_data['total_vulnerabilities']} vulnerabilities")

    if vuln_data['total_vulnerabilities'] == 0:
        print("  No vulnerabilities found!")
        exit(0)

    # Step 2: AI generates HTML report
    print("  AI is generating the report...")
    html_report = generate_report_html(vuln_data)
    print("  Report generated!")

    # Step 3: Convert to PDF
    print("  Converting to PDF...")
    html_to_pdf(html_report, args.pdf)
    size_kb = os.path.getsize(args.pdf) / 1024
    print(f"  Saved: {args.pdf} ({size_kb:.0f} KB)")

    print("\n" + "=" * 50)
    print("  Done!")
    print("=" * 50 + "\n")
