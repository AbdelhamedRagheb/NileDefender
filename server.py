"""
Usage: python server.py
Then open: http://localhost:5000

"""

from flask import Flask, jsonify, request, render_template
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
import sys
import threading
from datetime import datetime
from pathlib import Path


# Import scanner modules 
from subdomain_enum import SubdomainEnumerator
from url_crawler import URLCrawler

# Import database module 
from database import (
    init_db, get_session, create_scan, update_scan_status,
    save_subdomain, save_endpoint, get_scan_results,
    get_all_scans, get_scan_by_id, get_endpoints, get_subdomains
)

# Initialize Flask app with template and static folder configuration
app = Flask(
    __name__,
    template_folder='templates',
    static_folder='static',
    static_url_path='/static'
)
app.config['SECRET_KEY'] = 'niledefender-secret-key'

# Enable CORS for all routes
CORS(app, resources={r"/api/*": {"origins": "*"}})

socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize database - use output folder to share with CLI tools
OUTPUT_DIR = Path(__file__).parent / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = OUTPUT_DIR / "niledefender.db"

db_engine = init_db(f"sqlite:///{DB_PATH}")
db_session = get_session(db_engine)

# Store active scans
active_scans = {}


# ============================================================================
# BACKGROUND SCAN RUNNER - Uses callbacks for database operations
# ============================================================================

def emit_progress(scan_id, phase, message, progress=None):
    """Emit WebSocket progress update"""
    socketio.emit('scan_update', {
        'scan_id': scan_id,
        'status': 'running',
        'phase': phase,
        'message': message,
        'progress': progress
    }, room=f'scan_{scan_id}')


def run_scan_background(domain, scan_id, passive=True, active=False, crawl=True):
    """Run full reconnaissance workflow in background thread
    
    This mirrors the CLI: python recon_workflow.py -d domain --passive-only
    Database operations are handled via callbacks
    """
    try:
        print(f"[*] Starting scan {scan_id} for {domain}")
        print(f"    Options: passive={passive}, active={active}, crawl={crawl}")
        
        # Create a new database session for this thread
        thread_session = get_session(db_engine)
        
        # Define callbacks for database operations (only save alive subdomains)
        def on_alive_found(url, status_code, title):
            """Save alive subdomain to database (only alive ones are stored)"""
            save_subdomain(thread_session, scan_id, url,
                          is_alive=1, status_code=status_code, title=title)
            emit_progress(scan_id, 'alive_check', f'Alive: {url} [{status_code}]')
        
        def on_endpoint_found(endpoint):
            """Save endpoint to database"""
            save_endpoint(
                thread_session, scan_id,
                url=endpoint.get('url'),
                method=endpoint.get('method', 'GET'),
                parameters=endpoint.get('parameters'),
                body_params=endpoint.get('body_params'),
                extra_headers=endpoint.get('extra_headers'),
                source=endpoint.get('source', 'crawler'),
                form_details=endpoint.get('form_details')
            )
        
        # =====================================================================
        # PHASE 1: Subdomain Enumeration
        # =====================================================================
        emit_progress(scan_id, 'subdomain_enum', 'Phase 1: Starting subdomain enumeration...')
        
        enumerator = SubdomainEnumerator(
            domain,
            config_file='config.ini',
            on_alive_found=on_alive_found
        )
        
        # Run passive enumeration
        if passive:
            emit_progress(scan_id, 'subdomain_enum', 'Running passive reconnaissance (CT logs, APIs)...')
            enumerator.run_passive_recon()
        
        # Run active enumeration
        if active:
            emit_progress(scan_id, 'subdomain_enum', 'Running active reconnaissance (DNS brute-force)...')
            enumerator.run_active_recon()
        
        subdomains = enumerator.subdomains
        emit_progress(scan_id, 'subdomain_enum', f'Found {len(subdomains)} subdomains')
        
        if not subdomains:
            emit_progress(scan_id, 'complete', 'No subdomains found')
            update_scan_status(thread_session, scan_id, 'completed')
            return
        
        # Check alive subdomains (now in subdomain_enum module)
        emit_progress(scan_id, 'alive_check', 'Checking alive subdomains...')
        alive_urls = enumerator.check_alive_subdomains()
        emit_progress(scan_id, 'alive_check', f'Found {len(alive_urls)} alive subdomains')
        
        # =====================================================================
        # PHASE 2: URL Crawling & Parameter Extraction
        # =====================================================================
        if crawl and alive_urls:
            emit_progress(scan_id, 'url_crawl', 'Phase 2: Starting URL crawling...')
            
            crawler = URLCrawler(
                alive_urls=list(alive_urls),
                threads=10,
                on_endpoint_found=on_endpoint_found
            )
            
            # Crawl URLs
            emit_progress(scan_id, 'url_crawl', 'Crawling URLs...')
            crawler.crawl_urls()
            
            # Extract parameters
            emit_progress(scan_id, 'param_extract', 'Phase 3: Extracting parameters...')
            endpoints = crawler.extract_parameters()
            emit_progress(scan_id, 'param_extract', f'Found {len(endpoints)} endpoints with parameters')
        
        # =====================================================================
        # Complete scan
        # =====================================================================
        update_scan_status(thread_session, scan_id, 'completed')
        
        # Get final stats
        results = get_scan_results(thread_session, scan_id)
        total_subdomains = len(results.get('subdomains', []))
        total_endpoints = len(results.get('endpoints', []))
        
        socketio.emit('scan_completed', {
            'scan_id': scan_id,
            'status': 'completed',
            'message': f'Scan completed! Found {total_subdomains} subdomains and {total_endpoints} endpoints'
        }, room=f'scan_{scan_id}')
        
        print(f"[+] Scan {scan_id} completed successfully")
        
    except Exception as e:
        import traceback
        print(f"[!] Scan error: {e}")
        traceback.print_exc()
        
        # Mark as failed
        try:
            update_scan_status(thread_session, scan_id, 'failed')
        except:
            pass
        
        socketio.emit('scan_error', {
            'scan_id': scan_id,
            'status': 'failed',
            'error': str(e)
        }, room=f'scan_{scan_id}')
    
    finally:
        # Remove from active scans
        if scan_id in active_scans:
            del active_scans[scan_id]
        # Close thread session
        try:
            thread_session.close()
        except:
            pass



# ============================================================================
# API ROUTES
# ============================================================================

@app.route('/api/scans', methods=['GET'])
def list_scans():
    """Get all scans"""
    try:
        scans = get_all_scans(db_session)
        
        result = []
        for scan in scans:
            subdomains = get_subdomains(db_session, scan.id)
            endpoints = get_endpoints(db_session, scan.id)
            
            result.append({
                'id': scan.id,
                'domain': scan.domain,
                'scan_date': scan.scan_date.isoformat() if scan.scan_date else None,
                'status': scan.status,
                'subdomain_count': len(subdomains),
                'endpoint_count': len(endpoints)
            })
        
        return jsonify({'success': True, 'scans': result})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scans', methods=['POST'])
def create_new_scan():
    """Create new scan — subdomain enum -> URL crawling"""
    try:
        data = request.json
        target = data.get('target', '').strip()
        crawl = data.get('crawl', True)
        passive = data.get('passive', True)
        active = data.get('active', False)
        
        if not target:
            return jsonify({'success': False, 'error': 'Target is required'}), 400
        
        # Clean domain
        domain = target.replace('http://', '').replace('https://', '').strip('/')
        
        # Determine scan type for DB
        scan_type = 'passive'
        if passive and active:
            scan_type = 'full'
        elif active and not passive:
            scan_type = 'active'
        
        scan_id = create_scan(db_session, domain, scan_type)
        
        thread = threading.Thread(
            target=run_scan_background,
            args=(domain, scan_id),
            kwargs={'passive': passive, 'active': active, 'crawl': crawl}
        )
        thread.daemon = True
        thread.start()
        
        active_scans[scan_id] = thread
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': f'Domain scan started for {domain}'
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scans/<int:scan_id>', methods=['GET'])
def get_scan_details(scan_id):
    """Get scan details"""
    try:
        results = get_scan_results(db_session, scan_id)
        
        if not results:
            return jsonify({'success': False, 'error': 'Scan not found'}), 404
        
        return jsonify({
            'success': True,
            'scan': results
        })
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scans/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete scan and all related data (subdomains, endpoints, vulnerabilities)"""
    try:
        from sqlalchemy import text
        
        # First, expire and close any pending transactions on global session
        # This releases the database lock
        try:
            db_session.expire_all()
            db_session.close()
        except:
            pass
        
        # Use a fresh connection for raw SQL to avoid ORM session issues
        with db_engine.connect() as conn:
            # First check if scan exists
            result = conn.execute(text("SELECT domain FROM scan_history WHERE id = :id"), {"id": scan_id})
            row = result.fetchone()
            
            if not row:
                return jsonify({'success': False, 'error': 'Scan not found'}), 404
            
            domain = row[0]
            
            # Delete in order: vulnerabilities -> endpoints -> subdomains -> scan
            conn.execute(text("DELETE FROM vulnerabilities WHERE scan_id = :id"), {"id": scan_id})
            conn.execute(text("DELETE FROM endpoints WHERE scan_id = :id"), {"id": scan_id})
            conn.execute(text("DELETE FROM subdomains WHERE scan_id = :id"), {"id": scan_id})
            conn.execute(text("DELETE FROM scan_history WHERE id = :id"), {"id": scan_id})
            conn.commit()
        
        print(f"[*] Deleted scan {scan_id} for {domain}")
        
        return jsonify({
            'success': True,
            'message': f'Scan {scan_id} for {domain} deleted successfully'
        })
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scans/<int:scan_id>/stats', methods=['GET'])
def get_scan_stats(scan_id):
    """Get scan statistics (all subdomains in DB are alive)"""
    try:
        subdomains = get_subdomains(db_session, scan_id)
        endpoints = get_endpoints(db_session, scan_id)
        
        get_count = sum(1 for e in endpoints if e.method == 'GET')
        post_count = sum(1 for e in endpoints if e.method == 'POST')
        
        # All stored subdomains are alive (we only save alive ones now)
        stats = {
            'total_subdomains': len(subdomains),
            'get_endpoints': get_count,
            'post_endpoints': post_count
        }
        
        return jsonify({'success': True, 'stats': stats})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scans/<int:scan_id>/subdomains', methods=['GET'])
def get_scan_subdomains(scan_id):
    """Get subdomains for a scan"""
    try:
        subdomains = get_subdomains(db_session, scan_id)
        
        result = []
        for s in subdomains:
            result.append({
                'id': s.id,
                'subdomain': s.subdomain,
                'is_alive': s.is_alive,
                'status_code': s.status_code,
                'title': s.title or ''
            })
        
        return jsonify({'success': True, 'subdomains': result})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scans/<int:scan_id>/endpoints', methods=['GET'])
def get_scan_endpoints(scan_id):
    """Get endpoints for a scan"""
    try:
        endpoints = get_endpoints(db_session, scan_id)
        
        result = []
        for e in endpoints:
            result.append({
                'id': e.id if hasattr(e, 'id') else None,
                'url': e.url if hasattr(e, 'url') else '',
                'method': e.method if hasattr(e, 'method') else 'GET',
                'parameters': e.parameters if hasattr(e, 'parameters') else {},
                'body_params': e.body_params if hasattr(e, 'body_params') else {},
                'source': e.source if hasattr(e, 'source') else '',
                'form_details': e.form_details if hasattr(e, 'form_details') else {}
            })
        
        return jsonify({'success': True, 'endpoints': result})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    """Get overall dashboard statistics"""
    try:
        all_scans = get_all_scans(db_session)
        
        total_scans = len(all_scans)
        running_scans = sum(1 for s in all_scans if s.status == 'running')
        
        total_subdomains = 0
        total_endpoints = 0
        
        for scan in all_scans:
            subdomains = get_subdomains(db_session, scan.id)
            endpoints = get_endpoints(db_session, scan.id)
            total_subdomains += len(subdomains)
            total_endpoints += len(endpoints)
        
        stats = {
            'total_scans': total_scans,
            'running_scans': running_scans,
            'total_subdomains': total_subdomains,
            'total_endpoints': total_endpoints
        }
        
        return jsonify({'success': True, 'stats': stats})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================================
# WEBSOCKET EVENTS
# ============================================================================

@socketio.on('connect')
def handle_connect():
    """Client connected"""
    print("[WebSocket] Client connected")
    emit('connected', {'message': 'Connected to NileDefender'})


@socketio.on('join_scan')
def handle_join_scan(data):
    """Join scan room for real-time updates"""
    scan_id = data.get('scan_id')
    if scan_id:
        room = f'scan_{scan_id}'
        join_room(room)
        print(f"[WebSocket] Client joined scan {scan_id}")


# ============================================================================
# SERVE HTML INTERFACE
# ============================================================================

@app.route('/')
def index():
    """Serve the main HTML interface"""
    return render_template('index.html')


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🛡️  NILEDEFENDER - WEB VULNERABILITY SCANNER")
    print("="*70)
    print(f"🌐 Web Interface: http://localhost:5000")
    print(f"💾 Database: niledefender.db")
    print(f"📡 WebSocket: Enabled")
    print("="*70)
    print("\n[*] Starting server...")
    print("[*] Press CTRL+C to stop\n")
    
    # Run with SocketIO
    socketio.run(
        app,
        host='0.0.0.0',
        port=5000,
        debug=True,
        allow_unsafe_werkzeug=True
    )
