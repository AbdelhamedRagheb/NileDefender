#!/usr/bin/env python3


import logging
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, UniqueConstraint, JSON, create_engine, func, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.exc import IntegrityError


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
Base = declarative_base()



class ScanHistory(Base):
    __tablename__ = 'scan_history'
    
    id = Column(Integer, primary_key=True)
    domain = Column(String, unique=True, nullable=False, index=True)
    scan_date = Column(DateTime, default=func.now())
    scan_type = Column(String)  # 'full', 'recon_only', 'custom'
    status = Column(String, default='completed')  # 'running', 'completed', 'failed'
    
    # Relationships
    subdomains = relationship("Subdomain", back_populates="scan", cascade="all, delete-orphan")
    endpoints = relationship("Endpoint", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Scan(domain={self.domain}, date={self.scan_date}, status={self.status})>"


class Subdomain(Base):
    __tablename__ = 'subdomains'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scan_history.id'), nullable=False)
    subdomain = Column(String, nullable=False, index=True)
    is_alive = Column(Integer, default=0)  # 0=not checked, 1=alive, 2=dead
    status_code = Column(Integer)
    title = Column(String)
    technologies = Column(JSON)  # Detected technologies
    ip_address = Column(String)
    
    __table_args__ = (
        UniqueConstraint('scan_id', 'subdomain', name='unique_subdomain_per_scan'),
    )
    
    scan = relationship("ScanHistory", back_populates="subdomains")
    
    def __repr__(self):
        return f"<Subdomain(subdomain={self.subdomain}, alive={self.is_alive})>"


class Endpoint(Base):
    __tablename__ = 'endpoints'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scan_history.id'), nullable=False)
    url = Column(Text, nullable=False)
    method = Column(String, nullable=False, default='GET')
    parameters = Column(JSON)  # URL parameters
    body_params = Column(JSON)  # POST body parameters
    extra_headers = Column(JSON)  # Custom headers
    source = Column(String)  # 'wayback', 'crawler', 'manual', etc.
    has_parameters = Column(Integer, default=0)  # 0=no params, 1=has params
    
    __table_args__ = (
        UniqueConstraint('scan_id', 'url', 'method', name='unique_endpoint_per_scan'),
    )
    
    scan = relationship("ScanHistory", back_populates="endpoints")
    
    def __repr__(self):
        return f"<Endpoint(url={self.url[:50]}, method={self.method})>"


class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scan_history.id'), nullable=False)
    vulnerability_type = Column(String, nullable=False, index=True)  # 'XSS', 'SQLi', 'CSRF', etc.
    severity = Column(String, nullable=False, index=True)  # 'Critical', 'High', 'Medium', 'Low', 'Info'
    url = Column(Text, nullable=False)
    parameter = Column(String)  # Vulnerable parameter name
    payload = Column(Text)  # Payload used to exploit
    evidence = Column(Text)  # Proof/evidence of vulnerability
    vulnerability_data = Column(JSON)  # Full vulnerability details
    discovered_at = Column(DateTime, default=func.now())
    
    __table_args__ = (
        UniqueConstraint('scan_id', 'vulnerability_type', 'url', 'parameter', 
                        name='unique_vulnerability_per_scan'),
    )
    
    scan = relationship("ScanHistory", back_populates="vulnerabilities")
    
    def __repr__(self):
        return f"<Vulnerability(type={self.vulnerability_type}, severity={self.severity}, url={self.url[:50]})>"



def init_db(db_path='sqlite:///niledefender.db'):
    try:
        engine = create_engine(db_path, echo=False)
        Base.metadata.create_all(engine)
        logger.info(f"[DB] NileDefender database initialized: {db_path}")
        return engine
    except Exception as e:
        logger.error(f"[DB] Error initializing database: {e}")
        raise


def get_session(engine):
    Session = sessionmaker(bind=engine)
    return Session()



def create_scan(session, domain, scan_type='full'):
    try:
        # Check if scan already exists
        existing_scan = session.query(ScanHistory).filter_by(domain=domain).first()
        if existing_scan:
            logger.info(f"[DB] Scan for {domain} already exists. Updating...")
            existing_scan.scan_date = func.now()
            existing_scan.scan_type = scan_type
            existing_scan.status = 'running'
            session.commit()
            return existing_scan.id
        
        # Create new scan
        new_scan = ScanHistory(domain=domain, scan_type=scan_type, status='running')
        session.add(new_scan)
        session.commit()
        logger.info(f"[DB] Created new scan for {domain} (ID: {new_scan.id})")
        return new_scan.id
        
    except Exception as e:
        session.rollback()
        logger.error(f"[DB] Error creating scan: {e}")
        raise


def update_scan_status(session, scan_id, status):
    try:
        scan = session.query(ScanHistory).filter_by(id=scan_id).first()
        if scan:
            scan.status = status
            session.commit()
            logger.info(f"[DB] Updated scan {scan_id} status to {status}")
    except Exception as e:
        session.rollback()
        logger.error(f"[DB] Error updating scan status: {e}")



def save_subdomain(session, scan_id, subdomain, is_alive=0, status_code=None, 
                   title=None, technologies=None, ip_address=None):
    try:
        new_subdomain = Subdomain(
            scan_id=scan_id,
            subdomain=subdomain,
            is_alive=is_alive,
            status_code=status_code,
            title=title,
            technologies=technologies,
            ip_address=ip_address
        )
        session.add(new_subdomain)
        session.commit()
        logger.info(f"[DB] Saved subdomain: {subdomain}")
        
    except IntegrityError:
        session.rollback()
        # Update existing subdomain
        existing = session.query(Subdomain).filter_by(
            scan_id=scan_id, subdomain=subdomain
        ).first()
        if existing:
            existing.is_alive = is_alive
            existing.status_code = status_code
            existing.title = title
            existing.technologies = technologies
            existing.ip_address = ip_address
            session.commit()
            logger.debug(f"[DB] Updated subdomain: {subdomain}")
    except Exception as e:
        session.rollback()
        logger.error(f"[DB] Error saving subdomain: {e}")


def save_subdomains_bulk(session, scan_id, subdomains):
    for subdomain in subdomains:
        save_subdomain(session, scan_id, subdomain)



def save_endpoint(session, scan_id, url, method='GET', parameters=None, 
                 body_params=None, extra_headers=None, source='crawler'):
    try:
        has_params = 1 if (parameters or body_params) else 0
        
        new_endpoint = Endpoint(
            scan_id=scan_id,
            url=url,
            method=method,
            parameters=parameters,
            body_params=body_params,
            extra_headers=extra_headers,
            source=source,
            has_parameters=has_params
        )
        session.add(new_endpoint)
        session.commit()
        logger.info(f"[DB] Saved endpoint: {method} {url[:100]}")
        
    except IntegrityError:
        session.rollback()
        logger.debug(f"[DB] Duplicate endpoint skipped: {url[:100]}")
    except Exception as e:
        session.rollback()
        logger.error(f"[DB] Error saving endpoint: {e}")


def save_endpoints_bulk(session, scan_id, endpoints):
    for endpoint in endpoints:
        save_endpoint(
            session, scan_id,
            url=endpoint.get('url'),
            method=endpoint.get('method', 'GET'),
            parameters=endpoint.get('parameters'),
            body_params=endpoint.get('body_params'),
            extra_headers=endpoint.get('extra_headers'),
            source=endpoint.get('source', 'crawler')
        )

# prepared for next stage
def save_vulnerability(session, scan_id, vuln_type, severity, url, parameter=None,
                      payload=None, evidence=None, vuln_data=None):
    try:
        new_vuln = Vulnerability(
            scan_id=scan_id,
            vulnerability_type=vuln_type,
            severity=severity,
            url=url,
            parameter=parameter,
            payload=payload,
            evidence=evidence,
            vulnerability_data=vuln_data
        )
        session.add(new_vuln)
        session.commit()
        logger.info(f"[DB] Saved vulnerability: {vuln_type} ({severity}) at {url[:100]}")
        
    except IntegrityError:
        session.rollback()
        logger.debug(f"[DB] Duplicate vulnerability skipped: {vuln_type} at {url[:100]}")
    except Exception as e:
        session.rollback()
        logger.error(f"[DB] Error saving vulnerability: {e}")



def get_scan_by_domain(session, domain):
    """Get scan by domain name"""
    return session.query(ScanHistory).filter_by(domain=domain).first()


def get_scan_by_id(session, scan_id):
    """Get scan by ID"""
    return session.query(ScanHistory).filter_by(id=scan_id).first()


def get_all_scans(session):
    """Get all scans"""
    return session.query(ScanHistory).order_by(ScanHistory.scan_date.desc()).all()


def get_subdomains(session, scan_id, alive_only=False):
    """Get subdomains for a scan"""
    query = session.query(Subdomain).filter_by(scan_id=scan_id)
    if alive_only:
        query = query.filter_by(is_alive=1)
    return query.all()


def get_endpoints(session, scan_id, with_params_only=False):
    """Get endpoints for a scan"""
    query = session.query(Endpoint).filter_by(scan_id=scan_id)
    if with_params_only:
        query = query.filter_by(has_parameters=1)
    return query.all()


def get_vulnerabilities(session, scan_id, vuln_type=None, severity=None):
    """Get vulnerabilities for a scan"""
    query = session.query(Vulnerability).filter_by(scan_id=scan_id)
    if vuln_type:
        query = query.filter_by(vulnerability_type=vuln_type)
    if severity:
        query = query.filter_by(severity=severity)
    return query.all()


def get_vulnerability_stats(session, scan_id):
    """Get vulnerability statistics for a scan"""
    vulns = get_vulnerabilities(session, scan_id)
    
    stats = {
        'total': len(vulns),
        'by_type': {},
        'by_severity': {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
    }
    
    for vuln in vulns:
        # Count by type
        if vuln.vulnerability_type not in stats['by_type']:
            stats['by_type'][vuln.vulnerability_type] = 0
        stats['by_type'][vuln.vulnerability_type] += 1
        
        # Count by severity
        if vuln.severity in stats['by_severity']:
            stats['by_severity'][vuln.severity] += 1
    
    return stats


def get_scan_results(session, domain):

    scan = get_scan_by_domain(session, domain)
    if not scan:
        return None
    
    subdomains = get_subdomains(session, scan.id)
    endpoints = get_endpoints(session, scan.id)
    vulnerabilities = get_vulnerabilities(session, scan.id)
    stats = get_vulnerability_stats(session, scan.id)
    
    return {
        'scan': {
            'id': scan.id,
            'domain': scan.domain,
            'scan_date': scan.scan_date.isoformat() if scan.scan_date else None,
            'scan_type': scan.scan_type,
            'status': scan.status
        },
        'subdomains': [
            {
                'subdomain': s.subdomain,
                'is_alive': s.is_alive,
                'status_code': s.status_code,
                'title': s.title,
                'technologies': s.technologies,
                'ip_address': s.ip_address
            }
            for s in subdomains
        ],
        'endpoints': [
            {
                'url': e.url,
                'method': e.method,
                'parameters': e.parameters,
                'body_params': e.body_params,
                'extra_headers': e.extra_headers,
                'source': e.source
            }
            for e in endpoints
        ],
        'vulnerabilities': [
            {
                'type': v.vulnerability_type,
                'severity': v.severity,
                'url': v.url,
                'parameter': v.parameter,
                'payload': v.payload,
                'evidence': v.evidence,
                'discovered_at': v.discovered_at.isoformat() if v.discovered_at else None
            }
            for v in vulnerabilities
        ],
        'statistics': stats
    }


def delete_scan(session, scan_id):
    try:
        scan = get_scan_by_id(session, scan_id)
        if scan:
            session.delete(scan)
            session.commit()
            logger.info(f"[DB] Deleted scan {scan_id}")
            return True
        return False
    except Exception as e:
        session.rollback()
        logger.error(f"[DB] Error deleting scan: {e}")
        return False


# Test the database functions
if __name__ == "__main__":
    # Initialize database
    engine = init_db('sqlite:///test_niledefender.db')
    session = get_session(engine)
    
    # Test creating a scan
    scan_id = create_scan(session, 'example.com', 'full')
    
    # Test saving subdomains
    save_subdomain(session, scan_id, 'www.example.com', is_alive=1, status_code=200)
    save_subdomain(session, scan_id, 'api.example.com', is_alive=1, status_code=200)
    
    # Test saving endpoints
    save_endpoint(session, scan_id, 'https://example.com/search?q=test', 
                 parameters={'q': 'test'})
    
    # Test saving vulnerability
    save_vulnerability(session, scan_id, 'XSS', 'High', 
                      'https://example.com/search?q=<script>alert(1)</script>',
                      parameter='q', payload='<script>alert(1)</script>')
    
    # Update scan status
    update_scan_status(session, scan_id, 'completed')
    
    # Query results
    results = get_scan_results(session, 'example.com')
    print("\n=== NILEDEFENDER SCAN RESULTS ===")
    print(f"Domain: {results['scan']['domain']}")
    print(f"Subdomains: {len(results['subdomains'])}")
    print(f"Endpoints: {len(results['endpoints'])}")
    print(f"Vulnerabilities: {len(results['vulnerabilities'])}")
    print(f"Statistics: {results['statistics']}")
    
    session.close()
    print("\n[✓] NileDefender database test completed!")
