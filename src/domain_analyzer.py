"""
Domain analysis using WHOIS and other domain-related checks
"""

import socket
import ssl
import whois
import requests
from urllib.parse import urlparse
from datetime import datetime, timedelta
import traceback


class DomainAnalyzer:
    def __init__(self):
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download', 
            '.stream', '.science', '.racing', '.loan', '.win', '.bid'
        }
        
        self.legitimate_domains = {
            'google.com', 'facebook.com', 'youtube.com', 'amazon.com', 
            'wikipedia.org', 'twitter.com', 'instagram.com', 'linkedin.com',
            'microsoft.com', 'apple.com', 'netflix.com', 'paypal.com',
            'ebay.com', 'reddit.com', 'stackoverflow.com', 'github.com'
        }
    
    def analyze_domain(self, domain):
        """
        Comprehensive domain analysis
        
        Args:
            domain (str): Domain name to analyze
            
        Returns:
            dict: Domain analysis results
        """
        result = {
            'domain': domain,
            'is_suspicious_tld': False,
            'is_known_legitimate': False,
            'has_ip_address': False,
            'ssl_info': {},
            'whois_info': {},
            'dns_info': {},
            'reputation_score': 0.0
        }
        
        try:
            # Clean domain
            clean_domain = domain.lower().strip()
            if clean_domain.startswith('www.'):
                clean_domain = clean_domain[4:]
            
            # Check if domain is actually an IP address
            result['has_ip_address'] = self._is_ip_address(clean_domain)
            
            # Check TLD
            result['is_suspicious_tld'] = any(clean_domain.endswith(tld) for tld in self.suspicious_tlds)
            
            # Check if known legitimate domain
            result['is_known_legitimate'] = clean_domain in self.legitimate_domains
            
            # SSL/Certificate analysis
            result['ssl_info'] = self._analyze_ssl(clean_domain)
            
            # WHOIS analysis
            result['whois_info'] = self._analyze_whois(clean_domain)
            
            # DNS analysis
            result['dns_info'] = self._analyze_dns(clean_domain)
            
            # Calculate reputation score
            result['reputation_score'] = self._calculate_reputation_score(result)
            
        except Exception as e:
            result['error'] = str(e)
            result['reputation_score'] = 0.0
        
        return result
    
    def _is_ip_address(self, domain):
        """Check if domain is an IP address"""
        try:
            socket.inet_aton(domain)
            return True
        except socket.error:
            return False
    
    def _analyze_ssl(self, domain):
        """Analyze SSL certificate"""
        ssl_info = {
            'has_ssl': False,
            'certificate_valid': False,
            'issuer': None,
            'expires': None,
            'days_until_expiry': None
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    ssl_info['has_ssl'] = True
                    cert = ssock.getpeercert()
                    
                    if cert:
                        ssl_info['certificate_valid'] = True
                        ssl_info['issuer'] = dict(x[0] for x in cert.get('issuer', []))
                        
                        # Parse expiry date
                        not_after = cert.get('notAfter')
                        if not_after:
                            expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            ssl_info['expires'] = expiry_date.isoformat()
                            ssl_info['days_until_expiry'] = (expiry_date - datetime.now()).days
        
        except Exception as e:
            ssl_info['error'] = str(e)
        
        return ssl_info
    
    def _analyze_whois(self, domain):
        """Analyze WHOIS information"""
        whois_info = {
            'domain_age_days': None,
            'registrar': None,
            'creation_date': None,
            'expiry_date': None,
            'updated_date': None,
            'name_servers': [],
            'is_recently_registered': False
        }
        
        try:
            # Perform WHOIS lookup with timeout
            w = whois.whois(domain)
            
            if w:
                # Creation date
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0] if creation_date else None
                
                if creation_date:
                    whois_info['creation_date'] = creation_date.isoformat()
                    domain_age = (datetime.now() - creation_date).days
                    whois_info['domain_age_days'] = domain_age
                    whois_info['is_recently_registered'] = domain_age < 30
                
                # Expiry date
                expiry_date = w.expiration_date
                if isinstance(expiry_date, list):
                    expiry_date = expiry_date[0] if expiry_date else None
                
                if expiry_date:
                    whois_info['expiry_date'] = expiry_date.isoformat()
                
                # Updated date
                updated_date = w.updated_date
                if isinstance(updated_date, list):
                    updated_date = updated_date[0] if updated_date else None
                
                if updated_date:
                    whois_info['updated_date'] = updated_date.isoformat()
                
                # Registrar
                whois_info['registrar'] = str(w.registrar) if w.registrar else None
                
                # Name servers
                name_servers = w.name_servers
                if name_servers:
                    if isinstance(name_servers, list):
                        whois_info['name_servers'] = [str(ns).lower() for ns in name_servers]
                    else:
                        whois_info['name_servers'] = [str(name_servers).lower()]
        
        except Exception as e:
            whois_info['error'] = str(e)
        
        return whois_info
    
    def _analyze_dns(self, domain):
        """Analyze DNS records"""
        dns_info = {
            'a_records': [],
            'mx_records': [],
            'has_a_record': False,
            'has_mx_record': False
        }
        
        try:
            # A record lookup
            try:
                a_records = socket.gethostbyname_ex(domain)
                dns_info['a_records'] = a_records[2] if len(a_records) > 2 else []
                dns_info['has_a_record'] = len(dns_info['a_records']) > 0
            except socket.gaierror:
                pass
            
            # For MX records, we would need additional DNS libraries
            # For now, we'll skip MX record lookup to avoid additional dependencies
            
        except Exception as e:
            dns_info['error'] = str(e)
        
        return dns_info
    
    def _calculate_reputation_score(self, analysis_result):
        """
        Calculate domain reputation score (0-1, higher is more trustworthy)
        """
        score = 0.5  # Start with neutral score
        
        try:
            # Known legitimate domain
            if analysis_result.get('is_known_legitimate', False):
                score += 0.4
            
            # IP address instead of domain (suspicious)
            if analysis_result.get('has_ip_address', False):
                score -= 0.3
            
            # Suspicious TLD
            if analysis_result.get('is_suspicious_tld', False):
                score -= 0.2
            
            # SSL certificate
            ssl_info = analysis_result.get('ssl_info', {})
            if ssl_info.get('has_ssl', False):
                score += 0.1
                if ssl_info.get('certificate_valid', False):
                    score += 0.1
            
            # Domain age
            whois_info = analysis_result.get('whois_info', {})
            domain_age = whois_info.get('domain_age_days')
            if domain_age is not None:
                if domain_age > 365:  # More than 1 year
                    score += 0.2
                elif domain_age > 90:  # More than 3 months
                    score += 0.1
                elif domain_age < 30:  # Less than 1 month (suspicious)
                    score -= 0.2
            
            # Recently registered
            if whois_info.get('is_recently_registered', False):
                score -= 0.15
            
            # Has DNS records
            dns_info = analysis_result.get('dns_info', {})
            if dns_info.get('has_a_record', False):
                score += 0.05
            
        except Exception as e:
            print(f"Error calculating reputation score: {e}")
        
        # Ensure score is within bounds
        return max(0.0, min(1.0, score))
    
    def is_domain_suspicious(self, domain):
        """
        Quick check if domain appears suspicious
        
        Args:
            domain (str): Domain to check
            
        Returns:
            bool: True if domain appears suspicious
        """
        try:
            analysis = self.analyze_domain(domain)
            reputation_score = analysis.get('reputation_score', 0.5)
            
            # Consider suspicious if reputation score is low
            return reputation_score < 0.3
            
        except Exception:
            return True  # Assume suspicious if analysis fails
