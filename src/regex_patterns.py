"""
Regex patterns for detecting common phishing indicators
"""

import re
from urllib.parse import urlparse


class RegexPatterns:
    def __init__(self):
        self.patterns = {
            # Suspicious domain patterns
            'ip_address': r'http[s]?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}',
            'suspicious_subdomains': r'https?://[^/]*(?:secure|update|verify|confirm|account|banking|signin|login)-[^/]*',
            'typosquatting': r'https?://[^/]*(?:goog1e|payp4l|microsft|amaz0n|faceb00k)',
            'homograph_chars': r'[а-яё]',  # Cyrillic characters that look like Latin
            
            # Suspicious URL structure
            'too_many_subdomains': r'https?://(?:[^./]+\.){4,}[^/]+',
            'suspicious_tld': r'\.(?:tk|ml|ga|cf|top|click|download|stream|science|racing|loan|win|bid)(?:/|$)',
            'url_shortener': r'https?://(?:bit\.ly|tinyurl|t\.co|goo\.gl|short\.link|ow\.ly)',
            
            # Suspicious path patterns
            'suspicious_paths': r'/(?:secure|update|verify|confirm|signin|login|account|banking|suspend|limited)',
            'random_string': r'/[a-zA-Z0-9]{20,}',
            'multiple_extensions': r'\.[a-zA-Z]{2,4}\.[a-zA-Z]{2,4}',
            
            # Suspicious query parameters
            'suspicious_params': r'[?&](?:redirect|return|next|continue|goto|url)=https?://',
            'encoded_urls': r'%2[fF]|%3[aA]|%2[eE]',
            
            # Brand impersonation
            'banking_brands': r'(?:paypal|bank|visa|mastercard|american-?express|discover)',
            'tech_brands': r'(?:microsoft|google|apple|amazon|facebook|instagram|twitter)',
            'suspicious_keywords': r'(?:urgent|immediate|suspend|verify|confirm|update|security|alert)',
            
            # Phishing-specific patterns
            'fake_https': r'^http://[^/]*https?[^/]*',
            'port_in_url': r'https?://[^/]*:[0-9]+',
            'excessive_hyphens': r'-{2,}',
            'mixed_case_domain': r'https?://[^/]*[A-Z][a-z]*[A-Z]',
        }
        
        # Compile patterns for better performance
        self.compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.patterns.items()
        }
    
    def check_patterns(self, url):
        """
        Check URL against all regex patterns
        
        Args:
            url (str): URL to analyze
            
        Returns:
            list: List of matched pattern names
        """
        matches = []
        
        try:
            # Parse URL for additional checks
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query.lower()
            
            # Check each pattern
            for pattern_name, compiled_pattern in self.compiled_patterns.items():
                if compiled_pattern.search(url):
                    matches.append(pattern_name)
            
            # Additional custom checks
            matches.extend(self._additional_checks(url, parsed))
            
        except Exception as e:
            print(f"Error in pattern matching: {e}")
        
        return matches
    
    def _additional_checks(self, url, parsed_url):
        """
        Additional custom checks that are harder to express as simple regex
        
        Args:
            url (str): Original URL
            parsed_url: Parsed URL object
            
        Returns:
            list: List of additional suspicious patterns found
        """
        additional_matches = []
        
        try:
            domain = parsed_url.netloc.lower()
            path = parsed_url.path.lower()
            
            # Check for excessive URL length
            if len(url) > 200:
                additional_matches.append('excessive_url_length')
            
            # Check for excessive domain length
            if len(domain) > 50:
                additional_matches.append('excessive_domain_length')
            
            # Check for excessive special characters
            special_char_count = sum(1 for c in url if not c.isalnum() and c not in ':/.-_')
            if special_char_count > 15:
                additional_matches.append('excessive_special_chars')
            
            # Check for suspicious character sequences
            if any(seq in domain for seq in ['--', '__', '..']):
                additional_matches.append('suspicious_char_sequences')
            
            # Check for numeric domains (suspicious)
            domain_parts = domain.split('.')
            if len(domain_parts) > 1:
                main_domain = domain_parts[-2]  # Get main domain part
                if main_domain.isdigit():
                    additional_matches.append('numeric_domain')
            
            # Check for suspicious path depth
            path_depth = len([p for p in path.split('/') if p])
            if path_depth > 5:
                additional_matches.append('excessive_path_depth')
            
            # Check for URL encoding in domain
            if '%' in domain:
                additional_matches.append('encoded_domain')
            
            # Check for misleading protocol
            if 'https' in domain and not url.startswith('https://'):
                additional_matches.append('misleading_protocol')
            
            # Check for brand typosquatting (more sophisticated)
            additional_matches.extend(self._check_brand_typosquatting(domain))
            
        except Exception as e:
            print(f"Error in additional checks: {e}")
        
        return additional_matches
    
    def _check_brand_typosquatting(self, domain):
        """
        Check for sophisticated brand typosquatting attempts
        
        Args:
            domain (str): Domain to check
            
        Returns:
            list: List of typosquatting patterns found
        """
        typosquatting_matches = []
        
        # Common brand variations
        brand_variations = {
            'google': ['goog1e', 'googIe', 'gooogle', 'gogle', 'googel'],
            'paypal': ['payp4l', 'paypaI', 'paypal1', 'paipal', 'payp-al'],
            'microsoft': ['microsft', 'micr0soft', 'microsoft1', 'microsooft'],
            'amazon': ['amaz0n', 'amazom', 'amazon1', 'amazone', 'ammazon'],
            'facebook': ['faceb00k', 'facebok', 'facebook1', 'face-book'],
            'apple': ['app1e', 'apple1', 'aple', 'appl-e'],
            'instagram': ['instagr4m', 'instagram1', 'instgram', 'insta-gram'],
            'twitter': ['twiter', 'twitter1', 'tw1tter', 'twittter'],
        }
        
        try:
            # Remove common prefixes/suffixes
            clean_domain = domain
            for prefix in ['www.', 'secure.', 'login.', 'account.']:
                if clean_domain.startswith(prefix):
                    clean_domain = clean_domain[len(prefix):]
                    break
            
            # Check against brand variations
            for brand, variations in brand_variations.items():
                for variation in variations:
                    if variation in clean_domain:
                        typosquatting_matches.append(f'typosquatting_{brand}')
                        break
            
        except Exception as e:
            print(f"Error in brand typosquatting check: {e}")
        
        return typosquatting_matches
    
    def get_pattern_description(self, pattern_name):
        """
        Get human-readable description of a pattern
        
        Args:
            pattern_name (str): Name of the pattern
            
        Returns:
            str: Description of what the pattern detects
        """
        descriptions = {
            'ip_address': 'URL uses IP address instead of domain name',
            'suspicious_subdomains': 'Contains suspicious subdomains (secure, update, verify, etc.)',
            'typosquatting': 'Potential typosquatting of popular brands',
            'homograph_chars': 'Contains characters that look like Latin letters',
            'too_many_subdomains': 'Excessive number of subdomains',
            'suspicious_tld': 'Uses suspicious top-level domain',
            'url_shortener': 'Uses URL shortening service',
            'suspicious_paths': 'Contains suspicious path components',
            'random_string': 'Contains long random-looking strings',
            'multiple_extensions': 'Multiple file extensions in URL',
            'suspicious_params': 'Suspicious redirect parameters',
            'encoded_urls': 'Contains URL encoding',
            'banking_brands': 'Mentions banking/financial brands',
            'tech_brands': 'Mentions technology brands',
            'suspicious_keywords': 'Contains urgent/suspicious keywords',
            'fake_https': 'Fake HTTPS in domain name',
            'port_in_url': 'Unusual port number specified',
            'excessive_hyphens': 'Excessive use of hyphens',
            'mixed_case_domain': 'Mixed case in domain name',
            'excessive_url_length': 'URL is unusually long',
            'excessive_domain_length': 'Domain name is unusually long',
            'excessive_special_chars': 'Too many special characters',
            'suspicious_char_sequences': 'Suspicious character patterns',
            'numeric_domain': 'Domain name is purely numeric',
            'excessive_path_depth': 'URL path is too deep',
            'encoded_domain': 'Domain contains URL encoding',
            'misleading_protocol': 'Misleading protocol information',
        }
        
        # Handle typosquatting patterns
        if pattern_name.startswith('typosquatting_'):
            brand = pattern_name.split('_', 1)[1]
            return f'Potential typosquatting of {brand.capitalize()}'
        
        return descriptions.get(pattern_name, f'Suspicious pattern: {pattern_name}')
    
    def calculate_suspicion_score(self, matches):
        """
        Calculate suspicion score based on pattern matches
        
        Args:
            matches (list): List of matched pattern names
            
        Returns:
            float: Suspicion score (0-1, higher is more suspicious)
        """
        if not matches:
            return 0.0
        
        # Weight different patterns by severity
        pattern_weights = {
            'ip_address': 0.8,
            'typosquatting': 0.9,
            'suspicious_subdomains': 0.7,
            'homograph_chars': 0.8,
            'too_many_subdomains': 0.6,
            'suspicious_tld': 0.7,
            'fake_https': 0.9,
            'misleading_protocol': 0.8,
            'excessive_url_length': 0.4,
            'suspicious_keywords': 0.6,
            'encoded_domain': 0.7,
        }
        
        # Calculate weighted score
        total_weight = 0.0
        max_possible_weight = 0.0
        
        for match in matches:
            weight = pattern_weights.get(match, 0.3)  # Default weight for unspecified patterns
            total_weight += weight
            max_possible_weight += 1.0  # Each match could theoretically have weight 1.0
        
        # Normalize score to 0-1 range
        if max_possible_weight > 0:
            score = min(1.0, total_weight / max_possible_weight * 2)  # Multiply by 2 to make scoring more sensitive
        else:
            score = 0.0
        
        return score
