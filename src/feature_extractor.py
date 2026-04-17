"""
Feature extraction from URLs for machine learning model
"""

import re
import math
from urllib.parse import urlparse, parse_qs
from collections import Counter


class FeatureExtractor:
    def __init__(self):
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download', 
            '.stream', '.science', '.racing', '.loan', '.win', '.bid'
        }
        
        self.suspicious_keywords = {
            'secure', 'update', 'verify', 'confirm', 'account', 'banking',
            'signin', 'login', 'suspend', 'limited', 'urgent', 'immediate'
        }
    
    def extract_features(self, url, parsed_url=None):
        """
        Extract comprehensive features from URL
        
        Args:
            url (str): Original URL
            parsed_url: Pre-parsed URL object (optional)
            
        Returns:
            dict: Dictionary of extracted features
        """
        if parsed_url is None:
            parsed_url = urlparse(url)
        
        features = {}
        
        try:
            # Basic URL components
            scheme = parsed_url.scheme or ''
            netloc = parsed_url.netloc or ''
            path = parsed_url.path or ''
            query = parsed_url.query or ''
            fragment = parsed_url.fragment or ''
            
            # Length features
            features['url_length'] = len(url)
            features['domain_length'] = len(netloc)
            features['path_length'] = len(path)
            features['query_length'] = len(query)
            features['fragment_length'] = len(fragment)
            
            # Domain analysis
            features.update(self._extract_domain_features(netloc))
            
            # Path analysis
            features.update(self._extract_path_features(path))
            
            # Character analysis
            features.update(self._extract_character_features(url))
            
            # Structural features
            features.update(self._extract_structural_features(url, parsed_url))
            
            # Content analysis
            features.update(self._extract_content_features(url, netloc, path, query))
            
            # Entropy features
            features['url_entropy'] = self._calculate_entropy(url)
            features['domain_entropy'] = self._calculate_entropy(netloc)
            
        except Exception as e:
            print(f"Error extracting features: {e}")
            # Return default features in case of error
            features = self._get_default_features()
        
        return features
    
    def _extract_domain_features(self, domain):
        """Extract features from domain"""
        features = {}
        
        try:
            # Clean domain
            clean_domain = domain.lower().strip()
            
            # Subdomain count
            domain_parts = clean_domain.split('.')
            features['subdomain_count'] = max(0, len(domain_parts) - 2)  # Subtract main domain and TLD
            
            # IP address check
            features['has_ip'] = int(self._is_ip_address(clean_domain))
            
            # Port check
            features['has_port'] = int(':' in clean_domain and not clean_domain.endswith(':80') and not clean_domain.endswith(':443'))
            
            # TLD analysis
            if domain_parts:
                tld = '.' + domain_parts[-1] if len(domain_parts) > 1 else ''
                features['suspicious_tld'] = int(tld in self.suspicious_tlds)
            else:
                features['suspicious_tld'] = 0
            
            # Domain character analysis
            features['domain_digit_count'] = sum(1 for c in clean_domain if c.isdigit())
            features['domain_hyphen_count'] = clean_domain.count('-')
            features['domain_underscore_count'] = clean_domain.count('_')
            
        except Exception as e:
            print(f"Error in domain feature extraction: {e}")
            features = {
                'subdomain_count': 0,
                'has_ip': 0,
                'has_port': 0,
                'suspicious_tld': 0,
                'domain_digit_count': 0,
                'domain_hyphen_count': 0,
                'domain_underscore_count': 0
            }
        
        return features
    
    def _extract_path_features(self, path):
        """Extract features from URL path"""
        features = {}
        
        try:
            # Path depth
            path_parts = [p for p in path.split('/') if p]
            features['path_depth'] = len(path_parts)
            
            # Suspicious path keywords
            path_lower = path.lower()
            features['suspicious_path_keywords'] = sum(
                1 for keyword in self.suspicious_keywords 
                if keyword in path_lower
            )
            
            # File extension analysis
            if path_parts:
                last_part = path_parts[-1]
                if '.' in last_part:
                    extensions = last_part.split('.')
                    features['file_extension_count'] = len(extensions) - 1
                else:
                    features['file_extension_count'] = 0
            else:
                features['file_extension_count'] = 0
            
            # Path character analysis
            features['path_digit_count'] = sum(1 for c in path if c.isdigit())
            features['path_special_char_count'] = sum(
                1 for c in path 
                if not c.isalnum() and c not in '/-_.'
            )
            
        except Exception as e:
            print(f"Error in path feature extraction: {e}")
            features = {
                'path_depth': 0,
                'suspicious_path_keywords': 0,
                'file_extension_count': 0,
                'path_digit_count': 0,
                'path_special_char_count': 0
            }
        
        return features
    
    def _extract_character_features(self, url):
        """Extract character-based features"""
        features = {}
        
        try:
            # Character counts
            features['digit_count'] = sum(1 for c in url if c.isdigit())
            features['letter_count'] = sum(1 for c in url if c.isalpha())
            features['uppercase_count'] = sum(1 for c in url if c.isupper())
            features['lowercase_count'] = sum(1 for c in url if c.islower())
            
            # Special character counts
            features['special_char_count'] = sum(
                1 for c in url 
                if not c.isalnum() and c not in ':/.-_'
            )
            features['hyphen_count'] = url.count('-')
            features['underscore_count'] = url.count('_')
            features['dot_count'] = url.count('.')
            features['slash_count'] = url.count('/')
            features['question_count'] = url.count('?')
            features['ampersand_count'] = url.count('&')
            features['equal_count'] = url.count('=')
            
            # Character ratios
            url_length = len(url)
            if url_length > 0:
                features['digit_ratio'] = features['digit_count'] / url_length
                features['letter_ratio'] = features['letter_count'] / url_length
                features['special_char_ratio'] = features['special_char_count'] / url_length
            else:
                features['digit_ratio'] = 0
                features['letter_ratio'] = 0
                features['special_char_ratio'] = 0
            
        except Exception as e:
            print(f"Error in character feature extraction: {e}")
            features = {
                'digit_count': 0, 'letter_count': 0, 'uppercase_count': 0,
                'lowercase_count': 0, 'special_char_count': 0, 'hyphen_count': 0,
                'underscore_count': 0, 'dot_count': 0, 'slash_count': 0,
                'question_count': 0, 'ampersand_count': 0, 'equal_count': 0,
                'digit_ratio': 0, 'letter_ratio': 0, 'special_char_ratio': 0
            }
        
        return features
    
    def _extract_structural_features(self, url, parsed_url):
        """Extract structural features"""
        features = {}
        
        try:
            # Protocol features
            features['is_https'] = int(parsed_url.scheme == 'https')
            features['is_http'] = int(parsed_url.scheme == 'http')
            
            # Query parameter analysis
            query_params = parse_qs(parsed_url.query)
            features['query_param_count'] = len(query_params)
            
            # Suspicious parameters
            suspicious_params = {'redirect', 'return', 'next', 'continue', 'goto', 'url'}
            features['suspicious_param_count'] = sum(
                1 for param in query_params.keys() 
                if param.lower() in suspicious_params
            )
            
            # URL encoding
            features['url_encoded_chars'] = url.count('%')
            
            # Fragment analysis
            features['has_fragment'] = int(bool(parsed_url.fragment))
            
        except Exception as e:
            print(f"Error in structural feature extraction: {e}")
            features = {
                'is_https': 0, 'is_http': 0, 'query_param_count': 0,
                'suspicious_param_count': 0, 'url_encoded_chars': 0,
                'has_fragment': 0
            }
        
        return features
    
    def _extract_content_features(self, url, domain, path, query):
        """Extract content-based features"""
        features = {}
        
        try:
            # Keyword analysis
            full_text = (url + ' ' + domain + ' ' + path + ' ' + query).lower()
            
            # Brand mentions
            tech_brands = {'google', 'microsoft', 'apple', 'amazon', 'facebook', 'twitter', 'instagram'}
            financial_brands = {'paypal', 'visa', 'mastercard', 'bank', 'banking', 'finance'}
            
            features['tech_brand_mentions'] = sum(
                1 for brand in tech_brands 
                if brand in full_text
            )
            
            features['financial_brand_mentions'] = sum(
                1 for brand in financial_brands 
                if brand in full_text
            )
            
            # Suspicious keywords
            features['suspicious_keyword_count'] = sum(
                1 for keyword in self.suspicious_keywords 
                if keyword in full_text
            )
            
            # Language analysis (basic)
            features['non_ascii_chars'] = sum(
                1 for c in url 
                if ord(c) > 127
            )
            
        except Exception as e:
            print(f"Error in content feature extraction: {e}")
            features = {
                'tech_brand_mentions': 0,
                'financial_brand_mentions': 0,
                'suspicious_keyword_count': 0,
                'non_ascii_chars': 0
            }
        
        return features
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        try:
            # Count character frequencies
            char_counts = Counter(text.lower())
            text_length = len(text)
            
            # Calculate entropy
            entropy = 0.0
            for count in char_counts.values():
                probability = count / text_length
                if probability > 0:
                    entropy -= probability * math.log2(probability)
            
            return entropy
            
        except Exception as e:
            print(f"Error calculating entropy: {e}")
            return 0.0
    
    def _is_ip_address(self, domain):
        """Check if domain is an IP address"""
        try:
            import socket
            socket.inet_aton(domain)
            return True
        except socket.error:
            return False
    
    def _get_default_features(self):
        """Get default feature values in case of errors"""
        return {
            'url_length': 0, 'domain_length': 0, 'path_length': 0,
            'query_length': 0, 'fragment_length': 0, 'subdomain_count': 0,
            'path_depth': 0, 'special_char_count': 0, 'digit_count': 0,
            'letter_count': 0, 'uppercase_count': 0, 'has_ip': 0,
            'has_port': 0, 'is_https': 0, 'suspicious_tld': 0,
            'url_entropy': 0.0
        }
    
    def get_feature_names(self):
        """Get list of all feature names"""
        return [
            'url_length', 'domain_length', 'path_length', 'query_length',
            'fragment_length', 'subdomain_count', 'path_depth',
            'special_char_count', 'digit_count', 'letter_count',
            'uppercase_count', 'has_ip', 'has_port', 'is_https',
            'suspicious_tld', 'url_entropy'
        ]
