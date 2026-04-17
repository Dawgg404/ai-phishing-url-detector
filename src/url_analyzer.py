"""
Main URL analyzer that orchestrates all analysis components
"""

import traceback
from urllib.parse import urlparse
import time


class URLAnalyzer:
    def __init__(self, ml_model, domain_analyzer, regex_patterns, feature_extractor):
        self.ml_model = ml_model
        self.domain_analyzer = domain_analyzer
        self.regex_patterns = regex_patterns
        self.feature_extractor = feature_extractor
    
    def analyze_url(self, url, enable_whois=True):
        """
        Comprehensive URL analysis combining ML, regex, and domain analysis
        
        Args:
            url (str): URL to analyze
            enable_whois (bool): Whether to perform WHOIS lookup
            
        Returns:
            dict: Analysis results
        """
        try:
            start_time = time.time()
            
            # Parse URL
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                raise ValueError("Invalid URL format")
            
            # Extract features
            features = self.feature_extractor.extract_features(url, parsed_url)
            
            # ML prediction
            ml_confidence = 0.0
            ml_prediction = "Error"
            
            try:
                if self.ml_model.is_trained():
                    ml_confidence = self.ml_model.predict_single(features)
                    ml_prediction = "Phishing" if ml_confidence > 0.5 else "Legitimate"
            except Exception as e:
                print(f"ML prediction error: {e}")
            
            # Regex analysis
            regex_matches = self.regex_patterns.check_patterns(url)
            
            # Domain analysis
            domain_info = {}
            if enable_whois:
                try:
                    domain_info = self.domain_analyzer.analyze_domain(parsed_url.netloc)
                except Exception as e:
                    print(f"Domain analysis error: {e}")
                    domain_info = {"error": str(e)}
            
            # Combine results
            result = {
                "url": url,
                "confidence": ml_confidence,
                "ml_prediction": ml_prediction,
                "features": features,
                "regex_matches": regex_matches,
                "domain_info": domain_info,
                "analysis_time": time.time() - start_time,
                "is_phishing": ml_confidence > 0.5 or len(regex_matches) > 2
            }
            
            return result
            
        except Exception as e:
            return {
                "url": url,
                "error": str(e),
                "confidence": 0.0,
                "ml_prediction": "Error",
                "features": {},
                "regex_matches": [],
                "domain_info": {},
                "analysis_time": 0,
                "is_phishing": False
            }
    
    def analyze_batch(self, urls, enable_whois=True, progress_callback=None):
        """
        Analyze multiple URLs
        
        Args:
            urls (list): List of URLs to analyze
            enable_whois (bool): Whether to perform WHOIS lookup
            progress_callback (function): Optional callback for progress updates
            
        Returns:
            list: List of analysis results
        """
        results = []
        total_urls = len(urls)
        
        for i, url in enumerate(urls):
            try:
                result = self.analyze_url(url, enable_whois)
                results.append(result)
                
                if progress_callback:
                    progress_callback(i + 1, total_urls, url)
                    
            except Exception as e:
                error_result = {
                    "url": url,
                    "error": str(e),
                    "confidence": 0.0,
                    "ml_prediction": "Error",
                    "is_phishing": False
                }
                results.append(error_result)
        
        return results
