import streamlit as st
import pandas as pd
import numpy as np
import io
import time
from datetime import datetime
import traceback

from src.url_analyzer import URLAnalyzer
from src.ml_model import PhishingMLModel
from src.domain_analyzer import DomainAnalyzer
from src.regex_patterns import RegexPatterns
from src.feature_extractor import FeatureExtractor

# Initialize components
@st.cache_resource
def initialize_components():
    """Initialize all analysis components"""
    try:
        ml_model = PhishingMLModel()
        domain_analyzer = DomainAnalyzer()
        regex_patterns = RegexPatterns()
        feature_extractor = FeatureExtractor()
        url_analyzer = URLAnalyzer(ml_model, domain_analyzer, regex_patterns, feature_extractor)
        
        # Train model if not already trained
        if not ml_model.is_trained():
            with st.spinner("Training ML model... This may take a moment."):
                ml_model.train_model()
        
        return url_analyzer
    except Exception as e:
        st.error(f"Error initializing components: {str(e)}")
        st.stop()

def main():
    st.set_page_config(
        page_title="Phishing URL Detector",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Header
    st.title("🔒 Real-Time Phishing URL Detector")
    st.markdown("**Advanced cybersecurity tool for detecting malicious URLs using machine learning and domain analysis**")
    
    # Initialize analyzer
    url_analyzer = initialize_components()
    
    # Sidebar for configuration
    with st.sidebar:
        st.header("⚙️ Configuration")
        
        analysis_mode = st.selectbox(
            "Analysis Mode",
            ["Single URL", "Batch Analysis"]
        )
        
        confidence_threshold = st.slider(
            "Confidence Threshold",
            min_value=0.0,
            max_value=1.0,
            value=0.5,
            step=0.05,
            help="Minimum confidence score to classify as phishing"
        )
        
        enable_whois = st.checkbox(
            "Enable WHOIS Lookup",
            value=True,
            help="Perform domain registration analysis (may be slower)"
        )
        
        st.markdown("---")
        st.markdown("### 📊 Analysis Features")
        st.markdown("""
        - **ML Classification**: Trained model detection
        - **Regex Patterns**: Common phishing indicators
        - **URL Features**: Length, special characters, structure
        - **Domain Analysis**: WHOIS and reputation data
        - **Real-time Results**: Instant classification
        """)
    
    # Main content
    if analysis_mode == "Single URL":
        single_url_analysis(url_analyzer, confidence_threshold, enable_whois)
    else:
        batch_analysis(url_analyzer, confidence_threshold, enable_whois)
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666;'>
        <p>🛡️ Phishing URL Detector v1.0 | Built with Streamlit & Machine Learning</p>
    </div>
    """, unsafe_allow_html=True)

def single_url_analysis(url_analyzer, confidence_threshold, enable_whois):
    """Handle single URL analysis"""
    st.header("🔍 Single URL Analysis")
    
    # URL input
    col1, col2 = st.columns([3, 1])
    
    with col1:
        url_input = st.text_input(
            "Enter URL to analyze:",
            placeholder="https://example.com",
            help="Enter a complete URL including protocol (http/https)"
        )
    
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)  # Add spacing
        analyze_button = st.button("🔍 Analyze URL", type="primary")
    
    # Example URLs for testing
    st.markdown("**Quick Test URLs:**")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("Test Legitimate URL"):
            url_input = "https://www.google.com"
            st.rerun()
    
    with col2:
        if st.button("Test Suspicious URL"):
            url_input = "http://goog1e-security-update.tk/login"
            st.rerun()
    
    with col3:
        if st.button("Test Another Example"):
            url_input = "https://paypal-verification-secure.net/signin"
            st.rerun()
    
    # Analysis
    if url_input and (analyze_button or url_input):
        if not url_input.startswith(('http://', 'https://')):
            st.warning("⚠️ Please include protocol (http:// or https://) in the URL")
            return
        
        with st.spinner("Analyzing URL... This may take a few seconds."):
            try:
                result = url_analyzer.analyze_url(url_input, enable_whois)
                display_single_result(result, confidence_threshold)
            except Exception as e:
                st.error(f"❌ Analysis failed: {str(e)}")
                with st.expander("Error Details"):
                    st.code(traceback.format_exc())

def batch_analysis(url_analyzer, confidence_threshold, enable_whois):
    """Handle batch URL analysis"""
    st.header("📋 Batch URL Analysis")
    
    # File upload
    uploaded_file = st.file_uploader(
        "Upload file with URLs",
        type=['csv', 'txt'],
        help="CSV file with 'url' column or text file with one URL per line"
    )
    
    # Text area input
    st.markdown("**Or paste URLs directly:**")
    urls_text = st.text_area(
        "Enter URLs (one per line):",
        height=150,
        placeholder="https://example1.com\nhttps://example2.com\nhttps://example3.com"
    )
    
    # Process batch
    if st.button("🚀 Analyze Batch", type="primary"):
        urls = []
        
        # Get URLs from file or text
        if uploaded_file:
            urls = process_uploaded_file(uploaded_file)
        elif urls_text.strip():
            urls = [url.strip() for url in urls_text.strip().split('\n') if url.strip()]
        
        if not urls:
            st.warning("⚠️ Please provide URLs via file upload or text input")
            return
        
        # Validate URLs
        valid_urls = [url for url in urls if url.startswith(('http://', 'https://'))]
        if len(valid_urls) < len(urls):
            st.warning(f"⚠️ Filtered {len(urls) - len(valid_urls)} invalid URLs (missing protocol)")
        
        if not valid_urls:
            st.error("❌ No valid URLs found")
            return
        
        # Analyze batch
        analyze_batch_urls(url_analyzer, valid_urls, confidence_threshold, enable_whois)

def process_uploaded_file(uploaded_file):
    """Process uploaded file and extract URLs"""
    try:
        if uploaded_file.name.endswith('.csv'):
            df = pd.read_csv(uploaded_file)
            if 'url' in df.columns:
                return df['url'].dropna().tolist()
            elif len(df.columns) == 1:
                return df.iloc[:, 0].dropna().tolist()
            else:
                st.error("❌ CSV file must have a 'url' column or single column with URLs")
                return []
        else:  # txt file
            content = uploaded_file.getvalue().decode('utf-8')
            return [url.strip() for url in content.split('\n') if url.strip()]
    except Exception as e:
        st.error(f"❌ Error processing file: {str(e)}")
        return []

def analyze_batch_urls(url_analyzer, urls, confidence_threshold, enable_whois):
    """Analyze batch of URLs with progress tracking"""
    st.markdown(f"**Analyzing {len(urls)} URLs...**")
    
    # Progress tracking
    progress_bar = st.progress(0)
    status_text = st.empty()
    results_container = st.empty()
    
    results = []
    start_time = time.time()
    
    for i, url in enumerate(urls):
        status_text.text(f"Analyzing URL {i+1}/{len(urls)}: {url[:50]}...")
        
        try:
            result = url_analyzer.analyze_url(url, enable_whois)
            results.append(result)
        except Exception as e:
            # Add error result
            error_result = {
                'url': url,
                'is_phishing': False,
                'confidence': 0.0,
                'ml_prediction': 'Error',
                'error': str(e)
            }
            results.append(error_result)
        
        progress_bar.progress((i + 1) / len(urls))
    
    elapsed_time = time.time() - start_time
    status_text.text(f"✅ Analysis complete! Processed {len(urls)} URLs in {elapsed_time:.1f} seconds")
    
    # Display batch results
    display_batch_results(results, confidence_threshold)

def display_single_result(result, confidence_threshold):
    """Display results for single URL analysis"""
    # Main result card
    is_phishing = result.get('confidence', 0) >= confidence_threshold
    
    if is_phishing:
        st.error(f"🚨 **PHISHING DETECTED** (Confidence: {result.get('confidence', 0):.2%})")
    else:
        st.success(f"✅ **URL appears LEGITIMATE** (Confidence: {result.get('confidence', 0):.2%})")
    
    # Detailed analysis
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("📊 Analysis Summary")
        st.metric("ML Confidence", f"{result.get('confidence', 0):.2%}")
        st.metric("Classification", "Phishing" if is_phishing else "Legitimate")
        
        if 'regex_matches' in result:
            st.metric("Regex Matches", len(result['regex_matches']))
    
    with col2:
        st.subheader("🔍 URL Features")
        features = result.get('features', {})
        if features:
            st.write(f"**URL Length:** {features.get('url_length', 'N/A')}")
            st.write(f"**Domain Length:** {features.get('domain_length', 'N/A')}")
            st.write(f"**Special Characters:** {features.get('special_char_count', 'N/A')}")
            st.write(f"**Subdomain Count:** {features.get('subdomain_count', 'N/A')}")
    
    # Detailed breakdowns
    if 'regex_matches' in result and result['regex_matches']:
        with st.expander("🔍 Regex Pattern Matches"):
            for pattern in result['regex_matches']:
                st.write(f"- {pattern}")
    
    if 'domain_info' in result and result['domain_info']:
        with st.expander("🌐 Domain Information"):
            domain_info = result['domain_info']
            for key, value in domain_info.items():
                if value:
                    st.write(f"**{key.replace('_', ' ').title()}:** {value}")
    
    if 'features' in result:
        with st.expander("📈 All Features"):
            st.json(result['features'])

def display_batch_results(results, confidence_threshold):
    """Display results for batch analysis"""
    if not results:
        st.warning("No results to display")
        return
    
    # Summary metrics
    total_urls = len(results)
    phishing_count = sum(1 for r in results if r.get('confidence', 0) >= confidence_threshold)
    legitimate_count = total_urls - phishing_count
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total URLs", total_urls)
    with col2:
        st.metric("🚨 Phishing Detected", phishing_count)
    with col3:
        st.metric("✅ Legitimate", legitimate_count)
    
    # Results table
    st.subheader("📋 Detailed Results")
    
    # Prepare data for table
    table_data = []
    for result in results:
        is_phishing = result.get('confidence', 0) >= confidence_threshold
        table_data.append({
            'URL': result.get('url', 'N/A'),
            'Classification': '🚨 Phishing' if is_phishing else '✅ Legitimate',
            'Confidence': f"{result.get('confidence', 0):.2%}",
            'Regex Matches': len(result.get('regex_matches', [])),
            'Status': 'Error' if 'error' in result else 'Success'
        })
    
    df = pd.DataFrame(table_data)
    
    # Display with filtering
    filter_option = st.selectbox("Filter Results:", ["All", "Phishing Only", "Legitimate Only", "Errors Only"])
    
    if filter_option == "Phishing Only":
        df = df[df['Classification'].str.contains('Phishing')]
    elif filter_option == "Legitimate Only":
        df = df[df['Classification'].str.contains('Legitimate')]
    elif filter_option == "Errors Only":
        df = df[df['Status'] == 'Error']
    
    st.dataframe(df, use_container_width=True)
    
    # Export functionality
    if st.button("📥 Export Results"):
        csv_buffer = io.StringIO()
        
        # Prepare detailed export data
        export_data = []
        for result in results:
            is_phishing = result.get('confidence', 0) >= confidence_threshold
            export_data.append({
                'url': result.get('url', 'N/A'),
                'is_phishing': is_phishing,
                'confidence': result.get('confidence', 0),
                'classification': 'Phishing' if is_phishing else 'Legitimate',
                'regex_matches': len(result.get('regex_matches', [])),
                'url_length': result.get('features', {}).get('url_length', ''),
                'domain_length': result.get('features', {}).get('domain_length', ''),
                'timestamp': datetime.now().isoformat(),
                'error': result.get('error', '')
            })
        
        export_df = pd.DataFrame(export_data)
        export_df.to_csv(csv_buffer, index=False)
        
        st.download_button(
            label="Download CSV Report",
            data=csv_buffer.getvalue(),
            file_name=f"phishing_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

if __name__ == "__main__":
    main()
