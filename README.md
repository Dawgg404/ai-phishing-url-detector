# Phishing URL Detector

A comprehensive real-time phishing URL detection system that combines multiple analysis techniques to identify and classify malicious URLs.

---

## Features

- **Machine Learning Classification**: Trained using a Random Forest model with 16+ handcrafted features.
- **Regex Pattern Matching**: Detects suspicious URL structures, obfuscation, and known phishing tactics.
- **Domain Intelligence**: Performs WHOIS lookups, checks SSL certificate validity, and evaluates domain reputation.
- **Real-time Analysis**: Quickly classifies single URLs with a confidence score.
- **Batch Processing**: Analyze multiple URLs from a file with progress indicators.
- **Interactive Web UI**: Built with Streamlit for a simple and effective user experience.

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/phishing-url-detector.git
cd phishing-url-detector
```

### 2. Install Dependencies

Make sure you have Python 3.11+ installed.

```bash
pip install -r requirements.txt
```

### 3. Run the App

```bash
streamlit run app.py
```

Then open your browser and go to: http://localhost:8501

---

## Technology Stack

| Component       | Purpose                      |
|-----------------|------------------------------|
| Python 3.11+     | Core programming language     |
| Streamlit        | Frontend web interface        |
| scikit-learn     | Machine learning modeling     |
| pandas & numpy   | Data processing and analysis  |
| python-whois     | Domain lookup and analysis    |
| requests         | HTTP requests and validation  |

---

## License

This project is licensed under the MIT License. See LICENSE for more information.
