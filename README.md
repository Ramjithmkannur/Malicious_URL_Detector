# Malicious_URL_Detector
A simple Python tool to check if a URL is flagged as malicious using VirusTotal’s API. This this Script helps to detect phishing links, malicious domains, and unsafe URLs.

# Description
The Malicious URL Detector is a Python tool designed to interact with VirusTotal’s API to check the reputation of a URL. By analyzing the response from VirusTotal, it identifies whether a URL is Safe or Malicious.

## Features:
- Fetches URL reputation using VirusTotal’s public API.
- Checks if the URL is flagged as malicious.
- Provides feedback on URL safety status.

#### Installation

1. Clone the Repository
```
git clone https://github.com/your-username/malicious-url-detector.git
```

```
cd malicious-url-detector
```

2. Set Up Virtual Environment (Recommended)
```
python -m venv venv  # Create a virtual environment
```

```
source venv/bin/activate  # For Windows use `venv\Scripts\activate
```

3. Install Required Libraries
```
pip install requests tldextract
```

### Usage
1.Obtain a VirusTotal API Key
Sign up at VirusTotal and obtain an API key from API Settings.

2.Run the Script
```
python malicious_url_detector.py
```

3.Enter a URL to Check
The script will prompt you to enter a URL.
It will show whether the URL is Malicious or Safe.

### Example Output
> Enter a URL to check: https://www.example.com

> www.example.com - Status: Safe

