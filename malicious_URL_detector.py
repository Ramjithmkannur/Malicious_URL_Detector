import requests
import tldextract

def check_url_reputation(url):
    api_key = 'YOUR_VIRUSTOTAL_API_KEY'  # Replace with your API key
    vt_api_url = f'https://www.virustotal.com/api/v3/urls'

    # Extract domain from URL
    domain_info = tldextract.extract(url)
    domain = f'{domain_info.domain}.{domain_info.suffix}'

    headers = {
        'x-apikey': api_key
    }

    # Check URL reputation
    response = requests.get(f'{vt_api_url}/{domain}', headers=headers)
    
    if response.status_code == 200:
        result = response.json()
        # Check for the correct structure of the response
        if 'data' in result:
            last_analysis_stats = result['data']['attributes']['last_analysis_stats']
            if last_analysis_stats['malicious'] > 0:
                return 'Malicious'
            else:
                return 'Safe'
        else:
            return 'No Data Found'
    else:
        return 'Error in API Request'

# Example usage
if __name__ == "__main__":
    url = input("Enter a URL to check: ")
    result = check_url_reputation(url)
    print(f"URL: {url} - Status: {result}")
