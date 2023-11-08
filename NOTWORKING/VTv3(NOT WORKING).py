import requests

API_KEY = '68a54a91cf7d1f0575ff055fa3e860f68ab5716269acf8ac56339c97f50fa288'
URL_TO_CHECK = "https://youtube.com"  # Replace with the URL you want to check

def check_url_reputation(api_key, url):
    endpoint = 'https://www.virustotal.com/api/v3/urls/analyze'
    headers = {
        'x-apikey': api_key
    }
    data = {
        'url': url
    }
    response = requests.post(endpoint, headers=headers, json=data)

    if response.status_code == 200:
        result = response.json()
        return result
    else:
        print(f'Error: {response.status_code}')
        return None

if __name__ == '__main__':
    url_info = check_url_reputation(API_KEY, URL_TO_CHECK)

    if url_info:
        print('URL Information:')
        print(f'URL: {URL_TO_CHECK}')
        print(f'Scan Date: {url_info["data"]["attributes"]["last_modification_date"]}')
        print(f'Positives: {url_info["data"]["attributes"]["last_analysis_stats"]["malicious"]}')
        print(f'Total Scans: {url_info["data"]["attributes"]["last_analysis_stats"]["total"]}')
    else:
        print('URL information not available.')

