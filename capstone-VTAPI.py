import requests

# Replace with your actual VirusTotal API key
API_KEY = '68a54a91cf7d1f0575ff055fa3e860f68ab5716269acf8ac56339c97f50fa288'
URL_TO_CHECK = 'https://www.espn.com/'  # Replace with the URL you want to check

def URL_Check(api_key, url):
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': api_key, 'resource': url}
    response = requests.get(url, params=params)

    if response.status_code == 200:
        result = response.json()
        return result
    else:
        print(f'Error: {response.status_code}')
        return None

if __name__ == '__main__':
    url_info = URL_Check(API_KEY, URL_TO_CHECK)

    if url_info:
        print('URL Information:')
        print(f'URL: {URL_TO_CHECK}')
        print(f'Scan Date: {url_info["scan_date"]}')
        print(f'Positives: {url_info["positives"]}')
        print(f'Total Scans: {url_info["total"]}')
        print(f'Scan Results: {url_info["scans"]}')
    else:
        print('URL information not available.')
