from pysafebrowsing import SafeBrowsing
dakey = SafeBrowsing('AIzaSyAoY1tC4xBGny1DzE4jhZsez4UXiOnLf5M')
daurl = dakey.lookup_urls(['http://malware.testing.google.test/testing/malware/'])

for url, info in daurl.items():
    if info['malicious']:
        print(f'The URL {url} is Malicious.')
    else:
        print(f' {url} not rated as malicious .')