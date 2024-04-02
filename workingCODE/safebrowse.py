from pysafebrowsing import SafeBrowsing
dakey = SafeBrowsing('apikey')
daurl = dakey.lookup_urls(['http://malware.testing.google.test/testing/malware/'])

for url, info in daurl.items():
    if info['malicious']:
        print(f'The URL {url} is Malicious.')
    else:
        print(f' {url} not rated as malicious .')
