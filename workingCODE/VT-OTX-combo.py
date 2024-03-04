from OTXv2 import OTXv2, IndicatorTypes
import virustotal_python
from base64 import urlsafe_b64encode

# OTX and VT API keys
OTX_API_KEY = '6817b6201912aafd6e4edf725044c8abc7d00adf2f60d959eead0d0220c02bbb'
VT_API_KEY = '68a54a91cf7d1f0575ff055fa3e860f68ab5716269acf8ac56339c97f50fa288'

# Function to get pulses on OTX
def get_pulses(target):
    try:
        otx = OTXv2(OTX_API_KEY)
        data = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, target)
        pulses = data['general'].get('pulse_info', {}).get('pulses', [])
        return len(pulses)
    except Exception as err:
        print(f"Failed to send URL: {target} for analysis and get pulses: {err}")
        return None

target = input('Which URL would you like to check for maliciousness?: ')

# VirusTotal analysis
with virustotal_python.Virustotal(VT_API_KEY) as scanurl:
    try:
        resp = scanurl.request("urls", data={"url": target}, method="POST")
        url_id = urlsafe_b64encode(target.encode()).decode().strip("=")
        report = scanurl.request(f"urls/{url_id}")
        malicious_scans = report.data.get('attributes', {}).get('last_analysis_stats', {}).get('malicious')
        if malicious_scans == 0:
            print(f"URL is clean according to VirusTotal, with 0 detections.")
        else:
            print(f"URL is malicious according to VirusTotal, with {malicious_scans} detections.")
    except virustotal_python.VirustotalError as err:
        print(f"Failed to send URL: {target} for analysis and get the report: {err}")

# OTX analysis
num_pulses = get_pulses(target)
if num_pulses is not None:
    print(f"The domain/url {target} has {num_pulses} pulses on AlienVault OTX")