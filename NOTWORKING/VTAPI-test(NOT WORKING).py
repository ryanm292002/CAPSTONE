import virustotal_python
from pprint import pprint
from base64 import urlsafe_b64encode

url = "youtube.com"

with virustotal_python.Virustotal("68a54a91cf7d1f0575ff055fa3e860f68ab5716269acf8ac56339c97f50fa288") as vtotal:
    try:
        resp = vtotal.request("urls", data={"url": url}, method="POST")
        # Safe encode URL in base64 format
        # https://developers.virustotal.com/reference/url
        url_id = urlsafe_b64encode(url.encode()).decode().strip("=")
        report = vtotal.request(f"urls/{url_id}")
        pprint(report.object_type)
        pprint(report.data)
    except virustotal_python.VirustotalError as err:
        print(f"Failed to send URL: {url} for analysis and get the report: {err}")