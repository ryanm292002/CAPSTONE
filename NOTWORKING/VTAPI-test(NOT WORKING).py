import virustotal_python
from pprint import pprint
from base64 import urlsafe_b64encode

url = "youtube.com"

with virustotal_python.Virustotal("aa") as vtotal:
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
