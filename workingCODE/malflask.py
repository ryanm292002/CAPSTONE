from flask import Flask, render_template, request
from OTXv2 import OTXv2, IndicatorTypes
import virustotal_python
from base64 import urlsafe_b64encode

app = Flask(__name__)

OTX_API_KEY = '6817b6201912aafd6e4edf725044c8abc7d00adf2f60d959eead0d0220c02bbb'
VT_API_KEY  = '68a54a91cf7d1f0575ff055fa3e860f68ab5716269acf8ac56339c97f50fa288'

def get_pulses(target):
    try:
        otx = OTXv2(OTX_API_KEY)
        data = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, target)
        pulses = data['general'].get('pulse_info', {}).get('pulses', [])
        return len(pulses)
    except Exception as err:
        return f"Failed to send URL: {target} for analysis and get pulses: {err}"

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        target = request.form.get('urlInput')

        with virustotal_python.Virustotal(VT_API_KEY) as scanurl:
            try:
                resp = scanurl.request("urls", data={"url": target}, method="POST")
                url_id = urlsafe_b64encode(target.encode()).decode().strip("=")
                report = scanurl.request(f"urls/{url_id}")
                malicious_scans = report.data.get('attributes', {}).get('last_analysis_stats', {}).get('malicious')
                if malicious_scans == 0:
                    vt_result = f"URL is clean according to VirusTotal, with 0 detections."
                else:
                    vt_result = f"URL is malicious according to VirusTotal, with {malicious_scans} detections."
            except virustotal_python.VirustotalError as err:
                vt_result = f"Failed to send URL: {target} for analysis and get the report: {err}"

        num_pulses = get_pulses(target)
        if num_pulses is not None:
            if num_pulses > 0:
                otx_result = f"The domain/url {target} has {num_pulses} pulses on AlienVault OTX"
            else:
                otx_result = f"The domain/url {target} has no pulses on AlienVault OTX"
        else:
            otx_result = f"Failed to get pulses for target: {target} on AlienVault OTX"

        return render_template('results.html', vt_result=vt_result, otx_result=otx_result)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)