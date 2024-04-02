from flask import Flask, render_template, request
from flask_limiter import Limiter
from OTXv2 import OTXv2, IndicatorTypes
import virustotal_python
from pysafebrowsing import SafeBrowsing
from base64 import urlsafe_b64encode
from urllib.parse import urlparse

app = Flask(__name__)
limiter = Limiter(app)

OTX_API_KEY = 'xxxxxxxxxxxxxxxxxxb'
VT_API_KEY  = 'xxxxxxxxxxxxxx8'
SAFE_BROWSING_API_KEY = 'xxxxxxxxxxxxx'

def get_domain_from_url(url):
    parsed_uri = urlparse(url)
    domain = '{uri.netloc}'.format(uri=parsed_uri)
    return domain if domain else '{uri.path}'.format(uri=parsed_uri)

def get_pulses(target):
    try:
        otx = OTXv2(OTX_API_KEY)
        data = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, target)
        pulses = data['general'].get('pulse_info', {}).get('pulses', [])
        return len(pulses)
    except Exception as err:
        print(f"Failed to send URL: {target} for analysis, get pulses: {err}")
        return None

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("3/minute")  # Rate limit: max 3 requests per minute
def index():
    vt_result = otx_result = sb_result = score_result = error_message = ''
    risk_score_percentage = 0

    if request.method == 'POST':
        target = request.form.get('urlInput')
        target = get_domain_from_url(target)
        if not target:
            error_message = "No URL was entered. Please enter a URL."
            return render_template('index.html', error_message=error_message)

        with virustotal_python.Virustotal(VT_API_KEY) as scanurl:
            try:
                resp = scanurl.request("urls", data={"url": target}, method="POST")
                url_id = urlsafe_b64encode(target.encode()).decode().strip("=")
                report = scanurl.request(f"urls/{url_id}")
                malicious_scans = report.data.get('attributes', {}).get('last_analysis_stats', {}).get('malicious')
                if malicious_scans > 0:
                    vt_result = f"URL is malicious according to VirusTotal, with {malicious_scans} detections."
                    risk_score_percentage += 25
                else:
                    vt_result = f"URL is clean according to VirusTotal, with 0 detections."
            except virustotal_python.VirustotalError as err:
                vt_result = f"Failed to send URL: {target} for analysis and get the report: {err}"

        num_pulses = get_pulses(target)
        if num_pulses is not None and isinstance(num_pulses, int) and num_pulses > 0:
            risk_score_percentage += 25
            otx_result = f"The domain/url {target} has {num_pulses} pulses on AlienVault OTX"
        else:
            otx_result = f"The domain/url {target} has no pulses on AlienVault OTX"

        try:
            s = SafeBrowsing(SAFE_BROWSING_API_KEY)
            r = s.lookup_urls([target])
            if r[target]['malicious']:
                threats = ', '.join(r[target]['threats'])
                sb_result = f"The URL {target} is flagged as unsafe due to: {threats}"
                risk_score_percentage += 50
            else:
                sb_result = f"The URL {target} is Safe according to Google Safe Browsing."
        except Exception as err:
            sb_result = f"Failed to send URL: {target} for checking via Google Safe Browsing: {err}"

        risk_score_percentage = min(risk_score_percentage, 100)

        try:
            if risk_score_percentage >= 50:
                score_result = f"This URL is seen as a malicious threat // Please use maximum caution"
            elif risk_score_percentage > 25:
                score_result = f"This URL is seen as a possible risk, based off the individual results and your own research continue "
            else:
                score_result = f"We have not detected anything but please always continue with caution when using the internet :)"
        except Exception as e:
            print(f"An error occurred: {e}")
            score_result = f"An error occurred when calculating risk score: {e}"

        return render_template('results.html', vt_result=vt_result, otx_result=otx_result, score_result=score_result, sb_result=sb_result, risk_score_percentage=risk_score_percentage, error_message=error_message)
    return render_template('index.html', error_message=error_message)

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

if __name__ == '__main__':
    app.run(debug=False)
