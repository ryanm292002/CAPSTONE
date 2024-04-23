from flask import Flask, render_template, request  # loading modules from various packages needed to make the script run.
from flask_limiter import Limiter # limiter
from OTXv2 import OTXv2, IndicatorTypes # otx module
import virustotal_python # VT module
from pysafebrowsing import SafeBrowsing #safebrowsiing module
from base64 import urlsafe_b64encode #needed to convert url input to base64
from urllib.parse import urlparse # for parsing domain from full url
import subprocess


app = Flask(__name__)
limiter = Limiter(app)

OTX_API_KEY = 'apikeyshere' # API key variables
VT_API_KEY  = 'HAHA'
SAFE_BROWSING_API_KEY = 'zzz'

def get_domain_from_url(url): #functio to parse out domain from url
    parsed_uri = urlparse(url)
    domain = '{uri.netloc}'.format(uri=parsed_uri)
    return domain if domain else '{uri.path}'.format(uri=parsed_uri)



def get_pulses(target): # function to specifically focus on pulses which is otxs qualitative value on number of IOCs on domains/URLs
    try:
        otx = OTXv2(OTX_API_KEY)
        data = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, target)
        pulses = data['general'].get('pulse_info', {}).get('pulses', [])
        return len(pulses)
    except Exception as err:
        print(f"Failed to send URL: {target} for analysis, get pulses: {err}")
        return None

def get_mx_records(domain):
    try:
        # Use subprocess to call nslookup securely
        result = subprocess.run(
            ['nslookup', '-type=mx', domain],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            return f"Error executing nslookup: {result.stderr}"
        # Process the output to extract MX records
        return parse_nslookup_output(result.stdout)
    except subprocess.SubprocessError as e:
        return f"An error occurred while checking MX records: {str(e)}"


def parse_nslookup_output(output):
    lines = output.split("\n")
    mx_records = []
    for line in lines:
        if 'MX preference' in line or 'mail exchanger' in line:
            # Extract and clean the line for display
            parts = line.strip().split()
            if parts:
                mx_records.append(" ".join(parts))
    return mx_records  # Return as a list of records

@app.route('/', methods=['GET', 'POST']) #route to to the index page with the scripts inside the search bar, get brings to home page, post or the input on the search bar will initiate the scripts
@limiter.limit("3/minute")  # Rate limit: max 3 requests per minute
def index():
    vt_result = otx_result = sb_result = score_result = error_message = ''
    mx_result = []
    risk_score_percentage = 0   # setting the risk score initially as 0 as the minimum would be 0 and max is 100

    if request.method == 'POST':
        target = request.form.get('urlInput')
        domain = get_domain_from_url(target)  # Extract domain from URL input
        if not domain:
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


        num_pulses = get_pulses(domain)
        if num_pulses is not None and isinstance(num_pulses, int) and num_pulses > 0:
            otx_result = f"The domain/url {domain} has {num_pulses} pulses on AlienVault OTX"
            risk_score_percentage += 25
        else:
            otx_result = f"The domain/url {domain} has no pulses on AlienVault OTX"

        mx_result = get_mx_records(domain)

        try:
            safe = SafeBrowsing(SAFE_BROWSING_API_KEY)
            resultz = safe.lookup_urls([domain])
            if resultz[domain]['malicious']:
                threats = ', '.join(resultz[domain]['threats'])
                sb_result = f"The URL {domain} is flagged as unsafe due to: {threats}"
                risk_score_percentage += 50
            else:
                sb_result = f"The URL {domain} is Safe according to Google Safe Browsing."
        except Exception as err:
            sb_result = f"Failed to send URL: {domain} for checking, see following: {err}"

        risk_score_percentage = min(risk_score_percentage, 100)

        try:
            if risk_score_percentage >= 50:
                score_result = f"This URL is seen as a malicious threat // Please use maximum caution"
            elif risk_score_percentage >= 25:
                score_result = f"This URL is seen as a possible risk, use the individual results and your own research to determine saftey before proceeding "
            else:
                score_result = f"We have not detected anything but please always continue with caution when using the internet :)"
        except Exception as e:
            print(f"An error occurred: {e}")
            score_result = f"An error occurred when calculating risk score: {e}"

        return render_template('results.html', vt_result=vt_result, mx_result=mx_result, otx_result=otx_result, score_result=score_result, sb_result=sb_result, risk_score_percentage=risk_score_percentage, error_message=error_message)
    return render_template('index.html', error_message=error_message)
    #the above returns the actual results to the results.html page, aswell as returning the template for index.html which all of this is included in through the search bar.


@app.route('/about')  # routes to the about and contact page
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

if __name__ == '__main__':
    app.run(debug=False)   #starts the server
