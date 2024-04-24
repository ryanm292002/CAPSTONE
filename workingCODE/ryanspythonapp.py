# Import necessary libraries and modules for the Flask application.
from flask import Flask, render_template, request
from flask_limiter import Limiter  # For limiting the rate of API requests.
from OTXv2 import OTXv2, IndicatorTypes  # For accessing AlienVault OTX API.
import virustotal_python  # For interfacing with the VirusTotal API.
from pysafebrowsing import SafeBrowsing  # For using Google's Safe Browsing API.
from base64 import urlsafe_b64encode  # For encoding URLs into base64 safely.
from urllib.parse import urlparse  # To parse URLs to extract the domain.
import subprocess  # To run system commands like nslookup.

# Initialize the Flask application.
app = Flask(__name__)

# Set up rate limiting on the application to prevent abuse.
limiter = Limiter(app)

# API keys for various third-party services. Replace 'apikeyshere', 'HAHA', 'zzz' with actual API keys.
OTX_API_KEY = 'apikeyshere'
VT_API_KEY  = 'HAHA'
SAFE_BROWSING_API_KEY = 'zzz'

# Function to extract the domain from a URL.
def get_domain_from_url(url):
    parsed_uri = urlparse(url)
    domain = '{uri.netloc}'.format(uri=parsed_uri)
    return domain if domain else '{uri.path}'.format(uri=parsed_uri)

# Function to retrieve threat information about a domain from AlienVault OTX.
def get_pulses(target):
    try:
        otx = OTXv2(OTX_API_KEY)
        data = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, target)
        pulses = data['general'].get('pulse_info', {}).get('pulses', [])
        return len(pulses)
    except Exception as err:
        print(f"Failed to send URL: {target} for analysis, get pulses: {err}")
        return None

# Function to retrieve MX records for a domain using nslookup.
def get_mx_records(domain):
    try:
        result = subprocess.run(['nslookup', '-type=mx', domain], capture_output=True, text=True)
        if result.returncode != 0:
            return f"Error executing nslookup: {result.stderr}"
        return parse_nslookup_output(result.stdout)
    except subprocess.SubprocessError as e:
        return f"An error occurred while checking MX records: {str(e)}"

# Helper function to parse the output from nslookup command to make it look a little bit cleaner
def parse_nslookup_output(output):
    lines = output.split("\n")
    mx_records = []
    for line in lines:
        if 'MX preference' in line or 'mail exchanger' in line:
            parts = line.strip().split()
            if parts:
                mx_records.append(" ".join(parts))
    return mx_records
    
# Define the route for the home page of the website, handling both GET and POST requests.
@app.route('/', methods=['GET', 'POST'])
@limiter.limit("3/minute")  # Apply a rate limit of 3 requests per minute per client.
def index():
    # Initialize variables to store results and messages to display in the template.
    vt_result = otx_result = sb_result = score_result = error_message = ''
    mx_result = []
    risk_score_percentage = 0

    # Process form submission via post
    if request.method == 'POST':
        target = request.form.get('urlInput')
        domain = get_domain_from_url(target)
        if not domain:
            error_message = "No URL was entered. Please enter a URL."
            return render_template('index.html', error_message=error_message)

         # VirusTotal analysis (run if el input is post)
        with virustotal_python.Virustotal(VT_API_KEY) as scanurl:
            try:
                resp = scanurl.request("urls", data={"url": target}, method="POST")
                url_id = urlsafe_b64encode(target.encode()).decode().strip("=")
                report = scanurl.request(f"urls/{url_id}")
                malicious_scans = report.data.get('attributes', {}).get('last_analysis_stats', {}).get('malicious')
                if malicious_scans > 0:
                    vt_result = f"URL is malicious according to VirusTotal, with {malicious_scans} detections."
                    risk_score_percentage += 25  #adjustment of score whether or not there is or isnt any detections, this is same for VT,OTX and SB
                else:
                    vt_result = f"URL is clean according to VirusTotal, with 0 detections."
            except virustotal_python.VirustotalError as err:
                vt_result = f"Failed to send URL: {target} for analysis and get the report: {err}"

        # AlienVault OTX API call to get pulses data for the domain.
        num_pulses = get_pulses(domain)
        if num_pulses is not None and isinstance(num_pulses, int) and num_pulses > 0:
            otx_result = f"The domain/url {domain} has {num_pulses} pulses on AlienVault OTX"
            risk_score_percentage += 25
        else:
            otx_result = f"The domain/url {domain} has no pulses on AlienVault OTX"

        mx_result = get_mx_records(domain)

        # Use Google Safe Browsing API to check if the domain is considered safe.
        try:
            safe = SafeBrowsing(SAFE_BROWSING_API_KEY)
            resultz = safe.lookup_urls([domain])
            if resultz[domain]['malicious']:
                threats = ', '.join(resultz[domain]['threats'])
                sb_result = f"The URL {domain} is flagged as unsafe due to: {threats}"
                risk_score_percentage += 50  # Significantly increase risk score if flagged by Google.
            else:
                sb_result = f"The URL {domain} is Safe according to Google Safe Browsing."
        except Exception as err:
            sb_result = f"Failed to send URL: {domain} for checking, see following: {err}"

        risk_score_percentage = min(risk_score_percentage, 100)
# calculate the risk score based on the results
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

# Define routes for the About and Contact pages.
@app.route('/about')  
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')


# Start the Flask application if this script is run directly.
if __name__ == '__main__':
    app.run(debug=False)   # Turned off debugging as this is public, when testing locally I had turned this on
