# Import necessary libraries
import virustotal_python  # Import the Virustotal API Python library
from base64 import urlsafe_b64encode  # Import a function to encode URLs in base64 format

# Define VirusTotal API key
api_key = "MY KEY NOT YOURS"

# Define URL that needs to be scanned
url = input('Which URL would you like to check for maliciousness?: ')


# Create a Virustotal API instance using API key
with virustotal_python.Virustotal(api_key) as scanurl:
    try:
        # Submit the URL for analysis to Virustotal
        resp = scanurl.request("urls", data={"url": url}, method="POST")

        # Encode the URL in base64 format to use it as an identifier
        url_id = urlsafe_b64encode(url.encode()).decode().strip("=")

        # Retrieve the analysis report for the URL from Virustotal
        report = scanurl.request(f"urls/{url_id}")

        # Check if the report indicates that the URL is not malicious, if malicious print text, if no malicious flag say virus total finds it to be clean
        if report.data.get("attributes", {}).get("last_analysis_stats", {}).get("malicious") == 0:
            print("URL is clean according to Virus Total")
        else:
            print("URL is malicious According to Virus Total.")

        # Print additional information from the report
        print("Scan Date:", report.data.get("attributes", {}).get("last_analysis_date"))
        print("Total Scans:", report.data.get("attributes", {}).get("total"))
        print("Positive Scans:", report.data.get("attributes", {}).get("positives"))

        # Print the individual scan results from different antivirus engines
        print("Scan Results:")
        for scan, result in report.data.get("attributes", {}).get("last_analysis_results", {}).items():
            print(f"{scan}: {result.get('result')}")

    except virustotal_python.VirustotalError as err:
        print(f"Failed to send URL: {url} for analysis and get the report: {err}")
