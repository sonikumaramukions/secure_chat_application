# scanner_service.py (Final, Polling Version for Robust VT Detection)
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os
from urllib.parse import urlparse
import time

# --- IMPORTANT: PASTE YOUR API KEYS HERE ---
# NOTE: Using environment variables (os.environ.get) is the best practice.
# The hardcoded values below are placeholders and might be expired or invalid.
VIRUSTOTAL_API_KEY = os.environ.get("VT_API_KEY", "4f20311103753a8a81f2c6d2d883280980322160b050894d2a156d294fb4385f")
OTX_API_KEY = os.environ.get("OTX_API_KEY", "df1e85aba4f7578e8428e69ab9ff510fc85679df61d47bab3f3acf390034033f")

app = Flask(__name__)
CORS(app)

# -------------------------------------------------------------
# --- Individual API Check Functions (VirusTotal: Polling) ----
# -------------------------------------------------------------

def check_virustotal(url_to_check, headers):
    """
    Submits a URL for analysis to VirusTotal and polls for the final report.
    This prevents false negatives due to the scan not being immediately complete.
    """
    try:
        # Step 1: Submit the URL for analysis (POST)
        post_url = "https://www.virustotal.com/api/v3/urls"
        payload = { "url": url_to_check }
        response = requests.post(post_url, data=payload, headers=headers)
        response.raise_for_status()
        
        # Get the analysis ID for polling
        analysis_id = response.json()['data']['id']
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        
        # Step 2: Poll for the analysis report (GET with retries)
        MAX_ATTEMPTS = 10
        POLL_DELAY_SECONDS = 3 # Increased delay to respect Public API limits (4 requests/min)

        for attempt in range(MAX_ATTEMPTS):
            time.sleep(POLL_DELAY_SECONDS)
            
            report_response = requests.get(report_url, headers=headers)
            
            if report_response.status_code == 404:
                 # This should rarely happen for an analysis ID received immediately before
                return {"service": "VirusTotal", "status": "safe", "details": "Analysis ID not found"}
            
            report_response.raise_for_status()

            report_data = report_response.json()['data']['attributes']
            status = report_data.get('status')

            if status == 'completed':
                # Analysis finished, check the results
                stats = report_data.get('stats', {})
                if stats.get('malicious', 0) > 0:
                    return {"service": "VirusTotal", "status": "unsafe", "threat": "MALICIOUS"}
                
                # If completed but zero malicious detections
                return {"service": "VirusTotal", "status": "safe"}
            
            # If status is not 'completed', continue to the next attempt
            if attempt == MAX_ATTEMPTS - 1:
                print(f"[ERROR] VirusTotal analysis timed out after {MAX_ATTEMPTS} attempts.")
                return {"service": "VirusTotal", "status": "error", "details": "Timeout"}
            
    except requests.HTTPError as e:
        if e.response.status_code == 429:
            print("[ERROR] VirusTotal API Rate Limit Exceeded (429). Stop scanning.")
            return {"service": "VirusTotal", "status": "error", "details": "Rate Limit"}
        if e.response.status_code == 401:
            print("[ERROR] VirusTotal API Key Invalid (401).")
            return {"service": "VirusTotal", "status": "error", "details": "Invalid Key"}
        print(f"[ERROR] VirusTotal check failed with HTTP error: {e}")
        return {"service": "VirusTotal", "status": "error"}
    except Exception as e:
        print(f"[ERROR] VirusTotal check failed: {e}")
        return {"service": "VirusTotal", "status": "error"}

# -------------------------------------------------------------
# --- Individual API Check Functions (AlienVault OTX) ---------
# -------------------------------------------------------------

def check_otx(url_to_check, headers):
    """Checks the URL's HOSTNAME against the AlienVault OTX API."""
    try:
        hostname = urlparse(url_to_check).hostname
        if not hostname:
            return {"service": "OTX", "status": "safe", "details": "Could not parse hostname"}

        otx_api_url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{hostname}/general"
        response = requests.get(otx_api_url, headers=headers)
        
        if response.status_code == 404:
            return {"service": "OTX", "status": "safe", "details": "Not in database"}
        
        response.raise_for_status()
        
        # Check if the hostname is associated with any threat pulses
        if response.json().get('pulse_info', {}).get('count', 0) > 0:
            return {"service": "OTX", "status": "unsafe", "threat": "PULSE_DETECTED"}
        
        return {"service": "OTX", "status": "safe"}
    except Exception as e:
        print(f"[ERROR] OTX check failed: {e}")
        return {"service": "OTX", "status": "error"}

# -------------------------------------------------------------
# --- Flask Routes --------------------------------------------
# -------------------------------------------------------------

@app.route('/scan')
def scan_url():
    """Receives a URL and checks it against multiple security APIs."""
    url_to_check = request.args.get('url')
    if not url_to_check:
        return jsonify({"status": "error", "message": "URL parameter is missing."}), 400

    vt_headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    otx_headers = {"X-OTX-API-KEY": OTX_API_KEY}

    results = [
        check_virustotal(url_to_check, vt_headers),
        check_otx(url_to_check, otx_headers)
    ]
    
    print(f"\n[SCAN] Checking URL: {url_to_check}")
    for res in results:
        print(f"  - {res['service']}: {res['status']}")

    # Determine the final verdict
    for result in results:
        if result['status'] == 'unsafe':
            threat_type = result.get('threat', 'MALICIOUS')
            print(f"[VERDICT] UNSAFE. Flagged by {result['service']} as {threat_type}")
            return jsonify({"status": "unsafe", "threat": threat_type})
        elif result['status'] == 'error':
            # Handle API errors gracefully
            print(f"[VERDICT] ERROR. {result['service']} failed.")
            return jsonify({"status": "error", "message": f"Security check failed for {result['service']}."}), 500

    print(f"[VERDICT] SAFE.")
    return jsonify({"status": "safe"})

if __name__ == '__main__':
    # Running on 0.0.0.0 makes it accessible outside of the local machine (e.g., in a VM/Docker)
    # If running locally, 127.0.0.0 (default) is fine.
    app.run(host='127.0.0.1', port=5000)
