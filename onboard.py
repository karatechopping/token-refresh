import requests
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from airtable import Airtable
from token_refresh import encrypt_data, load_config
import threading

# Load environment variables
load_dotenv()

class CallbackHandler(BaseHTTPRequestHandler):
    code = None

    def do_GET(self):
        query = urlparse(self.path).query
        params = parse_qs(query)
        code = params.get('code', [None])[0]

        if code:
            CallbackHandler.code = code
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Authorization successful! You can close this window.")
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Missing authorization code")

def run_server():
    server = HTTPServer(('localhost', 3000), CallbackHandler)
    server.timeout = 120  # 2 minute timeout
    server.handle_request()

def get_authorization_code(client_id: str):
    url = f"https://marketplace.gohighlevel.com/oauth/chooselocation?response_type=code&client_id={client_id}&redirect_uri=http://localhost:3000/callback&scope=medias.write%20medias.readonly"
    webbrowser.open(url)

    print("Starting temporary server to capture callback...")
    run_server()

    if CallbackHandler.code:
        return CallbackHandler.code
    else:
        raise Exception("Authorization code not received within 2 minutes")

def exchange_code(client_id: str, client_secret: str, auth_code: str) -> dict:
    token_url = "https://services.leadconnectorhq.com/oauth/token"
    payload = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': 'http://localhost:3000/callback'
    }
    response = requests.post(token_url, data=payload)
    response.raise_for_status()
    return response.json()

def onboard_new_client():
    try:
        print("=== Automated GoHighLevel Onboarding ===")
        location_id = input("Enter Location ID: ").strip()
        client_id = input("Enter Client ID: ").strip()
        client_secret = input("Enter Client Secret: ").strip()

        # Step 1: Get authorization code automatically
        auth_code = get_authorization_code(client_id)
        if not auth_code:
            raise ValueError("Failed to obtain authorization code")

        # Step 2: Exchange code for tokens
        token_data = exchange_code(client_id, client_secret, auth_code)
        access_token = token_data['access_token']
        refresh_token = token_data['refresh_token']
        expires_in = token_data['expires_in']

        # Step 3: Encrypt and store
        config = load_config()
        encryption_key = config['encryption_key_bytes']

        airtable = Airtable(
            config["airtable_base_id"],
            config["airtable_table_name"],
            config["airtable_api_key"]
        )

        update_data = {
            'locationId': location_id,
            'client_id': client_id,
            'encrypted_secret': encrypt_data(client_secret, encryption_key),
            'encrypted_refresh': encrypt_data(refresh_token, encryption_key),
            'last_access_token': access_token,
            'access_token_expiry': (datetime.now(timezone.utc) +
                                   timedelta(seconds=expires_in)).isoformat()
        }

        # Update or create record
        existing = airtable.search("locationId", location_id)
        if existing:
            airtable.update(existing[0]['id'], update_data)
            print(f"✅ Updated existing record for location {location_id}")
        else:
            airtable.insert(update_data)
            print(f"✅ Created new record for location {location_id}")

    except Exception as e:
        print(f"🚨 Error: {str(e)}")

if __name__ == "__main__":
    onboard_new_client()